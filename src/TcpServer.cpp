#include "TcpServer.hpp"
#include "Config.hpp"
#include "FileDescriptor.hpp"
#include "Logger.hpp"
#include "PacketUtil.hpp"
#include "Protocol.hpp"
#include "SystemReader.hpp"
#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <unistd.h>

namespace SST {

// static std::string hexToBytes(const std::string &hex) {
//   std::string bytes;
//   for (unsigned int i = 0; i < hex.length(); i += 2) {
//     std::string byteString = hex.substr(i, 2);
//     char byte = (char)strtol(byteString.c_str(), NULL, 16);
//     bytes.push_back(byte);
//   }
//   return bytes;
// }

TcpServer::TcpServer(int port)
    : port_(port), server_fd_(-1), epoll_fd_(-1), timer_fd_(-1){
  if(!SST::Config::getServerKeypair(server_static_priv_, server_static_pub_)){
    throw std::runtime_error("Failed to load server keypair");
  }
  initSocket();
  initEpoll();
  initTimer();
}

TcpServer::~TcpServer() { SST::Logger::log("[Server] Stopped."); }

void TcpServer::initSocket() {
  int tmp_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (tmp_fd < 0) {
    throw std::runtime_error("Socket creation failed");
  }
  server_fd_ = SST::FD(tmp_fd);

  int opt = 1;
  // 서버를 재시작할 경우 커널이 이전 소켓을 정리하지 못하고 "Address already in
  // use" 에러가 발생할 수 있음 이를 방지하기 위해 SO_REUSEADDR 옵션을 설정하여
  // 소켓이 즉시 재사용될 수 있도록 함
  if (setsockopt(server_fd_.get(), SOL_SOCKET, SO_REUSEADDR, &opt,
                 sizeof(opt)) < 0) {
    throw std::runtime_error("socket option setting failed");
  }

  struct sockaddr_in addr;
  char ip_buf[INET_ADDRSTRLEN];
  std::memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(port_);
  const char *ip_str =
      inet_ntop(AF_INET, &addr.sin_addr, ip_buf, INET_ADDRSTRLEN);
  SST::Logger::log(std::string("[Server] Binding to address ") +
                   (ip_str ? ip_str : "Unknown"));

  setNonBlocking(server_fd_.get());
  if (bind(server_fd_.get(), (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    throw std::runtime_error("Socket bind failed");
  }

  if (listen(server_fd_.get(), MAX_EVENTS) < 0) {
    throw std::runtime_error("Socket listen failed");
  }

  SST::Logger::log("[Server] Listening on port " + std::to_string(port_));
}

void TcpServer::setNonBlocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags == -1)
    return;
  fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

void TcpServer::initEpoll() {
  epoll_fd_ = SST::FD(epoll_create1(0));
  if (epoll_fd_.get() == -1) {
    throw std::runtime_error("Epoll instance creation failed");
  }
  struct epoll_event event;
  event.events = EPOLLIN;
  event.data.fd = server_fd_.get();

  if (epoll_ctl(epoll_fd_.get(), EPOLL_CTL_ADD, server_fd_.get(), &event) == -1) {
    throw std::runtime_error("Epoll ctl add server fd failed");
  }
}

// 타이머 초기화 (1초 주기)
void TcpServer::initTimer() {
  int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
  if (tfd == -1) {
    throw std::runtime_error("Timerfd creation failed");
  }
  timer_fd_ = SST::FD(tfd);

  struct itimerspec ts;
  ts.it_interval.tv_sec = 1;
  ts.it_interval.tv_nsec = 0;
  ts.it_value.tv_sec = 1;
  ts.it_value.tv_nsec = 0;

  if (timerfd_settime(timer_fd_.get(), 0, &ts, nullptr) < 0) {
    throw std::runtime_error("Timerfd settime failed");
  }

  struct epoll_event event;
  event.events = EPOLLIN;
  event.data.fd = timer_fd_.get();
  if (epoll_ctl(epoll_fd_.get(), EPOLL_CTL_ADD, timer_fd_.get(), &event) < 0) {
    throw std::runtime_error("Timerfd epoll add failed");
  }
  SST::Logger::log("[Server] Timerfd initialized (1s interval)");
}

void TcpServer::run() {
  is_running_ = true;
  while (is_running_) {
    if (stop_flag_ && *stop_flag_) {
      is_running_ = false;
      break;
    }

    int occurred_fds = epoll_wait(epoll_fd_.get(), events, MAX_EVENTS, 500);
    if (occurred_fds < 0) {
      if (errno == EINTR)
        continue;
      SST::Logger::log("[Error] Epoll wait error");
      break;
    }

    for (int i = 0; i < occurred_fds; i++) {
      int cur_fd = events[i].data.fd;
      uint32_t ev = events[i].events;

      // 새로운 연결 요청 처리
      if (cur_fd == server_fd_.get()) {
        acceptConnection();
      } else if (cur_fd == timer_fd_.get()) {
        // 타이머 이벤트 처리 (Broadcast)
        uint64_t expirations;
        ssize_t n = read(cur_fd, &expirations,
                         sizeof(expirations)); // 타이머 읽어서 클리어
        if (n > 0)
          broadcastStats();
      } else {
        if (ev & EPOLLIN) {
          handleClientData(cur_fd); // 클라이언트 데이터 처리
        } else if (ev & EPOLLOUT) {
          handleWrite(cur_fd); // 클라이언트 쓰기 처리
        } 
        if (ev & (EPOLLERR | EPOLLHUP)) {
          handleDisconnect(cur_fd); // 클라이언트 연결 해제 관리
        }
      }
    }
  }
}

// 연결된 모든 클라이언트에게 송신
void TcpServer::broadcastStats(){
  if(clients_.empty()) return;

  SystemStats stats = SystemReader::getInstance().getStats();
  std::vector<uint8_t> body(sizeof(SystemStats));
  std::memcpy(body.data(), &stats, sizeof(SystemStats));

  for(auto &[fd, client_info] : clients_){
    if(!client_info.authenticated) continue; // 인증된 사용자에게만 송신

    auto state_it =  client_states_.find(fd);
    if(state_it == client_states_.end()) continue;
    ClientState &state = state_it->second;

    std::vector<uint8_t> packet = PacketUtil::createPacket(
        (uint8_t)SST::MessageType::RES_SystemStat, state.last_seq++, body);

    std::vector<uint8_t> cyperText = state.noise.encrypt(packet.data(), packet.size());
    if(cyperText.empty()) continue;

    uint32_t ct_len = (uint32_t)cyperText.size();
    uint8_t len_buf[4] = {
      uint8_t(ct_len),
      uint8_t(ct_len >> 8),
      uint8_t(ct_len >> 16),
      uint8_t(ct_len >> 24)
    };

    if(!state.write_buffer.write(len_buf, 4)) continue;
    if(!state.write_buffer.write(cyperText.data(), cyperText.size())) continue;
    updateEpollEvents(fd, EPOLLIN | EPOLLOUT);
  }
}

void TcpServer::acceptConnection() {
  struct sockaddr_in client_addr;
  socklen_t client_len = sizeof(client_addr);

  int access_fd = accept(server_fd_.get(), (struct sockaddr *)&client_addr, &client_len);
  if (access_fd < 0) return;

  // HandShake
  NoiseSession noise;
  if(!noise.handshakeServer(access_fd, server_static_priv_, server_static_pub_)){
    SST::Logger::log("[Security] Handshaek Failed - connection rejected");
    close(access_fd);
    return;
  }

  SST::FD client_fd(access_fd);
  if (client_fd.get() == -1) return;

  try {
    setNonBlocking(client_fd.get());
    struct epoll_event event;
    event.events = EPOLLIN;
    event.data.fd = client_fd.get();

    if (epoll_ctl(epoll_fd_.get(), EPOLL_CTL_ADD, client_fd.get(), &event) < 0) {
      SST::Logger::log("[Error] Epoll ctl add client fd failed");
      return;
    }

    int fd_val = client_fd.get();
    char buf[INET_ADDRSTRLEN];
    const char *ip_ptr = inet_ntop(AF_INET, &client_addr.sin_addr, buf, INET_ADDRSTRLEN);
    std::string ip = ip_ptr ? ip_ptr : "Unknown";
    clients_.erase(fd_val);
    client_states_.erase(fd_val);

    clients_.emplace(fd_val, ClientInfo(client_fd.get(), ip, false));
    ClientState& state = client_states_.emplace(fd_val, ClientState()).first->second;
    state.noise = std::move(noise); // Handshake 후 수립된 세션 저장
    client_fd.release(); // FD 제어권은 map으로 이동

    SST::Logger::log("[Server] HandShake OK - " + ip + "fd: " + std::to_string(fd_val) + ")");
  } catch (const std::exception &e) {
    SST::Logger::log(std::string("[Error] Accepting: ") + e.what());
  }
}

void TcpServer::handleClientData(int client_fd) {
  uint8_t temp_buf[4096];
  ssize_t bytes_read = read(client_fd, temp_buf, sizeof(temp_buf));
  if (bytes_read <= 0) {
    if (bytes_read < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
      return;
    handleDisconnect(client_fd);
    return;
  }

  ClientState &state = client_states_[client_fd];
  if (!state.read_buffer.write(temp_buf, bytes_read)) {
    SST::Logger::log("[Error] Buffer overflow for client fd " + std::to_string(client_fd));
    handleDisconnect(client_fd);
    return;
  }

  while(true){
    if(state.read_buffer.size() < 4) break;
    
    uint8_t len_buf[4];
    state.read_buffer.peek(len_buf,4);
    uint32_t cyperText_len = len_buf[0] | len_buf[1] << 8 | (len_buf[2] << 16) | (len_buf[3] << 24);

    if(state.read_buffer.size() < 4 + cyperText_len) break;

    state.read_buffer.consume(4);
    std::vector<uint8_t> cyperText(cyperText_len);
    state.read_buffer.read(cyperText.data(), cyperText_len);

    std::vector<uint8_t> plainText;
    if(!state.noise.decrypt(cyperText.data(), cyperText_len, plainText)){
      SST::Logger::log("[Security] Decrypt failed for fd " + std::to_string(client_fd));
      handleDisconnect(client_fd);
      return;
    }

    if(!processPacket(client_fd, plainText)){
      handleDisconnect(client_fd);
      return;
    }
  }
}

void TcpServer::handleDisconnect(int client_fd) {
  if (clients_.find(client_fd) == clients_.end())
    return;
  epoll_ctl(epoll_fd_.get(), EPOLL_CTL_DEL, client_fd, nullptr);

  std::string ip = clients_[client_fd].ip_address;
  clients_.erase(client_fd);
  client_states_.erase(client_fd);
  SST::Logger::log("[Server] Client disconnected: " + ip + " (fd " +
                   std::to_string(client_fd) + ")");
}

bool TcpServer::processPacket(int client_fd, std::vector<uint8_t> &packet) {
  auto it = clients_.find(client_fd);
  if (it == clients_.end()) {
    SST::Logger::log("[Error] processPacket called for unregistered client fd: " + std::to_string(client_fd));
    return false;
  }

  if(packet.size() < sizeof(SecureHeader)) return false;
  SecureHeader *header = (SecureHeader *)packet.data();

  if(header->magic != MAGIC_NUMBER){
    SST::Logger::log("[Error] Invalid magic from fd " + std::to_string(client_fd));
    return false;
  }
  
  using namespace std::chrono;
  uint64_t now_ms = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
  uint64_t pkt_ts = header->timestamp;

  if(pkt_ts > now_ms + 1000){
    SST::Logger::log("[Security] Future timestamp rejected from " + it->second.ip_address);
    return false;
  }
  if(now_ms - pkt_ts > 5000){
    SST::Logger::log("[Security] Replay detected(timestamp expired) from " +  it->second.ip_address);
    return false;
  }

  if(header->type == (uint8_t)MessageType::REQ_Connect){
    it->second.authenticated = true;
    SST::Logger::log("[Server] Client authenticated: " + it->second.ip_address);
  }

  return true;
}

// 쓰기 이벤트 처리
void TcpServer::handleWrite(int client_fd) {
  if (client_states_.find(client_fd) == client_states_.end())
    return;
  ClientState &state = client_states_[client_fd];

  if (state.write_buffer.empty()) {
    updateEpollEvents(client_fd, EPOLLIN);
    return;
  }

  uint8_t chunk[4096];
  size_t available = std::min((size_t)4096, state.write_buffer.size());

  state.write_buffer.peek(chunk, available);

  ssize_t sent = write(client_fd, chunk, available);
  if (sent > 0) {
    state.write_buffer.consume(sent);
  } else if (sent < 0) {
    if (errno != EAGAIN && errno != EWOULDBLOCK) {
      handleDisconnect(client_fd);
      return;
    }
  }

  if (state.write_buffer.empty()) {
    updateEpollEvents(client_fd, EPOLLIN);
  }
}

void TcpServer::updateEpollEvents(int fd, uint32_t events) {
  struct epoll_event ev;
  ev.events = events;
  ev.data.fd = fd;
  if (epoll_ctl(epoll_fd_.get(), EPOLL_CTL_MOD, fd, &ev) == -1) {
    SST::Logger::log("[Error] Epoll ctl mod failed for fd " + std::to_string(fd));
  }
}
} // namespace SST
