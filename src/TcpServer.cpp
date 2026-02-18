#include "TcpServer.hpp"
#include "Protocol.hpp"
#include "FileDescriptor.hpp"
#include "PacketUtil.hpp"
#include "SystemReader.hpp"
#include "Logger.hpp"
#include "sha256.hpp"
#include "Config.hpp"
#include <cerrno>
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h> 
#include <stdexcept>
#include <atomic>
#include <sys/timerfd.h>

namespace SST
{
    
    static std::string hexToBytes(const std::string& hex) {
        std::string bytes;
        for (unsigned int i = 0; i < hex.length(); i += 2) {
            std::string byteString = hex.substr(i, 2);
            char byte = (char)strtol(byteString.c_str(), NULL, 16);
            bytes.push_back(byte);
        }
        return bytes;
    }

    TcpServer::TcpServer(int port) : port_(port), server_fd_(-1), epoll_fd_(-1), timer_fd_(-1)
    {
        // 7. Config에서 키 로드 (필수 검증)
        std::string hex_key = Config::getString("security", "hmac_key", "");
        if (hex_key.empty()) {
            std::cerr << "[FATAL] No secure HMAC key configured in config/sstd.ini!" << std::endl;
            throw std::runtime_error("Insecure configuration - server refused to start");
        } 
        
        secret_key_ = hexToBytes(hex_key);

        initSocket();
        initEpoll();
        initTimer(); 
    }

    TcpServer::~TcpServer()
    {
        SST::Logger::log("[Server] Stopped.");
    }

    void TcpServer::initSocket()
    {
        int tmp_fd = socket(AF_INET, SOCK_STREAM, 0);
        if(tmp_fd < 0){
            throw std::runtime_error("Socket creation failed");
        }
        server_fd_ = SST::FD(tmp_fd);

        int opt = 1;
        // 서버를 재시작할 경우 커널이 이전 소켓을 정리하지 못하고 "Address already in use" 에러가 발생할 수 있음
        // 이를 방지하기 위해 SO_REUSEADDR 옵션을 설정하여 소켓이 즉시 재사용될 수 있도록 함
        if (setsockopt(server_fd_.get(), SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
        {
            throw std::runtime_error("socket option setting failed");
        }

        struct sockaddr_in addr;
        std::memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY; 
        SST::Logger::log(std::string("[Server] Binding to address ") + inet_ntoa(*(in_addr *)&addr.sin_addr.s_addr));
        addr.sin_port = htons(port_);

        setNonBlocking(server_fd_.get());
        if (bind(server_fd_.get(), (struct sockaddr *)&addr, sizeof(addr)) < 0)
        {
            throw std::runtime_error("Socket bind failed");
        }

        if (listen(server_fd_.get(), MAX_EVENTS) < 0)
        {
            throw std::runtime_error("Socket listen failed");
        }

        SST::Logger::log("[Server] Listening on port " + std::to_string(port_));
    }

    void TcpServer::setNonBlocking(int fd)
    {
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags == -1) return;
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }

    void TcpServer::initEpoll()
    {
        epoll_fd_ = SST::FD(epoll_create1(0));
        if (epoll_fd_.get() == -1)
        {
            throw std::runtime_error("Epoll instance creation failed");
        }
        struct epoll_event event;
        event.events = EPOLLIN;     
        event.data.fd = server_fd_.get(); 

        if (epoll_ctl(epoll_fd_.get(), EPOLL_CTL_ADD, server_fd_.get(), &event) == -1)
        {
            throw std::runtime_error("Epoll ctl add server fd failed");
        }
    }

    // 타이머 초기화 (1초 주기)
    void TcpServer::initTimer()
    {
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

    void TcpServer::run()
    {
        is_running_ = true;
        // 최초 실행시 호스트 정보 수집
        // 이 정보는 거의 바뀌지 않음으로 서버 실행시 단 한번 수집후 지속적으로 사용
        HostInfo host_info = SST::SystemReader::getInstance().getHostInfo();
        while (is_running_)
        {
            if (stop_flag_ && *stop_flag_) {
                is_running_ = false;
                break;
            }

            int occurred_fds = epoll_wait(epoll_fd_.get(), events, MAX_EVENTS, 500);
            if (occurred_fds < 0)
            {
                if (errno == EINTR) continue; 
                SST::Logger::log("[Error] Epoll wait error");
                break;
            }
            
            for (int i = 0; i < occurred_fds; i++)
            {
                int cur_fd = events[i].data.fd;
                uint32_t ev = events[i].events; 
                
                // 새로운 연결 요청 처리
                if (cur_fd == server_fd_.get()) { 
                    acceptConnection();
                } else if (cur_fd == timer_fd_.get()) {
                    // 타이머 이벤트 처리 (Broadcast)
                    uint64_t expirations;
                    ssize_t n = read(cur_fd, &expirations, sizeof(expirations)); // 타이머 읽어서 클리어
                    if (n > 0) broadcastStats();
                } else {
                    if(ev & EPOLLIN){
                        handleClientData(cur_fd); // 클라이언트 데이터 처리
                    } else if (ev & EPOLLOUT){
                        handleWrite(cur_fd);      // 클라이언트 쓰기 처리
                    } else if (ev & (EPOLLERR | EPOLLHUP)){
                        handleDisconnect(cur_fd); // 클라이언트 연결 해제 관리
                    }
                }
            }
        }
    }
    
    // [NEW] 모든 클라이언트에게 데이터 브로드캐스트
    void TcpServer::broadcastStats() {
        if (clients_.empty()) return;

        // 최신 통계 조회
        SystemStats stats = SystemReader::getInstance().getStats();
        
        // 브로드캐스트용 바디 생성
        std::vector<uint8_t> body(sizeof(SystemStats));
        std::memcpy(body.data(), &stats, sizeof(SystemStats));
        std::vector<uint8_t> pkt = PacketUtil::createPacket(0x02, 0, body, secret_key_);

        // 각 클라이언트마다 패킷 생성 (각자 시퀀스가 다르므로 개별 생성)
        for (auto& [fd, client_info] : clients_) {
            if(!client_info.authenticated) continue;
            
            auto state_it = client_states_.find(fd);
            if (state_it == client_states_.end()) continue; // 상태가 없으면 스킵

            ClientState& state = state_it->second;
            
            std::vector<uint8_t> packet = PacketUtil::createPacket(0x02, state.last_seq++, body, secret_key_); 

            if (!state.write_buffer.write(packet.data(), packet.size())) continue;
            updateEpollEvents(fd, EPOLLIN | EPOLLOUT);
        }
    }

    void TcpServer::acceptConnection()
    {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        int access_fd = accept(server_fd_.get(), (struct sockaddr *)&client_addr, &client_len);
        if(access_fd < 0) return;
        
        SST::FD client_fd(access_fd);
        if (client_fd.get() == -1) return;

        try
        {
            setNonBlocking(client_fd.get());
            struct epoll_event event;
            event.events = EPOLLIN; 
            event.data.fd = client_fd.get();

            if (epoll_ctl(epoll_fd_.get(), EPOLL_CTL_ADD, client_fd.get(), &event) < 0)
            {
                SST::Logger::log("[Error] Epoll ctl add client fd failed");
                return;
            }
            
            int fd_val = client_fd.get();
            std::string ip = inet_ntoa(client_addr.sin_addr);
            clients_.erase(fd_val); 
            client_states_.erase(fd_val); 
            
            clients_.emplace(fd_val, ClientInfo(std::move(client_fd.get()), ip, false));
            client_states_.emplace(fd_val, ClientState());
            client_fd.release(); // FD 제어권은 map으로 이동
            
            SST::Logger::log("[Server] Connection from " + ip + " (fd: " + std::to_string(fd_val) + ")");
        }
        catch (const std::exception &e)
        {
            SST::Logger::log(std::string("[Error] Accepting: ") + e.what());
        }
    }

    void TcpServer::handleClientData(int client_fd)
    {
        uint8_t temp_buf[4096];
        ssize_t bytes_read = read(client_fd, temp_buf, sizeof(temp_buf)); 
        if (bytes_read <= 0)
        {
            if (bytes_read < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return; 
            handleDisconnect(client_fd); 
            return;
        }

        ClientState &state = client_states_[client_fd];
        if (!state.read_buffer.write(temp_buf, bytes_read)) {
            SST::Logger::log("[Error] Buffer overflow for client fd " + std::to_string(client_fd));
            handleDisconnect(client_fd);
            return;
        }

        while (true)
        {
            if (state.read_buffer.size() < sizeof(SecureHeader)) break;
            
            SecureHeader header;
            state.read_buffer.peek(reinterpret_cast<uint8_t*>(&header), sizeof(SecureHeader)); // 헤더만 읽어옴

            if (header.magic != MAGIC_NUMBER) {
                 SST::Logger::log("[Error] Invalid Magic from " + std::to_string(client_fd));
                 handleDisconnect(client_fd);
                 return;
            }

            size_t total_packet_size = sizeof(SecureHeader) + header.body_len;
            if (state.read_buffer.size() < total_packet_size) {
                break; 
            }

            std::vector<uint8_t> packet(total_packet_size);
            state.read_buffer.read(packet.data(), total_packet_size);

            if (!processPacket(client_fd, packet)) {
                SST::Logger::log("[Error] Packet processing failed for fd " + std::to_string(client_fd));
                handleDisconnect(client_fd);
                return;
            }
        }
    }

    void TcpServer::handleDisconnect(int client_fd)
    {
        if (clients_.find(client_fd) == clients_.end()) return;
        epoll_ctl(epoll_fd_.get(), EPOLL_CTL_DEL, client_fd, nullptr);
        
        std::string ip = clients_[client_fd].ip_address;
        clients_.erase(client_fd);
        client_states_.erase(client_fd);
        SST::Logger::log("[Server] Client disconnected: " + ip + " (fd " + std::to_string(client_fd) + ")");
    }

    bool TcpServer::processPacket(int client_fd, std::vector<uint8_t>& packet)
    {
        SecureHeader* header = (SecureHeader*)packet.data();

        // HMAC Verification
        uint8_t tag[HMAC_TAG_SIZE];
        std::memcpy(tag, header->auth_tag, HMAC_TAG_SIZE);  
        std::memset(header->auth_tag, 0, HMAC_TAG_SIZE);    
        std::vector<uint8_t> calc_tag = SST::Sha256::hmac(secret_key_, packet.data(), packet.size());
        
        if(std::memcmp(tag, calc_tag.data(), HMAC_TAG_SIZE) != 0){
            SST::Logger::log("[Security] HMAC failed for " + clients_[client_fd].ip_address);
            return false;
        }
        using namespace std::chrono;
        uint64_t now_ms = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
        uint64_t pkt_ts = header->timestamp;
        
        // 5. 미래 타임스탬프 거부 (1초 오차 허용) 및 만료 검사 (5초)
        if (pkt_ts > now_ms + 1000) {
             SST::Logger::log("[Security] Future timestamp rejected from " + clients_[client_fd].ip_address);
             return false;
        }

        uint64_t diff = now_ms - pkt_ts; // 위에서 미래 시간 걸러냈으므로 안전함
        if (diff > 5000) {
            SST::Logger::log("[Security] Replay Attack Detected (Timestamp Expired) from " + clients_[client_fd].ip_address);
            return false;
        }

        uint16_t cmd = header->cmd_mask;
        
        if (cmd == 0x01) {
             clients_[client_fd].authenticated = true;
             SST::Logger::log("[Server] Client Authenticated: " + clients_[client_fd].ip_address);

             // Send Host Info
             HostInfo info = SystemReader::getInstance().getHostInfo();
             std::vector<uint8_t> body;
             
             auto pushStr = [&](const std::string& s) {
                 uint16_t len = static_cast<uint16_t>(s.size());
                 body.push_back(len & 0xFF);
                 body.push_back((len >> 8) & 0xFF);
                 body.insert(body.end(), s.begin(), s.end());
             };

             pushStr(info.hostname);
             pushStr(info.os_name);
             pushStr(info.release_info);
             
             sendResponse(client_fd, static_cast<uint16_t>(MessageType::RES_HostInfo), body);
        }
        return true;
    }

    void TcpServer::sendResponse(int client_fd, uint16_t cmd, const std::vector<uint8_t>& body) {
        ClientState& state = client_states_[client_fd];
        std::vector<uint8_t> packet = PacketUtil::createPacket(cmd, state.last_seq++, body, secret_key_);
        
        if (!state.write_buffer.write(packet.data(), packet.size())) {
             return; 
        }
        updateEpollEvents(client_fd, EPOLLIN | EPOLLOUT);
    }

    // 쓰기 이벤트 처리
    void TcpServer::handleWrite(int client_fd){
        if(client_states_.find(client_fd) == client_states_.end()) return;
        ClientState& state = client_states_[client_fd];
        
        if(state.write_buffer.empty()){
            updateEpollEvents(client_fd, EPOLLIN);
            return;
        }

        uint8_t chunk[4096];
        size_t available = std::min((size_t)4096, state.write_buffer.size());
        
        state.write_buffer.peek(chunk, available);
        
        ssize_t sent = write(client_fd, chunk, available);
        if(sent > 0){
            state.write_buffer.consume(sent);
        } else if(sent < 0){
            if(errno != EAGAIN && errno != EWOULDBLOCK){
                handleDisconnect(client_fd);
                return;
            }
        }
        
        if(state.write_buffer.empty()){
            updateEpollEvents(client_fd, EPOLLIN);
        }
    }

    void TcpServer::updateEpollEvents(int fd, uint32_t events){
        struct epoll_event ev;
        ev.events = events;
        ev.data.fd = fd;
        if(epoll_ctl(epoll_fd_.get(), EPOLL_CTL_MOD, fd, &ev) == -1){
           // Log error
        }
    }
}