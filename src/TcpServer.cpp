#include "TcpServer.hpp"
#include "Protocol.hpp"
#include "FileDescriptor.hpp"
#include "PacketUtil.hpp"
#include "SystemReader.hpp"
#include "Logger.hpp"
#include "sha256.hpp"
#include <cerrno>
#include <iostream>
#include <cstring>      // memset
#include <unistd.h>     // close, read, wright
#include <fcntl.h>      // fcntl(Non-blocking 설정)
#include <arpa/inet.h>  // sockaddr_in
#include <netinet/in.h> // htons
#include <sys/socket.h> // socket, build, listen
#include <stdexcept>    // runtime_error

namespace SST
{
    TcpServer::TcpServer(int port) : port_(port), server_fd_(-1), epoll_fd_(-1)
    {
        initSocket();
        initEpoll();
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
        server_fd_ = SST::FD(tmp_fd); // RAII를 통해 소켓을 안전하게 관리

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

    // non-blocking 모드 설정
    // 논블로킹을 설정하지 않으면 데이터가 수신될때까지 블로킹되어 프로세스(서버)가 멈춤
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

    void TcpServer::run()
    {
        is_running_ = true;
        while (is_running_)
        {
            if (stop_flag_ && *stop_flag_) {
                is_running_ = false;
                break;
            }

            // 500ms 타임아웃으로 시그널 플래그 확인 기회 제공
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
                uint32_t ev = events[i].events; // 이벤트 비트마스크(종류)
                if (cur_fd == server_fd_.get())
                { 
                    acceptConnection();
                }
                else
                {
                    if(ev & EPOLLIN){
                        handleClientData(cur_fd);
                    } else if (ev & EPOLLOUT){
                        handleWrite(cur_fd);
                    } else if (ev & (EPOLLERR | EPOLLHUP)){
                        handleDisconnect(cur_fd);
                    }
                }
            }
        }
    }

    // 새 클라이언트 접속 처리
    // accept() 호출하여 새로운 클라이언트 연결 수락
    // 새로운 클라이언트 소켓을 논블로킹 모드로 설정하고 epoll 인스턴스에 추가
    // 클라이언트 정보를 clients_ 맵에 저장
    // 접속시 HMAC을 사용한 인증 절차를 수행
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
            event.events = EPOLLIN; // 읽기 이벤트 및 연결 종료 이벤트 감지
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
            if (bytes_read < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                return; // 아직 데이터가 도착하지 않음
            handleDisconnect(client_fd); // 클라이언트가 연결을 종료한 경우
            return;
        }

        while (true)
        {
            if (state.read_buffer.size() < sizeof(SecureHeader)) break;
            
            // 헤더 Peek
            SecureHeader header;
            state.read_buffer.peek(reinterpret_cast<uint8_t*>(&header), sizeof(SecureHeader));

            // Magic Check Implementation
            // Migration Doc says: "if(header->magic != MAGIC_NUMBER)"
            // Assuming host order parsing (as per PacketUtil)
            if (header.magic != MAGIC_NUMBER) {
                 SST::Logger::log("[Error] Invalid Magic from " + std::to_string(client_fd) + ". Got: " + std::to_string(header.magic));
                 handleDisconnect(client_fd);
                 return;
            }

            size_t total_packet_size = sizeof(SecureHeader) + header.body_len;
            if (state.read_buffer.size() < total_packet_size) {
                break; // Wait for more data
            }

            // 전체 패킷 읽기
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
        
        // HMAC 검증 로직
        uint8_t tag[HMAC_TAG_SIZE];

        std::memcpy(tag, header->auth_tag, HMAC_TAG_SIZE);  // 원본 서명 백업
        std::memset(header->auth_tag, 0, HMAC_TAG_SIZE);    // 서명 필드 0으로 초기화

        // HMAC 계산
        std::vector<uint8_t> calc_tag = SST::Sha256::hmac(SECRET_KEY, packet.data(), packet.size());
        
        if(std::memcmp(tag, calc_tag.data(), HMAC_TAG_SIZE) != 0){
            SST::Logger::log("[Security] HMAC failed for " + clients_[client_fd].ip_address);
            return false; // 연결 끊기
        }

        // [New Feature] System Stats Response
        uint16_t cmd = header->cmd_mask;
        std::vector<uint8_t> response_body;

        if (cmd == 100) { // REQ_SystemStat (Example ID)
            SystemStats stats = SystemReader::getInstance().getStats();
            response_body.resize(sizeof(SystemStats));
            std::memcpy(response_body.data(), &stats, sizeof(SystemStats));
            SST::Logger::log("[Logic] Sending SystemStats to " + clients_[client_fd].ip_address);
        } else {
             std::string msg = "UNKNOWN CMD";
             response_body.assign(msg.begin(), msg.end());
        }

        sendResponse(client_fd, cmd, response_body);
        return true;
    }

    void TcpServer::sendResponse(int client_fd, uint16_t cmd, const std::vector<uint8_t>& body) {
        // request_id는 현재 단순 증가 (추후 요청의 ReqID를 Echo하도록 개선 가능)
        ClientState& state = client_states_[client_fd];
        std::vector<uint8_t> packet = PacketUtil::createPacket(cmd, state.last_seq++, body);
        
        // CircularBuffer write
        if (!state.write_buffer.write(packet.data(), packet.size())) {
            // Buffer Full -> 강제 연결 종료 or Drop?
             SST::Logger::log("[Error] Write buffer full for fd " + std::to_string(client_fd));
             return; 
        }
        
        // EPOLLOUT 활성화 (즉시 쓰기 시도 안하고 비동기로 넘김, 구조 단순화 목적)
        // 성능 최적화를 위해선 즉시 쓰기 시도 후 남은것만 버퍼링이 좋음 (기존 코드 참고)
        // 여기서는 기존 로직 복원: 즉시 쓰기 시도
        
        // 하지만 CircularBuffer 구조상 Peek -> Write -> Consume 패턴이 필요함.
        // 여기선 단순화를 위해 우선 이벤트를 켬. (Level Triggered이므로 바로 handleWrite 호출됨)
        updateEpollEvents(client_fd, EPOLLIN | EPOLLOUT);
    }

    void TcpServer::handleWrite(int client_fd){
        if(client_states_.find(client_fd) == client_states_.end()) return;
        ClientState& state = client_states_[client_fd];
        
        if(state.write_buffer.empty()){
            updateEpollEvents(client_fd, EPOLLIN);
            return;
        }

        // 벡터로 변환하여 전송 (CircularBuffer 파편화 때문에 writev를 쓰지 않는 한 한번 복사하거나, 두번 호출해야 함)
        // 여기선 CircularBuffer::peek로 앞부분 청크를 가져와서 보냄.
        
        // CircularBuffer에 직접 접근할 수 없으므로(Private), toVector()등을 쓰거나 Interface확장 필요.
        // 위에서 작성한 CircularBuffer.hpp에는 contiguous pointer access가 없음.
        // performance를 위해 peek(buf, len) 사용.
        
        uint8_t chunk[4096];
        size_t available = std::min((size_t)4096, state.write_buffer.size());
        
        // 1. Peek (Copy cost exists, but safe)
        state.write_buffer.peek(chunk, available);
        
        // 2. Write
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
            SST::Logger::log("[Error] Failed to update epoll events");
        }
    }
}