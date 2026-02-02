#include "TcpServer.hpp"
#include "Protocol.hpp"
#include "FileDescriptor.hpp"
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
        std::cout << "[Server] Stopped." << "\n";
    }

    // 소켓 생성 및 초기화
    void TcpServer::initSocket()
    {
        // 1. 소켓 생성(IpV4, TCP)
        server_fd_ = socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd_.get() < 0)
        {
            throw std::runtime_error("Socket creation failed");
        }

        //
        int opt = 1;
        // 서버를 재시작할 경우 커널이 이전 소켓을 정리하지 못하고 "Address already in use" 에러가 발생할 수 있음
        // 이를 방지하기 위해 SO_REUSEADDR 옵션을 설정하여 소켓이 즉시 재사용될 수 있도록 함
        if (setsockopt(server_fd_.get(), SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
        {
            throw std::runtime_error("socket option setting failed");
        }

        // 2. 바인딩 (주소, 포트 할당)
        struct sockaddr_in addr;
        std::memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY; // 서버의 ip 주소를 자동 할당
        std::cout << "[Server] Binding to address " << inet_ntoa(*(in_addr *)&addr.sin_addr.s_addr) << "\n";
        addr.sin_port = htons(port_);

        setNonBlocking(server_fd_);
        // 주소 바인딩
        if (bind(server_fd_, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        {
            throw std::runtime_error("Socket bind failed");
        }

        // 3. 리스닝 상태로 전환
        if (listen(server_fd_, MAX_EVENTS) < 0)
        {
            throw std::runtime_error("Socket listen failed");
        }

        std::cout << "[Server] Listening on port " << port_ << "\n";
    }

    // non-blocking 모드 설정
    // 논블로킹을 설정하지 않으면 데이터가 수신될때까지 블로킹되어 프로세스(서버)가 멈춤
    // 만약 실패한다면 재시도 로직을 추가해야하나?, 우선은 무시
    void TcpServer::setNonBlocking(int fd)
    {
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags == -1)
            return; // 이 부분은 실패시 로깅하는것이 맞으나, 지금은 보류
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }

    // epoll 인스턴스 생성
    // epoll 인스턴스는 서버의 소켓을 감시 대상으로 추가, 새로운 클라이언트 연결 요청을 감지, 데이터 수신 이벤트 처리 등을 담당
    void TcpServer::initEpoll()
    {
        epoll_fd_ = epoll_create1(0);
        if (epoll_fd_ == -1)
        {
            throw std::runtime_error("Epoll instance creation failed");
        }
        struct epoll_event event;
        event.events = EPOLLIN;     // 읽기 이벤트 감지
        event.data.fd = server_fd_; // 감시할 소켓 파일 디스크립터 설정

        if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, server_fd_, &event) == -1)
        {
            throw std::runtime_error("Epoll ctl add server fd failed");
        }
    }

    void TcpServer::run()
    {
        is_running_ = true;
        while (is_running_)
        {
            int occurred_fds = epoll_wait(epoll_fd_, events, MAX_EVENTS, -1);
            if (occurred_fds < 0)
            {
                if (errno == EINTR)
                    continue; // 신호에 의해 중단된 경우 재시도
                std::cerr << "Epoll wait error" << "\n";
                break;
            }

            for (int i = 0; i < occurred_fds; i++)
            {
                int cur_fd = events[i].data.fd;
                if (cur_fd == server_fd_)
                { // 리스닝 소켓에 이벤트 발생 -> 연결 요청임
                    acceptConnection();
                }
                else
                {
                    handleClientData(cur_fd); // 클라이언트 소켓 이벤트 발생 -> 데이터 처리
                }
            }
        }
    }

    // 새 클라이언트 접속 처리
    // accept() 호출하여 새로운 클라이언트 연결 수락
    // 새로운 클라이언트 소켓을 논블로킹 모드로 설정하고 epoll 인스턴스에 추가
    // 클라이언트 정보를 clients_ 맵에 저장
    // 접속시 HMAC을 사용한 인증 절차를 수행할 예정
    void TcpServer::acceptConnection()
    {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        int access_fd = accept(server_fd_.get(), (struct sockaddr *)&client_addr, &client_len);
        if(access_fd < 0) return;
        SST::FD client_fd(access_fd);
        if (client_fd.get() == -1)
        {
            if (errno != EAGAIN && errno != EWOULDBLOCK)
            {
                std::cerr << "Accept failed: " << strerror(errno) << "\n";
            }
            return;
        }
        try
        {
            setNonBlocking(client_fd.get());
            struct epoll_event event;
            event.events = EPOLLIN; // 읽기 이벤트 및 연결 종료 이벤트 감지
            event.data.fd = client_fd.get();

            if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, client_fd.get(), &event) < 0)
            {
                std::cerr << "Epoll ctl add client fd failed" << "\n";
                close(client_fd.get());
                return;
            }
            // 클라이언트 정보 저장
            int fd_val = client_fd.get();
            std::string ip = inet_ntoa(client_addr.sin_addr);
            clients_.emplace(fd_val, ClientInfo(std::move(client_fd.get()), ip, false));
            client_states_.emplace(fd_val, ClientState());
            std::cout << "[Server] New connection from " << clients_[fd_val].ip_address << "\n";
        }
        catch (const std::exception &e)
        {
            std::cerr << "Error during accepting connection: " << e.what() << "\n";
            close(client_fd);
            return;
        }
    }

    // 클라이언트 데이터 처리
    void TcpServer::handleClientData(int client_fd)
    {

        uint8_t buffer[4096];
        ssize_t bytes_read = read(client_fd, buffer, sizeof(buffer)); // 데이터를 읽어서 헤더 구조체에 저장
        if (bytes_read <= 0)
        {
            if (bytes_read < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return; // 아직 데이터가 도착하지 않음
            handleDisconnect(client_fd); // 클라이언트가 연결을 종료한 경우
            return;
        }
        ClientState &state = client_states_[client_fd]; // 클라이언트 상태 가져오기 혹은 새로 생성
        state.read_buffer.insert(state.read_buffer.end(), buffer, buffer + bytes_read);
        while (true)
        {
            if (state.read_buffer.size() < sizeof(SecureHeader)) break;
            SecureHeader* header = (SecureHeader *)state.read_buffer.data();
            if (header->magic != SST::MAGIC_NUMBER)
            {
                std::cerr << "[Server] Invalid magic number from " << clients_[client_fd].ip_address << "\n";
                handleDisconnect(client_fd);
                return;
            }

            size_t total_packet_size = sizeof(SecureHeader) + header->body_len;
            if(state.read_buffer.size() < total_packet_size) break;
            std::vector<uint8_t> packet(state.read_buffer.begin(), state.read_buffer.begin() + total_packet_size);

            if(processPacket(client_fd, packet)){
                state.read_buffer.erase(state.read_buffer.begin(), state.read_buffer.begin() + total_packet_size);
            } else {
                handleDisconnect(client_fd);
                return;
            }
        }

        // HMAC검증
    }

    // 연결 종료 처리
    void TcpServer::handleDisconnect(int client_fd)
    {
        epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, client_fd, nullptr);
        clients_.erase(client_fd);
        client_states_.erase(client_fd);
        std::cout << "[Server] Client disconnected: fd " << client_fd << "\n";
    }


    bool TcpServer::processPacket(int client_fd, std::vector<uint8_t>& packet)
    {
        SecureHeader* header = (SecureHeader*)packet.data();
        
        // HMAC 검증 로직
        uint8_t tag[HMAC_TAG_SIZE];

        std::memcpy(tag, header->auth_tag, HMAC_TAG_SIZE);  // 원본 서명 백업
        std::memset(header->auth_tag, 0, HMAC_TAG_SIZE);    // 서명 필드 0으로 초기화

        // HMAC 계산
        std::vector<uint8_t> calc_tag = Sha256::hmac(SECRET_KEY, packet.data(), packet.size());
        
        if(std::memcmp(tag, calc_tag.data(), HMAC_TAG_SIZE) != 0){
            std::cerr << "[Server] HMAC verification failed for client fd " << client_fd << "\n";
            return false;
        }
        std::memcpy(header->auth_tag, tag, HMAC_TAG_SIZE); // 원본 서명 복원
        return true;
    }

    // 이제 남은 것
    // 서버 데이터 수집(스레드화)
    // 클라이언트 요청에 대한 응답 작성 및 전송
    // 인증 절차 구현
}