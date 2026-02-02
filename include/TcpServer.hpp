#ifndef TCPSERVER_HPP
#define TCPSERVER_HPP

#include "FileDescriptor.hpp"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <map>
#include <vector>
#include <cstdint>
#include <string>
#include <atomic>

namespace SST {
    struct ClientInfo {
        SST::FD socket_fd;
        std::string ip_address;
        bool authenticated = false;

        ClientInfo(int fd, const std::string& ip, bool auth) 
            : socket_fd(std::move(fd)), ip_address(std::move(ip)), authenticated(auth) {}
        ClientInfo() = default;
    };
    struct ClientState {
        std::vector<uint8_t> read_buffer;
        std::vector<uint8_t> write_buffer;
        size_t write_offset = 0;
        size_t bytes_read = 0;
        size_t bytes_written = 0;
        uint32_t last_seq = 0;
    };

    class TcpServer { 
    public:
        // 명시적 생성자 및 소멸자
        explicit TcpServer(int port);
        ~TcpServer();

        // 복사 및 할당 금지
        TcpServer(const TcpServer&) = delete;
        TcpServer& operator=(const TcpServer&) = delete;

        // 서버 실행
        void run();

    private:

        constexpr const std::string SECRET_KEY = "sstd_tmp_secret_key_2026"; // 임시값임, 이건 나중에 반드시 config나 다른 방식으로 읽어오는 방식으로 대체할 것

        int port_;      // 서버 포트
        SST::FD server_fd_; // 리스닝 소켓
        SST::FD epoll_fd_;  // epoll 인스턴스
        std::atomic<bool> is_running_{false}; 
        
        static const int MAX_EVENTS = 64; // 최대 이벤트 수
        struct epoll_event events[MAX_EVENTS];

        // 연결된 클라이언트 관리 map
        // key: 소켓 파일 디스크립터, value: 클라이언트 정보
        std::map<int, ClientInfo> clients_;
        // 클라이언트 상태 관리 map
        // key: 소켓 파일 디스크립터, value: 클라이언트 상태
        std::map<int, ClientState> client_states_;

        void initSocket();                  // 소켓 생성 및 초기화
        void initEpoll();                   // epoll 인스턴스 생성
        void acceptConnection();            // 새 클라이언트 접속 처리
        void handleClientData(int client_fd);  // 클라이언트 데이터 처리
        void handleDisconnect(int client_fd); // 연결 종료 처리
        void setNonBlocking(int fd); // 논블로킹모드 설정 

        bool processPacket(int client_fd, std::vector<uint8_t>& buffer);
    };
}


#endif // TCPSERVER_HPP