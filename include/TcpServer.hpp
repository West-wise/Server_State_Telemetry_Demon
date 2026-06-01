#ifndef TCPSERVER_HPP
#define TCPSERVER_HPP

#include "CircularBuffer.hpp"
#include "FileDescriptor.hpp"
#include "NoiseSession.hpp"
#include <arpa/inet.h>
#include <atomic>
#include <csignal>
#include <cstdint>
#include <chrono>
#include <unordered_map>
#include <string>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace SST {

enum class HandshakePhase { WAIT_MSG1, WAIT_MSG3, DONE };

struct ClientInfo {
  SST::FD socket_fd;
  std::string ip_address;
  bool authenticated = false;

  ClientInfo(int fd, std::string ip, bool auth) : socket_fd(fd), ip_address(std::move(ip)), authenticated(auth) {}
  ClientInfo() = default;
};
struct ClientState {
  SST::CircularBuffer read_buffer;
  SST::CircularBuffer write_buffer;
  SST::NoiseSession   noise;
  uint32_t            last_seq = 0;

  HandshakePhase      phase = HandshakePhase::WAIT_MSG1;
  std::chrono::steady_clock::time_point hs_start = std::chrono::steady_clock::now();

  ClientState() : read_buffer(8192), write_buffer(8192) {}
};

class TcpServer {
public:
  // 명시적 생성자 및 소멸자
  explicit TcpServer(int port);
  ~TcpServer();

  // 복사 및 할당 금지
  TcpServer(const TcpServer &) = delete;
  TcpServer &operator=(const TcpServer &) = delete;

  // 서버 실행
  void run();

  // 시그널 핸들링을 위한 종료 플래그 설정
  void setStopFlag(volatile sig_atomic_t *flag) { stop_flag_ = flag; }

private:
  int port_;          // 서버 포트
  SST::FD server_fd_; // 리스닝 소켓
  SST::FD epoll_fd_;  // epoll 인스턴스
  SST::FD timer_fd_;  // 타이머 파일 디스크립터

  uint8_t server_static_priv_[32] = {};
  uint8_t server_static_pub_[32] = {};

  std::atomic<bool> is_running_{false};
  volatile sig_atomic_t *stop_flag_ = nullptr;

  static const int MAX_EVENTS = 64; // 최대 이벤트 수
  struct epoll_event events[MAX_EVENTS];

  // 연결된 클라이언트 관리 map
  // key: 소켓 파일 디스크립터, value: 클라이언트 정보
  std::unordered_map<int, ClientInfo> clients_;
  // 클라이언트 상태 관리 map
  // key: 소켓 파일 디스크립터, value: 클라이언트 상태    
  std::unordered_map<int, ClientState> client_states_;

  void initSocket();       // 소켓 생성 및 초기화
  void initEpoll();        // epoll 인스턴스 생성
  void initTimer();        // 타이머 초기화
  void broadcastStats();   // 모든 클라이언트에게 데이터 브로드캐스트
  void acceptConnection(); // 새 클라이언트 접속 처리
  void advanceHandshake(int client_fd);    // 핸드셰이크 단계 진행
  void evictStalledHandshakes();           // 타임아웃된 핸드셰이크 클라이언트 해제
  void handleClientData(int client_fd); // 클라이언트 데이터 처리
  void handleDisconnect(int client_fd); // 연결 종료 처리
  void setNonBlocking(int fd);          // 논블로킹모드 설정
  void handleWrite(int client_fd);      // 쓰기 이벤트 처리
  void updateEpollEvents(int fd,
                         uint32_t events); // epoll 이벤트를 변경 ( EPOLLIN <->
                                           // EPOLLIN | EPOLLOUT )

  bool processPacket(int client_fd, std::vector<uint8_t> &buffer);
};
} // namespace SST

#endif // TCPSERVER_HPP