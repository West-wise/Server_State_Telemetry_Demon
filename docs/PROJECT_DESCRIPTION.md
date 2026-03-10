# Server State Telemetry Daemon (SSTD) - Architecture & Design

## 1. Project Overview
**SSTD**는 Linux 기반의 경량 **시스템 상태 모니터링 데몬**입니다. 
외부 의존성(Boost, OpenSSL 등) 없이 **Pure C++17**과 **Linux System Call** (`epoll`, `socket`, `procfs`)만을 사용하여 구현되어, 임베디드 및 차량용 IVI 시스템과 같이 리소스가 제한적인 환경에 최적화되어 있습니다.

## 2. Core Philosophy
1.  **Zero Dependency**: 오직 C++ 표준 라이브러리와 필수 POSIX API만 사용합니다.
2.  **Performance**:
    *   **I/O Multiplexing**: `epoll` (Level Triggered) 기반의 비동기 네트워크 처리.
    *   **Circular Buffer**: 수신/송신 버퍼에 링 버퍼를 도입하여 메모리 복사 및 재할당 최소화.
    *   **Multi-threading**: 네트워크(Main), 수집(SystemReader), 로깅(Logger) 3중 스레드 구조로 병목 현상 제거.
3.  **Safety & Stability**:
    *   **RAII**: `SST::FD` 래퍼를 통해 소켓 등 파일 디스크립터 누수 완벽 차단.
    *   **Strict Error Handling**: 모든 시스템 콜에 대한 예외 처리 및 로깅.
    *   **Async Signal Safe**: 안전한 시그널 처리를 통한 종료 보장.

## 3. Architecture

### 3.1. Threading Model
*   **Main Thread (Network)**:
    *   `TcpServer` 클래스가 담당.
    *   `epoll_wait` 루프를 돌며 `accept`, `recv`, `send` 이벤트 처리.
    *   패킷 파싱 및 비즈니스 로직(HMAC 검증 포함) 수행.
*   **SystemReader Thread (Collector)**:
    *   `SystemReader` 싱글톤이 담당.
    *   1초 주기로 `/proc/stat`(CPU), `/proc/meminfo`(Memory) 파싱.
    *   수집된 데이터는 `shared_mutex`로 보호되어 메인 스레드에 제공.
*   **Logger Thread (I/O)**:
    *   `Async Logger` 패턴 적용.
    *   로그 메시지 큐(Queue)를 두고 별도 Worker 스레드가 파일 쓰기 전담.
    *   디스크 I/O Latency가 네트워크 처리에 영향을 주지 않음.

### 3.2. Data Flow
1.  **Inbound**: Client -> Socket -> `epoll` -> `handleClientData` -> `CircularBuffer` -> `processPacket`.
2.  **Processing**: Header Parsing -> HMAC Verification -> Command Logic (Fetch Stats from `SystemReader`) -> Response Generation.
3.  **Outbound**: `CircularBuffer` -> `epoll` (EPOLLOUT) -> `write` -> Client.

## 4. Security (SSTD Protocol v1.0)
*   **Format**: 42 Byte Packed Header (Little Endian).
*   **Integrity**: HMAC-SHA256 (Truncated to 16 bytes).
*   **Replay Protection**: Header Timestamp + Request ID (To be enforced).
*   **Credentials**: Shared Secret Key (현재는 Config/Memory 로드 방식).

## 5. Performance features
*   **Circular Buffer**: `std::vector::insert/erase`의 O(N) 비용 제거. read/write 오프셋 이동으로 O(1) 처리.
*   **Lock Contention**: `SystemReader`의 데이터는 `Reads`가 훨씬 빈번하므로 `std::shared_mutex`를 사용하여 Reader Lock 경합 최소화.

## 6. Directory Structure
```
SSTD/
├── config/         # sstd.ini (Configuration)
├── include/        # Header files (TcpServer, SystemReader, etc.)
├── lib/            # External sources (sha256 implementation)
├── src/            # Implementation files
├── test/           # Python test scripts
└── main.cpp        # Entry point
```
