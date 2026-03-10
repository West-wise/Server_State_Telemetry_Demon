# Server State Telemetry Daemon (SSTD) - 아키텍처 및 설계

## 1. 프로젝트 개요
**SSTD**는 Linux 기반의 경량 **시스템 상태 모니터링 데몬**입니다. 
외부 의존성(Boost, OpenSSL 등) 없이 **Pure C++17**과 **Linux System Call** (`epoll`, `socket`, `procfs`)만을 사용하여 구현되어, 임베디드 및 차량용 IVI 시스템과 같이 리소스가 제한적인 환경에 최적화되어 있습니다.

## 2. 핵심 철학 (Core Philosophy)
1.  **Zero Dependency**: 오직 C++ 표준 라이브러리와 필수 POSIX API만 사용합니다. 이는 배포를 단순화하고 바이너리 크기를 줄입니다.
2.  **Performance (성능 최우선)**:
    *   **I/O Multiplexing**: `epoll` (Level Triggered) 기반의 비동기 네트워크 처리를 수행합니다.
    *   **Circular Buffer**: 수신/송신 버퍼에 링 버퍼를 도입하여 메모리 복사 및 재할당 비용(`O(N)`)을 제거했습니다.
    *   **Multi-threading**: 네트워크(Main), 수집(SystemReader), 로깅(Logger) 3중 스레드 구조로 병목 현상을 방지합니다.
3.  **Safety & Stability (안전성)**:
    *   **RAII**: `SST::FD` 래퍼 클래스를 통해 소켓 등 파일 디스크립터 누수를 완벽하게 차단합니다.
    *   **Async Signal Safe**: 시그널 핸들러에서의 안전한 플래그 처리를 통해 예측 불가능한 동작을 방지합니다.

## 3. 아키텍처 상세

### 3.1. 스레딩 모델 (Threading Model)
*   **Main Thread (Network)**:
    *   `TcpServer` 클래스가 관리합니다.
    *   `epoll_wait` 루프를 돌며 `accept`, `recv`, `send` 이벤트를 처리합니다.
    *   패킷 파싱, HMAC 검증, 비즈니스 로직 실행을 담당합니다.
    *   **설계 의도**: 네트워크 로직을 메인 스레드에 집중시켜 컨텍스트 스위칭 비용을 최소화했습니다.
*   **SystemReader Thread (Collector)**:
    *   `SystemReader` 싱글톤 객체가 관리합니다.
    *   1초 주기로 깨어나 `/proc/stat`(CPU), `/proc/meminfo`(Memory) 파일을 파싱합니다.
    *   수집된 데이터는 `std::shared_mutex`로 보호되어, 메인 스레드가 안전하게 최신 값을 읽어갈 수 있습니다.
*   **Logger Thread (I/O)**:
    *   **Async Logger** 패턴을 구현했습니다.
    *   메인 스레드는 `std::queue`에 로그 문자열을 넣기만 하고 즉시 리턴합니다(Non-blocking).
    *   별도의 Worker 스레드가 큐를 지속적으로 감시하며 실제 파일 쓰기(`write`)를 수행합니다.
    *   **이유**: 디스크 I/O는 블로킹될 가능성이 높으므로, 이를 메인 스레드에서 분리하여 네트워크 지연을 방지했습니다.

### 3.2. 데이터 흐름 (Data Flow)
1.  **수신 (Inbound)**: Client -> Socket -> `epoll` -> `handleClientData` -> `CircularBuffer` -> `processPacket`
2.  **처리 (Processing)**: Header Parsing -> HMAC Verification -> Command Logic (`SystemReader` 조회) -> Response Generation
3.  **송신 (Outbound)**: `CircularBuffer` -> `epoll` (EPOLLOUT) -> `write` -> Client

## 4. 보안 (Security)
*   **패킷 포맷**: 42 Byte Packed Header (Little Endian).
*   **무결성 (Integrity)**: HMAC-SHA256 (16바이트 Truncated)을 사용하여 패킷 위/변조를 방지합니다.
*   **재전송 방지 (Replay Protection)**: 헤더에 `timestamp`와 `request_id` 필드를 포함합니다. (서버 측의 유효성 검증 로직은 다음 단계 구현 예정)
*   **자격 증명**: 사전 공유된 비밀 키(Shared Secret Key)를 사용합니다.

## 5. 성능 개선 사항
*   **Circular Buffer 도입**: 기존 `std::vector::insert/erase` 방식을 교체했습니다.
    *   *기존*: 처리된 바이트를 지우면 남은 데이터를 앞으로 당기느라 메모리 카피(`O(N)`) 발생.
    *   *개선*: `head` 인덱스만 이동시켜 복사 비용 제로(`O(1)`).
*   **Lock 경합 최소화**: 시스템 상태 정보는 '쓰기'는 1초에 한 번이지만 '읽기'는 빈번합니다. 이에 적합한 `std::shared_mutex`를 사용하여 읽기 작업 간의 병목을 없앴습니다.

## 6. 디렉토리 구조
```
SSTD/
├── config/         # 설정 파일 (sstd.ini)
├── docs/           # 문서 (프로젝트 설명서 등)
├── include/        # 헤더 파일 (TcpServer, SystemReader 등)
├── lib/            # 외부 라이브러리 소스 (sha256 등)
├── src/            # 구현 소스 파일
├── test/           # Python 테스트 스크립트
└── main.cpp        # 프로그램 진입점
```
