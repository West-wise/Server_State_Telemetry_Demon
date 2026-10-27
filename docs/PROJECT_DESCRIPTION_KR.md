# Server State Telemetry Daemon (SSTD) - 아키텍처 및 설계

## 1. 프로젝트 개요
**SSTD**는 Linux 기반의 경량 **시스템 상태 모니터링 데몬**입니다. 
`libsodium` 정적 라이브러리와 `spdlog` 헤더를 프로젝트에 포함합니다. **C++17**과 **Linux System Call** (`epoll`, `socket`, `procfs`)을 사용합니다. 표준 C++ 라이브러리와 시스템 라이브러리까지 완전히 정적으로 링크하는 구성은 아닙니다.

## 2. 핵심 철학 (Core Philosophy)
1.  **낮은 외부 의존성**: libsodium과 spdlog를 포함하여 해당 라이브러리를 실행 호스트에 별도로 설치하는 부담을 줄입니다.
2.  **Performance (성능 최우선)**:
    *   **I/O Multiplexing**: `epoll` 기반의 논블로킹 네트워크 처리를 수행합니다.
    *   **Circular Buffer**: 수신/송신 버퍼에 링 버퍼를 도입하여 처리한 데이터를 제거할 때 남은 데이터를 앞으로 이동하는 비용을 줄입니다. 읽기·쓰기 시 데이터 복사는 수행합니다.
    *   **Multi-threading**: 네트워크(Main), 수집(SystemReader), 로깅(Logger) 3중 스레드 구조로 병목 현상을 방지합니다.
3.  **Safety & Stability (안전성)**:
    *   **RAII**: `SST::FD` 래퍼 클래스를 통해 소켓 등 파일 디스크립터의 수명과 해제를 관리합니다.
    *   **Async Signal Safe**: 시그널 핸들러에서의 안전한 플래그 처리를 통해 예측 불가능한 동작을 방지합니다.

## 3. 아키텍처 상세

### 3.1. 스레딩 모델 (Threading Model)
*   **Main Thread (Network)**:
    *   `TcpServer` 클래스가 관리합니다.
    *   `epoll_wait` 루프를 돌며 `accept`, `recv`, `send` 이벤트를 처리합니다.
    *   Noise 복호화, 패킷 파싱, 매직·타임스탬프 검증, 비즈니스 로직 실행을 담당합니다.
    *   **설계 의도**: 네트워크 로직을 메인 스레드에 집중시켜 컨텍스트 스위칭 비용을 최소화했습니다.
*   **SystemReader Thread (Collector)**:
    *   `SystemReader` 싱글톤 객체가 관리합니다.
    *   1초 주기로 깨어나 `/proc/stat`(CPU), `/proc/meminfo`(Memory) 파일을 파싱합니다.
    *   수집된 데이터는 `std::shared_mutex`로 보호되어, 메인 스레드가 안전하게 최신 값을 읽어갈 수 있습니다.
*   **Logger Thread (I/O)**:
    *   spdlog의 비동기 rotating file sink를 사용합니다.
    *   메인 스레드는 비동기 로거에 로그를 전달하고, spdlog의 worker thread가 파일 쓰기를 수행합니다.
    *   **이유**: 디스크 I/O는 블로킹될 가능성이 높으므로, 이를 메인 스레드에서 분리하여 네트워크 지연을 방지했습니다.

### 3.2. 데이터 흐름 (Data Flow)
1.  **수신 (Inbound)**: Client -> Socket -> `epoll` -> `handleClientData` -> `CircularBuffer` -> `processPacket`
2.  **처리 (Processing)**: Noise 핸드셰이크 또는 ChaCha20-Poly1305 복호화 -> Header Parsing -> 매직·timestamp 검증 -> 선택적 `REQ_Connect` 처리. 통계 송신은 요청별 응답이 아닌 1초 타이머가 담당합니다.
3.  **송신 (Outbound)**: `CircularBuffer` -> `epoll` (EPOLLOUT) -> `write` -> Client

## 4. 보안 (Security - SSTD Protocol v2.0)
*   **보안 계층**: Noise_XX_25519_ChaChaPoly_BLAKE2b 프로토콜을 통한 서버 공개키 검증 및 전방 비밀성(Forward Secrecy) 제공.
*   **패킷 포맷**: `4B LE 암호문 길이 + ChaCha20-Poly1305(SecureHeader 24B + Body)`. 헤더와 body 전체를 함께 암호화합니다. `SystemStats` body는 134B이며 인증 태그까지 포함한 상태 프레임은 178B입니다. 프로젝트 버전은 2.0.0이고 wire version 필드는 `0x01`입니다.
*   **기밀성 및 무결성 (Integrity)**: 모든 패킷은 ChaCha20-Poly1305로 암호화되며 Poly1305 MAC을 통해 무결성을 검증합니다.
*   **timestamp 검사**: 의도한 범위는 과거 5초·미래 1초지만, unsigned 뺄셈 문제로 미래 1초 이내인 패킷도 거부합니다. `request_id` 중복, `version`, 실제 body 크기와 `body_len` 일치 여부는 검사하지 않습니다.
*   **자격 증명**: 서버 최초 실행 시 자동 생성된 X25519 정적 키를 사용하며, 클라이언트는 QR 코드를 통해 서버의 공개키를 핀닝(Pinning)합니다.
*   **클라이언트 상태**: MSG3 완료 시 스트리밍이 허용됩니다. `REQ_Connect`와 테스트 클라이언트의 `AUTH_ME` body는 인증 필수 조건이 아니며, 영구 클라이언트 신원·허용 목록은 검증하지 않습니다.

## 5. 성능 개선 사항
*   **Circular Buffer 도입**: 기존 `std::vector::insert/erase` 방식을 교체했습니다.
    *   *기존*: 처리된 바이트를 지우면 남은 데이터를 앞으로 당기느라 메모리 카피(`O(N)`) 발생.
    *   *개선*: 처리한 데이터를 소비할 때 인덱스를 이동합니다. 버퍼에서 데이터를 읽고 쓸 때는 복사를 수행합니다.
*   **Lock 경합 최소화**: 시스템 상태 정보는 '쓰기'는 1초에 한 번이지만 '읽기'는 빈번합니다. 이에 적합한 `std::shared_mutex`를 사용하여 읽기 작업 간의 병목을 없앴습니다.

## 6. 디렉토리 구조
```
SSTD/
├── config/         # 설정 파일 (sstd.ini)
├── docs/           # 문서 (프로젝트 설명서 등)
├── include/        # 헤더 파일 (TcpServer, SystemReader 등)
├── lib/            # 외부 라이브러리 소스 (libsodium 등)
├── src/            # 구현 소스 파일
├── test/           # Python 테스트 스크립트
└── main.cpp        # 프로그램 진입점
```

설정 API는 `include/Config.hpp`, INI 파싱과 키 관리는 `src/Config.cpp`에 있습니다.
QR과 네트워크 유틸리티는 `include/utility.hpp`·`src/utility.cpp`, 서비스와 배포 스크립트는 `deploy/`에 있습니다.

## 7. 실행·검증·배포

- Linux, C++17 컴파일러, CMake 3.13 이상으로 프로젝트 디렉터리에서 빌드하며 결과는 `build/sstd`입니다.
- 기본 설정은 `/etc/sstd/sstd.ini`, 키는 `/etc/sstd/sstd.key`입니다. 직접 실행과 QR 출력 모두 설정 파일, 키 디렉터리, 필요한 권한을 준비해야 합니다. 커스텀 설정 경로도 키 경로를 바꾸지 않습니다.
- `sudo bash ./install.sh`는 `deploy/sstd.service`를 사용하며 기존 설정을 보존합니다. 키는 데몬이 처음 사용할 때 생성합니다.
- Python 테스트 두 개는 `cryptography`와 읽을 수 있는 서버 개인키가 필요한 로컬 도구입니다. `SSTD_HOST`, `SSTD_PORT`, `SSTD_KEY_PATH`를 지원하며 기본 키 검색에는 `/etc/sstd/sstd.key`가 포함되지 않습니다.
- CI는 `main`·`dev` 대상 PR과 두 브랜치의 push에서 기존 테스트와 amd64/aarch64 빌드를 수행합니다. `docs/**`·`**/*.md`만 변경하면 생략합니다.
- 정식 Release는 `main`에서 수동 실행하며 Jenkins 배포는 별도 `deploy` 옵션을 선택한 경우에 호출합니다. 실제 조건과 절차는 [릴리즈 안내](RELEASE.md)를 따릅니다.

실행 예시는 [README.md](../README.md), 프로토콜 제약은 [한글 명세](PROTOCOL_KR.md), 향후 수정할 문제는 [REVIEW.md](../REVIEW.md)에 정리합니다.
