# SSTD 프로토콜 명세서 v1.0

## 1. 개요 (Overview)

**Server State Telemetry Daemon (SSTD)**는 TCP 기반의 커스텀 바이너리 프로토콜을 사용합니다. 이 프로토콜은 임베디드 환경에서의 고성능, 낮은 오버헤드, 보안성을 목표로 설계되었습니다.
서버가 인증된 클라이언트에게 주기적으로 상태 정보를 전송하는 **Push 모델 (Streaming)**을 따릅니다.

- **엔디안 (Endianness)**: Little Endian
- **전송 계층**: TCP/IP (Nginx 등을 통한 보안 연결 지원)
- **기본 포트**: 41924

## 2. 패킷 구조 (Packet Structure)

모든 패킷은 **42바이트 보안 헤더(Secure Header)**와 가변 길이의 **바디(Body)**로 구성됩니다.

```
[ Secure Header (42 Bytes) ] + [ Body (N Bytes) ]
```

### 2.1. 보안 헤더 (Secure Header)

헤더는 메모리 레이아웃 일관성을 위해 1바이트 단위로 패킹(`packed`) 되어 있습니다.

| 오프셋 | 필드명       | 타입          | 크기 | 설명                                        |
| ------ | ------------ | ------------- | ---- | ------------------------------------------- |
| 0      | `magic`      | `uint32_t`    | 4    | 매직 넘버 (`0x53535444` = "SSTD")           |
| 4      | `version`    | `uint8_t`     | 1    | 프로토콜 버전 (현재 `0x01`)                 |
| 5      | `type`       | `uint8_t`     | 1    | 메시지 타입 (0x01: 요청, 0x02: 응답/데이터) |
| 6      | `client_id`  | `uint16_t`    | 2    | 클라이언트 식별자 (서버는 0)                |
| 8      | `cmd_mask`   | `uint16_t`    | 2    | 명령/컨텍스트 마스크                        |
| 10     | `request_id` | `uint32_t`    | 4    | 시퀀스 넘버 (중복 방지)                     |
| 14     | `timestamp`  | `uint64_t`    | 8    | Unix 타임스탬프 (ms) - 재전송 공격 방지     |
| 22     | `body_len`   | `uint32_t`    | 4    | 뒤에 이어지는 바디의 길이                   |
| 26     | `auth_tag`   | `uint8_t[16]` | 16   | HMAC-SHA256 서명 (16바이트 절삭)            |

### 2.2. 인증 (HMAC)

- **알고리즘**: HMAC-SHA256
- **키**: 공유 비밀키 (`sstd.ini`에 설정됨)
- **범위**: 헤더와 바디를 포함한 **전체 패킷**에 대해 서명합니다.
  - _참고_: 검증 시에는 헤더의 `auth_tag` 부분을 0으로 채운 후 해시를 계산하여 비교해야 합니다.
- **절삭 (Truncation)**: SHA256 결과(32바이트) 중 앞 16바이트만 사용합니다.

## 3. 명령 및 메시지 타입

### 3.1. 명령 마스크 (`cmd_mask`)

패킷의 성격을 결정하는 필드입니다.

| 값       | 이름               | 방향             | 설명                             |
| -------- | ------------------ | ---------------- | -------------------------------- |
| `0x0001` | **CMD_AUTH**       | Client -> Server | 초기 연결 인증 요청 (핸드셰이크) |
| `0x0020` | **CMD_PUSH_STATS** | Server -> Client | 시스템 상태 통계 브로드캐스트    |

### 3.2. 메시지 흐름

#### A. 핸드셰이크 (인증)

1.  **Client**: 서버에 TCP 연결.
2.  **Client**: 패킷 전송
    - `type`: `0x01`
    - `cmd_mask`: `0x01` (CMD_AUTH)
    - `body`: 임의의 페이로드 (예: "AUTH_ME") 또는 비움.
    - `auth_tag`: 유효한 HMAC 서명 포함.
3.  **Server**: HMAC 검증.
    - **성공**: 해당 클라이언트를 `Authenticated` 상태로 전환.
    - **실패**: 즉시 연결 종료.

#### B. 데이터 스트리밍 (Push)

1.  **Server**: 타이머 이벤트 발생 (예: 1초 주기).
2.  **Server**: 연결된 클라이언트 목록 순회.
3.  **Server**: `Authenticated` 상태인 클라이언트 선별.
4.  **Server**: 패킷 전송
    - `type`: `0x02`
    - `cmd_mask`: `0x0020` (CMD_PUSH_STATS)
    - `request_id`: 서버 측 시퀀스 번호 (증가)
    - `body`: `SystemStats` 구조체 데이터 (24바이트)

## 4. 데이터 구조

### 4.1. 시스템 통계 (`SystemStats`)

Push 메시지의 바디로 전송되는 구조체입니다. (총 24바이트, 리틀 엔디안)

| 타입       | 필드명         | 설명                     |
| ---------- | -------------- | ------------------------ |
| `uint16_t` | `valid_mask`   | 데이터 유효성 비트마스크 |
| `uint16_t` | `reserved`     | 예약됨 (패딩)            |
| `uint8_t`  | `cpu_usage`    | CPU 사용량 (0-100%)      |
| `uint8_t`  | `mem_usage`    | 메모리 사용량 (0-100%)   |
| `uint8_t`  | `disk_usage`   | 디스크 사용량 (0-100%)   |
| `uint8_t`  | `temp_cpu`     | CPU 온도 (섭씨)          |
| `uint32_t` | `net_rx_bytes` | 네트워크 수신 바이트     |
| `uint32_t` | `net_tx_bytes` | 네트워크 송신 바이트     |
| `uint16_t` | `proc_count`   | 실행 중인 프로세스 수    |
| `uint16_t` | `user_count`   | 접속 중인 사용자 수      |
| `uint32_t` | `uptime_secs`  | 시스템 가동 시간 (초)    |

## 5. 보안 권장사항

1.  **재전송 공격 방지**: 수신 측은 `timestamp`가 현재 시간과 일정 오차(예: ±5초) 이내인지 반드시 검증해야 합니다.
2.  **키 교체**: `sstd.ini`의 `hmac_key`는 주기적으로 변경하는 것이 좋습니다.

## 6. 연결 URI 스킴 (Connection URI Scheme)

모바일 클라이언트 등에서의 손쉬운 서버 접속을 지원하기 위해 SSTD는 정형화된 URI 스킴을 제공합니다. 이 URI 포맷은 데몬 실행 시 `--show-qr` 인자를 넘기면 터미널 QR 코드로 출력됩니다.

**포맷:**

```
sst://server?name=<서버_이름>&ip=<IP_또는_호스트>&port=<포트>&hmac=<HMAC_KEY>
```

**파라미터:**

- `name`: URL 인코딩된 서버의 표시 이름 (예: `SST-NODE`).
- `ip`: 외부에서 접속 가능한 서버(또는 Nginx 프록시)의 IP/호스트 주소.
- `port`: 외부 포트 번호.
- `hmac`: 32자리의 Hex 문자열로 이루어진 공유 비밀키.

**예시:**

```
sst://server?name=SST-DEV-01&ip=192.168.0.10&port=9500&hmac=0123456789abcdef0123456789abcdef
```
