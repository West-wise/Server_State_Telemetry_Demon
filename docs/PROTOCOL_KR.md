# SSTD 프로토콜 명세서 v2.0

## 1. 개요 (Overview)

**Server State Telemetry Daemon (SSTD)**는 TCP 기반의 커스텀 바이너리 프로토콜을 사용합니다. 고성능, 낮은 오버헤드, 보안성을 목표로 설계되었습니다.
서버가 인증된 클라이언트에게 주기적으로 상태 정보를 전송하는 **Push 모델 (Streaming)**을 따릅니다.

- **엔디안 (Endianness)**: Little Endian
- **전송 계층**: TCP/IP (Nginx 등을 통한 보안 연결 지원)
- **기본 포트**: 41924

---

## 2. 보안 레이어: Noise_XX 핸드셰이크

SSTD 패킷 교환 이전에 **Noise 프로토콜** 세션이 먼저 수립됩니다.

### 2.1. 프로토콜 식별자

```
Noise_XX_25519_ChaChaPoly_BLAKE2b
```

| 항목 | 값 |
| ---- | --- |
| DH 함수 | X25519 (Curve25519) |
| 암호화 | ChaCha20-Poly1305 (IETF 방식) |
| 해시 | BLAKE2b-256 |

### 2.2. 서버 키쌍

서버는 최초 실행 시 X25519 정적 키쌍을 생성하여 32바이트 비밀키를 `/etc/sstd/sstd.key` (권한: `0600`)에 저장합니다. 대응되는 공개키(64자리 16진수)는 연결 QR 코드에 포함됩니다.

### 2.3. 핸드셰이크 메시지 (XX 패턴)

| 단계 | 방향 | 내용 | 크기 |
| ---- | ---- | ---- | ---- |
| MSG1 | Client → Server | 클라이언트 임시 공개키 `e` | 32바이트 |
| MSG2 | Server → Client | 서버 임시 공개키 `e` + 암호화된 서버 정적 공개키 `s, es` | 80바이트 |
| MSG3 | Client → Server | 암호화된 클라이언트 정적 공개키 `s, se` | 48바이트 |

MSG3 처리 완료 후 양측은 HKDF를 통해 대칭 송수신 키를 유도합니다. 이후 모든 트래픽은 ChaCha20-Poly1305로 암호화됩니다. 클라이언트는 MSG2 처리 중 QR 코드에서 고정된 `pub_key`와 서버 공개키를 비교하여 서버 신원을 검증합니다.

핸드셰이크 타임아웃: **10초**. 미완료 연결은 자동 강제 종료됩니다.

### 2.4. 전송 프레이밍

핸드셰이크 이후 모든 메시지는 다음 형식으로 프레이밍됩니다:

```
[ 4바이트: ciphertext_length (리틀 엔디안 uint32) ] + [ 암호문 ]
```

암호문(ChaCha20-Poly1305, 16바이트 Poly1305 MAC 포함)을 복호화하면 SSTD 패킷(`SecureHeader + Body`)이 됩니다.

---

## 3. 패킷 구조 (Packet Structure)

### 3.1. 보안 헤더 (24바이트)

헤더는 `#pragma pack(1)`로 패킹되어 있습니다.

| 오프셋 | 필드명 | 타입 | 크기 | 설명 |
| ------ | ------ | ---- | ---- | ---- |
| 0 | `magic` | `uint32_t` | 4 | 매직 넘버 (`0x53535444` = "SSTD") |
| 4 | `version` | `uint8_t` | 1 | 프로토콜 버전 (현재 `0x01`) |
| 5 | `type` | `uint8_t` | 1 | 메시지 타입 (§4 참조) |
| 6 | `client_id` | `uint16_t` | 2 | 클라이언트 식별자 (서버는 0) |
| 8 | `request_id` | `uint32_t` | 4 | 시퀀스 번호 (중복 방지) |
| 12 | `timestamp` | `uint64_t` | 8 | Unix 타임스탬프 (ms) — 재전송 공격 방지 |
| 20 | `body_len` | `uint32_t` | 4 | 바디 페이로드 길이 |

**합계: 24바이트** (`static_assert` 검증됨)

---

## 4. 메시지 타입

| 값 | 이름 | 방향 | 설명 |
| -- | ---- | ---- | ---- |
| `0x01` | `REQ_Connect` | Client → Server | 핸드셰이크 완료 후 초기 연결 요청 |
| `0x11` | `RES_SystemStat` | Server → Client | 시스템 상태 통계 브로드캐스트 |
| `0xFF` | `ERR_General` | 양방향 | 일반 에러 |

---

## 5. 메시지 흐름

### A. Noise 핸드셰이크

1. 클라이언트가 TCP 연결을 시작합니다.
2. 클라이언트가 **MSG1** (32바이트)을 전송합니다: 임시 공개키 `e`.
3. 서버가 **MSG2** (80바이트)를 전송합니다: 서버 임시 공개키 `e` + 암호화된 서버 정적 공개키.
4. 클라이언트가 QR 코드에 저장된 `pub_key`와 서버 공개키를 비교합니다. 불일치 시 연결을 종료합니다.
5. 클라이언트가 **MSG3** (48바이트)를 전송합니다: 암호화된 클라이언트 정적 공개키.
6. 서버가 MSG3을 처리하고 세션 키를 유도합니다. 클라이언트를 `Authenticated` 상태로 전환합니다.

### B. 애플리케이션 핸드셰이크

Noise 핸드셰이크 완료 후, 클라이언트가 암호화 채널 안에서 `REQ_Connect (0x01)` 패킷을 전송합니다:

- `type`: `0x01`
- `body`: 없음 (`body_len = 0`)
- `timestamp`: 현재 Unix ms

서버는 `magic`과 `timestamp` 유효 범위를 검증합니다. 성공 시 클라이언트 인증이 최종 확인됩니다.

### C. 데이터 스트리밍 (Push)

서버 타이머가 **1초** 주기로 실행됩니다:

1. 서버가 `SystemReader`를 통해 `SystemStats`를 수집합니다.
2. `Authenticated` 상태인 각 클라이언트에 대해:
   - SSTD 패킷 생성: `type = 0x11`, `body = SystemStats (134바이트)`
   - Noise 세션으로 암호화 (ChaCha20-Poly1305)
   - 4바이트 리틀 엔디안 길이 접두사로 프레이밍
   - 클라이언트 쓰기 버퍼에 큐잉

---

## 6. 데이터 구조

### 6.1. netInfo (20바이트)

| 타입 | 필드명 | 설명 |
| ---- | ------ | ---- |
| `uint64_t` | `byte_ps` | 초당 바이트 수 |
| `uint32_t` | `packet_ps` | 초당 패킷 수 |
| `uint32_t` | `err_ps` | 초당 에러 수 |
| `uint32_t` | `drop_ps` | 초당 드롭 수 |

### 6.2. fdInfo (8바이트)

| 타입 | 필드명 | 설명 |
| ---- | ------ | ---- |
| `uint32_t` | `allocated_fd_cnt` | FD 소프트 리밋 (시스템 최대값) |
| `uint32_t` | `using_fd_cnt` | 현재 사용 중인 FD 수 |

### 6.3. DiskSummary (64바이트)

| 타입 | 필드명 | 설명 |
| ---- | ------ | ---- |
| `uint64_t` | `total_root` | `/` 전체 바이트 |
| `uint64_t` | `used_root` | `/` 사용 바이트 |
| `uint64_t` | `total_home` | `/home` 전체 바이트 |
| `uint64_t` | `used_home` | `/home` 사용 바이트 |
| `uint64_t` | `total_var` | `/var` 전체 바이트 |
| `uint64_t` | `used_var` | `/var` 사용 바이트 |
| `uint64_t` | `total_boot` | `/boot` 전체 바이트 |
| `uint64_t` | `used_boot` | `/boot` 사용 바이트 |

### 6.4. SystemStats (134바이트) — `RES_SystemStat`의 바디

| 오프셋 | 타입 | 필드명 | 설명 |
| ------ | ---- | ------ | ---- |
| 0 | `uint16_t` | `valid_mask` | 유효 필드 비트마스크 |
| 2 | `uint16_t` | `reserved` | 패딩 |
| 4 | `uint8_t` | `cpu_usage` | CPU 사용량 (0–100%) |
| 5 | `uint8_t` | `mem_usage` | 메모리 사용량 (0–100%) |
| 6 | `netInfo` | `net_rx_bytes` | 네트워크 수신 통계 (20바이트) |
| 26 | `netInfo` | `net_tx_bytes` | 네트워크 송신 통계 (20바이트) |
| 46 | `uint32_t` | `proc_count` | 사용자 프로세스 수 |
| 50 | `uint32_t` | `total_proc_count` | 전체 프로세스 수 |
| 54 | `uint16_t` | `net_user_count` | 네트워크 연결 사용자 수 |
| 56 | `uint16_t` | `connected_user_count` | 전체 연결 사용자 수 |
| 58 | `uint32_t` | `uptime_secs` | 시스템 가동 시간 (초) |
| 62 | `fdInfo` | `fd_info` | 파일 디스크립터 정보 (8바이트) |
| 70 | `DiskSummary` | `disk_info` | 마운트 포인트별 디스크 사용량 (64바이트) |

**합계: 134바이트** (`static_assert` 검증됨)

---

## 7. 보안

1. **상호 인증**: Noise_XX 패턴. 클라이언트는 QR 코드의 `pub_key`로 서버 신원을 검증하고, 서버는 핸드셰이크를 완료한 모든 클라이언트를 수락합니다.
2. **재전송 공격 방지**: 서버는 `timestamp`가 현재 시간 기준 **5초** 이전이거나 **1초** 이상 미래인 패킷을 거부합니다.
3. **전방 비밀성 (Forward Secrecy)**: 각 세션에서 임시 X25519 키를 사용하여, 장기 키가 노출되어도 과거 세션이 보호됩니다.
4. **키 저장**: 서버 비밀키는 `/etc/sstd/sstd.key` (권한 `0600`)에 저장됩니다. 키 교체 시 파일을 삭제하고 데몬을 재시작합니다.
5. **핸드셰이크 타임아웃**: 10초. 미완료 연결은 자동 강제 종료됩니다.

---

## 8. 연결 URI 스킴

클라이언트의 손쉬운 서버 접속을 위해 정형화된 URI 스킴을 제공합니다. `./sstd --show-qr` 실행 시 터미널 QR 코드로 출력됩니다.

**포맷:**

```
sst://server?name=<서버_이름>&ip=<IP_또는_호스트>&port=<포트>&pub_key=<서버_공개키>&ts=<Unix_타임스탬프>
```

**파라미터:**

| 파라미터 | 설명 |
| -------- | ---- |
| `name` | URL 인코딩된 서버 표시 이름 |
| `ip` | 외부 IP 주소 또는 호스트명 |
| `port` | 외부 포트 번호 |
| `pub_key` | 서버 X25519 정적 공개키 (64자리 소문자 16진수) |
| `ts` | QR 코드 생성 시각 (Unix 초) — 최신성 표시용 |

**예시:**

```
sst://server?name=SST-DEV-01&ip=192.168.0.10&port=9500&pub_key=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef&ts=1748000000
```
