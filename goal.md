# SSTD Mobile Client Goal

이 문서는 SSTD 서버와 호환되는 Android/Kotlin 클라이언트를 구현하기 위한 목표와 요구사항을 정리한다.

아래 Android 기능과 마일스톤은 구현 목표다. 이 저장소에는 Linux 서버와 Python 테스트 클라이언트가 있으며 Android 앱 구현은 포함되어 있지 않다.

## 1. 목표

Android 클라이언트는 SSTD 서버의 QR URI를 읽고, 서버 공개키를 pinning한 뒤, 암호화된 TCP 세션으로 실시간 시스템 상태를 수신해 표시한다.

핵심 흐름:

```text
QR scan
  -> server registration
  -> TCP connect
  -> Noise-style handshake
  -> server public key verification
  -> encrypted frame parsing
  -> SystemStats display
```

## 2. 서버 프로토콜 요약

| 항목 | 값 |
| --- | --- |
| Transport | TCP |
| 기본 포트 | `41924` |
| Endianness | Little endian |
| Handshake | `Noise_XX_25519_ChaChaPoly_BLAKE2b` |
| Transport cipher | ChaCha20-Poly1305 IETF |
| Push interval | 1 second |
| Frame | `[4B LE ciphertext length][ciphertext]` |
| Plaintext | `SecureHeader(24B) + Body` |
| Telemetry body | `SystemStats(134B)` |

프로젝트 버전 2.0.0과 패킷 헤더의 wire version `0x01`은 별개다. 상태 프레임의 총 크기는 길이 4B, 헤더 24B, body 134B, 인증 태그 16B를 합한 178B다.

## 3. QR URI

서버는 `--show-qr` 또는 `-q` 실행 시 다음 URI를 담은 터미널 QR을 출력하고 종료한다.

```text
sst://server?name=<SERVER_NAME>&ip=<IP_OR_HOST>&port=<PORT>&pub_key=<64_HEX_PUBLIC_KEY>&ts=<UNIX_SECONDS>
```

필수 처리:

- `name`: 서버 표시 이름
- `ip`: 접속 대상 host 또는 IP
- `port`: 접속 포트
- `pub_key`: 서버 X25519 정적 공개키
- `ts`: QR 생성 시각

`pub_key`는 서버 신원 검증에 사용해야 한다. 핸드셰이크 중 복호화한 서버 정적 공개키와 다르면 연결을 중단한다.

## 4. 필수 기능

### F1. 서버 등록

- QR 스캔 또는 수동 입력으로 서버 등록.
- 서버 이름, host, port, pinned public key 저장.
- 등록된 서버 목록 조회/삭제/수정.

### F2. 암호화 연결

- TCP socket 연결.
- MSG1/MSG2/MSG3 핸드셰이크 수행.
- 서버 공개키 pinning 검증.
- 송신/수신 transport key와 nonce 관리.
- MSG3 완료 후 스트리밍 수신. `REQ_Connect`는 선택 사항이며 `AUTH_ME` body는 서버의 인증 정보가 아니다.

### F3. 프레임 수신

- 4바이트 little-endian ciphertext length 읽기.
- 지정 길이만큼 ciphertext 수신.
- ChaCha20-Poly1305 복호화.
- 복호화 실패 시 연결 종료 또는 재연결.

### F4. 패킷 검증

- `magic == 0x53535444` 확인.
- `version == 0x01` 확인.
- `body_len`과 실제 body 크기 확인.
- `timestamp` window 검증.

이 검증 항목은 Android 클라이언트의 요구사항이다. 현재 서버는 `version`과 `body_len` 일치 여부를 검사하지 않으며, 수신 timestamp의 미래 1초 허용도 unsigned 연산 문제로 동작하지 않는다. 서버로 요청을 보낼 때 이 제약을 고려한다. 상세 내용은 [프로토콜 명세](docs/PROTOCOL_KR.md)를 따른다.

### F5. 시스템 상태 표시

표시 대상:

- CPU 사용률
- 메모리 사용률
- 네트워크 RX/TX bytes, packets, errors, drops
- process count
- connected users
- uptime
- file descriptor usage
- disk usage for `/`, `/home`, `/var`, `/boot`

## 5. 권장 Android 기술 스택

| 영역 | 권장 |
| --- | --- |
| UI | Jetpack Compose |
| 비동기 처리 | Kotlin Coroutines |
| QR 스캔 | CameraX + ML Kit Barcode 또는 ZXing |
| 암호 primitive | libsodium 호환 라이브러리 |
| 로컬 저장 | DataStore 또는 Room |
| 민감값 저장 | Android Keystore 기반 암호화 저장소 |
| 차트 | Vico 또는 MPAndroidChart |

## 6. 구현 마일스톤

### M1. 연결 MVP

- QR URI parsing
- 서버 등록
- TCP 연결
- 핸드셰이크
- `pub_key` 검증
- 첫 `RES_SystemStat` 수신

### M2. 대시보드

- 주요 metric 표시
- 1초 갱신
- 연결 상태 표시
- 마지막 수신 시각 표시

### M3. 서버 목록

- 여러 서버 저장
- 서버별 접속/해제
- public key 변경 감지 경고

### M4. 안정화

- 재연결 backoff
- frame length 상한
- 복호화 실패 처리
- foreground service와 알림

## 7. 주의사항

- 서버는 현재 persistent client identity를 검증하지 않는다.
- `src/NoiseSession.cpp`와 Python 테스트 클라이언트는 BLAKE2b-256 및 keyed-BLAKE2b 키 파생을 사용한다. 클라이언트 구현 시 프로토콜 이름뿐 아니라 실제 파생 과정도 맞춰야 한다.
- 클라이언트 static key는 현재 테스트 클라이언트처럼 세션마다 새로 생성해도 서버와 호환된다.
- 프로토콜은 packed binary struct에 의존한다. Kotlin에서는 `ByteBuffer.order(ByteOrder.LITTLE_ENDIAN)`으로 offset 기반 parsing을 해야 한다.
- `docs/PROTOCOL.md`와 `docs/PROTOCOL_KR.md`를 우선 기준 문서로 삼는다.
- 서버의 테스트·빌드는 `main`·`dev` 대상 PR 및 push에서 수행하며 문서만 변경하면 생략한다. 정식 Release와 Jenkins 배포 조건은 [릴리즈 안내](docs/RELEASE.md)를 따른다.
