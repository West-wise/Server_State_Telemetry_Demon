# Server State Telemetry Daemon (SSTD)

Licensing information for SSTD and bundled dependencies is available in
`LICENSE`. The vendored spdlog and bundled fmt components are distributed
under the MIT License; see `lib/spdlog/LICENSE` for the dependency notice.

![Version](https://img.shields.io/badge/version-2.1.0-blue) ![Language](https://img.shields.io/badge/language-C%2B%2B17-orange) ![License](https://img.shields.io/badge/license-MIT-green)

C++17로 작성된 경량 시스템 상태 모니터링 데몬입니다.

---

## 📦 퀵 스타트

`main`·`dev` 대상 PR과 두 브랜치의 push에서 기존 멀티 클라이언트 테스트와
amd64/aarch64 빌드를 수행합니다. 변경 파일이 모두 `docs/**` 또는 `**/*.md`이면
CI를 실행하지 않으며, 코드와 문서를 함께 바꾸면 실행합니다. 정식 버전은 원하는 시점에
Actions의 `Release SSTD`를 `main`에서 수동 실행하여 발행합니다. Jenkins 운영 배포는
`deploy` 옵션을 선택한 경우에만 실행됩니다(기본값 OFF).
자세한 절차는 [릴리즈 안내](docs/RELEASE.md)를 참고하세요.

### 빌드

Linux의 `x86_64` 또는 `aarch64` 환경, C++17 컴파일러, CMake 3.13 이상이 필요합니다.
`CMakeLists.txt`의 선언은 3.10이지만 사용하는 `target_link_options`는 3.13 이상을 요구합니다.
프로젝트 디렉터리에서 실행합니다.

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

### 실행
```bash
./build/sstd                              # 기본 설정: /etc/sstd/sstd.ini
./build/sstd ./config/sstd.ini             # 커스텀 설정 파일
./build/sstd ./config/sstd.ini --show-qr   # 서버 접속용 QR 출력 후 종료
```

설정 파일은 존재해야 합니다. 직접 실행할 때도 `/etc/sstd` 디렉터리와 키 파일을
읽거나 생성할 권한이 필요합니다. 커스텀 INI 경로를 지정해도 키 경로는
`/etc/sstd/sstd.key`로 고정됩니다. 일반 실행에는 로그 경로의 쓰기 권한도 필요합니다.
`-q`는 `--show-qr`와 같습니다. QR 모드도 키를 읽거나 생성합니다.

### 설치

프로젝트 디렉터리에서 `sudo bash ./install.sh`를 실행합니다. Linux와 systemd가
필요하며 바이너리, `deploy/sstd.service`, 설정 파일을 설치합니다. 기존
`/etc/sstd/sstd.ini`는 보존하고 키는 데몬이 처음 사용할 때 생성합니다.
설치 경로는 `/opt/sstd/sstd`, `/etc/sstd`, `/var/log/sstd`,
`/etc/systemd/system/sstd.service`입니다.

---

## 🔐 보안

SSTD는 **Noise_XX_25519_ChaChaPoly_BLAKE2b** 프로토콜로 모든 통신을 보호합니다.

- 최초 실행 시 X25519 키쌍을 자동 생성하여 `/etc/sstd/sstd.key`에 저장합니다 (권한: `0600`).
- 클라이언트는 QR 코드에 포함된 서버 공개키(`pub_key`)로 서버 신원을 검증합니다.
- MSG3 처리 완료 시 스트리밍이 허용됩니다. `REQ_Connect`는 선택 사항이며,
  서버는 현재 영구 클라이언트 신원이나 허용 목록을 검증하지 않습니다.
- 세션마다 임시 키를 사용하여 전방 비밀성(Forward Secrecy)을 보장합니다.
- 키 교체: `/etc/sstd/sstd.key` 삭제 후 데몬 재시작.

---

## 📝 설정 예시 (sstd.ini)

```ini
[server]
port = 41924

[log]
path = logs/sstd.log
level = info
pattern = [%Y-%m-%d %H:%M:%S.%e] [%l] %v
max_size_mb = 10
max_files = 5

[proxy]
host = sstd.test.site
port = 443
interface = "eth0"
```

### 로깅 설정

로거는 spdlog의 비동기 회전 파일 sink를 사용합니다. `max_size_mb`는
현재 로그 파일 하나의 최대 크기이며, `max_files`는 회전된 백업 파일의
보관 개수입니다. 예를 들어 `max_files = 5`이면 현재 파일 외에
`sstd.1.log`부터 `sstd.5.log`까지 보관합니다.

`pattern`은 spdlog 패턴 문법을 사용합니다. 자주 사용하는 항목은 다음과
같습니다.

* `%Y-%m-%d`: 날짜
* `%H:%M:%S.%e`: 밀리초를 포함한 시각
* `%l`: 로그 레벨
* `%v`: 로그 메시지

현재 로거 API가 기록하는 메시지는 `info` 레벨입니다. `level` 설정은 로그
필터링과 향후 레벨별 로깅을 위해 유지됩니다.

---

## 📡 연결 QR 코드

`--show-qr` 실행 시 다음 형식의 URI가 QR 코드로 출력됩니다:

```
sst://server?name=<서버이름>&ip=<IP>&port=<포트>&pub_key=<64자리_공개키_hex>&ts=<Unix_타임스탬프>
```

모바일 클라이언트([SSTC](https://github.com/West-wise/Server_State_Telemetry_Client))는
QR 코드를 스캔하여 서버 공개키를 핀닝하고 자동 연결합니다.

QR host는 `proxy.host`, `proxy.interface`의 IPv4 주소, `server.ip` 순으로 선택합니다.
단, interface를 지정했는데 주소를 찾지 못하면 `127.0.0.1`을 사용하며 `server.ip`로
재시도하지 않습니다. 아무 값도 없으면 `127.0.0.1`을 사용합니다. port는 `proxy.port`,
없으면 `server.port`이고 name은 `server.name`, 없으면 `SST-NODE`입니다.
QR의 접속 안내 값은 실제 listen 주소 `0.0.0.0:server.port`를 바꾸지 않습니다.
INI 파서는 공백과 양끝의 큰따옴표 및 줄 전체의 `#`·`;` 주석을 처리하지만 인라인 주석은 처리하지 않습니다.

## 테스트와 프로토콜

서버를 별도로 실행한 뒤 로컬 테스트 환경에서 다음 명령을 사용합니다.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install cryptography
SSTD_HOST=127.0.0.1 SSTD_PORT=41924 SSTD_KEY_PATH=/etc/sstd/sstd.key .venv/bin/python test/test_client.py
SSTD_HOST=127.0.0.1 SSTD_PORT=41924 SSTD_KEY_PATH=/etc/sstd/sstd.key .venv/bin/python test/test_multi_client.py
```

테스트 프로세스는 `SSTD_KEY_PATH`의 개인키를 읽어 공개키를 유도하므로 해당 파일의
읽기 권한이 필요합니다. 원격 앱에는 서버 개인키를 전달하지 않고 QR의 공개키를 사용합니다.
두 스크립트 모두 기본 키 검색 경로에 `/etc/sstd/sstd.key`가 없으므로 설치된 서버를
시험할 때 명시적으로 지정합니다. `cryptography`의 `public_bytes_raw()` API를 사용합니다.

두 스크립트의 기본 host는 `127.0.0.1`입니다. 단일 클라이언트는 설정 파일의
`server.port`를 읽고, 멀티 클라이언트는 기본 port `41924`를 사용하며 둘 다
`SSTD_HOST`·`SSTD_PORT`로 덮어쓸 수 있습니다. 단일 클라이언트는 중단할 때까지 상태를
표시하고 멀티 클라이언트는 100개 연결을 30초 동안 시험합니다.

전송은 `[4B LE 암호문 길이][암호문]`이며 복호화 결과는
`SecureHeader(24B) + SystemStats(138B)`입니다. 인증 태그를 포함한 상태 프레임은 182B입니다.
프로젝트 버전은 2.1.0이지만 패킷 헤더의 wire version은 `0x01`입니다.
[영문 명세](docs/PROTOCOL.md), [한글 명세](docs/PROTOCOL_KR.md),
[구현 검토](REVIEW.md), [프로젝트 설명](docs/PROJECT_DESCRIPTION_KR.md)을 참고하세요.

---

## 📄 라이선스

*   이 프로젝트는 **MIT 라이선스** 하에 배포됩니다.
*   [Project Nayuki](https://www.nayuki.io/page/qr-code-generator-library)의 **QR Code generator library** (C++, MIT License)가 내장되어 있습니다.
