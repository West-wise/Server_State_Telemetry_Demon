# Server State Telemetry Daemon (SSTD)

![Version](https://img.shields.io/badge/version-2.0.0-blue) ![Language](https://img.shields.io/badge/language-C%2B%2B17-orange) ![License](https://img.shields.io/badge/license-MIT-green)

C++17로 작성된 경량 시스템 상태 모니터링 데몬입니다.

---

## 📦 퀵 스타트

### 빌드
```bash
mkdir build && cd build
cmake .. && make
```

### 실행
```bash
./sstd                  # 기본 설정 파일로 실행 (/etc/sstd/sstd.ini)
./sstd [config_path]    # 커스텀 설정 파일 지정 실행
./sstd --show-qr        # 서버 접속용 QR 출력 후 종료
```

---

## 🔐 보안

SSTD는 **Noise_XX_25519_ChaChaPoly_BLAKE2b** 프로토콜로 모든 통신을 보호합니다.

- 최초 실행 시 X25519 키쌍을 자동 생성하여 `/etc/sstd/sstd.key`에 저장합니다 (권한: `0600`).
- 클라이언트는 QR 코드에 포함된 서버 공개키(`pub_key`)로 서버 신원을 검증합니다.
- 세션마다 임시 키를 사용하여 전방 비밀성(Forward Secrecy)을 보장합니다.
- 키 교체: `/etc/sstd/sstd.key` 삭제 후 데몬 재시작.

---

## 📝 설정 예시 (sstd.ini)

```ini
[server]
port = 41924

[log]
path = logs/sstd.log

[proxy]
host = sstd.test.site
port = 443
interface = "eth0"
```

---

## 📡 연결 QR 코드

`--show-qr` 실행 시 다음 형식의 URI가 QR 코드로 출력됩니다:

```
sst://server?name=<서버이름>&ip=<IP>&port=<포트>&pub_key=<64자리_공개키_hex>&ts=<Unix_타임스탬프>
```

모바일 클라이언트는 QR 코드를 스캔하여 서버 공개키를 핀닝하고 자동 연결합니다.

---

## 📄 라이선스

*   이 프로젝트는 **MIT 라이선스** 하에 배포됩니다.
*   [Project Nayuki](https://www.nayuki.io/page/qr-code-generator-library)의 **QR Code generator library** (C++, MIT License)가 내장되어 있습니다.
