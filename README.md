# Server State Telemetry Daemon (SSTD)

![Version](https://img.shields.io/badge/version-1.0.0-blue) ![Language](https://img.shields.io/badge/language-C%2B%2B17-orange) ![License](https://img.shields.io/badge/license-MIT-green)

C++17로 작성된 경량 시스템 상태 모니터링 데몬입니다.

[🇺🇸 English README](./README_EN.md)

---

## 📦 퀵 스타트

### 빌드
```bash
mkdir build && cd build
cmake .. && make
```

### 실행
```bash
./sstd                  # 기본 설정 파일로 실행 (../config/sstd.ini)
./sstd [config_path]    # 커스텀 설정 파일 지정 실행
./sstd --show-qr        # 서버 접속용 QR 출력 후 종료
```

---

## 📝 설정 예시 (sstd.ini)

```ini
[server]
port = 41924

[log]
path = ../test/test.log

[proxy]
host = sstd.test.site
port = 443
interface = "test100"
```

---

## 📄 라이선스

*   이 프로젝트는 **MIT 라이선스** 하에 배포됩니다.
*   [Project Nayuki](https://www.nayuki.io/page/qr-code-generator-library)의 **QR Code generator library** (C++, MIT License)가 내장되어 있습니다.
