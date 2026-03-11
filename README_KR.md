# Server State Telemetry Daemon (SSTD)

![Version](https://img.shields.io/badge/version-1.0.0-blue) ![Language](https://img.shields.io/badge/language-C%2B%2B17-orange) ![License](https://img.shields.io/badge/license-MIT-green)

임베디드 시스템 및 리소스 제약 환경을 위해 설계된 경량 고성능 시스템 상태 모니터링 데몬입니다. CPU 및 메모리 사용량 등의 텔레메트리 데이터를 수집하여 TCP를 통해 전송합니다.

[🇺🇸 English README](./README.md)

## 🚀 주요 특징

- **의존성 제로 (Zero Dependency)**: 외부 라이브러리(Boost, OpenSSL 등) 없이 오직 C++17 STL과 Linux System Call만으로 구현되었습니다.
- **고성능 아키텍처**:
  - **Async I/O**: `epoll` (Level Triggered) 기반의 비동기 네트워크 처리를 수행합니다.
  - **Circular Buffering**: 링 버퍼(Ring Buffer)를 자체 구현하여 메모리 복사 및 재할당 오버헤드를 최소화했습니다.
  - **Async Logging**: 별도의 로깅 스레드를 두어 디스크 I/O 지연이 메인 네트워크 루프를 차단하지 않도록 했습니다.
  - **멀티스레딩**: 네트워크(Main), 수집(SystemReader), 로깅(Logger) 작업을 역할별로 분리하여 효율을 극대화했습니다.
- **안정성 및 신뢰성**:
  - **RAII 준수**: `SST::FD` 래퍼 클래스를 통해 파일 디스크립터 누수를 원천 차단했습니다.
  - **스레드 안전성**: `std::shared_mutex`를 도입하여 Reader/Writer 간의 경합을 최소화했습니다.
- **보안**:
  - **HMAC-SHA256**: 모든 패킷에 서명을 포함하여 비인가된 접근을 방지합니다.
- **유틸리티**:
  - **접속 QR 출력**: 커맨드라인에서 바로 서버 접속 정보를 담은 흑백 터미널 QR 코드를 출력하여 손쉬운 모바일 연동을 지원합니다.

## 🛠 아키텍처 요약

SSTD는 3개의 핵심 스레드로 구성됩니다:

1.  **Main Thread**: `epoll_wait` 이벤트 루프를 돌며 TCP 연결 수락, 패킷 파싱, 명령 실행을 담당합니다.
2.  **Collector Thread**: 1초마다 깨어나 `/proc/stat`, `/proc/meminfo` 등을 파싱하고 시스템 상태를 갱신합니다.
3.  **Logger Thread**: 큐에 쌓인 로그 메시지를 비동기적으로 디스크에 기록합니다.

상세한 아키텍처 내용은 [프로젝트 상세 설명서](./docs/PROJECT_DESCRIPTION_KR.md)를 참고하세요.

## 📦 빌드 및 실행

### 필수 요구사항

- Linux 환경 (Kernel 2.6 이상)
- C++17 지원 컴파일러 (GCC 8+ 또는 Clang 6+)
- CMake 3.10 이상

### 빌드하기

```bash
mkdir build && cd build
cmake ..
make
```

### 포그라운드(Foreground) 실행

```bash
# 기본 설정으로 실행
./sstd

# 설정 파일 지정 실행
./sstd ../config/sstd.ini

# 서버 접속용 QR 코드 출력 후 종료
./sstd --show-qr
```

### 데몬(Daemon) 실행 (systemd)

`systemd`를 이용해 서버를 백그라운드 서비스로 구동할 수 있습니다.
기본 제공되는 `sstd.service` 파일 내의 사용자(`User`)와 경로(`ExecStart`)를 본인 환경에 맞게 수정한 후 아래 명령어를 실행하세요.

```bash
sudo cp sstd.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl start sstd
sudo systemctl enable sstd   # 부팅 시 자동 시작
```

## 🧪 테스트

연결 및 프로토콜 로직 검증을 위한 Python 클라이언트 스크립트가 제공됩니다.

```bash
python3 test/test_client.py
```

## 📝 설정 (Configuration)

`config/sstd.ini` 파일에서 포트 및 로그 경로 등을 설정할 수 있습니다.

```ini
[server]
port = 41924
name = SST-DEV-01
ip = 192.168.0.10

[proxy]
# Nginx 등 외부 프록시 통신을 위한 설정
host = sst.example.com
port = 443

[log]
path = logs/sstd.log

[security]
hmac_key = 0123456789abcdef0123456789abcdef
```

_(`--show-qr` 사용 시 `proxy` 설정이 존재할 경우 해당 접속 정보가 QR에 우선 포함됩니다.)_

## 📄 라이선스

이 프로젝트는 MIT 라이선스 하에 배포됩니다.

## 📜 Third-Party Open Source Software

This project uses the following third-party software:

- **QR Code generator library** (C++)
  - Copyright (c) Project Nayuki.
  - Licensed under the [MIT License](https://github.com/nayuki/QR-Code-generator/blob/master/Readme.markdown)
  - Homepage: [Project Nayuki](https://www.nayuki.io/page/qr-code-generator-library)
