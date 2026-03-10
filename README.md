# Server State Telemetry Daemon (SSTD)

![Version](https://img.shields.io/badge/version-1.0.0-blue) ![Language](https://img.shields.io/badge/language-C%2B%2B17-orange) ![License](https://img.shields.io/badge/license-MIT-green)

A lightweight, high-performance system state monitoring daemon designed for embedded systems and resource-constrained environments. It collects telemetry data such as CPU and memory usage and transmits it securely over TCP.

[🇰🇷 한국어 README](./README_KR.md)

## 🚀 Key Features

- **Zero Dependency**: Implemented using only C++17 STL and Linux System Calls, without any external libraries (Boost, OpenSSL, etc.). This simplifies deployment and reduces binary size.
- **High-Performance Architecture**:
  - **Async I/O**: Performs asynchronous network processing based on `epoll` (Level Triggered).
  - **Circular Buffering**: Custom Ring Buffer implementation minimizes memory copying and reallocation overhead (`O(1)` operations).
  - **Async Logging**: A dedicated logging thread ensures disk I/O latency does not block the main network loop.
  - **Multi-threading**: Network (Main), Collection (SystemReader), and Logging tasks are separated for maximum efficiency.
- **Stability & Reliability**:
  - **RAII Compliance**: Prevents file descriptor leaks through the `SST::FD` wrapper class.
  - **Thread Safety**: Introduces `std::shared_mutex` to minimize Reader/Writer contention.
- **Security**:
  - **HMAC-SHA256**: Includes signatures in all packets to prevent unauthorized access.
- **Utility**:
  - **Connection QR Output**: Outputs a monochrome terminal QR code directly from the command line containing server connection information for easy mobile app integration.

## 🛠 Architecture Summary

SSTD consists of 3 core threads:

1.  **Main Thread**: Runs the `epoll_wait` event loop, handling TCP connection acceptance, packet parsing, and command execution.
2.  **Collector Thread**: Wakes up every second to parse `/proc/stat`, `/proc/meminfo`, etc., and updates the system state.
3.  **Logger Thread**: Asynchronously writes queued log messages to disk.

For detailed architecture information, please refer to the [Project Description](./docs/PROJECT_DESCRIPTION_EN.md) (or [Korean Version](./docs/PROJECT_DESCRIPTION_KR.md)).

## 📦 Build and Execution

### Prerequisites

- Linux Environment (Kernel 2.6 or higher)
- C++17 supported compiler (GCC 8+ or Clang 6+)
- CMake 3.10 or higher

### Building

```bash
mkdir build && cd build
cmake ..
make
```

### Running in Foreground

```bash
# Run with default settings
./sstd

# Run with a specified configuration file
./sstd ../config/sstd.ini

# Output a QR code for server connection and exit
./sstd --show-qr
```

### Running as a Daemon (systemd)

You can run the server as a background service using `systemd`.
Modify the user (`User`) and execution path (`ExecStart`) in the provided `sstd.service` file to match your environment, then execute the following commands:

```bash
sudo cp sstd.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl start sstd
sudo systemctl enable sstd   # Start automatically on boot
```

## 📝 Configuration

You can configure the port, log path, proxy settings, and security keys in the `config/sstd.ini` file.

```ini
[server]
port = 41924
name = SST-DEV-01
ip = 192.168.0.10

[proxy]
# Optional proxy settings (e.g., when behind Nginx SSL Proxy)
host = sst.example.com
port = 443

[log]
path = logs/sstd.log

[security]
hmac_key = 0123456789abcdef0123456789abcdef
```

_(When `--show-qr` is used, the `proxy` host/port will be embedded in the QR code if provided. Otherwise, it defaults to the `server` ip/port.)_

## 🧪 Testing

A Python client script is provided for verifying connection and protocol logic.

```bash
python3 test/test_client.py
```

## 📄 License

This project is distributed under the MIT License.

## 📜 Third-Party Open Source Software

This project uses the following third-party software:

- **QR Code generator library** (C++)
  - Copyright (c) Project Nayuki.
  - Licensed under the [MIT License](https://github.com/nayuki/QR-Code-generator/blob/master/Readme.markdown)
  - Homepage: [Project Nayuki](https://www.nayuki.io/page/qr-code-generator-library)
