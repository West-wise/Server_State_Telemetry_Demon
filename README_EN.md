# Server State Telemetry Daemon (SSTD)

![Version](https://img.shields.io/badge/version-1.0.0-blue) ![Language](https://img.shields.io/badge/language-C%2B%2B17-orange) ![License](https://img.shields.io/badge/license-MIT-green)

A lightweight system state monitoring daemon written in C++17.

[🇰🇷 한국어 README](./README.md)

---

## 📦 Quick Start

### Build
```bash
mkdir build && cd build
cmake .. && make
```

### Run
```bash
./sstd                  # Start with default config (../config/sstd.ini)
./sstd [config_path]    # Start with custom config path
./sstd --show-qr        # Print QR code for server connection and exit
```

---

## 📝 Configuration Example (sstd.ini)

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

## 📄 License

*   This project is distributed under the **MIT License**.
*   Includes the **QR Code generator library** (C++, MIT License) by [Project Nayuki](https://www.nayuki.io/page/qr-code-generator-library).

