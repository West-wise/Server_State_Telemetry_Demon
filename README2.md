# SSTD: Server State Telemetry Daemon

SSTD is a compact Linux daemon that streams server health data to clients over an encrypted TCP channel. It is built around a small binary protocol, a Noise-style handshake, and a once-per-second push loop.

## What It Does

SSTD collects host telemetry such as CPU usage, memory usage, network throughput, process counts, file descriptor usage, uptime, and disk usage. Authenticated clients receive the latest `SystemStats` packet every second.

The project is intentionally low-level:

- C++17
- Linux `epoll`
- Linux `timerfd`
- non-blocking TCP sockets
- `/proc` parsing
- bundled static libsodium
- binary protocol framing
- terminal QR connection bootstrap

## High-Level Flow

```text
Client
  |
  | TCP connect
  v
TcpServer
  |
  | Noise_XX handshake
  v
Encrypted session
  |
  | MSG3 complete (REQ_Connect optional)
  v
Authenticated client
  |
  | every 1 second
  v
SystemStats broadcast
```

## Architecture

```text
main.cpp
  loads config
  initializes logger
  starts SystemReader
  runs TcpServer

TcpServer
  owns listening socket
  handles epoll events
  advances Noise handshake
  encrypts and queues telemetry packets

SystemReader
  runs in a collector thread
  reads Linux system state
  exposes the latest SystemStats snapshot

NoiseSession
  implements the session handshake and transport encryption

PacketUtil
  builds SecureHeader + body packets
```

## Security Model

SSTD uses:

```text
Noise_XX_25519_ChaChaPoly_BLAKE2b
```

The server stores a static X25519 private key at:

```text
/etc/sstd/sstd.key
```

The matching public key is included in the QR connection URI. Clients use that pinned key to verify the server during the handshake. After the handshake, all application packets are encrypted with ChaCha20-Poly1305.

Current limitation: the server verifies that a client completed the handshake, but it does not yet maintain a persistent client allowlist or client identity registry.

## Wire Format

Each transport message is:

```text
uint32_le ciphertext_length
bytes     ciphertext
```

After decryption:

```text
SecureHeader(24 bytes) + Body
```

For telemetry broadcasts, the body is:

```text
SystemStats(134 bytes)
```

## Build

Use Linux, a C++17 compiler, and CMake 3.13 or newer. Run commands from the project directory.

```bash
mkdir -p build
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

Binary:

```text
build/sstd
```

The project version is 2.0.0 and the packet header wire version remains `0x01`. Outstanding implementation issues are tracked in [REVIEW.md](REVIEW.md).

## Run

```bash
./build/sstd
./build/sstd ./config/sstd.ini
./build/sstd --show-qr
./build/sstd ./config/sstd.ini --show-qr
```

The default config path is `/etc/sstd/sstd.ini`. The config must exist, and `/etc/sstd` must be prepared with permission to read or create `sstd.key`, including in QR mode. The configured log path must be writable for normal startup. `-q` also selects QR mode, which prints the QR and exits.

## Install As Service

```bash
sudo bash ./install.sh
```

Installed paths:

```text
/opt/sstd/sstd
/etc/sstd/sstd.ini
/etc/sstd/sstd.key
/var/log/sstd/sstd.log
/etc/systemd/system/sstd.service
```

The installer requires systemd and uses the tracked `deploy/sstd.service`. That unit has no `User` override and therefore runs as `root`. The installer preserves an existing config, and the daemon creates the key on first use. See [README.md](README.md) for config and QR address selection.

## Test Client

```bash
python3 -m venv .venv
.venv/bin/python -m pip install cryptography
SSTD_HOST=127.0.0.1 SSTD_PORT=41924 SSTD_KEY_PATH=/etc/sstd/sstd.key .venv/bin/python test/test_client.py
SSTD_HOST=127.0.0.1 SSTD_PORT=41924 SSTD_KEY_PATH=/etc/sstd/sstd.key .venv/bin/python test/test_multi_client.py
```

Run the daemon separately. The test process needs read permission on the server private key to derive its public key; these scripts are for local development. Their automatic key search does not include `/etc/sstd/sstd.key`, so set `SSTD_KEY_PATH` explicitly. A remote application uses the public key from the QR.

The single-client script sends the optional `REQ_Connect` after the handshake and displays `SystemStats` until interrupted. The multi-client script runs 100 clients for 30 seconds. See [README.md](README.md) for environment-variable defaults and test limitations.

## CI and Release

CI runs the existing test and amd64/aarch64 build jobs on pushes to `main` and `dev`, and on PRs targeting either branch. Changes limited to `docs/**` and `**/*.md` do not trigger CI; code and documentation changed together do. CI artifacts are validation outputs, not published releases.

Release remains a manual workflow restricted to `main`. Jenkins deployment is called only when the manual `deploy` option is selected, which defaults to false. See [docs/RELEASE.md](docs/RELEASE.md). The logger already uses bundled spdlog with async rotating files; its settings are documented in [README.md](README.md).

## Good Next Improvements

1. Harden frame parsing and write-buffer behavior.
2. Validate header version, body length, and timestamp arithmetic.
3. Add `sstd --check` for config, key, log path, interface, and port diagnostics.
4. Add persistent client identity and allowlist management.

## Repository Map

| Path | Purpose |
| --- | --- |
| `main.cpp` | Program entry point |
| `include/Protocol.hpp` | Wire structs and message types |
| `include/TcpServer.hpp`, `src/TcpServer.cpp` | TCP server and client session handling |
| `include/NoiseSession.hpp`, `src/NoiseSession.cpp` | Noise-style handshake and transport encryption |
| `include/SystemReader.hpp`, `src/SystemReader.cpp` | Linux telemetry collection |
| `include/Config.hpp`, `src/Config.cpp` | Config API, INI parsing, and server key management |
| `test/test_client.py` | Python protocol client |
| `test/test_multi_client.py` | Multi-client load smoke test |
| `docs/PROTOCOL.md` | English protocol specification |
| `docs/PROTOCOL_KR.md` | Korean protocol specification |
