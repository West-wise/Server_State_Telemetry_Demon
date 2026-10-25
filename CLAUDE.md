# SSTD Project Notes

SSTD is a C++17 Linux telemetry daemon. It collects system state once per second and broadcasts `SystemStats` to authenticated clients over a Noise-style encrypted TCP session.

## Build

Use Linux, a C++17 compiler, and CMake 3.13 or newer (`target_link_options`). Run commands from the project directory.

```bash
mkdir -p build
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

Output binary:

```text
build/sstd
```

## Run

```bash
./build/sstd
./build/sstd /path/to/sstd.ini
./build/sstd --show-qr
./build/sstd ./config/sstd.ini --show-qr
```

Default config path:

```text
/etc/sstd/sstd.ini
```

The config must exist. Normal startup and QR output both read or create `/etc/sstd/sstd.key`; prepare that directory and permissions first. A custom config path does not relocate the key. Normal startup needs write access to the log path. `-q` aliases `--show-qr`, which exits after QR output.

## Test and Install

```bash
python3 -m venv .venv
.venv/bin/python -m pip install cryptography
SSTD_HOST=127.0.0.1 SSTD_PORT=41924 SSTD_KEY_PATH=/etc/sstd/sstd.key .venv/bin/python test/test_client.py
SSTD_HOST=127.0.0.1 SSTD_PORT=41924 SSTD_KEY_PATH=/etc/sstd/sstd.key .venv/bin/python test/test_multi_client.py
sudo bash ./install.sh
```

Start the daemon separately for client tests. The test process must be able to read the private key to derive the pinned public key; these are local test tools. Neither script automatically searches `/etc/sstd/sstd.key`. The single-client script displays packets until interrupted; the multi-client script runs 100 clients for 30 seconds. See `README.md` for environment defaults.

Installation requires systemd and uses tracked `deploy/sstd.service`. The existing config is preserved, and the daemon generates the key on first use. Logger settings (`path`, `level`, `pattern`, `max_size_mb`, `max_files`) feed the bundled spdlog async rotating file sink through `Logger::Options`.

## CI and Release

- CI tests and builds amd64/aarch64 on `main`/`dev` push and PRs targeting either branch. Changes limited to `docs/**` and `**/*.md` skip the workflow; mixed code/documentation changes run it.
- Release is manual from `main`; `deploy` defaults to false and calls Jenkins only when selected. See `docs/RELEASE.md`.
- `Jenkinsfile` downloads Release assets, validates the manifest commit and checksums, then deploys to the configured hosts. CI success does not authorize deployment.
- Work branches target the relevant integration branch. Git cannot store both `cicd` and `cicd/*` refs; when `cicd` exists, use a flat name such as `cicd-dev-tests-docs` based on `cicd`. Do not merge PRs or create Releases as part of routine edits.

## Key Files

| File | Role |
| --- | --- |
| `main.cpp` | Loads config, initializes logger, starts `SystemReader`, runs `TcpServer` |
| `include/Protocol.hpp` | `SecureHeader`, `SystemStats`, `MessageType`, protocol size assertions |
| `include/NoiseSession.hpp`, `src/NoiseSession.cpp` | Noise-style handshake and ChaCha20-Poly1305 transport |
| `include/TcpServer.hpp`, `src/TcpServer.cpp` | epoll server, handshake state, encrypted broadcast loop |
| `include/SystemReader.hpp`, `src/SystemReader.cpp` | Linux system metrics collection |
| `include/Config.hpp`, `src/Config.cpp` | Config API, INI parsing, and `/etc/sstd/sstd.key` management |
| `include/Logger.hpp` | spdlog async rotating file logger facade |
| `src/PacketUtil.cpp` | Builds `SecureHeader + body` packets |
| `docs/PROTOCOL.md` | English protocol spec |
| `docs/PROTOCOL_KR.md` | Korean protocol spec |
| `.github/workflows/ci.yml`, `.github/workflows/release.yml` | CI validation and manual release workflows |
| `Jenkinsfile`, `deploy/` | Release verification and service deployment |

## Protocol Investigation Order

When changing protocol behavior, inspect files in this order:

```text
include/Protocol.hpp
include/NoiseSession.hpp
src/NoiseSession.cpp
src/TcpServer.cpp
src/PacketUtil.cpp
test/test_client.py
test/test_multi_client.py
docs/PROTOCOL.md
docs/PROTOCOL_KR.md
```

## Current Architecture

```text
main thread
  TcpServer
  epoll_wait
  accept/read/write
  handshake and packet dispatch

collector thread
  SystemReader
  refreshes SystemStats once per second

logger thread
  Logger
  spdlog worker writes and rotates log files
```

## Protocol Facts

- Transport: TCP
- Default port: `41924`
- Project version: `2.0.0`; packet header wire version: `0x01`
- Endianness: little endian
- Handshake: `Noise_XX_25519_ChaChaPoly_BLAKE2b`
- Transport AEAD: ChaCha20-Poly1305 IETF
- Frame format: `[4B LE ciphertext length][ciphertext]`
- Plaintext format: `SecureHeader(24B) + Body`
- `SystemStats` size: `134B`
- Server key path: `/etc/sstd/sstd.key`
- QR URI parameter for server key: `pub_key`

## Gotchas

- The project is Linux-specific. It uses `epoll`, `timerfd`, `accept4`, and Linux system files.
- CMake links bundled static libsodium from `lib/libsodium/{x86_64,aarch64}/lib/libsodium.a`.
- `SecureHeader` and `SystemStats` are packed binary structs. Any field change must update server, client, docs, and size assertions together.
- The current server does not maintain persistent client identity. MSG3 completion enables streaming; `REQ_Connect` is optional.
- `processPacket()` does not validate `version`, `body_len`, or request sequence. Its unsigned timestamp subtraction also rejects future timestamps inside the intended 1-second allowance; see the protocol docs and `REVIEW.md`.
- `broadcastStats()` checks buffer space after encryption increments the nonce; dropping a frame under backpressure can desynchronize transport counters. See `REVIEW.md`.
- `README.md`, `docs/PROTOCOL.md`, and `docs/PROTOCOL_KR.md` must be updated when protocol behavior changes.
