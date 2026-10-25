# SSTD Review Notes

**Date:** 2026-10-26

**Baseline:** `08f917c` (project version 2.0.0), with the CI trigger and documentation changes in this branch.

**Scope:** Static review of source, configuration, tests, and deployment workflows. Linux daemon integration tests were not run during this update.

## Current State

- The binary is `build/sstd`. libsodium is linked statically and bundled spdlog provides the async rotating file logger.
- The old `wirte_buffer` / `wirte` compile-blocking typos are already corrected in this baseline.
- `src/Config.cpp` implements INI and key handling. `deploy/sstd.service` is tracked and used by `install.sh`.
- CI retains the multi-client test and amd64/aarch64 builds on `main`/`dev` pushes and PRs targeting either branch. Changes limited to `docs/**` or `**/*.md` skip the workflow.
- Releases remain manual from `main`; Jenkins is called only when the manual `deploy` option is selected. CI artifacts are not formal Release assets. See [release instructions](docs/RELEASE.md).

## Open Findings

### 1. Receive frame lengths are not explicitly bounded

In `src/TcpServer.cpp`, `handleClientData()` parses a 4-byte ciphertext length before checking whether that frame is buffered. Each read buffer is 8192 bytes. Validate the length against the authentication-tag size and available capacity before arithmetic or allocation. Cast bytes to `uint32_t` before shifting and avoid overflow in `4 + cipherText_len`.

### 2. Backpressure can desynchronize transport nonces

`broadcastStats()` checks space for the complete prefix and ciphertext, which avoids queuing a partial frame in the single-threaded event loop. However, it calls `NoiseSession::encrypt()` first. Encryption advances the send nonce, so skipping an encrypted frame when the write buffer is full leaves the receiver expecting a different nonce for the next frame. Check capacity before advancing encryption state or disconnect a client that cannot accept the frame.

### 3. Header validation is incomplete

`processPacket()` checks minimum header size, `magic`, and timestamp. It does not validate `version`, actual body size against `body_len`, or request sequence uniqueness. Unknown message types pass existing checks without dispatch. `ERR_General` has no server send path. These limits are documented in both protocol specifications.

### 4. Timestamp arithmetic rejects the intended future allowance

The intended window is 5 seconds in the past through 1 second in the future. Unsigned `now_ms - pkt_ts` underflows for future values inside that allowance. For ordinary Unix timestamps, the accepted interval is `[now_ms - 5000, now_ms]`. A fix should compare time differences without unsigned underflow or unsafe conversion of untrusted values.

### 5. QR key-loading failure is not propagated

In `src/Config.cpp`, `getServerPubKeyHex()` ignores failure from `checkKeyFile()`. QR generation can continue with an unavailable or invalid key. Generation also logs a warning rather than failing if setting mode `0600` fails.

### 6. Service execution and deployment inputs need operational review

`deploy/sstd.service` has no `User` override, so the system service runs as root. A dedicated account would require deliberate ownership of config, key, and log paths. Jenkins validates the manifest commit and archive checksums, but its deployment stages reference workspace `deploy/` files despite `skipDefaultCheckout(true)`; check the job workspace setup before relying on a clean Jenkins agent. This update does not change deployment behavior.

### 7. Tooling prerequisites and test coverage are limited

- CMake declares 3.10 but uses `target_link_options`; use CMake 3.13 or newer.
- Both Python clients require `cryptography` and a readable private key to derive the pinned server public key. Set `SSTD_KEY_PATH` for an installed daemon; automatic key search does not include `/etc/sstd/sstd.key`.
- The single-client script displays packets until interrupted; the multi-client script runs 100 clients for 30 seconds. It counts packets and checks minimum header size and magic, but does not provide complete protocol conformance or regression coverage.
- Path-filtered CI does not report a completed check for documentation-only PRs. If branch rules require that check, review those rules together with the path filters.

## Recommended Order

1. Harden frame lengths, nonce-safe queuing, header validation, timestamp arithmetic, and key-error propagation.
2. Add focused Linux regression coverage for those cases and review clean-agent deployment inputs.
3. Add config/key/log/interface/port diagnostics and persistent client identity if required.

Update `README.md`, `README2.md`, `CLAUDE.md`, both protocol documents, the project description, and `goal.md` when their implementation assumptions change. `goal.md` describes Android client requirements; the Android application is maintained separately from this server repository.
