# SSTD Protocol Specification v2.0

This document describes the protocol implemented by the current SSTD daemon.

## 1. Overview

SSTD uses a custom binary protocol over TCP. A Noise XX session is established
first. MSG3 completion enables periodic statistics streaming; the encrypted
application connection request is optional.

- Endianness: Little endian
- Transport: TCP/IP
- Default server port: `41924`
- Noise pattern: `Noise_XX_25519_ChaChaPoly_BLAKE2b`

The daemon project is version 2.0.0; the packet header wire version remains `0x01`.
The implementation uses BLAKE2b-256 and keyed-BLAKE2b key derivation. Match
`src/NoiseSession.cpp` and the Python clients when implementing another client;
the protocol name alone does not describe those implementation details.

## 2. Noise Session

The server creates an X25519 static key pair on first start and stores the
32-byte private key at `/etc/sstd/sstd.key` with mode `0600`. The corresponding
64-character lowercase hexadecimal public key is included in the QR URI.

Key handling is implemented in `src/Config.cpp`. The parent directory must
already exist and be readable/writable as needed, including in QR mode.
Changing the config path does not change the key path. A failure to set
`0600` currently logs a warning rather than failing generation.

### 2.1. Handshake messages

| Message | Direction | Contents | Size |
| --- | --- | --- | ---: |
| MSG1 | Client → Server | Client ephemeral public key | 32 bytes |
| MSG2 | Server → Client | Server ephemeral public key and encrypted server static public key | 80 bytes |
| MSG3 | Client → Server | Encrypted client public key | 48 bytes |

The client verifies the server static public key from MSG2 against the
`pub_key` value scanned from the QR code. The server does not verify a
client identity; MSG3 completion sets its authenticated flag without a
persistent identity registry or allowlist.

Handshake messages are fixed-size and have no transport length prefix.
The server checks incomplete handshakes on its 1-second timer and closes
connections whose elapsed handshake time exceeds 10 seconds.

### 2.2. Transport framing

After the handshake, each encrypted message is framed as follows:

```
[ 4-byte ciphertext length, little endian ] + [ ciphertext ]
```

The ciphertext is produced by ChaCha20-Poly1305 and includes its 16-byte
Poly1305 authentication tag. Decryption yields an SSTD packet consisting of a
`SecureHeader` followed by its body.

A telemetry frame is `4 + 24 + 134 + 16 = 178` bytes. Per-client read and
write buffers are each 8192 bytes; the receive parser currently has no
explicit minimum/maximum ciphertext length check. This is an implementation
constraint, not a negotiated protocol limit; see [REVIEW.md](../REVIEW.md).

## 3. Packet Structure

The decrypted packet uses a packed 24-byte header followed by a variable-size
body.

### 3.1. SecureHeader

| Offset | Field | Type | Size | Description |
| ---: | --- | --- | ---: | --- |
| 0 | `magic` | `uint32_t` | 4 | `0x53535444` (`SSTD`) |
| 4 | `version` | `uint8_t` | 1 | Wire version, currently `0x01` |
| 5 | `type` | `uint8_t` | 1 | Message type (§4) |
| 6 | `client_id` | `uint16_t` | 2 | Client identifier; SSTD currently writes `0` |
| 8 | `request_id` | `uint32_t` | 4 | Request/sequence identifier |
| 12 | `timestamp` | `uint64_t` | 8 | Unix timestamp in milliseconds |
| 20 | `body_len` | `uint32_t` | 4 | Body length in bytes |

Total size: **24 bytes**. The implementation checks minimum header size,
magic, and timestamp. It does not validate `version`, the actual body size
against `body_len`, or request sequence uniqueness.

The intended timestamp window is 5 seconds in the past through 1 second in
the future. Current code first checks `pkt_ts > now_ms + 1000`, then evaluates
unsigned `now_ms - pkt_ts > 5000`. Even a timestamp 1 millisecond ahead of
the sampled server time underflows and is rejected. For ordinary Unix
timestamps, the effective accepted interval is `[now_ms - 5000, now_ms]`.
Timestamp filtering alone does not deduplicate requests.

## 4. Message Types

| Value | Name | Direction | Description |
| ---: | --- | --- | --- |
| `0x01` | `REQ_Connect` | Client → Server | Application connection request after Noise |
| `0x11` | `RES_SystemStat` | Server → Client | System statistics push |
| `0xFF` | `ERR_General` | Either direction | Reserved general error type |

`REQ_Connect` is optional; MSG3 has already enabled streaming. The Python
clients send `AUTH_ME` as the body, but the server does not inspect that body
or use it as a credential. There is no fixed required body for this request.

`ERR_General` is declared but has no server send path. Invalid packets
generally cause disconnection. Unknown message types pass the existing
header checks without dispatch.

## 5. Message Flow

1. The client opens a TCP connection.
2. The client and server complete MSG1, MSG2, and MSG3.
3. The client verifies the server public key from MSG2.
4. MSG3 enables streaming; the client may send an encrypted `REQ_Connect` packet.
5. Every second, the server collects `SystemStats` and sends an encrypted
   `RES_SystemStat` packet to each authenticated client.

## 6. Data Structures

All structures below are packed and use little-endian integer representation.

### 6.1. `netInfo` — 20 bytes

| Type | Field | Description |
| --- | --- | --- |
| `uint64_t` | `byte_ps` | Bytes per second |
| `uint32_t` | `packet_ps` | Packets per second |
| `uint32_t` | `err_ps` | Errors per second |
| `uint32_t` | `drop_ps` | Dropped packets per second |

### 6.2. `fdInfo` — 8 bytes

| Type | Field | Description |
| --- | --- | --- |
| `uint32_t` | `allocated_fd_cnt` | Allocated file handles from the first field of `/proc/sys/fs/file-nr` |
| `uint32_t` | `using_fd_cnt` | Currently used file descriptors |

### 6.3. `DiskSummary` — 64 bytes

For each mount point, the structure contains a total and used byte count:
`/`, `/home`, `/var`, and `/boot`.

| Type | Fields |
| --- | --- |
| `uint64_t` | `total_root`, `used_root` |
| `uint64_t` | `total_home`, `used_home` |
| `uint64_t` | `total_var`, `used_var` |
| `uint64_t` | `total_boot`, `used_boot` |

### 6.4. `SystemStats` — 134 bytes

| Offset | Type | Field | Description |
| ---: | --- | --- | --- |
| 0 | `uint16_t` | `valid_mask` | Valid-field bitmask; current collector sets `0xFFFF` |
| 2 | `uint16_t` | `reserved` | Reserved |
| 4 | `uint8_t` | `cpu_usage` | CPU usage, 0–100% |
| 5 | `uint8_t` | `mem_usage` | Memory usage, 0–100% |
| 6 | `netInfo` | `net_rx_bytes` | Aggregated non-loopback receive rate |
| 26 | `netInfo` | `net_tx_bytes` | Aggregated non-loopback transmit rate |
| 46 | `uint32_t` | `proc_count` | Currently running process count |
| 50 | `uint32_t` | `total_proc_count` | Total process count |
| 54 | `uint16_t` | `net_user_count` | Distinct established TCP peer count |
| 56 | `uint16_t` | `connected_user_count` | Logged-in user count from `utmp` |
| 58 | `uint32_t` | `uptime_secs` | System uptime in seconds |
| 62 | `fdInfo` | `fd_info` | File descriptor information |
| 70 | `DiskSummary` | `disk_info` | Disk usage for supported mount points |

Disk information is refreshed every 10 seconds. The other collected values
are updated on the one-second collector cycle.

## 7. Connection URI

`sstd --show-qr` prints a terminal QR code containing this URI:

```
sst://server?name=<SERVER_NAME>&ip=<IP_OR_HOST>&port=<PORT>&pub_key=<64_HEX_CHARS>&ts=<UNIX_SECONDS>
```

| Parameter | Description |
| --- | --- |
| `name` | URL-encoded server display name; default `SST-NODE` |
| `ip` | Proxy host, configured interface address, or configured server IP |
| `port` | Proxy port, or the server port when no proxy port is configured |
| `pub_key` | Server X25519 static public key as 64 lowercase hex characters |
| `ts` | QR generation time in Unix seconds |

Example:

```
sst://server?name=SST-DEV-01&ip=192.168.0.10&port=9500&pub_key=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef&ts=1748000000
```
