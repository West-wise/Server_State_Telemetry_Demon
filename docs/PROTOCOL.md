# SSTD Protocol Specification v1.0

## 1. Overview

The **Server State Telemetry Daemon (SSTD)** uses a custom binary protocol over TCP. The protocol is designed for high performance, low overhead, and security in embedded environments.
It utilizes a **Push-Model (Streaming)** architecture where the server broadcasts state updates to authenticated clients.

- **Endianness**: Little Endian
- **Transport**: TCP/IP (Optional TLS via Nginx Proxy)
- **Default Port**: 41924

## 2. Packet Structure

Every packet consists of a **42-byte Secure Header** followed by a variable-length **Body**.

```
[ Secure Header (42 Bytes) ] + [ Body (N Bytes) ]
```

### 2.1. Secure Header (42 Bytes)

The header is packed (`#pragma pack(1)`) to ensure consistent memory layout.

| Offset | Field        | Type          | Size | Description                                       |
| ------ | ------------ | ------------- | ---- | ------------------------------------------------- |
| 0      | `magic`      | `uint32_t`    | 4    | Magic Number (`0x53535444` = "SSTD")              |
| 4      | `version`    | `uint8_t`     | 1    | Protocol Version (Currently `0x01`)               |
| 5      | `type`       | `uint8_t`     | 1    | Message Type (0x01: Request, 0x02: Response/Data) |
| 6      | `client_id`  | `uint16_t`    | 2    | Client Identifier (0 for Server)                  |
| 8      | `cmd_mask`   | `uint16_t`    | 2    | Command / Context Mask                            |
| 10     | `request_id` | `uint32_t`    | 4    | Sequence Number (De-duplication)                  |
| 14     | `timestamp`  | `uint64_t`    | 8    | Unix Timestamp (ms) for Replay Protection         |
| 22     | `body_len`   | `uint32_t`    | 4    | Length of the Body payload                        |
| 26     | `auth_tag`   | `uint8_t[16]` | 16   | HMAC-SHA256 Truncated Signature                   |

### 2.2. Authentication (HMAC)

- **Algorithm**: HMAC-SHA256
- **Key**: Shared Secret Key (Loaded from `sstd.ini`)
- **Scope**: The signature covers the **entire packet** (Header + Body).
  - _Note_: When verifying, the receiver must temporarily zero out the `auth_tag` field in the header before calculating the HMAC.
- **Truncation**: First 16 bytes of the SHA256 output.

## 3. Command & Message Types

### 3.1. Command Masks (`cmd_mask`)

The `cmd_mask` field determines the purpose of the payload.

| Value    | Name               | Direction        | Description                                |
| -------- | ------------------ | ---------------- | ------------------------------------------ |
| `0x0001` | **CMD_AUTH**       | Client -> Server | Initial Handshake / Authentication Request |
| `0x0020` | **CMD_PUSH_STATS** | Server -> Client | System Statistics Broadcast                |

### 3.2. Message Flows

#### A. Handshake (Authentication)

1.  **Client** connects to Server.
2.  **Client** sends a packet:
    - `type`: `0x01`
    - `cmd_mask`: `0x01` (CMD_AUTH)
    - `body`: Arbitrary payload (e.g., "AUTH_ME") or empty.
    - `auth_tag`: Valid HMAC of the packet.
3.  **Server** verifies HMAC.
    - **Success**: Marks the client as `Authenticated`.
    - **Failure**: Closes the connection immediately.

#### B. Data Streaming (Push)

1.  **Server** timer triggers (e.g., every 1 second).
2.  **Server** iterates through connected clients.
3.  **Server** checks if client is `Authenticated`.
4.  **Server** sends a packet:
    - `type`: `0x02`
    - `cmd_mask`: `0x0020` (CMD_PUSH_STATS)
    - `request_id`: Server-side Sequence Number (Incrementing)
    - `body`: `SystemStats` Structure (24 Bytes)

## 4. Data Structures

### 4.1. SystemStats (Body for `CMD_PUSH_STATS`)

Total Size: **24 Bytes** (Packed)

| Type       | Name           | Description                    |
| ---------- | -------------- | ------------------------------ |
| `uint16_t` | `valid_mask`   | Bitmask verifying valid fields |
| `uint16_t` | `reserved`     | Padding / Future use           |
| `uint8_t`  | `cpu_usage`    | CPU Usage (0-100%)             |
| `uint8_t`  | `mem_usage`    | Memory Usage (0-100%)          |
| `uint8_t`  | `disk_usage`   | Disk Usage (0-100%)            |
| `uint8_t`  | `temp_cpu`     | CPU Temperature (Celsius)      |
| `uint32_t` | `net_rx_bytes` | Network Received Bytes         |
| `uint32_t` | `net_tx_bytes` | Network Transmitted Bytes      |
| `uint16_t` | `proc_count`   | Number of running processes    |
| `uint16_t` | `user_count`   | Number of active users         |
| `uint32_t` | `uptime_secs`  | System Uptime in seconds       |

## 5. Security Recommendations

1.  **Replay Protection**: Receivers should validate `timestamp` is within a reasonable window (e.g., ±5 sec) of current time.
2.  **Key Rotation**: The `hmac_key` in `sstd.ini` should be rotated periodically.

## 6. Connection URI Scheme

To facilitate easy connections from mobile clients, SSTD defines a standardized URI scheme. This URI can be generated as a terminal QR code using the `--show-qr` argument when running the daemon.

**Format:**

```
sst://server?name=<SERVER_NAME>&ip=<IP_OR_HOST>&port=<PORT>&hmac=<HMAC_KEY>
```

**Parameters:**

- `name`: URL-encoded display name of the server (e.g., `SST-NODE`).
- `ip`: The external IP address or Hostname of the server (or Nginx proxy).
- `port`: The external port number (e.g., `9500`).
- `hmac`: The 32-character hex string representing the shared secret key.

**Example:**

```
sst://server?name=SST-DEV-01&ip=192.168.0.10&port=9500&hmac=0123456789abcdef0123456789abcdef
```
