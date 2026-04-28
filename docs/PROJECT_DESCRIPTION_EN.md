# Server State Telemetry Daemon (SSTD) - Architecture & Design

## 1. Project Overview
**SSTD** is a lightweight **System State Monitoring Daemon** based on Linux.
It is implemented using **Pure C++17** and **Linux System Calls** (`epoll`, `socket`, `procfs`) without any external dependencies (like Boost or OpenSSL), making it optimized for resource-constrained environments such as embedded systems or automotive IVI units.

## 2. Core Philosophy
1.  **Zero Dependency**: Use only the C++ Standard Library and essential POSIX APIs. This simplifies deployment and reduces binary size.
2.  **Performance First**:
    *   **I/O Multiplexing**: Uses `epoll` (Level Triggered) for asynchronous network processing.
    *   **Circular Buffer**: Introduces a ring buffer for both receive and send paths to eliminate `O(N)` memory copy costs associated with vector shifting.
    *   **Multi-threading**: A 3-thread architecture separates Network, Collection, and Logging concerns to prevent bottlenecks.
3.  **Safety & Stability**:
    *   **RAII**: Resource Acquisition Is Initialization is strictly enforced via `SST::FD` wrappers to prevent file descriptor leaks.
    *   **Async Signal Safe**: Proper signal handling ensures graceful shutdowns without undefined behaviors.

## 3. Architecture Details

### 3.1. Threading Model
*   **Main Thread (Network)**:
    *   Managed by `TcpServer` class.
    *   Runs the `epoll_wait` loop to handle `accept`, `recv`, and `send` events.
    *   Performs packet parsing, HMAC verification, and command dispatching.
    *   **Design Decision**: Keeping the network logic in the main thread avoids context switching overhead for high-frequency packet handling.
*   **SystemReader Thread (Collector)**:
    *   Managed by the `SystemReader` singleton.
    *   Wakes up every 1 second to parse `/proc/stat` (CPU) and `/proc/meminfo` (Memory).
    *   Parsed data is guarded by `std::shared_mutex`, allowing multiple readers (Main Thread) but exclusive writers (Collector Thread).
*   **Logger Thread (I/O)**:
    *   Implements the **Async Logger** pattern.
    *   The Main Thread pushes strings to a `std::queue`.
    *   A persistent Worker Thread consumes the queue and writes to the disk.
    *   **Why?**: Disk I/O syscalls (`write`, `fsync`) are blocking. Doing this in the Main Thread would stall network processing.

### 3.2. Data Flow
1.  **Inbound**: Client -> Socket -> `epoll` -> `handleClientData` -> `CircularBuffer` -> `processPacket`.
2.  **Processing**: Header Parsing -> HMAC Check -> Command Logic (Fetch Stats from `SystemReader`) -> Response Generation.
3.  **Outbound**: `CircularBuffer` -> `epoll` (EPOLLOUT) -> `write` -> Client.

## 4. Security
*   **Message Format**: 42 Byte Packed Header (Little Endian).
*   **Integrity**: HMAC-SHA256 (Truncated to 16 bytes) ensures that packets are not tampered with.
*   **Replay Protection**: The header includes a `timestamp` and `request_id`. (Note: Server-side validation logic for these fields is planned for next phase).
*   **Credentials**: Shared Secret Key is currently loaded from config/memory.

## 5. Performance Improvements
*   **Circular Buffer**: Replaced `std::vector::insert/erase` with a custom `CircularBuffer`.
    *   *Before*: Removing processed bytes triggers memmove of remaining bytes. Complexity: `O(N)`.
    *   *After*: Simply advancing the `head` index. Complexity: `O(1)`.
*   **Lock Contention**: Since system stats are read frequently but updated only once per second, `std::shared_mutex` is used. This allows the Main Thread to read stats concurrently without blocking each other (though currently single-threaded network, this future-proofs for multi-threaded workers).

## 6. Directory Structure
```
SSTD/
├── config/         # Configuration files (sstd.ini)
├── docs/           # Documentation
├── include/        # Header files (TcpServer, SystemReader, etc.)
├── lib/            # External sources (sha256 implementation)
├── src/            # Implementation files
├── test/           # Python test scripts
└── main.cpp        # Entry point
```
