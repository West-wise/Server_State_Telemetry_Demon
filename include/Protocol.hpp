#ifndef PROTOCOL_HPP
#define PROTOCOL_HPP

#include <cstdint>

namespace SST {
    constexpr uint16_t MAGIC_NUMBER = 0XABCD; // Temporary value
    constexpr int HMAC_TAG_SIZE = 16;

    enum class MessageType : uint8_t {
        REQ_Connect    = 0x01,
        REQ_SystemStat = 0x10,
        RES_SystemStat = 0x11,
        ERR_General    = 0xFF
    };

    #pragma pack(push, 1)
    struct SecureHeader {
        uint16_t magic;           // 0x484D
        uint8_t  version;         // 0x01
        uint8_t  type;            // MessageType
        uint16_t client_id;       // 1:N 식별자
        uint16_t cmd_mask;        // 요청 데이터 마스크
        uint32_t request_id;      // 중복 방지 (Sequence)
        uint64_t timestamp;       // Replay 방지 (Unix MS)
        uint32_t body_len;        // Payload 길이
        uint8_t  auth_tag[HMAC_TAG_SIZE]; // HMAC-SHA256 (Truncated)
    };


    struct SystemStats {
        uint16_t valid_mask;  // 데이터 유효성 마스크
        uint16_t reserved;    // 패딩
        
        uint8_t cpu_usage;
        uint8_t mem_usage;
        uint8_t disk_usage;
        uint8_t temp_cpu;

        uint32_t net_rx_bytes;
        uint32_t net_tx_bytes;
        uint16_t proc_count;
        uint16_t user_count;
        uint32_t uptime_secs;
    };
    #pragma pack(pop)
    static_assert(sizeof(SecureHeader) == 40, "SecureHeader size mismatch");
    static_assert(sizeof(SystemStats) == 24, "SystemStats size mismatch");
}

#endif // PROTOCOL_HPP