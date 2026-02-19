#ifndef PROTOCOL_HPP
#define PROTOCOL_HPP

#include <cstdint>
#include <arpa/inet.h>
#include <string>

namespace SST {
    constexpr uint32_t MAGIC_NUMBER = 0x53535444; // SSTD
    constexpr int HMAC_TAG_SIZE = 16;

    enum class MessageType : uint16_t {
        REQ_Connect    = 0x01,
        RES_SystemStat = 0x11,
        RES_HostInfo   = 0x12,
        ERR_General    = 0xFF
    };

    #pragma pack(push, 1)
    struct SecureHeader {
        uint32_t magic;           // 0x53535444
        uint8_t  version;         // 0x01
        uint8_t  type;            // MessageType
        uint16_t client_id;       // 1:N 식별자
        uint16_t cmd_mask;        // 요청 데이터 마스크, 0x01=HostInfo, 0x20=Stats
        uint32_t request_id;      // 중복 방지 (Sequence)
        uint64_t timestamp;       // Replay 방지 (Unix MS)
        uint32_t body_len;        // Payload 길이
        uint8_t  auth_tag[HMAC_TAG_SIZE]; // HMAC-SHA256 (Truncated)
    } __attribute__((packed));


    struct netInfo {
        uint32_t byte_ps; // ps : per sec
        uint32_t packet_ps;
        uint32_t err_ps;
        uint32_t drop_ps;
    };

    struct fdInfo {
        uint16_t allocated_fd_cnt; // 할당된 fd 제한(soft limit)
        uint16_t using_fd_cnt;    // 현재 시스템애서 사용중인 fd
        uint64_t max_limit_fd;    // 최대 리밋 제한
    };

    struct SystemStats {
        uint16_t valid_mask;  // 데이터 유효성 마스크
        uint16_t reserved;    // 패딩
        
        uint8_t cpu_usage;    // cpu 사용량
        uint8_t mem_usage;    // memory 사용량
        uint8_t disk_usage;   // disk 사용량
        uint8_t temp_cpu;     // cpu 온도

        netInfo net_rx_bytes; // network receive bytes
        netInfo net_tx_bytes; // network transmit bytes
        
        uint16_t proc_count;
        uint16_t total_proc_count;
        uint16_t net_user_count;
        uint16_t connected_user_count;
        uint32_t uptime_secs;
        fdInfo fd_info;
    };
    #pragma pack(pop)

    static_assert(sizeof(SecureHeader) == 42, "SecureHeader size mismatch");
    static_assert(sizeof(SystemStats) == 64, "SystemStats size mismatch");

    // 최초 연결시 서버 호스트 정보를 전달하기 위한 구조체
    struct HostInfo {
        char hostname[64];
        char os_name[32];
        char release_info[64];
    };
}

#endif // PROTOCOL_HPP