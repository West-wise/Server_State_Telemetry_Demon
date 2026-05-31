#ifndef PROTOCOL_HPP
#define PROTOCOL_HPP
#include <arpa/inet.h>
#include <cstdint>
#include <string>

namespace SST {
constexpr uint32_t MAGIC_NUMBER = 0x53535444; // SSTD

enum class MessageType : uint8_t {
  REQ_Connect = 0x01,    // 연결요청
  RES_SystemStat = 0x11, // 통계 데이터(일반 메세지)
  ERR_General = 0xFF     // 에러
};

#pragma pack(push, 1)
struct SecureHeader {
  uint32_t magic;                  // 0x53535444
  uint8_t version;                 // 0x01
  uint8_t type;                    // MessageType
  uint16_t client_id;              // 1:N 식별자
  uint32_t request_id;             // 중복 방지 (Sequence)
  uint64_t timestamp;              // Replay 방지 (Unix MS) 
  uint32_t body_len;               // Payload 길이
} __attribute__((packed));

struct netInfo {
  uint64_t byte_ps; // ps : per sec
  uint32_t packet_ps;
  uint32_t err_ps;
  uint32_t drop_ps;
};

struct fdInfo {
  uint32_t allocated_fd_cnt; // 할당된 fd 제한(soft limit)
  uint32_t using_fd_cnt;     // 현재 시스템애서 사용중인 fd
};

struct DiskSummary {
  uint64_t total_root;
  uint64_t used_root;

  uint64_t total_home;
  uint64_t used_home;

  uint64_t total_var;
  uint64_t used_var;

  uint64_t total_boot;
  uint64_t used_boot;
};

struct SystemStats {
  uint16_t valid_mask; // 데이터 유효성 마스크
  uint16_t reserved;   // 패딩

  uint8_t cpu_usage; // cpu 사용량
  uint8_t mem_usage; // memory 사용량

  netInfo net_rx_bytes; // network receive bytes
  netInfo net_tx_bytes; // network transmit bytes

  uint32_t proc_count;
  uint32_t total_proc_count;
  uint16_t net_user_count;
  uint16_t connected_user_count;

  uint32_t uptime_secs;

  fdInfo fd_info;

  DiskSummary disk_info;
};
#pragma pack(pop)

static_assert(sizeof(SecureHeader) == 24, "SecureHeader size mismatch");
static_assert(sizeof(SystemStats) == 134, "SystemStats size mismatch");
} // namespace SST

#endif // PROTOCOL_HPP