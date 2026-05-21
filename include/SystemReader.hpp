#ifndef SYSTEMREADER_HPP
#define SYSTEMREADER_HPP

#include "Protocol.hpp"
#include <atomic>
#include <chrono>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <thread>
#include <utility>

namespace SST {

class SystemReader {
public:
  // Singleton Access
  static SystemReader &getInstance();

  void start();
  void stop();

  // 최신 통계 조회 (Thread-Safe)
  SystemStats getStats();

private:
  SystemReader() = default;
  ~SystemReader();

  // 복사 방지
  SystemReader(const SystemReader &) = delete;
  SystemReader &operator=(const SystemReader &) = delete;

  std::atomic<bool> running_{false};
  std::thread collector_thread_;

  mutable std::shared_mutex mutex_;

  // 시스템 통계 관련
  SystemStats current_stats_{};

  // CPU Usage Calculation State
  struct CpuData {
    uint64_t total_time = 0;
    uint64_t idle_time = 0;
  } prev_cpu_{};
  bool cpu_prev_valid_{false};

  // 네트워크 정보 관련
  struct NetCounter {
    uint64_t rx_bytes{0}, rx_packets{0}, rx_errs{0}, rx_drop{0};
    uint64_t tx_bytes{0}, tx_packets{0}, tx_errs{0}, tx_drop{0};
  } prev_net_{};
  bool net_prev_valid_{false};
  std::chrono::steady_clock::time_point prev_net_tp_{};

  void updateLoop();
  void parseProcStat(SystemStats &stats);
  void parseMemInfo(SystemStats &stats);
  void parseDiskUsage(SystemStats &stats); // Optional
  void parseUptime(SystemStats &stats);
  void getNetDevInfo(SystemStats &stats);
  void numberOfProcess(SystemStats &stats);
  void fileDescriptorsInfo(SystemStats &stats);
  void networkConnectedClients(SystemStats &stats);
  void connectedUsersInfo(SystemStats &stats);
  void partitionsInfo(SystemStats &stats);
  void nfsPartitionsInfo(SystemStats &stats);
  bool parseNetDevInfo(NetCounter &out);
  static std::string getHostName();
};
} // namespace SST

#endif // SYSTEMREADER_HPP
