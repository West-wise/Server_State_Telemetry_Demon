#include "SystemReader.hpp"
#include "PacketUtil.hpp"
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstring>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
#include <unistd.h>

using namespace std::chrono_literals;

static void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

static uint64_t readKb(const char *path, const std::string &key) {
  std::ifstream file(path);
  std::string line;
  while (std::getline(file, line)) {
    if (line.compare(0, key.size(), key) == 0)
      return std::stoull(line.substr(key.size()));
  }
  throw std::runtime_error("Missing memory counter");
}

int main() {
  auto &reader = SST::SystemReader::getInstance();
  try {
    require(reader.getStats().daemon_cpu_usage == SST::USAGE_UNAVAILABLE,
            "Uncollected CPU must be unavailable");
    reader.start();
    const auto first_deadline = std::chrono::steady_clock::now() + 800ms;
    while (reader.getStats().daemon_mem_usage == SST::USAGE_UNAVAILABLE &&
           std::chrono::steady_clock::now() < first_deadline)
      std::this_thread::sleep_for(10ms);
    const auto first = reader.getStats();
    require(first.daemon_mem_usage <= 10000, "RSS sample missing");
    require(first.daemon_cpu_usage == SST::USAGE_UNAVAILABLE,
            "First CPU interval must be unavailable");

    std::this_thread::sleep_for(2200ms);
    const auto idle = reader.getStats();
    require(idle.daemon_cpu_usage <= 10000, "Idle CPU sample missing");

    // Touch pages so RSS (rather than virtual size) actually grows.
    std::vector<unsigned char> memory(128 * 1024 * 1024, 0x5a);
    std::thread worker([] {
      volatile uint64_t counter = 0;
      const auto deadline = std::chrono::steady_clock::now() + 3200ms;
      while (std::chrono::steady_clock::now() < deadline)
        ++counter;
    });
    worker.join();
    const auto busy = reader.getStats();
    require(busy.daemon_cpu_usage > idle.daemon_cpu_usage,
            "Worker thread CPU usage was not collected");
    const double one_core = 10000.0 / sysconf(_SC_NPROCESSORS_ONLN);
    require(busy.daemon_cpu_usage < one_core * 1.5 + 2,
            "CPU is not normalized to whole-machine capacity");
    const auto total = readKb("/proc/meminfo", "MemTotal:");
    const auto rss = readKb("/proc/self/status", "VmRSS:");
    const auto expected = std::lround(10000.0 * rss / total);
    require(std::abs(static_cast<long>(busy.daemon_mem_usage) - expected) <= 2,
            "RSS ratio or fixed-point scale mismatch");
    require(busy.daemon_mem_usage > first.daemon_mem_usage,
            "Resident allocation not reflected in memory usage");
    require(memory.back() == 0x5a, "Memory allocation lost");
    reader.stop();

    reader.start();
    std::this_thread::sleep_for(300ms);
    require(reader.getStats().daemon_cpu_usage == SST::USAGE_UNAVAILABLE,
            "Restart must reset CPU baseline");
    reader.stop();

    // Known bytes also serve as a fixture for the Python receiver test.
    SST::SystemStats stats{};
    stats.cpu_usage = 42;
    stats.disk_info.used_boot = 123456789;
    stats.daemon_cpu_usage = 123;
    stats.daemon_mem_usage = SST::USAGE_UNAVAILABLE;
    std::vector<uint8_t> body(sizeof(stats));
    std::memcpy(body.data(), &stats, sizeof(stats));
    const auto packet = SST::PacketUtil::createPacket(0x11, 7, body);
    SST::SecureHeader header{};
    std::memcpy(&header, packet.data(), sizeof(header));
    require(header.body_len == 138 && packet.size() == 162,
            "Wire packet size mismatch");
    require(packet[24 + 134] == 123 && packet[24 + 135] == 0 &&
            packet[24 + 136] == 255 && packet[24 + 137] == 255,
            "Daemon fields wire offset or endian mismatch");
    std::ofstream fixture("daemon_packet.bin", std::ios::binary);
    fixture.write(reinterpret_cast<const char *>(packet.data()), packet.size());
    require(static_cast<bool>(fixture), "Could not write packet fixture");
    std::cout << "PASS: baseline, idle, worker CPU, RSS, restart, packet layout\n";
    return 0;
  } catch (const std::exception &error) {
    reader.stop();
    std::cerr << error.what() << '\n';
    return 1;
  }
}
