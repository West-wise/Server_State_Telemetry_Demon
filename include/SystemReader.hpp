#ifndef SYSTEMREADER_HPP
#define SYSTEMREADER_HPP

#include "Protocol.hpp"
#include <string>
#include <thread>
#include <atomic>
#include <shared_mutex>
#include <chrono>
#include <mutex>

namespace SST {

    class SystemReader {
    public:
        // Singleton Access
        static SystemReader& getInstance();

        void start();
        void stop();
        
        // 최신 통계 조회 (Thread-Safe)
        SystemStats getStats();

    private:
        SystemReader() = default;
        ~SystemReader();

        // 복사 방지
        SystemReader(const SystemReader&) = delete;
        SystemReader& operator=(const SystemReader&) = delete;

        void updateLoop();
        void parseProcStat();
        void parseMemInfo();
        void parseDiskUsage(); // Optional
        void parseUptime();

        std::atomic<bool> running_{false};
        std::thread collector_thread_;
        
        mutable std::shared_mutex mutex_;
        SystemStats current_stats_{};

        // CPU Usage Calculation State
        struct CpuData {
            unsigned long long total_time = 0;
            unsigned long long idle_time = 0;
        } prev_cpu_;
    };
}

#endif // SYSTEMREADER_HPP
