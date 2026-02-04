#include "SystemReader.hpp"
#include <fstream>
#include <sstream>
#include <vector>
#include <iostream>
#include <unistd.h>
#include <sys/sysinfo.h>

namespace SST {

    SystemReader& SystemReader::getInstance() {
        static SystemReader instance;
        return instance;
    }

    SystemReader::~SystemReader() {
        stop();
    }

    void SystemReader::start() {
        if (running_) return;
        running_ = true;
        collector_thread_ = std::thread(&SystemReader::updateLoop, this);
    }

    void SystemReader::stop() {
        if (!running_) return;
        running_ = false;
        if (collector_thread_.joinable()) {
            collector_thread_.join();
        }
    }

    SystemStats SystemReader::getStats() {
        std::shared_lock lock(mutex_);
        return current_stats_;
    }

    void SystemReader::updateLoop() {
        while (running_) {
            {
                std::unique_lock lock(mutex_);
                // 데이터 수집
                parseProcStat();
                parseMemInfo();
                parseUptime();
                // Network, Disk 등은 추후 확장
                current_stats_.valid_mask = 0xFFFF; // 유효함 표시
            }
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }

    void SystemReader::parseProcStat() {
        std::ifstream file("/proc/stat");
        if (!file.is_open()) return;

        std::string line;
        if (std::getline(file, line)) {
            if (line.substr(0, 3) == "cpu") {
                std::istringstream iss(line);
                std::string header;
                unsigned long long user, nice, system, idle, iowait, irq, softirq, steal;
                iss >> header >> user >> nice >> system >> idle >> iowait >> irq >> softirq >> steal;

                unsigned long long total = user + nice + system + idle + iowait + irq + softirq + steal;
                unsigned long long total_idle = idle + iowait;

                unsigned long long diff_total = total - prev_cpu_.total_time;
                unsigned long long diff_idle = total_idle - prev_cpu_.idle_time;

                if (diff_total > 0) {
                    double usage = 100.0 * (diff_total - diff_idle) / diff_total;
                    current_stats_.cpu_usage = static_cast<uint8_t>(usage);
                }

                prev_cpu_.total_time = total;
                prev_cpu_.idle_time = total_idle;
            }
        }
    }

    void SystemReader::parseMemInfo() {
        std::ifstream file("/proc/meminfo");
        if (!file.is_open()) return;

        std::string line;
        unsigned long total_mem = 0;
        unsigned long free_mem = 0;
        unsigned long available_mem = 0;

        while (std::getline(file, line)) {
            std::istringstream iss(line);
            std::string key;
            unsigned long value;
            std::string unit;
            iss >> key >> value >> unit;

            if (key == "MemTotal:") total_mem = value;
            else if (key == "MemFree:") free_mem = value; // Available을 쓰는게 더 정확함
            else if (key == "MemAvailable:") available_mem = value;
        }

        if (total_mem > 0) {
            unsigned long used = total_mem - available_mem;
            double usage = 100.0 * used / total_mem;
            current_stats_.mem_usage = static_cast<uint8_t>(usage);
        }
    }

    void SystemReader::parseUptime() {
        struct sysinfo info;
        if (sysinfo(&info) == 0) {
            current_stats_.uptime_secs = static_cast<uint32_t>(info.uptime);
        }
    }
}
