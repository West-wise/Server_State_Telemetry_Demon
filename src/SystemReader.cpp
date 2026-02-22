#include "SystemReader.hpp"
#include "utility.hpp"
#include "Config.hpp"
#include "Logger.hpp"
#include <fstream>
#include <sstream>
#include <vector>
#include <iostream>
#include <unistd.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>
#include <sys/statvfs.h> // statvfs()
#include <sys/stat.h>    // stat()
#include <climits>
#include <cstring>
#include <string>
#include <utmp.h>
#include <unordered_set>
#include <set>
#include <mntent.h>

// 제공 대상 정보 수집
// host info
// CPU info
// RAM info
// network(upload/download) info
// network connected clients
// number of process
// number of file descriptors
// display uptime
// connected users info
// partitions info
// NFS partitions info


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

    // 락을 걸고 현재 수집된 정보를 반환
    SystemStats SystemReader::getStats() {
        std::shared_lock lock(mutex_);
        return current_stats_;
    }

    // 최초 실행시 호스트 정보 수집(해당 정보는 변하지 않으므로 캐싱)
    HostInfo SystemReader::getHostInfo() {
        std::call_once(init_flag_, [this]() {
            HostInfo local = this -> collectHostInfo();
            {
                std::unique_lock<std::shared_mutex> wlock(mutex_);
                host_info_ = std::move(local);
            }
        });
        std::shared_lock<std::shared_mutex> rlock(mutex_);
        return host_info_;
    }

    void SystemReader::updateLoop() {
        int disk_update_counter = 0; // disk정보는 자주 변하지 않는 정보이기 때문에 10초마다 갱신

        while (running_) {
            {
                SystemStats next_stats{};
                // 데이터 수집
                parseProcStat(next_stats);              // CPU info
                parseMemInfo(next_stats);               // RAM info
                getNetDevInfo(next_stats);
                networkConnectedClients(next_stats);    // network connected clients
                numberOfProcess(next_stats);            // number of process
                fileDescriptorsInfo(next_stats);        // number of file descriptors
                parseUptime(next_stats);                // uptime info
                connectedUsersInfo(next_stats);         // connected users info(who)
                if (disk_update_counter == 0) {
                    partitionsInfo(next_stats);         // partitions info
                } else {
                    // 10초가 안되었으면 이전 측정값을 그대로 복사
                    std::shared_lock lock(mutex_);
                    next_stats.disk_info = current_stats_.disk_info;
                }
                disk_update_counter = (disk_update_counter + 1) % 10;
                next_stats.valid_mask = 0xFFFF;
                { // 커밋, 커밋 시점에만 락
                    std::unique_lock lock(mutex_);
                    current_stats_ = next_stats;
                }
            }
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }

    void SystemReader::parseProcStat(SystemStats& out) {
        std::ifstream file("/proc/stat");
        if (!file.is_open()) return;

        std::string line;
        if (std::getline(file, line)) {
            if (line.substr(0, 3) == "cpu") {
                std::istringstream iss(line);
                std::string header;
                uint64_t user, nice, system, idle, iowait, irq, softirq, steal;
                iss >> header >> user >> nice >> system >> idle >> iowait >> irq >> softirq >> steal;

                uint64_t total = user + nice + system + idle + iowait + irq + softirq + steal;
                uint64_t total_idle = idle + iowait;

                uint64_t diff_total = total - prev_cpu_.total_time;
                uint64_t diff_idle = total_idle - prev_cpu_.idle_time;

                if(!cpu_prev_valid_){
                    cpu_prev_valid_ = true;
                    prev_cpu_.total_time = total;
                    prev_cpu_.idle_time = total_idle;
                    out.cpu_usage = 0;
                    return;
                }

                if (diff_total > 0) {
                    double usage = 100.0 * (diff_total - diff_idle) / diff_total;
                    out.cpu_usage = static_cast<uint8_t>(usage);
                }

                prev_cpu_.total_time = total;
                prev_cpu_.idle_time = total_idle;
            }
        }
    }

    void SystemReader::parseMemInfo(SystemStats& out) {
        std::ifstream file("/proc/meminfo");
        if (!file.is_open()) return;

        std::string line;
        uint64_t total_mem = 0;
        uint64_t free_mem = 0;
        uint64_t available_mem = 0;

        while (std::getline(file, line)) {
            std::istringstream iss(line);
            std::string key;
            uint64_t value;
            std::string unit;
            iss >> key >> value >> unit;

            if (key == "MemTotal:") total_mem = value;
            else if (key == "MemFree:") free_mem = value;
            else if (key == "MemAvailable:") available_mem = value;
        }
        if (available_mem == 0) {
            available_mem = free_mem;
        }

        if (total_mem > 0) {
            uint64_t used = total_mem - available_mem;
            double usage = 100.0 * used / total_mem;
            out.mem_usage = static_cast<uint8_t>(usage);
        }
    }

    void SystemReader::parseUptime(SystemStats& out) {
        struct sysinfo info;
        if (sysinfo(&info) == 0) {
            out.uptime_secs = static_cast<uint32_t>(info.uptime);
        }
    }

    std::string SystemReader::getHostName(){
        char hostname_buf[HOST_NAME_MAX+1];
        std::memset(hostname_buf, 0, sizeof(hostname_buf));
        if(gethostname(hostname_buf, sizeof(hostname_buf)) == 0){
            return std::string(hostname_buf);
        }
        return "Unknown";
    }

    HostInfo SystemReader::collectHostInfo(){
        HostInfo out{};

        // 기본값 설정
        std::string hostname = getHostName();
        std::string os_name = "Unknown OS";
        std::string release_info = "Unknown Release";

        // Uname 정보 수집 시도
        struct utsname sys_info;
        if(uname(&sys_info) != -1){
            out.os_name = std::string(sys_info.sysname) + " " + std::string(sys_info.release);
        } else {
            SST::Logger::log("[Warning] Failed to get system info using uname");
        }

        // os-release 파일 읽기 시도
        const char* paths[] = {"/etc/os-release", "/usr/lib/os-release"};
        for(const char* path : paths){
            std::ifstream file(path);
            if(!file.is_open()) continue;
            
            std::string line;
            while(std::getline(file, line)){
                if(line.empty() || line[0] == '#') continue;
                std::istringstream ss(line);
                std::string key, value;
                if(std::getline(ss, key, '=') && std::getline(ss, value)){
                    if(key == "PRETTY_NAME"){
                        out.release_info = std::string(SST::Utils::String::trim(value));
                        break;
                    }
                }
            }
            if (out.release_info != "Unknown Release") break;    
        }
        return out;
    }

    bool SystemReader::parseNetDevInfo(NetCounter& out){
        std::ifstream file("/proc/net/dev");
        if(!file.is_open()) return false;
        std::string line;
        
        // 헤더 2줄 스킵
        if(!std::getline(file, line)) return false;
        if(!std::getline(file, line)) return false;

        NetCounter sum{};

        // 그중에서 [0~3]은 수신(RX), [8~11]은 송신(TX)
        while(std::getline(file, line)){
            if(line.empty()) continue;

            const auto pos = line.find(':');
            if(pos == std::string::npos) continue;

            std::string iface_name = std::string(SST::Utils::String::trim(line.substr(0,pos)));
            if(iface_name == "lo") continue;

            std::istringstream iss(line.substr(pos + 1));
            // /proc/net/dev는 숫자 16개 (rx 8 + tx 8)
            uint64_t rx_bytes=0, rx_packets=0, rx_errs=0, rx_drop=0;
            uint64_t rx_fifo=0, rx_frame=0, rx_comp=0, rx_mcast=0;
            uint64_t tx_bytes=0, tx_packets=0, tx_errs=0, tx_drop=0;
            uint64_t tx_fifo=0, tx_colls=0, tx_carrier=0, tx_comp=0;

            if (!(iss >> rx_bytes >> rx_packets >> rx_errs >> rx_drop
                    >> rx_fifo >> rx_frame >> rx_comp >> rx_mcast
                    >> tx_bytes >> tx_packets >> tx_errs >> tx_drop
                    >> tx_fifo >> tx_colls >> tx_carrier >> tx_comp)) {
                continue;
            }

            sum.rx_bytes   += rx_bytes;
            sum.rx_packets += rx_packets;
            sum.rx_errs    += rx_errs;
            sum.rx_drop    += rx_drop;

            sum.tx_bytes   += tx_bytes;
            sum.tx_packets += tx_packets;
            sum.tx_errs    += tx_errs;
            sum.tx_drop    += tx_drop;
            
        }
        out = sum;
        return true;
    }

    inline uint64_t delta(uint64_t cur_val, uint64_t prev_val){
        return (cur_val >= prev_val) ? (cur_val - prev_val) : 0ULL;
    }

    void SystemReader::getNetDevInfo(SystemStats& out){
        NetCounter cur{};
        if(!parseNetDevInfo(cur)) return;
        const auto now = std::chrono::steady_clock::now();
        
        if(!net_prev_valid_){
            prev_net_ = cur;
            prev_net_tp_ = now;
            net_prev_valid_ = true;

            out.net_rx_bytes = {0,0,0,0};
            out.net_tx_bytes = {0,0,0,0};
            return;
        }

        const std::chrono::duration<double> dt = now - prev_net_tp_;
        const double sec = dt.count();

        if( sec <= 0.0 ){
            prev_net_ = cur;
            prev_net_tp_ = now;
            return;
        }

        const uint64_t d_rx_bytes = delta(cur.rx_bytes, prev_net_.rx_bytes);
        const uint64_t d_rx_pkts = delta(cur.rx_packets, prev_net_.rx_packets);
        const uint64_t d_rx_errs = delta(cur.rx_errs, prev_net_.rx_errs);
        const uint64_t d_rx_drop = delta(cur.rx_drop, prev_net_.rx_drop);

        const uint64_t d_tx_bytes = delta(cur.tx_bytes, prev_net_.tx_bytes);
        const uint64_t d_tx_pkts = delta(cur.tx_packets, prev_net_.tx_packets);
        const uint64_t d_tx_errs = delta(cur.tx_errs, prev_net_.tx_errs);
        const uint64_t d_tx_drop = delta(cur.tx_drop, prev_net_.tx_drop);

        out.net_rx_bytes = {
            static_cast<uint32_t>(d_rx_bytes / sec),
            static_cast<uint32_t>(d_rx_pkts / sec),
            static_cast<uint32_t>(d_rx_errs / sec),
            static_cast<uint32_t>(d_rx_drop / sec)
        };

        out.net_tx_bytes = {
            static_cast<uint32_t>(d_tx_bytes / sec),
            static_cast<uint32_t>(d_tx_pkts / sec),
            static_cast<uint32_t>(d_tx_errs / sec),
            static_cast<uint32_t>(d_tx_drop / sec)
        };

        prev_net_ = cur;
        prev_net_tp_ = now;
    }

    void SystemReader::numberOfProcess(SystemStats& stats){
        std::ifstream file("/proc/loadavg");
        if(!file.is_open()) return;
        std::string line;
        if(!std::getline(file, line)) return;
        std::vector<std::string_view> tokens = SST::Utils::String::split(line);
        if(tokens.size() < 4) return;
        std::string proc_info = std::string(tokens[3]);
        std::vector<std::string_view> tokens2 = SST::Utils::String::split(proc_info, '/');
        if(tokens2.size() < 2) return;
        try {
            stats.proc_count = std::stoi(std::string(tokens2[0]));
            stats.total_proc_count = std::stoi(std::string(tokens2[1]));
        } catch (const std::exception& e) {
            stats.proc_count = 0;
            stats.total_proc_count = 0;
            SST::Logger::log("SystemReader::numberOfProcess: parse error");
        }
    }

    void SystemReader::fileDescriptorsInfo(SystemStats& stats){
        // /proc/sys/fs/file-nr
        std::ifstream file("/proc/sys/fs/file-nr");
        if(!file.is_open()) return;
        
        uint16_t allocated = 0, used = 0;
        if(!(file >> allocated >> used)){
            SST::Logger::log("fileDescriptorsInfo: pared failed");
            return;
        }
        stats.fd_info.allocated_fd_cnt = allocated;
        stats.fd_info.using_fd_cnt = used;
    }

    // 12개의 필드중 4번째 st를 파싱해서 st값이 (01 : Established)인 경우만 카운트
    // 단, 중복을 잘 고려해야한다.
    void SystemReader::networkConnectedClients(SystemStats& stats){
        // /proc/net/tcp
        const std::vector<std::string> source = {"/proc/net/tcp", "/proc/net/tcp6"};
        std::unordered_set<std::string> ip_set;
        int totalCnt = 0;

        for(const auto& path : source){
            std::ifstream file(path);
            if(!file.is_open()) continue;
            std::string line;
            if(!std::getline(file, line)) continue; // 헤더 스킵
            
            while(std::getline(file, line)){
                std::istringstream iss(line);
                std::string sl, local, remote, state;
                if (!(iss >> sl >> local >> remote >> state)) continue;
                if(state == "01"){
                    auto tokens = SST::Utils::String::split(remote, ':', 2);
                    if(tokens.size() < 2) continue;
                    if(ip_set.insert(std::string(tokens[0])).second){
                        totalCnt++;
                    }
                }
            }

            stats.net_user_count = totalCnt;
        }
    }

    void SystemReader::connectedUsersInfo(SystemStats& stats){
        std::set<std::string> users;
        // utmp 파일의 시작부분으로 포인터 이동
        setutent();

        struct utmp* entry;
        while((entry = getutent()) != nullptr) {
            if(entry->ut_type == USER_PROCESS){
                users.insert(entry->ut_user);
            }
        }
        endutent();
        stats.connected_user_count = static_cast<uint16_t>(users.size());
    }

    static bool pathExists(const char* path){
        if(path == nullptr) return false;
        struct stat st{};
        return (::stat(path, &st) == 0);
    }

    static void getDiskUsage(const char* path, uint64_t& total, uint64_t& used){
        total = 0, used = 0;
        if(path == nullptr) return;
        struct statvfs st{};
        if(statvfs(path, &st) == 0){
            const uint64_t fr = (uint64_t)st.f_frsize;
            const uint64_t blocks = (uint64_t)st.f_blocks;
            const uint64_t bfree = (uint64_t)st.f_bfree;
            total = blocks * fr;
            used = (blocks >= bfree) ? ((blocks - bfree) * fr) : 0;
        }
    }

    void SystemReader::partitionsInfo(SystemStats& stats){
        getDiskUsage("/", stats.disk_info.total_root, stats.disk_info.used_root);
        getDiskUsage("/home", stats.disk_info.total_home, stats.disk_info.used_home);
        getDiskUsage("/var", stats.disk_info.total_var, stats.disk_info.used_var);
        getDiskUsage("/boot", stats.disk_info.total_boot, stats.disk_info.used_boot);
    }
}
