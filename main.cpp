#include "PacketUtil.hpp"
#include "Protocol.hpp"
#include "SystemReader.hpp"
#include "TcpServer.hpp"
#include "Config.hpp"
#include "Logger.hpp"
#include "utility.hpp"
#include <vector>
#include <csignal>
#include <iostream>
#include <atomic>
#include <string>
#include <cstring>

// Signal handling
volatile sig_atomic_t g_stop_signal = 0;

void handle_signal(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        g_stop_signal = 1;
    }
}

int main(int argc, char* argv[]) {
    // 시그널 등록
    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    // Config 로드 (argv 지원)
    std::string config_path = std::string(CONFIG_FILE_PATH);
    bool show_qr = false;

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "-q") == 0 || std::strcmp(argv[i], "--show-qr") == 0) {
            show_qr = true;
        } else if (argv[i][0] != '-') {
            config_path = argv[i]; // '-'로 시작하지 않으면 설정 파일 경로로 간주
        }
    }

    if (!SST::Config::load(config_path)) {
        std::cerr << "Failed to load config file: " << config_path << std::endl;
        return -1;
    }

    // 설정 값 읽기
    int port = SST::Config::getInt("server", "port", 41924);
    std::string log_path = SST::Config::getString("log", "path", "logs/sstd.log");
    std::string secret_key = SST::Config::getString("security", "hmac_key", "");

    if (show_qr) {
        std::string ext_host = SST::Config::getString("proxy", "host", "");
        if (ext_host.empty()) {
            std::string ext_interface = SST::Config::getString("proxy", "interface", "");
            if (!ext_interface.empty()) {
                ext_host = SST::Utils::Network::getInterfaceIP(ext_interface);
            } else {
                ext_host = SST::Config::getString("server", "ip", "127.0.0.1");
            }
        }
        int ext_port = SST::Config::getInt("proxy", "port", port);

        SST::Utils::printTerminalQRCode(ext_host, ext_port, secret_key);
        return 0; // 즉시 종료
    }

    // Async Logger 초기화
    if (!SST::Logger::init(log_path)) {
        std::cerr << "[Server] Logger init failed." << std::endl;
        return -1;
    }
    SST::Logger::log("[Server] Server starting...");

    // SystemReader 시작 (시스템 정보 수집 스레드)
    SST::SystemReader::getInstance().start();
    SST::Logger::log("[Server] SystemReader started.");

    // TCP Server 실행 (Main Thread)
    try {
        SST::TcpServer sstd(port);
        SST::Logger::log("[Server] TCP Server Listening on port " + std::to_string(port));
        sstd.setStopFlag(&g_stop_signal);
        sstd.run();
    } catch (const std::exception& e) {
        SST::Logger::log(std::string("[Server] Exception: ") + e.what());
    }

    SST::Logger::log("[Server] Shutdown sequence initiated...");

    // Cleanup
    SST::SystemReader::getInstance().stop();
    SST::Logger::shutdown();
    return 0;
}