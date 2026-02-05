#include "PacketUtil.hpp"
#include "Protocol.hpp"
#include "SystemReader.hpp"
#include "TcpServer.hpp"
#include "Config.hpp"
#include "Logger.hpp"
#include <vector>
#include <csignal>
#include <iostream>
#include <atomic>
#include <string>
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
    std::string config_path = (argc > 1) ? argv[1] : std::string(CONFIG_FILE_PATH);
    if (!SST::Config::load(config_path)) {
        std::cerr << "Failed to load config file: " << config_path << std::endl;
        return -1;
    }

    // 설정 값 읽기
    int port = SST::Config::getInt("server", "port", 41924);
    std::string log_path = SST::Config::getString("log", "path", "logs/sstd.log");

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
        
        // 메인 루프에서 시그널 체크를 위해 timeout이 있는 runWithTimeout 혹은 외부 flag 참조 필요
        // 여기서는 TcpServer::run() 내부를 수정하여 g_stop_signal을 체크하거나
        // run()이 블로킹이므로, 별도 처리가 필요함.
        // 가장 깔끔한 방법: TcpServer에 atomic pointer를 넘겨주거나, stop 메서드 호출.
        // 하지만 signal handler는 제한적이므로 g_stop_signal을 모니터링해야 함.
        
        // TcpServer::run()을 호출하면 control을 뺏기므로, 
        // TcpServer가 주기적으로 g_stop_signal을 확인하도록 수정 필요.
        // 임시로 sstd 인스턴스에 전역 플래그 주소 전달 또는 getter 사용.
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