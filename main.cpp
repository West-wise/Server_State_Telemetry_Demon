#include "PacketUtil.hpp"
#include "Protocol.hpp"
#include "SystemReader.hpp"
#include "TcpServer.hpp"
#include "Config.hpp"
#include "Logger.hpp"
#include <vector>
#include <csignal>

// 시그널 핸들러 등록
// Daemon이지만 kill명령어를 통해서 종료 신호를 받을 수 있기때문에 시그널 핸들러를 등록해둠


// 파일에서 바이너리 키 데이터 로드
std::vector<uint8_t> loadKeyFile(const std::string_view filepath){
    std::ifstream file(std::string(filepath), std::ios::binary | std::ios::ate); // 맨 끝으로 이동
    if(!file.is_open()) return {};

    std::streamsize size = file.tellg(); // 크기 측정
    file.seekg(0, std::ios::beg); // 처음으로 이동

    std::vector<uint8_t> buffer(size);
    if(file.read((char*)buffer.data(), size)) return buffer;
    return {};
}

int main(){
    
    if(!SST::Config::load(std::string(CONFIG_FILE_PATH))){
        std::cerr << "Failed to load config file." << "\n";
        return -1;
    }

    int port = SST::Config::getInt("server", "port");
    std::cout << "Configured to use port: " << port << "\n";
    std::string log_path = SST::Config::getString("log", "path");
    std::cout << "Configured to use log path: " << log_path << "\n";
    std::string hmac_key_path = SST::Config::getString("security", "hmac_key");
    std::cout << "Configured to use HMAC key path: " << hmac_key_path << "\n";

    // demonize 설정

    // 모든 설정이 끝난 후 디스크립터 이동
    if(!SST::Logger::init(log_path)){
        std::cerr << "[Logger] Logger initialization failed." << "\n";
        return -1;
    };

    // 실행
    SST::TcpServer sstd(port);
    std::cout << "Starting Server State Telemetry Daemon on port " << port << "...\n";
    sstd.run();

    return 0;

}