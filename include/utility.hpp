#ifndef UTILITY_HPP
#define UTILITY_HPP
#include <vector>
#include <charconv>
#include <iostream>
#include <string>
#include <cstring>
#include "qrcodegen.hpp"

#ifdef __linux__
#include <sys/types.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

namespace SST::Utils::String{
    // 공백 제거
    inline std::string_view trim(std::string_view s){
        constexpr auto whitespace = " \t\n\r\f\v\"";
        const auto first = s.find_first_not_of(whitespace);
        if (first == std::string_view::npos) {
            return {};
        }
        const auto last = s.find_last_not_of(whitespace);
        return s.substr(first, last - first + 1);
    }

    // 예상 토큰 갯수를 입력받아, 메모리 할당을 최적화
    // 기본 구분자는 공백, 기본 메모리 할당은 5개(임의 지정 한 것..)
    inline std::vector<std::string_view> split(std::string_view s, char delimiter = ' ', int token_cnt = 5){
        std::vector<std::string_view> tokens;
        tokens.reserve(token_cnt);
        
        size_t start = 0;
        size_t end = s.find(delimiter);
        
        while(end != std::string_view::npos){
            std::string_view token = s.substr(start, end - start);
            if(!token.empty()) tokens.push_back(token);
            start = end + 1;
            end = s.find(delimiter, start);
        }
        std::string_view lastToken = s.substr(start);
        if(!lastToken.empty()){
            tokens.push_back(lastToken);
        }
        return tokens;
    }
}

namespace SST::Utils::Network {
    inline uint32_t hexToUint32(const std::string_view hex_str){
        uint32_t value;
        auto [ptr, ec] = std::from_chars(hex_str.data(), hex_str.data() + hex_str.size(), value, 16);
        if(ec != std::errc()) return 0;
        return value; // 호스트 바이트 오더 반환
    }

    // 주어진 네트워크 인터페이스 이름(예: "ens160", "eth0")의 IPv4 주소를 반환합니다.
    inline std::string getInterfaceIP(const std::string& interface_name) {
#ifdef __linux__
        struct ifaddrs *interfaces = nullptr;
        struct ifaddrs *ifa = nullptr;
        std::string ip_address = "";

        if (getifaddrs(&interfaces) == 0) {
            for (ifa = interfaces; ifa != nullptr; ifa = ifa->ifa_next) {
                if (ifa->ifa_addr == nullptr) continue;
                
                // IPv4 체크 및 인터페이스 이름 매칭
                if (ifa->ifa_addr->sa_family == AF_INET && 
                    std::strcmp(ifa->ifa_name, interface_name.c_str()) == 0) {
                    
                    char ip[INET_ADDRSTRLEN];
                    void* addr_ptr = &((struct sockaddr_in*)ifa->ifa_addr)->sin_addr;
                    inet_ntop(AF_INET, addr_ptr, ip, INET_ADDRSTRLEN);
                    ip_address = ip;
                    break;
                }
            }
            freeifaddrs(interfaces);
        }
        return ip_address.empty() ? "127.0.0.1" : ip_address;
#else
        // Windows 등 타 OS Fallback
        return "127.0.0.1";
#endif
    }
}

namespace SST::Utils {
    // 터미널에 QR 코드를 ANSI 특수문자 조합으로 그려주는 헬퍼 함수
    inline void printTerminalQRCode(const std::string& ip, int port, const std::string& key) {
        // 예: sstd://127.0.0.1:41924?key=3e4a4f4e05...
        std::string connectionString = "sstd://" + ip + ":" + std::to_string(port) + "?key=" + key;
        using qrcodegen::QrCode;
        QrCode qr = QrCode::encodeText(connectionString.c_str(), QrCode::Ecc::LOW);
        int border = 2;
        std::cout << "\n[ SSTD Server Connection QR Code ]\n" << std::endl;
        for (int y = -border; y < qr.getSize() + border; y++) {
            for (int x = -border; x < qr.getSize() + border; x++) {
                if (qr.getModule(x, y)) {
                    std::cout << "\033[40m  \033[0m"; 
                } else {
                    std::cout << "\033[47m  \033[0m"; 
                }
            }
            std::cout << std::endl;
        }
        std::cout << "\n* Connection String: " << connectionString << "\n" << std::endl;
    }
}

#endif