#ifndef UTILITY_HPP
#define UTILITY_HPP

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace SST::Utils::String {
std::string_view trim(std::string_view s);
std::vector<std::string_view> split(std::string_view s,
                                    char delimiter = ' ',
                                    int token_cnt = 5);
}

namespace SST::Utils::Network {
uint32_t hexToUint32(std::string_view hex_str);
std::string getInterfaceIP(const std::string &interface_name);
}

namespace SST::Utils {
void printTerminalQRCode(const std::string &name,
                         const std::string &ip,
                         int port,
                         const std::string &key);
}

#endif