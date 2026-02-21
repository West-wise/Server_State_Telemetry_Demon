#ifndef UTILITY_HPP
#define UTILITY_HPP
#include <vector>
#include <charconv>

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
}

#endif