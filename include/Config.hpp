#ifndef CONFIG_HPP
#define CONFIG_HPP

#include <string>
#include <map>
#include <fstream>
#include <algorithm>
#include <string_view>
#include <iostream>
#include <mutex>

// 이 상대경로 문제는 좀더 고민해볼 것...
constexpr std::string_view CONFIG_FILE_PATH = "../config/sstd.ini";
namespace SST {
    class Config {
        public:
        using SectionMap = std::map<std::string, std::string>;
        using ConfigMap = std::map<std::string, SectionMap>;
        
        // 설정 파일 로드
        // 첫 실행시 단 한번만 호출할 것
        static bool load(const std::string& filename){
            config_data_.clear();
            std::ifstream file(filename);
            if(!file.is_open()) return false;
            std::string line;
            std::string current_section;
            while(getline(file, line)){
                // 공백 제거
                auto vline = trim(line);
                
                // 빈줄 혹은 주석 무시
                if(vline.empty() || vline[0] == '#' || vline[0] == ';') continue;

                // 섹션 파싱
                if(vline.front() == '[' && vline.back() == ']'){
                    current_section = std::string(vline.substr(1, vline.size() - 2));
                    continue;
                }

                // 키-값 파싱
                size_t delim_pos = vline.find('=');
                if(delim_pos != std::string::npos){
                    auto key = trim(vline.substr(0, delim_pos));
                    auto value = trim(vline.substr(delim_pos + 1));
                    
                    if(!current_section.empty()){
                        std::cout << "Config Load: [" << current_section << "] " << key << " = " << value << "\n";
                        config_data_[current_section].emplace(key, value);
                    }
                }
            }
            return true;
        }
        
        // string값 가져오기
        static std::string getString(const std::string& section, const std::string& key, const std::string& default_value = ""){
            if(config_data_.empty()) return default_value;
            if(config_data_.find(section) != config_data_.end()){
                if(config_data_[section].find(key) != config_data_[section].end()){
                    return config_data_[section][key];
                }
            }
            return default_value;
        }

        // int값 가져오기
        static int getInt(const std::string& section, const std::string& key, int default_value = 0){
            if(config_data_.empty()) return default_value;
            std::string value = getString(section, key);
            if(value.empty()) return default_value;
            try {
                return stoi(value);
            } catch(const std::exception&){
                return default_value;
            }
        }

        

    private:
        static inline ConfigMap config_data_;    
        static std::string_view trim(std::string_view s){
            constexpr auto whitespace = " \t\n\r\f\v";
            const auto first = s.find_first_not_of(whitespace);
            if (first == std::string_view::npos) {
                return {};
            }
            const auto last = s.find_last_not_of(whitespace);
            return s.substr(first, last - first + 1);
        }
    };
}


#endif // CONFIG_HPP