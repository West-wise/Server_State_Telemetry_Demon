#ifndef CONFIG_HPP
#define CONFIG_HPP

#include "utility.hpp"
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unordered_map>
#include <vector>

// 이 상대경로 문제는 좀더 고민해볼 것...
constexpr std::string_view CONFIG_FILE_PATH = "../config/sstd.ini";
namespace SST {
class Config {
public:
  using SectionMap = std::unordered_map<std::string, std::string>;
  using ConfigMap = std::unordered_map<std::string, SectionMap>;

  // 설정 파일 로드
  // 첫 실행시 단 한번만 호출할 것
  static bool load(const std::string &filename) {
    config_data_.clear();
    std::ifstream file(filename);
    if (!file.is_open())
      return false;
    std::string line;
    std::string current_section;
    while (getline(file, line)) {
      // 공백 제거
      auto vline = SST::Utils::String::trim(line);

      // 빈줄 혹은 주석 무시
      if (vline.empty() || vline[0] == '#' || vline[0] == ';')
        continue;

      // 섹션 파싱
      if (vline.front() == '[' && vline.back() == ']') {
        current_section = std::string(vline.substr(1, vline.size() - 2));
        continue;
      }

      // 키-값 파싱
      size_t delim_pos = vline.find('=');
      if (delim_pos != std::string::npos) {
        auto key = SST::Utils::String::trim(vline.substr(0, delim_pos));
        auto value = SST::Utils::String::trim(vline.substr(delim_pos + 1));

        if (!current_section.empty()) {
          std::cout << "Config Load: [" << current_section << "] " << key
                    << " = " << value << std::endl;
          config_data_[current_section].emplace(key, value);
        }
      }
    }
    return true;
  }

  // string값 가져오기
  static std::string_view getString(const std::string &section,
                                    const std::string &key,
                                    std::string_view default_value = "") {
    if (config_data_.empty())
      return default_value;

    auto sec_it = config_data_.find(section);
    if (sec_it != config_data_.end()) {
      auto key_it = sec_it->second.find(key);
      if (key_it != sec_it->second.end()) {
        return key_it->second;
      }
    }
    return default_value;
  }

  // int값 가져오기
  static int getInt(const std::string &section, const std::string &key,
                    int default_value = 0) {
    if (config_data_.empty())
      return default_value;

    std::string_view value = getString(section, key);
    if (value.empty())
      return default_value;

    try {
      return std::stoi(std::string(value));
    } catch (const std::exception &) {
      return default_value;
    }
  }
  static std::string_view getHashKey() {
    if (hash_key_.empty())
      checkKeyFile();
    return hash_key_;
  }

private:
  static inline ConfigMap config_data_;
  static inline std::string hash_key_ = "";

  constexpr static const char *key_path =
      "sstd.key"; // 추후 /etc/sstd/sstd.key로 변경

  static void checkKeyFile() {
    std::ifstream file(key_path);
    if (file.is_open()) { // 키파일 이미 존재
      std::getline(file, hash_key_);
      file.close();
    } else {
      std::cout << "[Info] Key file not existed. Generating..." << std::endl;
      genKey();
    }
  }

  static bool genKey() {
    std::ifstream urandom("/dev/urandom", std::ios::in | std::ios::binary);
    if (!urandom) {
      std::cerr << "[Error] Cannot open /dev/urandom" << std::endl;
      return false;
    }
    std::vector<uint8_t> tmp_key(16);
    urandom.read(reinterpret_cast<char *>(tmp_key.data()), 16);

    const char *hex_chars = "0123456789abcdef";
    hash_key_.clear();
    for (uint8_t byte : tmp_key) {
      hash_key_.push_back(hex_chars[byte >> 4]);
      hash_key_.push_back(hex_chars[byte & 0x0F]);
    }
    std::ofstream out_file(key_path);
    if (out_file.is_open()) {
      out_file << hash_key_;
      out_file.close();

      if (chmod(key_path, int(S_IREAD) | int(S_IWRITE)) != 0) {
        std::cerr << "[Warning] Failed to set permissions 0600 on key file!"
                  << std::endl;
      }
      return true;
    }
    return false;
  }
};
} // namespace SST

#endif // CONFIG_HPP