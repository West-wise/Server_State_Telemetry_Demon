#ifndef CONFIG_HPP
#define CONFIG_HPP

#include "utility.hpp"
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sodium.h>
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
  static std::string getString(const std::string &section,
                                    const std::string &key,
                                    std::string default_value = "") {
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

    std::string value = getString(section, key);
    if (value.empty())
      return default_value;

    try {
      return std::stoi(std::string(value));
    } catch (const std::exception &) {
      return default_value;
    }
  }
  // 키쌍을 로드
  // 만약 키파일이 없으면 새로운 키쌍을 생성(각각 32바이트 크기의 private, public key)
  // 생성된 private key는 sstd.key 파일로 저장
  static bool getServerKeypair(uint8_t private_out[32], uint8_t public_out[32]) {
    if (!key_loaded_) {
      if (!checkKeyFile()) return false;
    }
    memcpy(private_out, static_priv_, 32);
    memcpy(public_out,  static_pub_,  32);
    return true;
  }

  // 서버 공개키를 64자리 16진수 문자열로 반환 (QR 코드 출력용)
  static std::string getServerPubKeyHex() {
    if (!key_loaded_) checkKeyFile();
    const char *hex_chars = "0123456789abcdef";
    std::string out;
    // 인덱스 직접 대입을 통한 성능 최적화를 위해 문자열 크기를 미리 64로 설정합니다.
    out.resize(64);
    for (int i = 0; i < 32; ++i) {
      out[i * 2]     = hex_chars[static_pub_[i] >> 4];
      out[i * 2 + 1] = hex_chars[static_pub_[i] & 0x0F];
    }
    return out;
  }

private:
  static inline ConfigMap config_data_;
  static inline uint8_t static_priv_[32] = {};
  static inline uint8_t static_pub_[32]  = {};
  static inline bool    key_loaded_      = false;

  constexpr static const char *key_path =
      "sstd.key"; // 추후 /etc/sstd/sstd.key로 변경

  static bool checkKeyFile() {
    std::ifstream file(key_path, std::ios::binary);
    if (file.is_open()) {
      file.read(reinterpret_cast<char*>(static_priv_), 32);
      if (file.gcount() != 32) {
        std::cerr << "[Error] Key file corrupt (expected 32 bytes)" << std::endl;
        return false;
      }
      file.close();
    } else {
      std::cout << "[Info] Key file not found. Generating X25519 keypair..." << std::endl;
      if (!genKey()) return false;
    }
    // Derive public key from private key
    crypto_scalarmult_base(static_pub_, static_priv_);
    key_loaded_ = true;
    return true;
  }

  static bool genKey() {
    // libsodium을 사용하여 유효한 private key를 생성
    crypto_box_keypair(static_pub_, static_priv_);
    std::ofstream out_file(key_path, std::ios::binary);
    if (!out_file.is_open()) {
      std::cerr << "[Error] Cannot write key file: " << key_path << std::endl;
      return false;
    }
    out_file.write(reinterpret_cast<const char*>(static_priv_), 32);
    out_file.close();
    if (chmod(key_path, S_IRUSR | S_IWUSR) != 0) {
      std::cerr << "[Warning] Failed to set 0600 permissions on key file" << std::endl;
    }
    return true;
  }
};
} // namespace SST

#endif // CONFIG_HPP