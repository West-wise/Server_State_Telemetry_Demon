#ifndef CONFIG_HPP
#define CONFIG_HPP

#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>

// 이 상대경로 문제는 좀더 고민해볼 것...
constexpr std::string_view CONFIG_FILE_PATH = "/etc/sstd/sstd.ini";
namespace SST {
class Config {
public:
  using SectionMap = std::unordered_map<std::string, std::string>;
  using ConfigMap = std::unordered_map<std::string, SectionMap>;

  // 설정 파일 로드
  // 첫 실행시 단 한번만 호출할 것
  static bool load(const std::string &filename);

  // string값 가져오기
  static std::string getString(const std::string &section,
                                    const std::string &key,
                                    std::string default_value = "");

  // int값 가져오기
  static int getInt(const std::string &section, const std::string &key,
                    int default_value = 0);
  // 키쌍을 로드
  // 만약 키파일이 없으면 새로운 키쌍을 생성(각각 32바이트 크기의 private, public key)
  // 생성된 private key는 sstd.key 파일로 저장
  static bool getServerKeypair(uint8_t private_out[32], uint8_t public_out[32]);

  // 서버 공개키를 64자리 16진수 문자열로 반환 (QR 코드 출력용)
  static std::string getServerPubKeyHex();
private:
  static inline ConfigMap config_data_;
  static inline uint8_t static_priv_[32] = {};
  static inline uint8_t static_pub_[32]  = {};
  static inline bool    key_loaded_      = false;

  constexpr static const char *key_path = "/etc/sstd/sstd.key";

  static bool checkKeyFile();
  static bool genKey();
};
} // namespace SST

#endif // CONFIG_HPP