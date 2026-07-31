#include "Config.hpp"
#include "utility.hpp"

#include <cstring>
#include <exception>
#include <fstream>
#include <iostream>
#include <sodium.h>
#include <sys/stat.h>

namespace SST{
    
    bool Config::load(const std::string &filename){
        config_data_.clear();
        std::ifstream file(filename);
        if(!file.is_open()) return false;

        std::string line;
        std::string current_section;

        while(getline(file, line)){
            auto vline = SST::Utils::String::trim(line);


            if(vline.empty() || vline[0] == '#' || vline[0] == ';') continue;

            if(vline.front() == '[' && vline.back() == ']'){
                current_section = std::string(vline.substr(1, vline.size() - 2));
                continue;
            }

            size_t delim_pos = vline.find('=');

            if(delim_pos != std::string::npos){
                auto key = SST::Utils::String::trim(vline.substr(0, delim_pos));
                auto value = SST::Utils::String::trim(vline.substr(delim_pos + 1));

                if(!current_section.empty()){
                    std::cout << "Config Load: ["
                              << current_section << "] "
                              << key << " = " << value << std::endl;
                    config_data_[current_section].emplace(key,value);
                }
            }
        }
        return true;
    }

    std::string Config::getString(const std::string &section, const std::string &key, std::string default_value){
        if(config_data_.empty()) return default_value;

        auto sec_it = config_data_.find(section);
        if(sec_it != config_data_.end()){
            auto key_it = sec_it->second.find(key);
            if(key_it != sec_it->second.end()){
                return key_it->second;
            }
        }
        return default_value;
    }

    int Config::getInt(const std::string &section, const std::string &key, int default_value){
        if(config_data_.empty()) return default_value;

        std::string value = getString(section, key);
        if(value.empty()) return default_value;

        try{
            return std::stoi(std::string(value));
        } catch(const std::exception &){
            return default_value;
        }
    }

    bool Config::getServerKeypair(uint8_t private_out[32], uint8_t public_out[32]){
        if(!key_loaded_) {
            if(!checkKeyFile()) return false;
        }

        std::memcpy(private_out, static_priv_, 32);
        std::memcpy(public_out, static_pub_, 32);
        return true;
    }

    std::string Config::getServerPubKeyHex(){
        if(!key_loaded_) checkKeyFile();
        const char *hex_chars = "0123456789abcdef";
        std::string out;
        out.resize(64);
        for(int i = 0; i < 32; ++i){
            out[i*2]     = hex_chars[static_pub_[i] >> 4];
            out[i*2 + 1] = hex_chars[static_pub_[i] & 0x0F];
        }
        return out;
    }

    bool Config::checkKeyFile(){
        std::ifstream file(key_path, std::ios::binary);
        if(file.is_open()){
            file.read(reinterpret_cast<char *>(static_priv_),32);
            if(file.gcount() != 32){
                std::cerr << "Error: Failed to read private key from file." << std::endl;
                return false;
            }
            file.close();
        } else {
            std::cout << "[Info] Key file not found. Generating X25519 keypair..." << std::endl;
            if(!genKey()){
                return false;
            }
        }
        crypto_scalarmult_base(static_pub_, static_priv_);
        key_loaded_ = true;
        return true;
    }
    bool Config::genKey() {
        // libsodium을 사용하여 유효한 private key를 생성
        crypto_box_keypair(static_pub_, static_priv_);
        std::ofstream out_file(key_path, std::ios::binary);
        if (!out_file.is_open()) {
            std::cerr << "[Error] Cannot write key file: " << key_path << std::endl;
            return false;
        }
        out_file.write(reinterpret_cast<const char *>(static_priv_), 32);
        out_file.close();
        if (chmod(key_path, S_IRUSR | S_IWUSR) != 0) {
            std::cerr << "[Warning] Failed to set 0600 permissions on key file"
                    << std::endl;
        }
        return true;
    }
}