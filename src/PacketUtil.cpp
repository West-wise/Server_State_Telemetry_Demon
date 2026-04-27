#include "PacketUtil.hpp"
#include "Protocol.hpp"
#include "sha256.hpp"
#include "siphash.hpp"
#include <chrono>
#include <cstring>


namespace SST {

    std::vector<uint8_t> PacketUtil::createPacket(uint16_t cmd_mask, uint8_t MsgType ,uint32_t req_id, const std::vector<uint8_t>& body, const std::string& key) {
        SecureHeader hdr;
        std::memset(&hdr, 0, sizeof(SecureHeader));

        hdr.magic = MAGIC_NUMBER;
        hdr.version = 0x01;
        hdr.type = MsgType;
        hdr.client_id = 0;
        hdr.cmd_mask = cmd_mask;
        hdr.request_id = req_id;
        
        using namespace std::chrono;
        hdr.timestamp = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
        
        hdr.body_len = static_cast<uint32_t>(body.size());
        
        // 1. Packet Buffer 생성
        std::vector<uint8_t> packet(sizeof(SecureHeader) + body.size());
        std::memcpy(packet.data(), &hdr, sizeof(SecureHeader));
        if (!body.empty()) {
            std::memcpy(packet.data() + sizeof(SecureHeader), body.data(), body.size());
        }

  // 2. SipHash 계산
  std::vector<uint8_t> key_vec(key.begin(), key.end());
  std::vector<uint8_t> mac = SipHash::hash(key_vec, packet.data(), packet.size());
  
  // 3. Header에 MAC 주입
  SecureHeader *final_hdr = reinterpret_cast<SecureHeader *>(packet.data());
  std::memcpy(final_hdr->auth_tag, mac.data(), AUTH_TAG_SIZE);

        return packet;
    }
}
