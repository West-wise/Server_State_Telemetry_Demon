#include "PacketUtil.hpp"
#include "Protocol.hpp"
#include "sha256.hpp"
#include <cstring>
#include <chrono>

namespace SST {

    std::vector<uint8_t> PacketUtil::createPacket(uint16_t cmd_mask, uint32_t req_id, const std::vector<uint8_t>& body, const std::string& key) {
        SecureHeader hdr;
        std::memset(&hdr, 0, sizeof(SecureHeader));

        hdr.magic = MAGIC_NUMBER;
        hdr.version = 0x01;
        hdr.type = 0x02;
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

        // 2. HMAC 계산 (전달받은 Key 사용)
        std::vector<uint8_t> mac = Sha256::hmac(key, packet.data(), packet.size());
        
        // 3. Header에 HMAC 주입
        // packet 벡터 내부의 헤더 영역을 포인터로 다시 얻어옴
        SecureHeader* final_hdr = reinterpret_cast<SecureHeader*>(packet.data());
        std::memcpy(final_hdr->auth_tag, mac.data(), HMAC_TAG_SIZE);

        return packet;
    }
}
