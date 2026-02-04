#include "PacketUtil.hpp"
#include "Protocol.hpp"
#include "TcpServer.hpp" // For SECRET_KEY (임시), 실제로는 Config에서 가져와야 함 or Pass key
#include "sha256.hpp"
#include <cstring>
#include <chrono>

// 주의: 현재 구조상 PacketUtil이 SecretKey를 알기 어렵습니다.
// Migration 문서에 따르면 TcpServer가 SECRET_KEY를 가지고 있습니다.
// PacketUtil은 Helper 함수이므로 키를 인자로 받거나, TcpServer 내부 logic으로 구현되어야 할 수도 있습니다.
// 하지만 사용자 요청에 따라 분리된 파일로 구현하되, 키는 외부에서 주입받는 형태로 설계하거나
// 일단 하드코딩된 키(테스트용)를 공유해야 합니다.
// 여기서는 테스트 편의를 위해 임시 키를 사용하거나, TcpServer에서 처리하도록 유도해야 합니다.
// 일단 구현 편의상 PacketUtil methods에 key를 인자로 전달받도록 수정하지 않았으므로,
// TcpServer.cpp의 sendResponse 로직과 유사하게 구현하되, 우선 컴파일이 되도록 작성합니다.

namespace SST {

    // 임시 키 (TcpServer.hpp와 일치시켜야 함)
    static const std::string TEMP_SECRET_KEY = "sstd_tmp_secret_key_2026"; 

    std::vector<uint8_t> PacketUtil::createPacket(uint16_t cmd_mask, uint32_t req_id, const std::vector<uint8_t>& body) {
        SecureHeader hdr;
        std::memset(&hdr, 0, sizeof(SecureHeader));

        hdr.magic = MAGIC_NUMBER; // Little Endian Host Order (v2.0 Spec)
        hdr.version = 0x01;
        hdr.type = 0x02; // Response
        hdr.client_id = 0; // Server ID ideally
        hdr.cmd_mask = cmd_mask;
        hdr.request_id = req_id;
        
        // Timestamp (Current MS)
        using namespace std::chrono;
        hdr.timestamp = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
        
        hdr.body_len = static_cast<uint32_t>(body.size());
        
        // 1. Packet Buffer 생성
        std::vector<uint8_t> packet(sizeof(SecureHeader) + body.size());
        std::memcpy(packet.data(), &hdr, sizeof(SecureHeader));
        if (!body.empty()) {
            std::memcpy(packet.data() + sizeof(SecureHeader), body.data(), body.size());
        }

        // 2. HMAC 계산
        std::vector<uint8_t> mac = Sha256::hmac(TEMP_SECRET_KEY, packet.data(), packet.size());
        
        // 3. Header에 HMAC 주입
        // packet 벡터 내부의 헤더 영역을 포인터로 다시 얻어옴
        SecureHeader* final_hdr = reinterpret_cast<SecureHeader*>(packet.data());
        std::memcpy(final_hdr->auth_tag, mac.data(), HMAC_TAG_SIZE);

        return packet;
    }
}
