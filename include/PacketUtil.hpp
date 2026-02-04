#ifndef PACKETUTIL_HPP
#define PACKETUTIL_HPP

#include "Protocol.hpp"
#include <vector>
#include <cstdint>

namespace SST {
    class PacketUtil {
    public:
        // [Migration v2.0] Little Endian (Host Order) 준수
        // 별도의 엔디안 변환 없이 직렬화/역직렬화 수행
        
        static std::vector<uint8_t> createPacket(uint16_t cmd_mask, uint32_t req_id, const std::vector<uint8_t>& body);
        static std::vector<uint8_t> createErrorResponse(uint32_t req_id);
    };
}

#endif // PACKETUTIL_HPP
