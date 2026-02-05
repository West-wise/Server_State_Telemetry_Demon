#ifndef PACKETUTIL_HPP
#define PACKETUTIL_HPP

#include "Protocol.hpp"
#include <vector>
#include <cstdint>

namespace SST {
    class PacketUtil {
    public:
        static std::vector<uint8_t> createPacket(uint16_t cmd_mask, uint32_t req_id, 
            const std::vector<uint8_t>& body, const std::string& key);
    };
}

#endif // PACKETUTIL_HPP
