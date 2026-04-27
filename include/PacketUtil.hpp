#ifndef PACKETUTIL_HPP
#define PACKETUTIL_HPP

#include <cstdint>
#include <string>
#include <vector>

namespace SST {
class PacketUtil {
public:
  static std::vector<uint8_t> createPacket(uint8_t MsgType,
                                           uint32_t req_id,
                                           const std::vector<uint8_t> &body,
                                           const std::string &key);
};
} // namespace SST

#endif // PACKETUTIL_HPP
