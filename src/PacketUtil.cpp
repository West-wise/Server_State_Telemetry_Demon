#include "PacketUtil.hpp"
#include "Protocol.hpp"
#include <chrono>
#include <cstring>

namespace SST {

std::vector<uint8_t> PacketUtil::createPacket(uint8_t MsgType, uint32_t req_id,
                                              const std::vector<uint8_t> &body) {
  SecureHeader hdr;
  std::memset(&hdr, 0, sizeof(SecureHeader));

  hdr.magic = MAGIC_NUMBER;
  hdr.version = 0x01;
  hdr.type = MsgType;
  hdr.client_id = 0;
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

  return packet;
}
} // namespace SST
