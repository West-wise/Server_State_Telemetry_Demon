#ifndef SIPHASH_HPP
#define SIPHASH_HPP

#include <cstdint>
#include <cstring>
#include <vector>

namespace SST {
class SipHash {
private:
  // 비트 순환 이동 함수
  static inline uint64_t rotl(uint64_t x, int b) {
    return (x << b) | (x >> (64 - b));
  }

  // mixing Round
  static inline void sipRound(uint64_t &v0, uint64_t &v1, uint64_t &v2,
                              uint64_t &v3) {
    v0 += v1;
    v1 = rotl(v1, 13);
    v1 += v0;
    v0 = rotl(v0, 32);

    v2 += v3;
    v3 = rotl(v3, 16);
    v3 ^= v2;

    v0 += v3;
    v3 = rotl(v3, 21);
    v3 ^= v0;

    v2 += v1;
    v1 = rotl(v1, 17);
    v1 ^= v2;
    v2 = rotl(v2, 32);
  }

public:
  static std::vector<uint8_t> hash(const std::vector<uint8_t> &key,
                                   const uint8_t *in, size_t inlen) {
    if (key.size() != 16)
      return {};

    uint64_t k0, k1;
    std::memcpy(&k0, key.data(), 8);
    std::memcpy(&k1, key.data() + 8, 8);
    // 초기 상태 (128비트 출력을 위해 v1에 0xee를 XOR)
    uint64_t v0 = 0x736f6d6570736575ULL ^ k0;
    uint64_t v1 = 0x646f72616e646f6dULL ^ k1 ^ 0xee;
    uint64_t v2 = 0x6c7967656e657261ULL ^ k0;
    uint64_t v3 = 0x7465646279746573ULL ^ k1;

    const uint8_t *end = in + inlen - (inlen % 8);
    int left = inlen & 7;
    uint64_t b = ((uint64_t)inlen) << 56;

    // 8바이트 단위로 처리 (2 라운드)
    for (const uint8_t *m = in; m != end; m += 8) {
      uint64_t mi;
      std::memcpy(&mi, m, 8);
      v3 ^= mi;
      sipRound(v0, v1, v2, v3);
      sipRound(v0, v1, v2, v3);
      v0 ^= mi;
    }
    // 남은 바이트 처리
    uint64_t t = 0;
    const uint8_t *pt = end;
    switch (left) {
    case 7:
      t |= ((uint64_t)pt[6]) << 48;
      [[fallthrough]];
    case 6:
      t |= ((uint64_t)pt[5]) << 40;
      [[fallthrough]];
    case 5:
      t |= ((uint64_t)pt[4]) << 32;
      [[fallthrough]];
    case 4:
      t |= ((uint64_t)pt[3]) << 24;
      [[fallthrough]];
    case 3:
      t |= ((uint64_t)pt[2]) << 16;
      [[fallthrough]];
    case 2:
      t |= ((uint64_t)pt[1]) << 8;
      [[fallthrough]];
    case 1:
      t |= ((uint64_t)pt[0]);
      break;
    case 0:
      break;
    }
    b |= t;

    v3 ^= b;
    sipRound(v0, v1, v2, v3);
    sipRound(v0, v1, v2, v3);
    v0 ^= b;

    // 첫 번째 8바이트 (64비트) 출력 (4 라운드)
    v2 ^= 0xee;
    sipRound(v0, v1, v2, v3);
    sipRound(v0, v1, v2, v3);
    sipRound(v0, v1, v2, v3);
    sipRound(v0, v1, v2, v3);
    uint64_t out0 = v0 ^ v1 ^ v2 ^ v3;

    // 두 번째 8바이트 출력 (4 라운드)
    v1 ^= 0xdd;
    sipRound(v0, v1, v2, v3);
    sipRound(v0, v1, v2, v3);
    sipRound(v0, v1, v2, v3);
    sipRound(v0, v1, v2, v3);
    uint64_t out1 = v0 ^ v1 ^ v2 ^ v3;

    // 16바이트 벡터로 병합 후 반환
    std::vector<uint8_t> mac(16);
    std::memcpy(mac.data(), &out0, 8);
    std::memcpy(mac.data() + 8, &out1, 8);
    return mac;
  }
};
} // namespace SST

#endif