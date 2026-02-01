#ifndef SHA256_HPP
#define SHA256_HPP

#include <string>
#include <vector>
#include <cstdint>
#include <cstddef>

namespace HMT {

    class Sha256 {
    public:
        // HMAC-SHA256 계산 함수 (우리가 필요한 건 딱 이거 하나!)
        // key: 비밀키, data: 데이터, out_tag: 결과(16바이트 Truncated) 저장 버퍼
        static void hmac(const void* key, size_t key_len,
                         const void* data, size_t data_len,
                         uint8_t* out_tag);

    private:
        struct Context {
            uint8_t  data[64];
            uint32_t datalen;
            uint64_t bitlen;
            uint32_t state[8];
        };

        static void init(Context& ctx);
        static void update(Context& ctx, const uint8_t* data, size_t len);
        static void final(Context& ctx, uint8_t* hash);
        static void transform(Context& ctx, const uint8_t* data);
    };

}

#endif