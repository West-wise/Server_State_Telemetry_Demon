#include "sha256.hpp"
#include <cstring>
#include <iostream>

namespace HMT {
    namespace {
        inline constexpr uint32_t rotr(uint32_t x, unsigned int n){
            return ( x >> n ) | ( x << (32 - n));
        } 
        inline constexpr uint32_t rotl(uint32_t x, unsigned int n){
            return ( x << n ) | ( x >> (32 - n));
        }
        inline constexpr uint32_t choose (uint32_t x, uint32_t y, uint32_t z){
            return  ( x & y ) ^ ( ~x & z);
        }
        inline constexpr uint32_t majority (uint32_t x, uint32_t y, uint32_t z){
            return ( x & y ) ^ ( x & z ) ^ ( y & z);
        }
        inline constexpr uint32_t ep0 (uint32_t x){
            return rotr(x,2) ^ rotr(x,13) ^ rotr(x,22);
        }
        inline constexpr uint32_t ep1 (uint32_t x){
            return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x,25);
        }
        inline constexpr uint32_t sig0 (uint32_t x){
            return rotr(x,7) ^ rotr(x,18) ^ ( x >> 3);
        }
        inline constexpr uint32_t sig1 (uint32_t x){
            return rotr(x,17) ^ rotr(x,19) ^ ( x >> 10);
        }

    }

    void Sha256::transform(Context& ctx, const uint8_t* data) {
        uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

        for (i = 0, j = 0; i < 16; ++i, j += 4)
            m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
        for (; i < 64; ++i)
            m[i] = sig1(m[i - 2]) + m[i - 7] + sig0(m[i - 15]) + m[i - 16];

        a = ctx.state[0]; b = ctx.state[1]; c = ctx.state[2]; d = ctx.state[3];
        e = ctx.state[4]; f = ctx.state[5]; g = ctx.state[6]; h = ctx.state[7];

        for (i = 0; i < 64; ++i) {
            t1 = h + ep1(e) + choose(e, f, g) + k[i] + m[i];
            t2 = ep0(a) + majority(a, b, c);
            h = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }

        ctx.state[0] += a; ctx.state[1] += b; ctx.state[2] += c; ctx.state[3] += d;
        ctx.state[4] += e; ctx.state[5] += f; ctx.state[6] += g; ctx.state[7] += h;
    }

    void Sha256::init(Context& ctx) {
        ctx.datalen = 0;
        ctx.bitlen = 0;
        ctx.state[0] = 0x6a09e667; ctx.state[1] = 0xbb67ae85; ctx.state[2] = 0x3c6ef372; ctx.state[3] = 0xa54ff53a;
        ctx.state[4] = 0x510e527f; ctx.state[5] = 0x9b05688c; ctx.state[6] = 0x1f83d9ab; ctx.state[7] = 0x5be0cd19;
    }

    void Sha256::update(Context& ctx, const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            ctx.data[ctx.datalen] = data[i];
            ctx.datalen++;
            if (ctx.datalen == 64) {
                transform(ctx, ctx.data);
                ctx.bitlen += 512;
                ctx.datalen = 0;
            }
        }
    }

    void Sha256::final(Context& ctx, uint8_t* hash) {
        uint32_t i = ctx.datalen;

        if (ctx.datalen < 56) {
            ctx.data[i++] = 0x80;
            while (i < 56) ctx.data[i++] = 0x00;
        } else {
            ctx.data[i++] = 0x80;
            while (i < 64) ctx.data[i++] = 0x00;
            transform(ctx, ctx.data);
            std::memset(ctx.data, 0, 56);
        }

        ctx.bitlen += ctx.datalen * 8;
        ctx.data[63] = ctx.bitlen;
        ctx.data[62] = ctx.bitlen >> 8;
        ctx.data[61] = ctx.bitlen >> 16;
        ctx.data[60] = ctx.bitlen >> 24;
        ctx.data[59] = ctx.bitlen >> 32;
        ctx.data[58] = ctx.bitlen >> 40;
        ctx.data[57] = ctx.bitlen >> 48;
        ctx.data[56] = ctx.bitlen >> 56;
        transform(ctx, ctx.data);

        for (i = 0; i < 4; ++i) {
            hash[i]      = (ctx.state[0] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 4]  = (ctx.state[1] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 8]  = (ctx.state[2] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 12] = (ctx.state[3] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 16] = (ctx.state[4] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 20] = (ctx.state[5] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 24] = (ctx.state[6] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 28] = (ctx.state[7] >> (24 - i * 8)) & 0x000000ff;
        }
    }

    // [핵심] HMAC 구현 (RFC 2104) - 메모리 할당 없음!
    void Sha256::hmac(const void* key, size_t key_len, const void* data, size_t data_len, uint8_t* out_tag) {
        if(key == nullptr || data == nullptr || out_tag == nullptr) {
            std::cerr << "HMAC-SHA256: Null pointer input!" << "\n";
            return;
        }
        Context ctx_inner, ctx_outer;
        uint8_t k_pad_inner[64] = {0};
        uint8_t k_pad_outer[64] = {0};
        uint8_t tk[32];
        const uint8_t* k = (const uint8_t*)key;

        if (key_len > 64) {
            Context tctx; init(tctx); update(tctx, k, key_len); final(tctx, tk);
            k = tk;
            key_len = 32;
        }

        std::memcpy(k_pad_inner, k, key_len);
        std::memcpy(k_pad_outer, k, key_len);

        for (int i = 0; i < 64; ++i) {
            k_pad_inner[i] ^= 0x36;
            k_pad_outer[i] ^= 0x5C;
        }

        uint8_t inner_hash[32];
        init(ctx_inner);
        update(ctx_inner, k_pad_inner, 64);
        update(ctx_inner, (const uint8_t*)data, data_len);
        final(ctx_inner, inner_hash);

        uint8_t full_mac[32];
        init(ctx_outer);
        update(ctx_outer, k_pad_outer, 64);
        update(ctx_outer, inner_hash, 32);
        final(ctx_outer, full_mac);

        // 앞 16바이트만 복사 (Truncation)
        std::memcpy(out_tag, full_mac, 16);
    }
}