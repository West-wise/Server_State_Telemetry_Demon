#ifndef NOISE_SESSION_HPP
#define NOISE_SESSION_HPP

#include <sodium.h>
#include <cstdint>
#include <vector>

namespace SST {

// Noise_XX_25519_ChaChaPoly_BLAKE2b
// 외부 Noise_XX라이브러리 같은 경우에는 CMake를 지원하지 않아 libsodium에서 제공하는 프리미티브 로구현
class NoiseSession {
public:
    static constexpr size_t KEY_SIZE   = 32;
    static constexpr size_t MAC_SIZE   = 16;
    static constexpr size_t NONCE_SIZE = 12; // IETF ChaCha20-Poly1305

    // Non-blocking server handshake: phase 1
    // MSG1 (32 bytes) → builds MSG2 (80 bytes) into msg2_out.
    bool hsProcessMsg1(const uint8_t msg1[KEY_SIZE],
                       uint8_t msg2_out[KEY_SIZE * 2 + MAC_SIZE],
                       const uint8_t s_priv[KEY_SIZE],
                       const uint8_t s_pub[KEY_SIZE]);

    // Non-blocking server handshake: phase 2
    // MSG3 (48 bytes) → completes handshake, sets ready_=true.
    bool hsProcessMsg3(const uint8_t msg3[KEY_SIZE + MAC_SIZE]);

    // Client (initiator) handshake — blocking read/write on fd.
    // server_pub: server static public key (from QR code).
    bool handshakeClient(int fd, const uint8_t server_pub[KEY_SIZE]);

    // Transport: encrypt plaintext → ciphertext (len + MAC_SIZE bytes).
    std::vector<uint8_t> encrypt(const uint8_t* msg, size_t len);

    // Transport: decrypt ciphertext → plaintext. Returns false on auth failure.
    bool decrypt(const uint8_t* ct, size_t ct_len, std::vector<uint8_t>& out);

    bool isReady() const { return ready_; }

private:
    uint8_t  send_key_[KEY_SIZE] = {};
    uint8_t  recv_key_[KEY_SIZE] = {};
    uint64_t send_nonce_ = 0;
    uint64_t recv_nonce_ = 0;
    bool     ready_ = false;

    // Handshake symmetric state
    uint8_t  h_[KEY_SIZE]  = {}; // handshake hash
    uint8_t  ck_[KEY_SIZE] = {}; // chaining key
    uint8_t  k_[KEY_SIZE]  = {}; // current cipher key
    uint64_t n_ = 0;             // handshake nonce counter

    // Ephemeral state between hsProcessMsg1 and hsProcessMsg3
    uint8_t hs_se_priv_[KEY_SIZE] = {}; // server ephemeral private key
    uint8_t hs_e_pub_c_[KEY_SIZE] = {}; // client ephemeral public key

    void initializeSymmetric();
    void mixHash(const uint8_t* data, size_t len);
    void mixKey(const uint8_t dh[KEY_SIZE]);
    bool encryptAndHash(const uint8_t* pt, size_t pt_len, uint8_t* ct);
    bool decryptAndHash(const uint8_t* ct, size_t ct_len, uint8_t* pt);
    void split(bool is_initiator);

    static void buildNonce(uint64_t n, uint8_t nonce_out[NONCE_SIZE]);
    static bool recvAll(int fd, uint8_t* buf, size_t len);
    static bool sendAll(int fd, const uint8_t* buf, size_t len);
};

} // namespace SST

#endif // NOISE_SESSION_HPP
