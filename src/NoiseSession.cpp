#include "NoiseSession.hpp"
#include <cstring>
#include <unistd.h>

namespace SST {

// Protocol: Noise_XX_25519_ChaChaPoly_BLAKE2b
// HASHLEN = 32 (BLAKE2b-256 output), so no truncation needed for cipher keys.
static constexpr const char* PROTOCOL_NAME =
    "Noise_XX_25519_ChaChaPoly_BLAKE2b";

// ─── Symmetric state helpers ─────────────────────────────────────────────────

void NoiseSession::initializeSymmetric() {
    // len(PROTOCOL_NAME) = 34 > HASHLEN=32 → h = HASH(name)
    crypto_generichash(h_, KEY_SIZE,
                       reinterpret_cast<const uint8_t*>(PROTOCOL_NAME),
                       strlen(PROTOCOL_NAME), nullptr, 0);
    memcpy(ck_, h_, KEY_SIZE);
    memset(k_, 0, KEY_SIZE);
    n_ = 0;
}

// h = BLAKE2b(h || data)
void NoiseSession::mixHash(const uint8_t* data, size_t len) {
    crypto_generichash_state st;
    crypto_generichash_init(&st, nullptr, 0, KEY_SIZE);
    crypto_generichash_update(&st, h_, KEY_SIZE);
    crypto_generichash_update(&st, data, len);
    crypto_generichash_final(&st, h_, KEY_SIZE);
}

// HKDF(ck, dh) → new ck, new k
// temp_key = BLAKE2b(dh, key=ck)
// ck  = BLAKE2b(0x01,      key=temp_key)
// k   = BLAKE2b(ck||0x02,  key=temp_key)
void NoiseSession::mixKey(const uint8_t dh[KEY_SIZE]) {
    uint8_t temp_key[KEY_SIZE];
    crypto_generichash(temp_key, KEY_SIZE, dh, KEY_SIZE, ck_, KEY_SIZE);

    uint8_t b1 = 0x01;
    crypto_generichash(ck_, KEY_SIZE, &b1, 1, temp_key, KEY_SIZE);

    uint8_t buf[KEY_SIZE + 1];
    memcpy(buf, ck_, KEY_SIZE);
    buf[KEY_SIZE] = 0x02;
    crypto_generichash(k_, KEY_SIZE, buf, KEY_SIZE + 1, temp_key, KEY_SIZE);

    n_ = 0;
}

// AEAD encrypt; ad = current h; then MixHash(ciphertext)
// ct must be pt_len + MAC_SIZE bytes
bool NoiseSession::encryptAndHash(const uint8_t* pt, size_t pt_len, uint8_t* ct) {
    uint8_t nonce[NONCE_SIZE];
    buildNonce(n_++, nonce);
    unsigned long long ct_written;
    if (crypto_aead_chacha20poly1305_ietf_encrypt(
            ct, &ct_written,
            pt, pt_len,
            h_, KEY_SIZE,   // associated data = h
            nullptr, nonce, k_) != 0)
        return false;
    mixHash(ct, static_cast<size_t>(ct_written));
    return true;
}

// AEAD decrypt; ad = current h; then MixHash(ciphertext)
// pt must be ct_len - MAC_SIZE bytes
bool NoiseSession::decryptAndHash(const uint8_t* ct, size_t ct_len, uint8_t* pt) {
    uint8_t nonce[NONCE_SIZE];
    buildNonce(n_++, nonce);
    unsigned long long pt_written;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            pt, &pt_written,
            nullptr,
            ct, ct_len,
            h_, KEY_SIZE,   // associated data = h (before update)
            nonce, k_) != 0)
        return false;
    mixHash(ct, ct_len); // MixHash with ciphertext AFTER decrypt
    return true;
}

// HKDF(ck, b"") → k1, k2
// Initiator: send=k1, recv=k2
// Responder:  send=k2, recv=k1
void NoiseSession::split(bool is_initiator) {
    uint8_t temp_key[KEY_SIZE];
    // BLAKE2b("", key=ck)
    crypto_generichash(temp_key, KEY_SIZE, nullptr, 0, ck_, KEY_SIZE);

    uint8_t b1 = 0x01;
    uint8_t k1[KEY_SIZE];
    crypto_generichash(k1, KEY_SIZE, &b1, 1, temp_key, KEY_SIZE);

    uint8_t buf[KEY_SIZE + 1];
    memcpy(buf, k1, KEY_SIZE);
    buf[KEY_SIZE] = 0x02;
    uint8_t k2[KEY_SIZE];
    crypto_generichash(k2, KEY_SIZE, buf, KEY_SIZE + 1, temp_key, KEY_SIZE);

    if (is_initiator) {
        memcpy(send_key_, k1, KEY_SIZE);
        memcpy(recv_key_, k2, KEY_SIZE);
    } else {
        memcpy(send_key_, k2, KEY_SIZE);
        memcpy(recv_key_, k1, KEY_SIZE);
    }

    // Clear handshake state
    sodium_memzero(k_, KEY_SIZE);
    sodium_memzero(ck_, KEY_SIZE);
    sodium_memzero(h_, KEY_SIZE);
}

// Nonce: 4 zero bytes + 8-byte little-endian counter (IETF ChaCha20)
void NoiseSession::buildNonce(uint64_t n, uint8_t nonce_out[NONCE_SIZE]) {
    memset(nonce_out, 0, NONCE_SIZE);
    for (int i = 0; i < 8; ++i)
        nonce_out[4 + i] = static_cast<uint8_t>((n >> (8 * i)) & 0xff);
}

bool NoiseSession::recvAll(int fd, uint8_t* buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t n = read(fd, buf + total, len - total);
        if (n <= 0) return false;
        total += static_cast<size_t>(n);
    }
    return true;
}

bool NoiseSession::sendAll(int fd, const uint8_t* buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t n = write(fd, buf + total, len - total);
        if (n <= 0) return false;
        total += static_cast<size_t>(n);
    }
    return true;
}

// ─── Handshake ───────────────────────────────────────────────────────────────

// Non-blocking server handshake: phase 1
// Consumes MSG1 (32 bytes), builds MSG2 (80 bytes) into msg2_out.
// Stores hs_se_priv_ and hs_e_pub_c_ for phase 2.
bool NoiseSession::hsProcessMsg1(const uint8_t msg1[KEY_SIZE],
                                    uint8_t msg2_out[KEY_SIZE * 2 + MAC_SIZE],
                                    const uint8_t s_priv[KEY_SIZE],
                                  const uint8_t s_pub[KEY_SIZE]) {
    initializeSymmetric();

    memcpy(hs_e_pub_c_, msg1, KEY_SIZE);
    mixHash(hs_e_pub_c_, KEY_SIZE);

    uint8_t se_pub[KEY_SIZE];
    crypto_box_keypair(se_pub, hs_se_priv_);
    mixHash(se_pub, KEY_SIZE);

    uint8_t dh_ee[KEY_SIZE];
    if (crypto_scalarmult(dh_ee, hs_se_priv_, hs_e_pub_c_) != 0) return false;
    mixKey(dh_ee);
    sodium_memzero(dh_ee, KEY_SIZE);

    uint8_t encrypted_s[KEY_SIZE + MAC_SIZE];
    if (!encryptAndHash(s_pub, KEY_SIZE, encrypted_s)) return false;

    uint8_t dh_es[KEY_SIZE];
    if (crypto_scalarmult(dh_es, s_priv, hs_e_pub_c_) != 0) return false;
    mixKey(dh_es);
    sodium_memzero(dh_es, KEY_SIZE);

    memcpy(msg2_out,            se_pub,      KEY_SIZE);
    memcpy(msg2_out + KEY_SIZE, encrypted_s, KEY_SIZE + MAC_SIZE);
    return true;
}

// Non-blocking server handshake: phase 2
// Consumes MSG3 (48 bytes), completes handshake, sets ready_=true.
// Zeroes intermediate ephemeral state.
bool NoiseSession::hsProcessMsg3(const uint8_t msg3[KEY_SIZE + MAC_SIZE]) {
    uint8_t c_pub[KEY_SIZE];
    if (!decryptAndHash(msg3, KEY_SIZE + MAC_SIZE, c_pub)) return false;

    uint8_t dh_se[KEY_SIZE];
    if (crypto_scalarmult(dh_se, hs_se_priv_, c_pub) != 0) return false;
    mixKey(dh_se);
    sodium_memzero(dh_se, KEY_SIZE);

    sodium_memzero(hs_se_priv_, KEY_SIZE);
    sodium_memzero(hs_e_pub_c_, KEY_SIZE);

    split(false);
    send_nonce_ = 0;
    recv_nonce_ = 0;
    ready_ = true;
    return true;
}

// Noise_XX client (initiator) side:
//   -> e          (send)
//   <- e,ee,s,es  (recv)
//   -> s,se       (send)
bool NoiseSession::handshakeClient(int fd, const uint8_t server_pub[KEY_SIZE]) {
    initializeSymmetric();

    // ── Message 1: send e ─────────────────────────────────────────────────
    uint8_t e_priv[KEY_SIZE], e_pub[KEY_SIZE];
    crypto_box_keypair(e_pub, e_priv);
    mixHash(e_pub, KEY_SIZE);
    if (!sendAll(fd, e_pub, KEY_SIZE)) return false;

    // ── Message 2: recv e, ee, s, es ──────────────────────────────────────
    uint8_t msg2[KEY_SIZE + KEY_SIZE + MAC_SIZE];
    if (!recvAll(fd, msg2, sizeof(msg2))) return false;

    uint8_t se_pub[KEY_SIZE];
    memcpy(se_pub, msg2, KEY_SIZE);
    mixHash(se_pub, KEY_SIZE);

    // ee = DH(e_priv, se_pub)
    uint8_t dh_ee[KEY_SIZE];
    if (crypto_scalarmult(dh_ee, e_priv, se_pub) != 0) return false;
    mixKey(dh_ee);

    // Decrypt s
    uint8_t encrypted_s[KEY_SIZE + MAC_SIZE];
    memcpy(encrypted_s, msg2 + KEY_SIZE, KEY_SIZE + MAC_SIZE);
    uint8_t s_pub_recv[KEY_SIZE];
    if (!decryptAndHash(encrypted_s, sizeof(encrypted_s), s_pub_recv)) return false;

    // Verify server public key
    if (sodium_memcmp(s_pub_recv, server_pub, KEY_SIZE) != 0) return false;

    // es = DH(e_priv, s_pub_recv)
    uint8_t dh_es[KEY_SIZE];
    if (crypto_scalarmult(dh_es, e_priv, s_pub_recv) != 0) return false;
    mixKey(dh_es);

    // ── Message 3: send s, se ─────────────────────────────────────────────
    // Client static keypair (ephemeral per-session in this impl)
    uint8_t c_priv[KEY_SIZE], c_pub[KEY_SIZE];
    crypto_box_keypair(c_pub, c_priv);

    uint8_t encrypted_c[KEY_SIZE + MAC_SIZE];
    if (!encryptAndHash(c_pub, KEY_SIZE, encrypted_c)) return false;

    // se = DH(c_priv, se_pub)
    uint8_t dh_se[KEY_SIZE];
    if (crypto_scalarmult(dh_se, c_priv, se_pub) != 0) return false;
    mixKey(dh_se);

    if (!sendAll(fd, encrypted_c, sizeof(encrypted_c))) return false;

    split(true); // initiator
    send_nonce_ = 0;
    recv_nonce_ = 0;
    ready_ = true;

    sodium_memzero(e_priv, KEY_SIZE);
    sodium_memzero(c_priv, KEY_SIZE);
    return true;
}

// ─── Transport ───────────────────────────────────────────────────────────────

// Returns ciphertext (plaintext + 16-byte Poly1305 tag).
std::vector<uint8_t> NoiseSession::encrypt(const uint8_t* msg, size_t len) {
    std::vector<uint8_t> ct(len + MAC_SIZE);
    uint8_t nonce[NONCE_SIZE];
    buildNonce(send_nonce_++, nonce);
    unsigned long long ct_len;
    if (crypto_aead_chacha20poly1305_ietf_encrypt(
            ct.data(), &ct_len,
            msg, len,
            nullptr, 0,    // no additional data in transport phase
            nullptr, nonce, send_key_) != 0)
        return {};
    ct.resize(static_cast<size_t>(ct_len));
    return ct;
}

// Returns false if authentication fails; out is cleared.
bool NoiseSession::decrypt(const uint8_t* ct, size_t ct_len,
                            std::vector<uint8_t>& out) {
    if (ct_len < MAC_SIZE) return false;
    out.resize(ct_len - MAC_SIZE);
    uint8_t nonce[NONCE_SIZE];
    buildNonce(recv_nonce_++, nonce);
    unsigned long long pt_len;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            out.data(), &pt_len,
            nullptr,
            ct, ct_len,
            nullptr, 0,    // no additional data in transport phase
            nonce, recv_key_) != 0) {
        out.clear();
        return false;
    }
    out.resize(static_cast<size_t>(pt_len));
    return true;
}

} // namespace SST
