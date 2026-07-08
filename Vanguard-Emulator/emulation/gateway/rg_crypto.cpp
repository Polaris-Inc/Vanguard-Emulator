#include "rg_crypto.hpp"
#include "ri_crypto.hpp"
#include "rsa_session.hpp"
#include "proto_builder.hpp"
#include "aes_gcm_session.hpp"
#include <cstring>

namespace RgCrypto {

static std::vector<uint8_t> decrypt_envelope_payload(const std::vector<uint8_t>& payload, const std::vector<uint8_t>& private_key) {
    if (payload.size() < 12 + 4) return {};
    size_t pos = 12;
    uint32_t key_len = 0;
    std::memcpy(&key_len, payload.data() + pos, 4); pos += 4;
    if (pos + key_len > payload.size()) return {};
    std::vector<uint8_t> enc_key(payload.begin() + pos, payload.begin() + pos + key_len);
    pos += key_len;
    RsaSession rsa;
    if (!rsa.import_private_key(private_key)) return {};
    std::vector<uint8_t> aes_key_blob = rsa.decrypt_oaep(enc_key);
    if (aes_key_blob.size() < 4 + 32) return {};
    uint32_t inner_key_len = 0;
    std::memcpy(&inner_key_len, aes_key_blob.data(), 4);
    if (inner_key_len + 4 > aes_key_blob.size()) return {};
    std::vector<uint8_t> aes_key(aes_key_blob.begin() + 4, aes_key_blob.begin() + 4 + inner_key_len);
    std::vector<uint8_t> iv(aes_key_blob.begin() + 4 + inner_key_len, aes_key_blob.end());
    if (pos + 12 > payload.size()) return {};
    std::vector<uint8_t> nonce(payload.begin() + pos, payload.begin() + pos + 12); pos += 12;
    uint32_t cipher_total = 0;
    if (pos + 4 > payload.size()) return {};
    std::memcpy(&cipher_total, payload.data() + pos, 4); pos += 4;
    size_t remaining = payload.size() - pos;
    if (cipher_total > remaining || cipher_total < 16) return {};
    std::vector<uint8_t> ciphertext(payload.begin() + pos, payload.end() - 16);
    std::vector<uint8_t> tag(payload.end() - 16, payload.end());
    AesGcmSession aes;
    aes.set_key(aes_key);
    aes.set_iv(nonce);
    return aes.decrypt(ciphertext, tag);
}

RgCipherKey parse_access_response(const std::vector<uint8_t>& payload, const std::vector<uint8_t>& private_key) {
    RgCipherKey ck;
    auto plain = decrypt_envelope_payload(payload, private_key);
    if (plain.empty()) return ck;
    auto env = ProtoBuilder::decode_envelope(plain);
    if (env.type != 5) return ck; // TOKEN_RESPONSE
    if (env.payload.size() < 32) return ck;
    ck.aes_key.assign(env.payload.begin(), env.payload.begin() + 32);
    if (env.payload.size() >= 44) {
        ck.iv.assign(env.payload.begin() + 32, env.payload.begin() + 44);
    } else {
        ck.iv = {0,0,0,0,0,0,0,0,0,0,0,0};
    }
    ck.valid = true;
    return ck;
}

RgCipherKey parse_handshake_response(const std::vector<uint8_t>& payload, const std::vector<uint8_t>& private_key) {
    RgCipherKey ck;
    auto hs = RiCrypto::decode_handshake(payload);
    if (hs.data.empty()) return ck;
    auto decrypted = RiCrypto::decode_handshake_data(hs.data, private_key);
    if (decrypted.empty()) return ck;
    auto env = ProtoBuilder::decode_envelope(decrypted);
    if (env.type != 5) return ck;
    if (env.payload.size() < 32) return ck;
    ck.aes_key.assign(env.payload.begin(), env.payload.begin() + 32);
    if (env.payload.size() >= 44) {
        ck.iv.assign(env.payload.begin() + 32, env.payload.begin() + 44);
    } else {
        ck.iv = {0,0,0,0,0,0,0,0,0,0,0,0};
    }
    ck.valid = true;
    return ck;
}

}
