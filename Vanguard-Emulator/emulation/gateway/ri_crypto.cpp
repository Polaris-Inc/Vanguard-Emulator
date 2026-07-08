#include "ri_crypto.hpp"
#include "rsa_session.hpp"
#include <cstring>
#include <algorithm>

namespace RiCrypto {

std::vector<uint8_t> encode_envelope(const RgEnvelope& env, const std::vector<uint8_t>& raw_public_key) {
    std::vector<uint8_t> result;
    const uint8_t magic[] = {0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x50};
    result.insert(result.end(), magic, magic + 12);
    auto enc_key = RsaSession::encrypt_with_key(raw_public_key, raw_public_key, true);
    uint32_t key_len = (uint32_t)enc_key.size();
    auto key_len_bytes = reinterpret_cast<const uint8_t*>(&key_len);
    result.insert(result.end(), key_len_bytes, key_len_bytes + 4);
    result.insert(result.end(), enc_key.begin(), enc_key.end());
    result.insert(result.end(), env.nonce.begin(), env.nonce.end());
    uint32_t payload_len = (uint32_t)(env.encrypted.size() + env.tag.size());
    auto payload_len_bytes = reinterpret_cast<const uint8_t*>(&payload_len);
    result.insert(result.end(), payload_len_bytes, payload_len_bytes + 4);
    result.insert(result.end(), env.encrypted.begin(), env.encrypted.end());
    result.insert(result.end(), env.tag.begin(), env.tag.end());
    return result;
}

static std::vector<uint8_t> decrypt_with_rsa_key_blob(const std::vector<uint8_t>& data, const std::vector<uint8_t>& private_key_blob) {
    RsaSession rsa;
    if (!rsa.import_private_key(private_key_blob)) return {};
    return rsa.decrypt_oaep(data);
}

RgEnvelope decode_envelope(const std::vector<uint8_t>& data, const std::vector<uint8_t>& raw_public_key) {
    RgEnvelope env;
    if (data.size() < 12 + 4 + 256 + 12 + 4) return env;
    size_t pos = 12;
    uint32_t key_len = 0;
    if (pos + 4 > data.size()) return env;
    std::memcpy(&key_len, data.data() + pos, 4); pos += 4;
    if (pos + key_len + 12 + 4 > data.size()) return env;
    pos += key_len;
    if (pos + 12 > data.size()) return env;
    env.nonce.assign(data.begin() + pos, data.begin() + pos + 12); pos += 12;
    if (pos + 4 > data.size()) return env;
    uint32_t payload_len = 0;
    std::memcpy(&payload_len, data.data() + pos, 4); pos += 4;
    size_t remaining = data.size() - pos;
    if (payload_len > remaining || payload_len < 16) return env;
    env.tag.assign(data.end() - 16, data.end());
    env.encrypted.assign(data.begin() + pos, data.end() - 16);
    return env;
}

RgHandshake decode_handshake(const std::vector<uint8_t>& data) {
    RgHandshake hs;
    if (data.size() < 256 + 12 + 16 + 2) {
        hs.data = data;
        return hs;
    }
    const uint8_t* d = data.data();
    size_t sz = data.size();
    if (d[0] == 0x02 && d[1] == 0x00) {
        hs.data.assign(d + 2, d + 2 + 512);
        if (sz > 2 + 512) {
            hs.signature.assign(d + 2 + 512, d + sz);
        }
    }
    if (hs.data.empty()) hs.data = data;
    return hs;
}

std::vector<uint8_t> decode_handshake_data(const std::vector<uint8_t>& handshake_data, const std::vector<uint8_t>& private_key) {
    if (handshake_data.empty()) return {};
    return decrypt_with_rsa_key_blob(handshake_data, private_key);
}

}
