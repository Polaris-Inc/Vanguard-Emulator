#include "rg_crypto.hpp"
#include "ri_crypto.hpp"
#include "rsa_session.hpp"
#include "proto_builder.hpp"
#include <cstring>

namespace RgCrypto {

RgCipherKey parse_handshake_response(const std::vector<uint8_t>& payload, const std::vector<uint8_t>& private_key) {
    RgCipherKey ck;
    auto plain = RiCrypto::decrypt_payload(payload, private_key);
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

RgCipherKey parse_access_response(const std::vector<uint8_t>& payload, const std::vector<uint8_t>& private_key) {
    RgCipherKey ck;
    auto plain = RiCrypto::decrypt_payload(payload, private_key);
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

}
