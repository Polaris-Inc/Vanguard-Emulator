#pragma once
#include <vector>
#include <cstdint>
#include <string>

namespace RiCrypto {

struct RgCipherInfo {
    std::vector<uint8_t> key;
    std::vector<uint8_t> iv;
};

struct RgEnvelope {
    std::vector<uint8_t> nonce;
    std::vector<uint8_t> encrypted;
    std::vector<uint8_t> tag;
};

struct RgHandshake {
    std::vector<uint8_t> data;
    std::vector<uint8_t> signature;
};

std::vector<uint8_t> encode_envelope(const RgEnvelope& env, const std::vector<uint8_t>& raw_public_key);
RgEnvelope decode_envelope(const std::vector<uint8_t>& data, const std::vector<uint8_t>& raw_public_key);

RgHandshake decode_handshake(const std::vector<uint8_t>& data);

std::vector<uint8_t> decode_handshake_data(const std::vector<uint8_t>& handshake_data, const std::vector<uint8_t>& private_key);

}
