#pragma once
#include <vector>
#include <cstdint>
#include <string>

namespace RgCrypto {

struct RgCipherKey {
    std::vector<uint8_t> aes_key;
    std::vector<uint8_t> iv;
    uint64_t hb_key_rotation = 0;
    bool valid = false;
};

RgCipherKey parse_access_response(const std::vector<uint8_t>& payload, const std::vector<uint8_t>& private_key);
RgCipherKey parse_handshake_response(const std::vector<uint8_t>& payload, const std::vector<uint8_t>& private_key);

bool verify_response_mac(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key);

}
