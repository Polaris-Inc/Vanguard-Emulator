#pragma once
#include <vector>
#include <cstdint>
#include <string>

namespace RiCrypto {

std::vector<uint8_t> build_payload(
    const std::vector<uint8_t>& plaintext,
    uint32_t type,
    const std::vector<uint8_t>& server_public_key_blob
);

std::vector<uint8_t> decrypt_payload(
    const std::vector<uint8_t>& payload,
    const std::vector<uint8_t>& private_key_blob
);

bool gcm_decrypt_one_shot(
    const std::vector<uint8_t>& key,
    const uint8_t* nonce12,
    const uint8_t* ciphertext, int cipher_len,
    const uint8_t* tag16,
    std::vector<uint8_t>& out_plain
);

bool is_pe(const std::vector<uint8_t>& d);
int find_ricrypto_magic(const std::vector<uint8_t>& blob);
std::vector<uint8_t> proto_field1(const std::vector<uint8_t>& data);
std::vector<uint8_t> decrypt_ricrypto_blob(const std::vector<uint8_t>& blob, size_t ri_off);
std::vector<uint8_t> decrypt_rg_blob(const std::vector<uint8_t>& blob, const uint8_t* session_aes_key);
std::vector<uint8_t> extract_embedded_pe(const std::vector<uint8_t>& d);
std::vector<uint8_t> try_unwrap(const std::vector<uint8_t>& http_body, const uint8_t* session_aes = nullptr);

}
