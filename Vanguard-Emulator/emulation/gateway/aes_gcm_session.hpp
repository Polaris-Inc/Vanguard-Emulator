#pragma once
#include <vector>
#include <cstdint>
#include <string>
#include <windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

class AesGcmSession {
public:
    AesGcmSession();
    ~AesGcmSession();

    bool set_key(const std::vector<uint8_t>& key); // expects 32 bytes
    bool set_iv(const std::vector<uint8_t>& iv);   // expects 12 bytes

    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext);
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& tag);

    bool has_key() const { return key_set_; }
    const std::vector<uint8_t>& current_iv() const { return iv_; }

    void rotate_iv();
    void invalidate() { key_set_ = false; }

private:
    BCRYPT_ALG_HANDLE alg_handle_;
    BCRYPT_KEY_HANDLE key_handle_;
    bool key_set_;
    std::vector<uint8_t> key_;
    std::vector<uint8_t> iv_;
};
