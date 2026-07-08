#pragma once
#include <vector>
#include <cstdint>
#include <windows.h>
#include <bcrypt.h>
#include <string>

#pragma comment(lib, "bcrypt.lib")

class RsaSession {
public:
    RsaSession();
    ~RsaSession();

    bool generate_key();
    std::vector<uint8_t> encrypt_oaep(const std::vector<uint8_t>& plaintext);
    std::vector<uint8_t> decrypt_oaep(const std::vector<uint8_t>& ciphertext);

    std::vector<uint8_t> export_public_key() const;
    std::vector<uint8_t> export_private_key() const;
    bool import_public_key(const std::vector<uint8_t>& blob);
    bool import_private_key(const std::vector<uint8_t>& blob);

    static std::vector<uint8_t> encrypt_with_key(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& public_key_blob, bool use_sha512);

    bool has_key() const { return key_handle_ != nullptr; }

private:
    BCRYPT_ALG_HANDLE alg_handle_;
    BCRYPT_KEY_HANDLE key_handle_;

    std::vector<uint8_t> do_oaep(bool encrypt, const std::vector<uint8_t>& data);
};
