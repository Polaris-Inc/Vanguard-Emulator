#include "aes_gcm_session.hpp"
#include <stdexcept>

AesGcmSession::AesGcmSession() : alg_handle_(nullptr), key_handle_(nullptr), key_set_(false) {
    if (BCryptOpenAlgorithmProvider(&alg_handle_, BCRYPT_AES_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0) != 0) {
        alg_handle_ = nullptr;
    }
}

AesGcmSession::~AesGcmSession() {
    if (key_handle_) BCryptDestroyKey(key_handle_);
    if (alg_handle_) BCryptCloseAlgorithmProvider(alg_handle_, 0);
}

bool AesGcmSession::set_key(const std::vector<uint8_t>& key) {
    if (!alg_handle_ || key.size() != 32) return false;
    key_ = key;
    key_set_ = false;
    if (BCryptSetProperty(alg_handle_, BCRYPT_CHAINING_MODE, (PUINT8)BCRYPT_CHAIN_MODE_GCM, (ULONG)(sizeof(BCRYPT_CHAIN_MODE_GCM) + 1), 0) != 0)
        return false;
    if (key_handle_) { BCryptDestroyKey(key_handle_); key_handle_ = nullptr; }
    NTSTATUS st = BCryptGenerateSymmetricKey(alg_handle_, &key_handle_, nullptr, 0, (PUINT8)key.data(), (ULONG)key.size(), 0);
    if (st != 0) return false;
    key_set_ = true;
    return true;
}

bool AesGcmSession::set_iv(const std::vector<uint8_t>& iv) {
    if (iv.size() != 12) return false;
    iv_ = iv;
    return true;
}

std::vector<uint8_t> AesGcmSession::encrypt(const std::vector<uint8_t>& plaintext) {
    if (!key_set_ || !key_handle_) return {};
    if (iv_.empty()) return {};
    std::vector<uint8_t> ciphertext(plaintext.size());
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
    BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
    auth_info.pbNonce = iv_.data();
    auth_info.cbNonce = (ULONG)iv_.size();
    uint8_t tag_buf[16] = {0};
    auth_info.pbTag = tag_buf;
    auth_info.cbTag = sizeof(tag_buf);
    ULONG result_size = 0;
    NTSTATUS st = BCryptEncrypt(key_handle_, (PUINT8)plaintext.data(), (ULONG)plaintext.size(),
        &auth_info, nullptr, 0, ciphertext.data(), (ULONG)ciphertext.size(), &result_size, 0);
    if (st != 0) return {};
    std::vector<uint8_t> result;
    result.reserve(ciphertext.size() + 16);
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());
    result.insert(result.end(), tag_buf, tag_buf + 16);
    return result;
}

std::vector<uint8_t> AesGcmSession::decrypt(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& tag) {
    if (!key_set_ || !key_handle_) return {};
    if (iv_.empty() || ciphertext.empty() || tag.size() != 16) return {};
    std::vector<uint8_t> plaintext(ciphertext.size() + 16, 0);
    ULONG result_size = 0;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
    BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
    auth_info.pbNonce = iv_.data();
    auth_info.cbNonce = (ULONG)iv_.size();
    auth_info.pbTag = (PUINT8)const_cast<uint8_t*>(tag.data());
    auth_info.cbTag = 16;
    auth_info.pbAuthData = nullptr;
    auth_info.cbAuthData = 0;
    NTSTATUS st = BCryptDecrypt(key_handle_, (PUINT8)ciphertext.data(), (ULONG)ciphertext.size(),
        &auth_info, nullptr, 0, plaintext.data(), (ULONG)plaintext.size(), &result_size, 0);
    if (st != 0) return {};
    plaintext.resize(result_size);
    return plaintext;
}

void AesGcmSession::rotate_iv() {
    if (iv_.size() != 12) return;
    for (int i = 11; i >= 0; --i) {
        if (++iv_[i] != 0) break;
    }
}
