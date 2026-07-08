#include "rsa_session.hpp"
#include <stdexcept>
#include <algorithm>

RsaSession::RsaSession() : alg_handle_(nullptr), key_handle_(nullptr) {
    if (BCryptOpenAlgorithmProvider(&alg_handle_, BCRYPT_RSA_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0) != 0) {
        alg_handle_ = nullptr;
    }
}

RsaSession::~RsaSession() {
    if (key_handle_) BCryptDestroyKey(key_handle_);
    if (alg_handle_) BCryptCloseAlgorithmProvider(alg_handle_, 0);
}

bool RsaSession::generate_key() {
    if (!alg_handle_) return false;
    if (key_handle_) { BCryptDestroyKey(key_handle_); key_handle_ = nullptr; }
    if (BCryptGenerateKeyPair(alg_handle_, &key_handle_, 2048, 0) != 0) return false;
    if (BCryptFinalizeKeyPair(key_handle_, 0) != 0) return false;
    return true;
}

std::vector<uint8_t> RsaSession::export_public_key() const {
    if (!key_handle_) return {};
    ULONG sz = 0;
    BCryptExportKey(key_handle_, nullptr, BCRYPT_RSAPUBLIC_BLOB, nullptr, 0, &sz, 0);
    std::vector<uint8_t> blob(sz);
    if (BCryptExportKey(key_handle_, nullptr, BCRYPT_RSAPUBLIC_BLOB, blob.data(), sz, &sz, 0) != 0)
        return {};
    return blob;
}

std::vector<uint8_t> RsaSession::export_private_key() const {
    if (!key_handle_) return {};
    ULONG sz = 0;
    BCryptExportKey(key_handle_, nullptr, BCRYPT_RSAFULLPRIVATE_BLOB, nullptr, 0, &sz, 0);
    std::vector<uint8_t> blob(sz);
    if (BCryptExportKey(key_handle_, nullptr, BCRYPT_RSAFULLPRIVATE_BLOB, blob.data(), sz, &sz, 0) != 0)
        return {};
    return blob;
}

bool RsaSession::import_public_key(const std::vector<uint8_t>& blob) {
    if (!alg_handle_) return false;
    if (key_handle_) { BCryptDestroyKey(key_handle_); key_handle_ = nullptr; }
    return BCryptImportKeyPair(alg_handle_, nullptr, BCRYPT_RSAPUBLIC_BLOB, &key_handle_,
        (PUINT8)blob.data(), (ULONG)blob.size(), 0) == 0;
}

bool RsaSession::import_private_key(const std::vector<uint8_t>& blob) {
    if (!alg_handle_) return false;
    if (key_handle_) { BCryptDestroyKey(key_handle_); key_handle_ = nullptr; }
    return BCryptImportKeyPair(alg_handle_, nullptr, BCRYPT_RSAFULLPRIVATE_BLOB, &key_handle_,
        (PUINT8)blob.data(), (ULONG)blob.size(), 0) == 0;
}

std::vector<uint8_t> RsaSession::do_oaep(bool encrypt, const std::vector<uint8_t>& data) {
    if (!key_handle_) return {};
    ULONG result_size = 0;
    BCRYPT_OAEP_PADDING_INFO padding_info;
    padding_info.pszAlgId = BCRYPT_SHA512_ALGORITHM;
    padding_info.pbLabel = nullptr;
    padding_info.cbLabel = 0;
    if (encrypt) {
        NTSTATUS st = BCryptEncrypt(key_handle_, (PUINT8)data.data(), (ULONG)data.size(),
            &padding_info, nullptr, 0, nullptr, 0, &result_size, BCRYPT_PAD_OAEP);
        if (st != 0) return {};
        std::vector<uint8_t> result(result_size);
        st = BCryptEncrypt(key_handle_, (PUINT8)data.data(), (ULONG)data.size(),
            &padding_info, nullptr, 0, result.data(), result_size, &result_size, BCRYPT_PAD_OAEP);
        if (st != 0) return {};
        return result;
    } else {
        NTSTATUS st = BCryptDecrypt(key_handle_, (PUINT8)data.data(), (ULONG)data.size(),
            &padding_info, nullptr, 0, nullptr, 0, &result_size, BCRYPT_PAD_OAEP);
        if (st != 0) return {};
        std::vector<uint8_t> result(result_size);
        st = BCryptDecrypt(key_handle_, (PUINT8)data.data(), (ULONG)data.size(),
            &padding_info, nullptr, 0, result.data(), result_size, &result_size, BCRYPT_PAD_OAEP);
        if (st != 0) return {};
        result.resize(result_size);
        return result;
    }
}

std::vector<uint8_t> RsaSession::encrypt_oaep(const std::vector<uint8_t>& plaintext) {
    return do_oaep(true, plaintext);
}

std::vector<uint8_t> RsaSession::decrypt_oaep(const std::vector<uint8_t>& ciphertext) {
    return do_oaep(false, ciphertext);
}

std::vector<uint8_t> RsaSession::encrypt_with_key(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& public_key_blob, bool use_sha512) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE key = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_RSA_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0) != 0) return {};
    if (BCryptImportKeyPair(alg, nullptr, BCRYPT_RSAPUBLIC_BLOB, &key,
        (PUINT8)const_cast<uint8_t*>(public_key_blob.data()), (ULONG)public_key_blob.size(), 0) != 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return {};
    }
    ULONG result_size = 0;
    BCRYPT_OAEP_PADDING_INFO padding_info;
    padding_info.pszAlgId = BCRYPT_SHA512_ALGORITHM;
    padding_info.pbLabel = nullptr;
    padding_info.cbLabel = 0;
    NTSTATUS st = BCryptEncrypt(key, (PUINT8)plaintext.data(), (ULONG)plaintext.size(),
        &padding_info, nullptr, 0, nullptr, 0, &result_size, BCRYPT_PAD_OAEP);
    if (st != 0) { BCryptDestroyKey(key); BCryptCloseAlgorithmProvider(alg, 0); return {}; }
    std::vector<uint8_t> result(result_size);
    st = BCryptEncrypt(key, (PUINT8)plaintext.data(), (ULONG)plaintext.size(),
        &padding_info, nullptr, 0, result.data(), result_size, &result_size, BCRYPT_PAD_OAEP);
    BCryptDestroyKey(key);
    BCryptCloseAlgorithmProvider(alg, 0);
    if (st != 0) return {};
    return result;
}
