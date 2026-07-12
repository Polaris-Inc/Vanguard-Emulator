#include "rsa_session.hpp"
#include <windows.h>
#include <wincrypt.h>
#include <stdexcept>
#include <algorithm>
#pragma comment(lib, "crypt32.lib")

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
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_RSA_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0) != 0) { printf("[rsa] OpenAlgorithmProvider failed\n"); return {}; }

    // Decode SPKI DER -> BCrypt key handle
    DWORD pki_sz = 0;
    PCERT_PUBLIC_KEY_INFO pki = nullptr;
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
            public_key_blob.data(), (DWORD)public_key_blob.size(),
            CRYPT_DECODE_ALLOC_FLAG, nullptr, &pki, &pki_sz)) {
        printf("[rsa] CryptDecodeObjectEx failed\n");
        BCryptCloseAlgorithmProvider(alg, 0);
        return {};
    }
    if (!CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, pki,
            CRYPT_OID_INFO_PUBKEY_ENCRYPT_KEY_FLAG, nullptr, &key)) {
        printf("[rsa] CryptImportPublicKeyInfoEx2 failed\n");
        LocalFree(pki);
        BCryptCloseAlgorithmProvider(alg, 0);
        return {};
    }
    LocalFree(pki);

    ULONG result_size = 0;
    BCRYPT_OAEP_PADDING_INFO padding_info;
    padding_info.pszAlgId = use_sha512 ? BCRYPT_SHA512_ALGORITHM : BCRYPT_SHA1_ALGORITHM;
    padding_info.pbLabel = nullptr;
    padding_info.cbLabel = 0;
    NTSTATUS st = BCryptEncrypt(key, (PUINT8)plaintext.data(), (ULONG)plaintext.size(),
        &padding_info, nullptr, 0, nullptr, 0, &result_size, BCRYPT_PAD_OAEP);
    if (st != 0) { printf("[rsa] Encrypt size query failed: 0x%lx\n", st); BCryptDestroyKey(key); BCryptCloseAlgorithmProvider(alg, 0); return {}; }
    printf("[rsa] encrypt result_size=%lu\n", result_size);
    std::vector<uint8_t> result(result_size);
    st = BCryptEncrypt(key, (PUINT8)plaintext.data(), (ULONG)plaintext.size(),
        &padding_info, nullptr, 0, result.data(), result_size, &result_size, BCRYPT_PAD_OAEP);
    BCryptDestroyKey(key);
    BCryptCloseAlgorithmProvider(alg, 0);
    if (st != 0) { printf("[rsa] Encrypt failed: 0x%lx\n", st); return {}; }
    printf("[rsa] encrypt actual_len=%lu\n", result_size);
    return result;
}
