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

std::string RsaSession::export_public_key_spki_b64() const {
    auto blob = export_public_key();
    if (blob.size() < 20) return {};

    uint32_t cb_exp = *(uint32_t*)(blob.data() + 8);
    uint32_t cb_mod = *(uint32_t*)(blob.data() + 12);
    if (cb_exp + cb_mod + 16 > blob.size()) return {};

    const uint8_t* exp_bytes = blob.data() + 16;
    const uint8_t* mod_bytes = exp_bytes + cb_exp;

    // Build SPKI DER manually
    auto append_tag_len = [](std::vector<uint8_t>& d, uint8_t tag, size_t len) {
        d.push_back(tag);
        if (len < 0x80) { d.push_back((uint8_t)len); return; }
        if (len < 0x100) { d.push_back(0x81); d.push_back((uint8_t)len); return; }
        d.push_back(0x82);
        d.push_back((uint8_t)(len >> 8));
        d.push_back((uint8_t)(len & 0xFF));
    };

    // Inner RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
    std::vector<uint8_t> inner_ints;
    // INTEGER modulus (with leading 0x00 if high bit set)
    bool zero_pad = (mod_bytes[0] & 0x80) != 0;
    size_t int_mod_len = cb_mod + (zero_pad ? 1 : 0);
    append_tag_len(inner_ints, 0x02, int_mod_len);
    if (zero_pad) inner_ints.push_back(0x00);
    inner_ints.insert(inner_ints.end(), mod_bytes, mod_bytes + cb_mod);
    // INTEGER exponent
    append_tag_len(inner_ints, 0x02, cb_exp);
    inner_ints.insert(inner_ints.end(), exp_bytes, exp_bytes + cb_exp);

    // Wrap in SEQUENCE
    std::vector<uint8_t> inner_seq;
    append_tag_len(inner_seq, 0x30, inner_ints.size());
    inner_seq.insert(inner_seq.end(), inner_ints.begin(), inner_ints.end());

    // BIT STRING wrapping
    std::vector<uint8_t> bitstr;
    bitstr.push_back(0x00);
    bitstr.insert(bitstr.end(), inner_seq.begin(), inner_seq.end());

    // AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters NULL }
    std::vector<uint8_t> alg_id_content;
    append_tag_len(alg_id_content, 0x06, 9);
    const uint8_t oid[] = {0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01};
    alg_id_content.insert(alg_id_content.end(), oid, oid + 9);
    alg_id_content.push_back(0x05); alg_id_content.push_back(0x00);

    std::vector<uint8_t> alg_id;
    append_tag_len(alg_id, 0x30, alg_id_content.size());
    alg_id.insert(alg_id.end(), alg_id_content.begin(), alg_id_content.end());

    // BIT STRING field wrapping the inner structures
    std::vector<uint8_t> bitstr_field;
    append_tag_len(bitstr_field, 0x03, bitstr.size());
    bitstr_field.insert(bitstr_field.end(), bitstr.begin(), bitstr.end());

    // Outer SEQUENCE
    std::vector<uint8_t> der;
    append_tag_len(der, 0x30, alg_id.size() + bitstr_field.size());
    der.insert(der.end(), alg_id.begin(), alg_id.end());
    der.insert(der.end(), bitstr_field.begin(), bitstr_field.end());

    // Base64 encode
    DWORD b64_len = 0;
    CryptBinaryToStringA(der.data(), (DWORD)der.size(), CRYPT_STRING_BASE64, nullptr, &b64_len);
    std::string b64(b64_len, 0);
    CryptBinaryToStringA(der.data(), (DWORD)der.size(), CRYPT_STRING_BASE64, &b64[0], &b64_len);
    // Remove newlines and trailing null
    std::string clean;
    for (char c : b64) if (c != '\r' && c != '\n' && c != '\0') clean += c;
    return clean;
}
