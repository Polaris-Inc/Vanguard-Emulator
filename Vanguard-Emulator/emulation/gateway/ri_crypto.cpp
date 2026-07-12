#include "ri_crypto.hpp"
#include "rsa_session.hpp"
#include "aes_gcm_session.hpp"
#include <windows.h>
#include <bcrypt.h>
#include <cstring>
#include <algorithm>
#include <random>
#include <set>

#pragma comment(lib, "bcrypt.lib")

namespace RiCrypto {

static std::vector<uint8_t> random_bytes(size_t n) {
    std::vector<uint8_t> buf(n);
    if (BCryptGenRandom(nullptr, buf.data(), (ULONG)buf.size(), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        std::random_device rd;
        for (size_t i = 0; i < n; i++) buf[i] = (uint8_t)rd();
    }
    return buf;
}

static void append_varint(std::vector<uint8_t>& buf, uint64_t val) {
    while (val >= 0x80) {
        buf.push_back((uint8_t)(val & 0x7F) | 0x80);
        val >>= 7;
    }
    buf.push_back((uint8_t)val);
}

std::vector<uint8_t> build_payload(
    const std::vector<uint8_t>& plaintext,
    uint32_t type,
    const std::vector<uint8_t>& server_public_key_blob
) {
    auto aes_key = random_bytes(32);
    auto iv = random_bytes(12);

    AesGcmSession aes;
    if (!aes.set_key(aes_key)) { printf("[ri] aes set_key failed\n"); return {}; }
    if (!aes.set_iv(iv)) { printf("[ri] aes set_iv failed\n"); return {}; }
    auto encrypted = aes.encrypt(plaintext);
    if (encrypted.size() < 16) { printf("[ri] aes encrypt failed (size=%zu)\n", encrypted.size()); return {}; }

    printf("[ri] server key blob size=%zu\n", server_public_key_blob.size());
    auto rsa_enc_key = RsaSession::encrypt_with_key(aes_key, server_public_key_blob, true);
    printf("[ri] rsa encrypted key size=%zu\n", rsa_enc_key.size());
    if (rsa_enc_key.size() != 256) { printf("[ri] rsa encrypt failed (expected 256)\n"); return {}; }

    std::vector<uint8_t> rito;
    const uint8_t rg_magic[] = {0x52, 0x47, 0x01, 0x00};
    rito.insert(rito.end(), rg_magic, rg_magic + 4);
    rito.insert(rito.end(), rsa_enc_key.begin(), rsa_enc_key.end());
    rito.insert(rito.end(), iv.begin(), iv.end());
    rito.insert(rito.end(), encrypted.begin(), encrypted.end() - 16);
    rito.insert(rito.end(), encrypted.end() - 16, encrypted.end());

    std::vector<uint8_t> result;
    result.push_back(0x08);
    append_varint(result, type);
    result.push_back(0x12);
    append_varint(result, rito.size());
    result.insert(result.end(), rito.begin(), rito.end());

    return result;
}

std::vector<uint8_t> decrypt_payload(
    const std::vector<uint8_t>& payload,
    const std::vector<uint8_t>& private_key_blob
) {
    if (payload.size() < 3 + 4 + 256 + 12 + 16) return {};

    size_t pos = 0;
    if (payload[pos++] != 0x08) return {};
    while (pos < payload.size() && (payload[pos] & 0x80)) pos++;
    pos++;
    if (pos + 1 >= payload.size() || payload[pos++] != 0x12) return {};
    while (pos < payload.size() && (payload[pos] & 0x80)) pos++;
    pos++;

    if (pos + 4 > payload.size()) return {};
    const uint8_t rg_magic[] = {0x52, 0x47, 0x01, 0x00};
    if (std::memcmp(payload.data() + pos, rg_magic, 4) != 0) return {};
    pos += 4;

    if (pos + 256 > payload.size()) return {};
    std::vector<uint8_t> rsa_key(payload.begin() + pos, payload.begin() + pos + 256);
    pos += 256;

    if (pos + 12 > payload.size()) return {};
    std::vector<uint8_t> iv(payload.begin() + pos, payload.begin() + pos + 12);
    pos += 12;

    if (payload.size() - pos < 16) return {};
    std::vector<uint8_t> tag(payload.end() - 16, payload.end());
    std::vector<uint8_t> ciphertext(payload.begin() + pos, payload.end() - 16);

    RsaSession rsa;
    if (!rsa.import_private_key(private_key_blob)) return {};
    auto decrypted_key = rsa.decrypt_oaep(rsa_key);
    if (decrypted_key.size() != 32) return {};

    AesGcmSession aes;
    if (!aes.set_key(decrypted_key)) return {};
    if (!aes.set_iv(iv)) return {};
    return aes.decrypt(ciphertext, tag);
}

bool gcm_decrypt_one_shot(
    const std::vector<uint8_t>& key,
    const uint8_t* nonce12,
    const uint8_t* ciphertext, int cipher_len,
    const uint8_t* tag16,
    std::vector<uint8_t>& out_plain
) {
    std::vector<uint8_t> iv(nonce12, nonce12 + 12);
    std::vector<uint8_t> ct(ciphertext, ciphertext + cipher_len);
    std::vector<uint8_t> tag(tag16, tag16 + 16);

    AesGcmSession aes;
    if (!aes.set_key(key)) return false;
    if (!aes.set_iv(iv)) return false;
    out_plain = aes.decrypt(ct, tag);
    return !out_plain.empty();
}

bool is_pe(const std::vector<uint8_t>& d) {
    if (d.size() < 0x40 || d[0] != 0x4D || d[1] != 0x5A) return false;
    int peOff; memcpy(&peOff, d.data() + 0x3C, 4);
    if (peOff < 0 || (size_t)(peOff + 4) > d.size()) return false;
    return d[peOff] == 0x50 && d[peOff+1] == 0x45 && d[peOff+2] == 0x00 && d[peOff+3] == 0x00;
}

int find_ricrypto_magic(const std::vector<uint8_t>& blob) {
    static const uint8_t kMagic[] = {'R','I','C','R','Y','P','T','O'};
    for (size_t i = 0; i + 8 <= blob.size(); ++i)
        if (memcmp(blob.data() + i, kMagic, 8) == 0) return (int)i;
    return -1;
}

std::vector<uint8_t> proto_field1(const std::vector<uint8_t>& data) {
    if (data.size() < 2) return {};
    size_t pos = 0;
    auto read_varint = [&](size_t len) -> uint64_t {
        uint64_t val = 0; int shift = 0;
        while (pos < len && shift < 64) {
            uint8_t b = data[pos++];
            val |= (uint64_t)(b & 0x7F) << shift;
            if (!(b & 0x80)) return val;
            shift += 7;
        }
        return 0;
    };
    uint64_t tag = read_varint(data.size());
    if ((tag & 7) != 2 || (tag >> 3) != 1) return {};
    uint64_t len = read_varint(data.size());
    if (!len || pos + len > data.size()) return {};
    return std::vector<uint8_t>(data.begin() + pos, data.begin() + pos + (size_t)len);
}

std::vector<uint8_t> decrypt_ricrypto_blob(const std::vector<uint8_t>& blob, size_t ri_off) {
    static const int kHeaderSize = 92, kKeyOff = 24, kKeySize = 32;
    static const int kNonceOffsets[] = {56, 59, 60, 64, 68, 72};
    static const int kCtOffsets[]    = {88, 92, 96};
    if (blob.size() < ri_off + kHeaderSize + 32) return {};

    std::vector<uint8_t> hdr_key(blob.begin() + ri_off + kKeyOff,
                                  blob.begin() + ri_off + kKeyOff + kKeySize);
    std::vector<uint8_t> best; bool best_is_pe = false;

    for (int ct_rel : kCtOffsets) {
        size_t abs_ct = ri_off + ct_rel;
        if (abs_ct >= blob.size()) continue;
        size_t avail = blob.size() - abs_ct;
        if (avail < 32) continue;

        for (int nonce_rel : kNonceOffsets) {
            size_t abs_nonce = ri_off + nonce_rel;
            if (abs_nonce + 12 > blob.size()) continue;
            const uint8_t* nonce = blob.data() + abs_nonce;

            if (avail > 16) {
                size_t ct_len = avail - 16;
                std::vector<uint8_t> pt;
                if (gcm_decrypt_one_shot(hdr_key, nonce,
                        blob.data() + abs_ct, (int)ct_len,
                        blob.data() + blob.size() - 16, pt)) {
                    if (pt.size() >= 256) {
                        if (is_pe(pt)) return pt;
                        if (!best_is_pe && pt.size() >= 65536 && pt.size() > best.size()) best = pt;
                    }
                }
            }

            if (ri_off + 72 <= blob.size() && avail > 16) {
                size_t ct_len = avail - 16;
                std::vector<uint8_t> pt;
                if (gcm_decrypt_one_shot(hdr_key, nonce,
                        blob.data() + abs_ct, (int)ct_len,
                        blob.data() + ri_off + 56, pt)) {
                    if (pt.size() >= 256) {
                        if (is_pe(pt)) return pt;
                        if (!best_is_pe && pt.size() >= 65536 && pt.size() > best.size()) best = pt;
                    }
                }
            }
        }
    }
    return best;
}

std::vector<uint8_t> decrypt_rg_blob(const std::vector<uint8_t>& blob, const uint8_t* session_aes_key) {
    static const uint8_t kRgMagic[] = {0x52, 0x47, 0x01, 0x00};
    for (size_t i = 0; i + 4 <= blob.size(); ++i) {
        if (memcmp(blob.data() + i, kRgMagic, 4) != 0) continue;
        const int kRsa = 256, kNonce = 12, kTag = 16;
        size_t off = i + 4 + kRsa;
        if (off + kNonce + kTag > blob.size()) continue;
        const uint8_t* nonce = blob.data() + off; off += kNonce;
        size_t ct_len = blob.size() - off - kTag;
        if ((int)ct_len <= 0) continue;
        std::vector<uint8_t> key_vec(session_aes_key, session_aes_key + 32), pt;
        if (gcm_decrypt_one_shot(key_vec, nonce,
                blob.data() + off, (int)ct_len,
                blob.data() + blob.size() - kTag, pt)
                && pt.size() >= 4096) return pt;
    }
    return {};
}

std::vector<uint8_t> extract_embedded_pe(const std::vector<uint8_t>& d) {
    for (size_t i = 1; i + 64 < d.size(); ++i) {
        if (d[i] != 0x4D || d[i+1] != 0x5A || i + 0x40 > d.size()) continue;
        int peOff; memcpy(&peOff, d.data() + i + 0x3C, 4);
        if (peOff < 0 || i + (size_t)peOff + 4 > d.size()) continue;
        if (d[i+peOff] == 0x50 && d[i+peOff+1] == 0x45 &&
            d[i+peOff+2] == 0x00 && d[i+peOff+3] == 0x00)
            return std::vector<uint8_t>(d.begin() + i, d.end());
    }
    return {};
}

std::vector<uint8_t> try_unwrap(const std::vector<uint8_t>& http_body, const uint8_t* session_aes) {
    if (http_body.empty()) return {};
    if (is_pe(http_body)) return http_body;
    std::vector<uint8_t> blob = proto_field1(http_body);
    if (blob.empty()) blob = http_body;
    if (is_pe(blob)) return blob;
    int ri_off = find_ricrypto_magic(blob);
    if (ri_off >= 0) {
        auto dec = decrypt_ricrypto_blob(blob, ri_off);
        if (!dec.empty()) return dec;
    }
    if (session_aes) {
        auto rg = decrypt_rg_blob(blob, session_aes);
        if (!rg.empty()) return rg;
    }
    auto emb = extract_embedded_pe(blob);
    if (!emb.empty()) return emb;
    return blob.size() >= 65536 ? blob : std::vector<uint8_t>{};
}

}
