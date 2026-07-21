#include "module_cache_manager.hpp"
#include "ri_crypto.hpp"
#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <fstream>
#include <sstream>
#include <regex>
#include <cstdio>
#include <filesystem>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")

namespace fs = std::filesystem;

namespace ModuleCache {

ModuleCacheManager::ModuleCacheManager(const std::string& cache_root)
    : _cache_root(cache_root)
{
    CreateDirectoryA(_cache_root.c_str(), nullptr);
}

uint64_t ModuleCacheManager::now_ms() {
    FILETIME ft; GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    return uli.QuadPart / 10000ULL;
}

std::string ModuleCacheManager::extract_mod_id(const std::string& cdn_path)
{
    std::regex re("/v1/cdn/mod/(\\d+)");
    std::smatch m;
    if (std::regex_search(cdn_path, m, re))
        return m[1].str();
    return "unknown";
}

std::string ModuleCacheManager::sanitize_cdn_path(const std::string& cdn_path)
{
    if (cdn_path.empty()) return "";
    std::string path = cdn_path;
    while (!path.empty() && (path[0] == ' ' || path[0] == '\t'))
        path.erase(0, 1);
    while (!path.empty() && (path.back() == ' ' || path.back() == '\t'))
        path.pop_back();

    if (path.find("http") == 0)
    {
        size_t idx = path.find("/v1/cdn/mod/");
        if (idx != std::string::npos)
            path = path.substr(idx);
    }

    std::regex re("/v1/cdn/mod/\\d+\\?verify=[0-9A-Za-z%\\-\\._\\+/=]+");
    std::smatch m;
    if (std::regex_search(path, m, re))
        return m.str();

    size_t nul = path.find('\0');
    if (nul != std::string::npos)
        path = path.substr(0, nul);
    while (!path.empty() && (path[0] == ' ' || path[0] == '\t'))
        path.erase(0, 1);
    return path;
}

std::string ModuleCacheManager::resolve_cdn_url(const std::string& cdn_path, const std::string& region)
{
    std::string path = sanitize_cdn_path(cdn_path);
    if (path.find("http://") == 0 || path.find("https://") == 0)
        return path;

    if (!path.empty() && path[0] != '/')
        path = "/" + path;

    if (path.find("/v1/cdn/") == 0 && path.find("/vanguard/") != 0)
        path = "/vanguard" + path;

    return "https://" + region + ".vg.ac.pvp.net:8443" + path;
}

bool ModuleCacheManager::verify_pe_magic(const std::vector<uint8_t>& data)
{
    if (data.size() < 0x40 || data[0] != 0x4D || data[1] != 0x5A)
        return false;

    uint32_t pe_offset = (uint32_t)data[0x3C] | ((uint32_t)data[0x3D] << 8) |
                         ((uint32_t)data[0x3E] << 16) | ((uint32_t)data[0x3F] << 24);
    if (pe_offset + 4 > data.size())
        return false;

    return data[pe_offset] == 0x50 && data[pe_offset + 1] == 0x45 &&
           data[pe_offset + 2] == 0x00 && data[pe_offset + 3] == 0x00;
}

std::string ModuleCacheManager::sha256_hex(const std::vector<uint8_t>& data)
{
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (!hAlg) return "";

    DWORD hash_len = 0;
    BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&hash_len, sizeof(hash_len), nullptr, 0);
    std::vector<uint8_t> hash(hash_len);
    BCryptHash(hAlg, nullptr, 0, (PUCHAR)data.data(), (ULONG)data.size(), hash.data(), (ULONG)hash.size());
    BCryptCloseAlgorithmProvider(hAlg, 0);

    const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(hash.size() * 2);
    for (uint8_t b : hash)
    {
        out += hex[b >> 4];
        out += hex[b & 0xF];
    }
    return out;
}

bool ModuleCacheManager::has_module(const std::string& cdn_path)
{
    std::string clean = sanitize_cdn_path(cdn_path);
    if (clean.empty()) return false;
    std::lock_guard<std::mutex> lock(_mutex);
    return _cache.find(clean) != _cache.end();
}

bool ModuleCacheManager::try_get_module(const std::string& cdn_path, VgModule& out)
{
    std::string clean = sanitize_cdn_path(cdn_path);
    if (clean.empty()) return false;
    std::lock_guard<std::mutex> lock(_mutex);
    auto it = _cache.find(clean);
    if (it == _cache.end()) return false;
    out = it->second;
    return true;
}

void ModuleCacheManager::ingest_blob(const std::string& cdn_path, const std::vector<uint8_t>& data)
{
    std::string clean = sanitize_cdn_path(cdn_path);
    if (clean.empty() || data.empty()) return;

    std::string mod_id = extract_mod_id(clean);
    std::string sha = sha256_hex(data);
    bool pe = verify_pe_magic(data);

    log("Ingest mod=" + mod_id + " bytes=" + std::to_string(data.size()) +
        " sha=" + sha.substr(0, 16) + " pe=" + (pe ? "1" : "0"));

    VgModule m;
    m.mod_id = mod_id;
    m.cdn_path = clean;
    m.sha256_hex = sha;
    m.size = (int)data.size();
    m.is_pe = pe;
    m.data = data;

    std::lock_guard<std::mutex> lock(_mutex);
    _cache[clean] = std::move(m);
    _failed_urls.erase(clean);

    std::string cache_path = _cache_root + "\\" + mod_id + ".bin";
    std::ofstream f(cache_path, std::ios::binary);
    f.write((const char*)data.data(), data.size());
    f.close();
}

void ModuleCacheManager::download_module(const std::string& cdn_path, const std::string& region)
{
    std::string clean = sanitize_cdn_path(cdn_path);
    if (clean.empty()) return;

    {
        std::lock_guard<std::mutex> lock(_mutex);
        if (_cache.find(clean) != _cache.end()) return;
        auto fit = _failed_urls.find(clean);
        if (fit != _failed_urls.end() && (now_ms() - fit->second) < 120000ULL) return;
    }

    std::string mod_id = extract_mod_id(clean);
    log("Download start mod=" + mod_id + " region=" + region);

    std::string host_str = region + ".vg.ac.pvp.net";
    std::string full_url = resolve_cdn_url(clean, region);
    size_t path_pos = full_url.find(":8443");
    if (path_pos == std::string::npos) return;
    std::string path_str = full_url.substr(path_pos + 5);
    std::wstring host_w(host_str.begin(), host_str.end());
    std::wstring path_w(path_str.begin(), path_str.end());

    HINTERNET hS = WinHttpOpen(L"vanguard/1.18.4-31+20260715.133553",
                               WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                               WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hS) return;
    WinHttpSetTimeouts(hS, 5000, 10000, 30000, 30000);
    DWORD protos = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
    WinHttpSetOption(hS, WINHTTP_OPTION_SECURE_PROTOCOLS, &protos, sizeof(protos));
    HINTERNET hC = WinHttpConnect(hS, host_w.c_str(), 8443, 0);
    if (!hC) { WinHttpCloseHandle(hS); return; }
    HINTERNET hR = WinHttpOpenRequest(hC, L"GET", path_w.c_str(), nullptr,
                                       WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                       WINHTTP_FLAG_SECURE);
    if (!hR) { WinHttpCloseHandle(hC); WinHttpCloseHandle(hS); return; }
    DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                     SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
    WinHttpSetOption(hR, WINHTTP_OPTION_SECURITY_FLAGS, &secFlags, sizeof(secFlags));

    WinHttpSendRequest(hR, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                       WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    WinHttpReceiveResponse(hR, nullptr);

    DWORD status = 0, status_sz = sizeof(DWORD);
    WinHttpQueryHeaders(hR, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        nullptr, &status, &status_sz, nullptr);

    std::vector<uint8_t> raw;
    if (status == 200) {
        DWORD total = 0, read = 0;
        std::vector<uint8_t> buf(65536);
        while (WinHttpReadData(hR, buf.data() + total, (DWORD)(buf.size() - total), &read) && read > 0) {
            total += read;
            if (buf.size() - total < 4096) buf.resize(buf.size() * 2);
        }
        raw.assign(buf.begin(), buf.begin() + total);
    }

    WinHttpCloseHandle(hR);
    WinHttpCloseHandle(hC);
    WinHttpCloseHandle(hS);

    if (raw.empty() || status != 200) {
        log("Download FAIL mod=" + mod_id + " st=" + std::to_string(status));
        std::lock_guard<std::mutex> lock(_mutex);
        _failed_urls[clean] = now_ms();
        return;
    }

    auto unwrapped = RiCrypto::try_unwrap(raw, _session_aes);
    if (!unwrapped.empty() && unwrapped.size() != raw.size()) {
        log("RICRYPTO unwrap mod=" + mod_id + " " +
            std::to_string(raw.size()) + "b->" + std::to_string(unwrapped.size()) + "b");
        raw = std::move(unwrapped);
    }

    ingest_blob(clean, raw);
}

void ModuleCacheManager::fetch_module_async(const std::string& cdn_path, const std::string& region)
{
    if (has_module(cdn_path)) return;
    std::thread([this, cdn_path, region]{
        this->download_module(cdn_path, region);
    }).detach();
}

void ModuleCacheManager::log(const std::string& msg)
{
    printf("[CDN] %s\n", msg.c_str());
}

}
