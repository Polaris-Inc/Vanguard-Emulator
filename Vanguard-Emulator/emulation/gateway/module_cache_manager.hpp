#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <unordered_map>
#include <chrono>
#include <thread>
#include <functional>

namespace ModuleCache {

struct VgModule {
    std::string          mod_id;
    std::string          cdn_path;
    std::string          sha256_hex;
    int                  size   = 0;
    bool                 is_pe  = false;
    std::vector<uint8_t> data;
};

class ModuleCacheManager {
public:
    explicit ModuleCacheManager(const std::string& cache_root);

    std::string sanitize_cdn_path(const std::string& cdn_path);
    std::string resolve_cdn_url(const std::string& cdn_path, const std::string& region);
    bool has_module(const std::string& cdn_path);
    bool try_get_module(const std::string& cdn_path, VgModule& out);
    void ingest_blob(const std::string& cdn_path, const std::vector<uint8_t>& data);
    void download_module(const std::string& cdn_path, const std::string& region);
    void fetch_module_async(const std::string& cdn_path, const std::string& region);

    void set_session_aes_key(const uint8_t* key) { if (key) memcpy(_session_aes, key, 32); }

private:
    std::string _cache_root;
    std::mutex _mutex;
    std::unordered_map<std::string, VgModule> _cache;
    std::unordered_map<std::string, uint64_t> _failed_urls;
    uint8_t _session_aes[32] = {};

    std::string extract_mod_id(const std::string& cdn_path);
    bool verify_pe_magic(const std::vector<uint8_t>& data);
    std::string sha256_hex(const std::vector<uint8_t>& data);
    uint64_t now_ms();
    void log(const std::string& msg);
};

}
