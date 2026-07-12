#include "task_payload_helper.hpp"
#include <cstring>
#include <ctime>
#include <cstdio>
#include <windows.h>

namespace TaskPayloadHelper {

static void write_varint(std::vector<uint8_t>& buf, uint64_t value)
{
    while (value >= 0x80)
    {
        buf.push_back((uint8_t)((value & 0x7F) | 0x80));
        value >>= 7;
    }
    buf.push_back((uint8_t)(value & 0x7F));
}

static void write_tag(std::vector<uint8_t>& buf, int field, int wire_type)
{
    write_varint(buf, (uint64_t)((field << 3) | wire_type));
}

static void generate_correlation_salt(uint8_t salt[16])
{
    memset(salt, 0, 16);
    uint64_t ts = (uint64_t)time(nullptr);
    memcpy(salt, &ts, sizeof(ts));
}

std::vector<uint8_t> encode_task_performance(
    uint64_t duration_ns,
    uint32_t queue_depth,
    uint32_t retry_count,
    uint32_t lane_failure_mask,
    const uint8_t* correlation_salt,
    size_t salt_len)
{
    std::vector<uint8_t> buf;

    if (duration_ns > 0)
    {
        write_tag(buf, 1, 0);
        write_varint(buf, duration_ns);
    }

    if (queue_depth > 0)
    {
        write_tag(buf, 2, 0);
        write_varint(buf, queue_depth);
    }

    if (retry_count > 0)
    {
        write_tag(buf, 3, 0);
        write_varint(buf, retry_count);
    }

    if (lane_failure_mask > 0)
    {
        write_tag(buf, 4, 0);
        write_varint(buf, lane_failure_mask);
    }

    uint8_t salt_buf[16];
    if (!correlation_salt || salt_len == 0)
    {
        generate_correlation_salt(salt_buf);
        correlation_salt = salt_buf;
        salt_len = 16;
    }
    else if (salt_len > 16)
        salt_len = 16;

    write_tag(buf, 5, 2);
    write_varint(buf, salt_len);
    buf.insert(buf.end(), correlation_salt, correlation_salt + salt_len);

    if (salt_len < 16)
        buf.insert(buf.end(), 16 - salt_len, 0);

    return buf;
}

bool is_pc_task_id(const std::string& task_id)
{
    if (task_id.size() < 14) return false;
    std::string prefix = task_id;
    for (auto& c : prefix) c = (char)tolower(c);
    return prefix.find("6a499d4a816869") == 0;
}

bool is_valid_task_id_hex(const std::string& task_id)
{
    if (task_id.size() != 24) return false;
    std::string lower = task_id;
    for (auto& c : lower) c = (char)tolower(c);
    if (lower.find("6a49") != 0 && lower.find("6a4a") != 0)
        return false;
    for (char c : lower)
    {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    }
    return true;
}

std::string build_npt_survey_json() {
    SYSTEM_INFO si = {}; GetNativeSystemInfo(&si);
    int logi = (int)si.dwNumberOfProcessors;
    int phys = logi > 1 ? logi / 2 : 1;
    unsigned long long ts_ms = (unsigned long long)::time(nullptr) * 1000ULL;
    char buf[1024];
    sprintf_s(buf, sizeof(buf),
        "{\"npt\":{\"cpu\":13,\"device\":{\"cpu_feature_word\":13"
        ",\"logical_cpu_count\":%d,\"physical_cpu_count\":%d"
        ",\"platform\":\"windows\",\"arch\":\"AMD64\""
        ",\"ram_total_bytes\":0,\"collector\":\"gatewaycmd_vps_npt\""
        ",\"ts_ms\":%llu},\"qpc_source\":\"hv_state7\",\"probes\":32}}",
        logi, phys, ts_ms);
    return buf;
}

std::string build_mc_sentinel_json() {
    return "{\"mc\":{\"0\":1}}";
}

std::string build_pc_task_json() {
    char buf[128];
    sprintf_s(buf, sizeof(buf), "{\"pc\":{\"status\":1,\"ts\":%llu}}",
              (unsigned long long)::time(nullptr));
    return buf;
}

std::string build_module_result_json(const std::string& mod_id,
                                     const std::string& sha256_hex,
                                     int size, bool pe_ok) {
    std::string commit = sha256_hex.size() >= 40 ? sha256_hex.substr(0, 40) : sha256_hex;
    char buf[512];
    sprintf_s(buf, sizeof(buf),
        "{\"module\":{\"id\":\"%s\",\"sha256\":\"%s\",\"size\":%d"
        ",\"pe\":%s,\"commit_sha\":\"%s\",\"loaded\":%s,\"ts\":%llu}}",
        mod_id.c_str(), sha256_hex.c_str(), size,
        pe_ok ? "true" : "false", commit.c_str(),
        pe_ok ? "true" : "false", (unsigned long long)::time(nullptr));
    return buf;
}

}
