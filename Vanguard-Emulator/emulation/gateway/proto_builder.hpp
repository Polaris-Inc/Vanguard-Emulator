#pragma once
#include <vector>
#include <string>
#include <cstdint>
#include <cstring>
#include <algorithm>
#include <stdexcept>
#include <map>

enum VgMsgType : uint32_t {
    VG_INVALID_MSG_TYPE = 0,
    VG_EMPTY = 1,
    VG_ERROR_RESPONSE = 2,
    VG_AUTH_REQ = 3,
    VG_ACCESS_REQ = 4,
    VG_TOKEN_RESP = 5,
    VG_MODULES_RESP = 6,
    VG_HB_REQ = 7,
    VG_HB_RESP = 8,
    VG_TASK_RESULT = 9,
    VG_DISCONNECT = 10,
    VG_TASK_RESULT_RESPONSE = 11,
};

inline const char* vg_type_name(uint32_t t) {
    switch (t) {
        case 0: return "INVALID_MESSAGE_TYPE"; case 1: return "EMPTY";
        case 2: return "ERROR_RESPONSE"; case 3: return "AUTH_REQUEST";
        case 4: return "ACCESS_REQUEST"; case 5: return "TOKEN_RESPONSE";
        case 6: return "MODULES_RESPONSE"; case 7: return "HEARTBEAT_REQUEST";
        case 8: return "HEARTBEAT_RESPONSE"; case 9: return "TASK_RESULT_REQUEST";
        case 10: return "CLIENT_DISCONNECT_REQUEST"; case 11: return "TASK_RESULT_RESPONSE";
        default: return "UNKNOWN";
    }
}

struct VgEnvelope {
    uint32_t type = 0;
    std::vector<uint8_t> payload;
};

struct VgAuthRequest {
    std::string machine_id;                              // field 1  - bytes
    // os_info is encoded inline, no separate struct       // field 2  - OsInfo sub-msg
    uint32_t platform_type = 1;                          // field 3  - varint
    std::string game_token;                              // field 4  - string
    std::vector<uint8_t> client_rsa_public_key;          // field 5  - bytes
    // game_version encoded inline                         // field 6  - Version sub-msg
    // vanguard_version encoded inline                     // field 7  - Version sub-msg
    std::string game_id = "com.riotgames.valorant";      // field 8  - string
    uint32_t boot_state = 3;                             // field 9  - varint
    std::vector<uint8_t> ephemeral_identifiers;          // field 10 - repeated bytes
    // cpu_info encoded inline                             // field 11 - CpuInfo sub-msg
    std::string external_sid;                            // field 13 - string
    std::map<std::string, std::string> flags;            // field 14 - map entry, repeated
    std::map<std::string, std::string> metadata;         // field 15 - map entry, repeated
};

struct VgAccessRequest {
    std::string auth_token;
};

struct VgTokenResponse {
    std::vector<uint8_t> token;
    uint64_t exp = 0;
    std::vector<uint8_t> server_rsa_public_key;
    std::vector<uint8_t> ephemeral_identifiers;
    std::map<std::string, std::string> feature_flags;
    std::map<std::string, std::string> config;
    std::string session_id;
};

struct VgHeartbeatRequest {
    std::string access_token;
    std::vector<std::string> additional_requested_tasks;
};

struct VgHeartbeatResponse {
    uint64_t timestamp = 0;
    std::vector<uint32_t> active_task_ids;
    std::vector<std::string> active_task_strings;
    bool should_disconnect = false;
};

struct VgTaskResult {
    uint32_t id = 0;
    std::string id_str;
    std::vector<uint8_t> id_bytes;
    std::vector<uint8_t> data;
    uint32_t status = 1;
    std::vector<uint8_t> performance;
};

struct VgTaskResultRequest {
    std::string access_token;
    std::vector<VgTaskResult> results;
};

struct VgDisconnectRequest {
    std::string access_token;
};

struct VgModule {
    std::string id;
    std::string arguments;
    std::string cdn_url;
};

struct VgModuleResult {
    std::string commit_sha;
};

struct VgModulesResponse {
    std::vector<VgModule> modules;
};

struct VgTask {
    std::string id;
};

struct VgTaskPerformance {
    std::vector<uint8_t> data;
};

namespace ProtoBuilder {

std::vector<uint8_t> encode_envelope(const VgEnvelope& env);
VgEnvelope decode_envelope(const std::vector<uint8_t>& data);

std::vector<uint8_t> encode_auth_request(const VgAuthRequest& req);
std::vector<uint8_t> encode_access_request(const VgAccessRequest& req);
VgTokenResponse decode_token_response(const std::vector<uint8_t>& data);

std::vector<uint8_t> encode_heartbeat_request(const VgHeartbeatRequest& req);
VgHeartbeatResponse decode_heartbeat_response(const std::vector<uint8_t>& data);

std::vector<uint8_t> encode_task_result_request(const VgTaskResultRequest& req);
std::vector<uint8_t> encode_disconnect_request(const VgDisconnectRequest& req);

bool looks_like_protobuf_root(const uint8_t* d, size_t sz);
std::vector<uint8_t> find_heartbeat_protobuf_slice(const std::vector<uint8_t>& plain);

std::vector<std::string> extract_cdn_paths(const std::vector<uint8_t>& data);
std::vector<std::string> extract_task_ids(const std::vector<uint8_t>& data);
std::string module_id_from_path(const std::string& cdn_path);
std::string sanitize_cdn_path(const std::string& raw);

}
