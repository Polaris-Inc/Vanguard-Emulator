#pragma once
#include <vector>
#include <string>
#include <cstdint>
#include <functional>
#include <windows.h>

#include "aes_gcm_session.hpp"
#include "rsa_session.hpp"
#include "proto_builder.hpp"

namespace GatewayClient {

struct CdnModule {
    std::string id;
    std::string cdn_url;
    bool valid = false;
};

struct GatewaySession {
    AesGcmSession aes;
    RsaSession rsa;
    std::vector<uint8_t> public_key_blob;
    std::vector<uint8_t> private_key_blob;
    std::string access_token;
    bool authenticated = false;
    uint64_t last_hb_timestamp = 0;
    int region_index = 0;
    int auth_count_since_region_switch = 0;
};

enum class GatewayRegion {
    AP, EU, NA, LA
};

GatewayRegion get_current_region();
void set_region_from_string(const std::string& region_str);
std::string get_region_host(GatewayRegion r);
GatewayRegion next_region(GatewayRegion r);

void init_session();
void shutdown_session();

bool do_auth_handshake(const std::string& jwt, const std::string& puuid, const std::string& session_state);
bool do_access_request();
bool do_heartbeat();
bool do_gateway_full_auth(const std::string& jwt, const std::string& puuid, const std::string& session_state);

bool fetch_modules();
bool submit_task_result(uint32_t task_id, const std::vector<uint8_t>& result_data);

GatewaySession& session();

bool is_gateway_active();
bool has_task_module();

  std::vector<CdnModule> get_pending_tasks();

  void rotate_region();
  bool send_disconnect();

}
