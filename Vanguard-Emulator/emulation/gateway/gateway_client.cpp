#include "gateway_client.hpp"
#include "gateway_config.hpp"
#include "rg_crypto.hpp"
#include "ri_crypto.hpp"
#include "proto_builder.hpp"
#include "vgc_state.hpp"
#include <string>
#include <vector>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <thread>
#include <chrono>
#include <winhttp.h>
#include <sstream>

#pragma comment(lib, "winhttp.lib")

namespace GatewayClient {

static GatewaySession g_session;
static GatewayRegion g_region = GatewayRegion::LA;
static std::mutex g_region_mutex;
static bool g_active = false;
static bool g_has_task = false;
static std::vector<CdnModule> g_pending_modules;
static std::mutex g_module_mutex;

static const char* kGatewayPath = "/vanguard/v1/gateway";
static const int kGatewayPort = 8443;

GatewayRegion get_current_region() {
    std::lock_guard<std::mutex> lock(g_region_mutex);
    return g_region;
}

std::string get_region_host(GatewayRegion r) {
    switch (r) {
        case GatewayRegion::AP: return "ap.vg.ac.pvp.net";
        case GatewayRegion::EU: return "eu.vg.ac.pvp.net";
        case GatewayRegion::NA: return "na.vg.ac.pvp.net";
        case GatewayRegion::LA: return "la.vg.ac.pvp.net";
        default: return "la.vg.ac.pvp.net";
    }
}

GatewayRegion next_region(GatewayRegion r) {
    switch (r) {
        case GatewayRegion::AP: return GatewayRegion::EU;
        case GatewayRegion::EU: return GatewayRegion::AP;
        case GatewayRegion::NA: return GatewayRegion::LA;
        case GatewayRegion::LA: return GatewayRegion::NA;
        default: return GatewayRegion::NA;
    }
}

void rotate_region() {
    std::lock_guard<std::mutex> lock(g_region_mutex);
    g_region = next_region(g_region);
    g_active = false;
}

void init_session() {
    g_session = GatewaySession();
    g_session.rsa.generate_key();
    g_session.public_key_blob = g_session.rsa.export_public_key();
    g_session.private_key_blob = g_session.rsa.export_private_key();
    g_active = true;
    g_has_task = false;
}

void shutdown_session() {
    g_active = false;
    g_has_task = false;
    g_pending_modules.clear();
    g_session = GatewaySession();
}

GatewaySession& session() {
    return g_session;
}

bool is_gateway_active() {
    return g_active;
}

bool has_task_module() {
    return g_has_task;
}

std::vector<CdnModule> get_pending_tasks() {
    std::lock_guard<std::mutex> lock(g_module_mutex);
    return g_pending_modules;
}

static std::vector<uint8_t> http_post(const std::string& host, int port, const std::string& path,
    const std::vector<uint8_t>& body, std::string& extra_headers, long* status_out)
{
    std::vector<uint8_t> result;
    HINTERNET hSession = WinHttpOpen(L"vanguard/1.18.3-77+20260625.030831",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, nullptr, nullptr, 0);
    if (!hSession) return result;

    std::wstring whost(host.begin(), host.end());
    HINTERNET hConnect = WinHttpConnect(hSession, whost.c_str(), (INTERNET_PORT)port, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return result; }

    std::wstring wpath(path.begin(), path.end());
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", wpath.c_str(),
        nullptr, nullptr, nullptr, WINHTTP_FLAG_SECURE);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return result; }

    DWORD sec_flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
        SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &sec_flags, sizeof(sec_flags));

    std::wstring wheaders(extra_headers.begin(), extra_headers.end());
    WinHttpSendRequest(hRequest, wheaders.c_str(), (DWORD)wheaders.length(),
        (LPVOID)body.data(), (DWORD)body.size(), (DWORD)body.size(), 0);
    WinHttpReceiveResponse(hRequest, nullptr);

    DWORD status_code = 0;
    DWORD status_sz = sizeof(status_code);
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        nullptr, &status_code, &status_sz, nullptr);
    if (status_out) *status_out = (long)status_code;

    DWORD total = 0, read = 0;
    std::vector<uint8_t> buf(65536);
    while (WinHttpReadData(hRequest, buf.data() + total, (DWORD)(buf.size() - total), &read) && read > 0) {
        total += read;
        if (buf.size() - total < 4096) buf.resize(buf.size() * 2);
    }
    result.assign(buf.begin(), buf.begin() + total);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return result;
}

static std::string make_headers() {
    std::string hdrs;
    hdrs += "Content-Type: application/x-protobuf\r\n";
    hdrs += "X-VG-1: ";
    hdrs += GatewayConfig::kVanguardFlagVersion;
    hdrs += "\r\n";
    hdrs += "X-VG-3: ";
    hdrs += GatewayConfig::kVanguardFlagVersion;
    hdrs += "\r\n";
    return hdrs;
}

static std::vector<uint8_t> send_envelope(uint32_t msg_type, const std::vector<uint8_t>& payload) {
    VgEnvelope outer;
    outer.type = msg_type;
    outer.payload = payload;
    auto final_data = ProtoBuilder::encode_envelope(outer);

    std::string region_host = get_region_host(get_current_region());
    std::string hdrs = make_headers();
    long status = 0;
    auto response = http_post(region_host, kGatewayPort, kGatewayPath, final_data, hdrs, &status);

    if (status != 200) return {};
    return response;
}

static std::vector<uint8_t> aes_encrypt_envelope(const VgEnvelope& env) {
    auto envelope_data = ProtoBuilder::encode_envelope(env);
    auto encrypted = g_session.aes.encrypt(envelope_data);
    if (encrypted.size() < 16) return {};
    return encrypted;
}

static std::vector<uint8_t> aes_decrypt_response(const std::vector<uint8_t>& response) {
    if (response.size() < 16) return {};
    auto resp_env = ProtoBuilder::decode_envelope(response);
    if (resp_env.payload.size() < 16) return {};
    std::vector<uint8_t> tag(resp_env.payload.end() - 16, resp_env.payload.end());
    std::vector<uint8_t> cipher(resp_env.payload.begin(), resp_env.payload.end() - 16);
    return g_session.aes.decrypt(cipher, tag);
}

bool do_auth_handshake(const std::string& jwt, const std::string& puuid, const std::string& session_state) {
    if (jwt.empty() || puuid.empty()) return false;

    VgAuthRequest auth_req;
    auth_req.game_token = jwt;
    auth_req.external_sid = puuid;
    auth_req.game_id = "com.riotgames.valorant";
    auth_req.client_rsa_public_key = g_session.public_key_blob;
    auth_req.machine_id = "00000000-0000-0000-0000-000000000000";
    auth_req.metadata["platform"] = "Windows";
    auth_req.metadata["platform_version"] = "10.0.19045";

    auto auth_payload = ProtoBuilder::encode_auth_request(auth_req);

    VgEnvelope auth_env;
    auth_env.type = VG_AUTH_REQ;
    auth_env.payload = auth_payload;
    auto envelope_data = ProtoBuilder::encode_envelope(auth_env);

    auto raw_pub = g_session.public_key_blob;
    RiCrypto::RgEnvelope rg_env;
    rg_env.nonce = {0,0,0,0,0,0,0,0,0,0,0,1};
    AesGcmSession temp_aes;
    temp_aes.set_key({0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0});
    temp_aes.set_iv(rg_env.nonce);
    auto encrypted = temp_aes.encrypt(envelope_data);
    if (encrypted.size() < 16) return false;
    rg_env.encrypted.assign(encrypted.begin(), encrypted.end() - 16);
    rg_env.tag.assign(encrypted.end() - 16, encrypted.end());

    auto final_payload = RiCrypto::encode_envelope(rg_env, raw_pub);

    std::string region_host = get_region_host(get_current_region());
    std::string hdrs = make_headers();
    long status = 0;
    auto response = http_post(region_host, kGatewayPort, kGatewayPath, final_payload, hdrs, &status);
    printf("[gateway] Handshake HTTP status=%ld body_len=%zu\n", status, response.size());
    if (status != 200 || response.empty()) return false;

    auto ck = RgCrypto::parse_handshake_response(response, g_session.private_key_blob);
    if (!ck.valid) {
        ck = RgCrypto::parse_access_response(response, g_session.private_key_blob);
    }
    if (!ck.valid) return false;

    g_session.aes.set_key(ck.aes_key);
    g_session.aes.set_iv(ck.iv);
    g_session.authenticated = true;
    return true;
}

bool do_access_request() {
    if (!g_session.authenticated)
    {
        printf("[gateway] Access request skipped: not authenticated\n");
        return false;
    }

    VgAccessRequest access_req;
    access_req.auth_token = g_session.access_token;
    auto access_payload = ProtoBuilder::encode_access_request(access_req);

    VgEnvelope access_env;
    access_env.type = VG_ACCESS_REQ;
    access_env.payload = access_payload;
    auto encrypted = aes_encrypt_envelope(access_env);
    if (encrypted.empty())
    {
        printf("[gateway] Access request encrypt failed\n");
        return false;
    }

    auto response = send_envelope(VG_ACCESS_REQ, encrypted);
    printf("[gateway] Access response size=%zu\n", response.size());
    if (response.empty()) return false;

    auto plain = aes_decrypt_response(response);
    if (plain.empty())
    {
        printf("[gateway] Access response decrypt failed\n");
        return false;
    }
    printf("[gateway] Access response decrypted, size=%zu\n", plain.size());

    auto inner = ProtoBuilder::decode_envelope(plain);
    if (inner.type != VG_TOKEN_RESP)
    {
        printf("[gateway] Access response unexpected type=%u\n", inner.type);
        return false;
    }

    auto token_resp = ProtoBuilder::decode_token_response(inner.payload);
    if (!token_resp.token.empty()) {
        g_session.access_token.assign(token_resp.token.begin(), token_resp.token.end());
        VgcState::set_token(token_resp.token);
    }

    g_session.aes.rotate_iv();
    bool has_token = !g_session.access_token.empty();
    printf("[gateway] Access request %s\n", has_token ? "OK" : "failed (no token)");
    return has_token;
}

bool do_heartbeat() {
    if (!g_session.authenticated || g_session.access_token.empty()) return false;

    VgHeartbeatRequest hb_req;
    hb_req.access_token = g_session.access_token;
    auto hb_payload = ProtoBuilder::encode_heartbeat_request(hb_req);

    VgEnvelope hb_env;
    hb_env.type = VG_HB_REQ;
    hb_env.payload = hb_payload;
    auto encrypted = aes_encrypt_envelope(hb_env);
    if (encrypted.empty()) return false;

    std::string region_host = get_region_host(get_current_region());
    std::string hdrs = make_headers();
    long status = 0;
    auto final_data = ProtoBuilder::encode_envelope({VG_HB_REQ, encrypted});
    auto response = http_post(region_host, kGatewayPort, kGatewayPath, final_data, hdrs, &status);

    if (status == 429) return false;
    if (status != 200 || response.empty()) return false;

    auto plain = aes_decrypt_response(response);
    if (plain.empty()) return false;

    auto inner = ProtoBuilder::decode_envelope(plain);
    if (inner.type != VG_HB_RESP) return false;

    auto hb_resp = ProtoBuilder::decode_heartbeat_response(inner.payload);
    g_session.last_hb_timestamp = hb_resp.timestamp;
    g_session.aes.rotate_iv();

    bool had_tasks = false;
    {
        std::lock_guard<std::mutex> lock(g_module_mutex);
        g_pending_modules.clear();
        for (auto& task_str : hb_resp.active_task_strings) {
            CdnModule mod;
            mod.id = task_str;
            mod.cdn_url = "/" + task_str;
            mod.valid = true;
            g_pending_modules.push_back(mod);
            had_tasks = true;
        }
    }

    if (had_tasks) g_has_task = true;
    return true;
}

bool do_gateway_full_auth(const std::string& jwt, const std::string& puuid, const std::string& session_state) {
    for (int attempt = 0; attempt < 3; ++attempt) {
        if (attempt > 0) std::this_thread::sleep_for(std::chrono::seconds(3));

        init_session();
        printf("[gateway] Auth attempt %d/3...\n", attempt + 1);

        if (!do_auth_handshake(jwt, puuid, session_state))
        {
            printf("[gateway] Auth handshake failed on attempt %d\n", attempt + 1);
            continue;
        }
        printf("[gateway] Auth handshake OK\n");

        if (!do_access_request())
        {
            printf("[gateway] Access request failed on attempt %d\n", attempt + 1);
            continue;
        }
        printf("[gateway] Access request OK\n");

        g_session.auth_count_since_region_switch++;
        if (g_session.auth_count_since_region_switch >= 4) {
            g_session.auth_count_since_region_switch = 0;
            rotate_region();
        }
        return true;
    }
    g_active = false;
    printf("[gateway] Full auth failed after 3 attempts\n");
    return false;
}

bool fetch_modules() {
    std::lock_guard<std::mutex> lock(g_module_mutex);
    return !g_pending_modules.empty();
}

bool submit_task_result(uint32_t task_id, const std::vector<uint8_t>& result_data) {
    if (!g_session.authenticated || g_session.access_token.empty()) return false;

    VgTaskResult tr;
    tr.id = task_id;
    tr.data = result_data;
    tr.status = 1;

    VgTaskResultRequest req;
    req.access_token = g_session.access_token;
    req.results.push_back(tr);

    auto task_payload = ProtoBuilder::encode_task_result_request(req);

    VgEnvelope result_env;
    result_env.type = VG_TASK_RESULT;
    result_env.payload = task_payload;
    auto encrypted = aes_encrypt_envelope(result_env);
    if (encrypted.empty()) return false;

    auto response = send_envelope(VG_TASK_RESULT, encrypted);
    return !response.empty();
}

bool send_disconnect() {
    if (!g_session.authenticated || g_session.access_token.empty()) return false;

    VgDisconnectRequest disc_req;
    disc_req.access_token = g_session.access_token;
    auto disc_payload = ProtoBuilder::encode_disconnect_request(disc_req);

    VgEnvelope disc_env;
    disc_env.type = VG_DISCONNECT;
    disc_env.payload = disc_payload;
    auto encrypted = aes_encrypt_envelope(disc_env);
    if (encrypted.empty()) return false;

    auto response = send_envelope(VG_DISCONNECT, encrypted);
    return !response.empty();
}

}
