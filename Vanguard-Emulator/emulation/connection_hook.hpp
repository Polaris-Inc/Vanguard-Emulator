#pragma once

#include <string_view>
#include "emulation/gateway/gateway_client.hpp"
#include "emulation/gateway/module_runner.hpp"

bool PipeExists()
{
    return WaitNamedPipeW(PIPE_NAME, 0);
}

template <typename T>
static inline void append_bytes(std::vector<unsigned char>& out, const T& value)
{
    const unsigned char* begin = reinterpret_cast<const unsigned char*>(&value);
    out.insert(out.end(), begin, begin + sizeof(T));
}

class TimestampGenerator
{
public:
    struct Config
    {
        int64_t jitter_ms = 50;
        bool use_monotonic = false;
    };

public:
    explicit TimestampGenerator(Config cfg = {})
        : config(cfg),
        rng(std::random_device{}()),
        dist(-cfg.jitter_ms, cfg.jitter_ms)
    {
    }

    uint64_t now()
    {
        uint64_t base = get_base_time();
        int64_t jitter = dist(rng);

        return safe_add(base, jitter);
    }

private:
    Config config;
    std::mt19937_64 rng;
    std::uniform_int_distribution<int64_t> dist;

private:
    uint64_t get_base_time()
    {
        using namespace std::chrono;

        if (config.use_monotonic)
        {
            return duration_cast<milliseconds>(
                steady_clock::now().time_since_epoch()
            ).count();
        }

        return duration_cast<milliseconds>(
            system_clock::now().time_since_epoch()
        ).count();
    }

    static uint64_t safe_add(uint64_t base, int64_t delta)
    {
        if (delta < 0)
        {
            uint64_t abs_delta = static_cast<uint64_t>(-delta);
            return (base > abs_delta) ? (base - abs_delta) : 0;
        }

        return base + static_cast<uint64_t>(delta);
    }
};

uint64_t get_realistic_timestamp()
{
    static TimestampGenerator gen({ .jitter_ms = 50 });
    return gen.now();
}

std::vector<uint8_t> create_auth_packet(
    uint32_t magic,
    AuthVersion version,
    const uint8_t* uuid_bin)
{
    std::vector<uint8_t> out;
    VanguardHeader hdr{};

    hdr.vMagic = magic + 1;
    hdr.vMessageType = MessageType::Heartbeat;

    auto append = [&](const auto& v)
        {
            const uint8_t* p = reinterpret_cast<const uint8_t*>(&v);
            out.insert(out.end(), p, p + sizeof(v));
        };

    switch (version)
    {
    case AuthVersion::V1:
    {
        hdr.vTotalSize = 40 + 8;
        hdr.vPayloadSize = 8;

        append(hdr);
        out.insert(out.end(), 8, 0);
        break;
    }

    case AuthVersion::V2:
    {
        hdr.vTotalSize = 40 + 8;
        hdr.vPayloadSize = 8;

        append(hdr);
        out.insert(out.end(), uuid_bin, uuid_bin + 8);
        break;
    }

    case AuthVersion::V3:
    {
        hdr.vTotalSize = 40 + 16;
        hdr.vPayloadSize = 16;

        append(hdr);
        out.insert(out.end(), uuid_bin, uuid_bin + 16);
        break;
    }

    case AuthVersion::V4:
    {
        hdr.vTotalSize = 40 + 8;
        hdr.vPayloadSize = 8;

        append(hdr);

        uint64_t ts = get_realistic_timestamp();
        append(ts);
        break;
    }

    case AuthVersion::V5:
    {
        hdr.vTotalSize = 40 + 16 + 8;
        hdr.vPayloadSize = 24;

        append(hdr);
        out.insert(out.end(), uuid_bin, uuid_bin + 16);

        uint64_t ts = get_realistic_timestamp();
        append(ts);
        break;
    }
    }

    return out;
}

std::vector<unsigned char> create_server_ack(unsigned int magic)
{
    std::vector<unsigned char> out;
    out.reserve(sizeof(VanguardHeader) + 8);

    VanguardHeader header{};
    header.vMagic = magic + 1;
    header.vTotalSize = sizeof(VanguardHeader) + 8;
    header.vMessageType = MessageType::ServerAck;
    header.vPayloadSize = 8;

    append_bytes(out, header);

    unsigned long long padding = 0;
    append_bytes(out, padding);

    return out;
}

/*std::vector<uint8_t> create_server_ack(uint32_t magic)
{
    PacketBuilder b;

    VanguardHeader header{};
    header.vMagic = magic + 1;
    header.vTotalSize = sizeof(VanguardHeader) + 8;
    header.vMessageType = MessageType::ServerAck;
    header.vPayloadSize = 8;

    b.write(header);

    uint64_t zero = 0;
    b.write(zero);

    return std::move(b.data);
}*/

/*std::vector<unsigned char> create_server_ack(uint32_t magic)
{
    std::vector<unsigned char> resp;
    VanguardHeader vanguard_header = { 0 };

    vanguard_header.vMagic = magic + 1;
    vanguard_header.vTotalSize = 40;
    vanguard_header.vMessageType = MessageType::Heartbeat;
    vanguard_header.vPayloadSize = 8;

    resp.insert(resp.end(), reinterpret_cast<unsigned char*>(&vanguard_header), reinterpret_cast<unsigned char*>(&vanguard_header) + sizeof(vanguard_header));
    resp.insert(resp.end(), 8, 0);

    return resp;
}*/

std::vector<unsigned char> create_heartbeat_response(const unsigned char* data, unsigned __int64 size)
{
    return { data, data + size };
}

static inline unsigned char hex_to_byte(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

static inline unsigned char parse_byte(char hi, char lo)
{
    return (hex_to_byte(hi) << 4) | hex_to_byte(lo);
}

void uuid_string_to_binary(const char* str, unsigned char* out)
{
    int i = 0;

    auto read = [&](int& idx) -> unsigned char
        {
            while (str[idx] == '-') idx++;
            unsigned char b = parse_byte(str[idx], str[idx + 1]);
            idx += 2;
            return b;
        };

    int idx = 0;

    for (int i = 0; i < 16; i++)
        out[i] = read(idx);
}

bool find_last_uuid(const unsigned char* data,
    unsigned __int64 size,
    unsigned char* uuid_bin,
    char* uuid_str)
{
    constexpr unsigned __int64 UUID_LEN = 36;

    std::string_view text(reinterpret_cast<const char*>(data), size);

    std::string_view last_match;

    for (unsigned __int64 i = 0; i + UUID_LEN <= text.size(); i++)
    {
        auto slice = text.substr(i, UUID_LEN);

        if (slice[8] != '-' ||
            slice[13] != '-' ||
            slice[18] != '-' ||
            slice[23] != '-')
            continue;

        bool valid = true;

        for (char c : slice)
        {
            if (c == '-') continue;
            if (!std::isxdigit(static_cast<unsigned char>(c)))
            {
                valid = false;
                break;
            }
        }

        if (valid)
            last_match = slice;
    }

    if (last_match.empty())
        return false;

    std::memcpy(uuid_str, last_match.data(), UUID_LEN);
    uuid_str[36] = '\0';

    uuid_string_to_binary(uuid_str, uuid_bin);

    return true;
}

static bool is_jwt_char(char c)
{
    return std::isalnum((unsigned char)c) ||
        c == '.' || c == '_' || c == '-' || c == '=';
}

std::string find_longest_jwt(const unsigned char* data, unsigned __int64 size)
{
    std::string_view sv(reinterpret_cast<const char*>(data), size);

    std::string best;
    std::string current;

    for (char c : sv)
    {
        if (is_jwt_char(c))
        {
            current += c;
        }
        else
        {
            if (current.rfind("eyJ", 0) == 0)
            {
                if (current.size() > best.size())
                    best = current;
            }
            current.clear();
        }
    }

    if (current.rfind("eyJ", 0) == 0 && current.size() > best.size())
        best = current;

    return best;
}

void handle_connection(HANDLE connection)
{
    vanguard::current_connection.store(connection);
    std::vector<unsigned char> buffer(16384);
    unsigned long bytesRead;

    unsigned char uuid_bin[16] = { 0 };
    char uuid_str[37] = { 0 };
    bool gateway_auth_started = false;

    while (g_Running.load())
    {
        if (!ReadFile(connection, buffer.data(), buffer.size(), &bytesRead, NULL) || bytesRead == 0)
            break;

        VanguardHeader* vanguard_header = reinterpret_cast<VanguardHeader*>(buffer.data());
        std::vector<unsigned char> response;

        switch (vanguard_header->vMessageType)
        {
        case MessageType::Heartbeat:
        {
            response = create_heartbeat_response(buffer.data(), bytesRead);

            if (GatewayClient::has_task_module())
            {
                auto modules = GatewayClient::get_pending_tasks();
                for (auto& mod : modules)
                {
                    if (!mod.valid) continue;
                    console::debug("Gateway task: " + mod.id);
                    std::vector<uint8_t> result;
                    if (ModuleRunner::run_task(mod.id, mod.cdn_url, vanguard::region, result))
                    {
                        console::debug("Module executed: " + mod.id + " (" + std::to_string(result.size()) + " bytes)");
                        GatewayClient::submit_task_result(0, result);
                    }
                    else
                        console::debug("Module execution failed: " + mod.id + " (expected for test)");
                }
            }
            break;
        }
        case MessageType::ServerAck:
        {
            response = create_server_ack(vanguard_header->vMagic);
            break;
        }
        case MessageType::AuthRequest:
        {
            vanguard::game_token = find_longest_jwt(buffer.data(), bytesRead);
            bool has_jwt = !vanguard::game_token.empty();
            bool uuid_found = find_last_uuid(buffer.data(), bytesRead, uuid_bin, uuid_str);

            if (uuid_found)
            {
                vanguard::sid = uuid_str;
                vanguard::g_SessionReady.store(has_jwt);
                response = create_auth_packet(vanguard_header->vMagic, AuthVersion::V5, uuid_bin);
            }
            else
            {
                vanguard::g_SessionReady.store(false);
                response = create_auth_packet(vanguard_header->vMagic, AuthVersion::V1, uuid_bin);
            }

            vanguard::extracted_token = vanguard::game_token;
            console::debug(Encrypt("Token Request handled"));

            if (!gateway_auth_started)
            {
                gateway_auth_started = true;
                vanguard::region = riotgames::normalize_region(riotgames::get_region());
                console::debug("SID: " + vanguard::sid);
                console::debug("Game Token: " + vanguard::game_token.substr(0, 20) + "...");
                console::debug("Region: " + vanguard::region);

                std::thread([]
                {
                    console::info(Encrypt("Authenticating session (immediate)..."));
                    bool ok = false;
                    for (int i = 0; i < 3 && !ok; i++)
                    {
                        if (i > 0)
                        {
                            console::info(Encrypt("Retrying gateway auth (attempt ") + std::to_string(i + 1) + Encrypt("/3)..."));
                            Sleep(3000);
                        }
                        ok = session::authenticate_session_auto();
                    }
                    vanguard::g_GatewaySuccess.store(ok);
                    if (ok)
                    {
                        console::info(Encrypt("Gateway authentication succeeded (200 OK)"));
                        vanguard::g_authenticated_once.store(true);
                        vanguard::g_session_start_time = std::chrono::steady_clock::now();
                        vanguard::g_auth_counter++;
                        if (vanguard::g_auth_counter >= 4)
                        {
                            vanguard::g_auth_counter = 0;
                            std::string old_region = vanguard::region;
                            if (old_region == "ap") vanguard::region = "eu";
                            else if (old_region == "eu") vanguard::region = "ap";
                            else if (old_region == "na") vanguard::region = "la";
                            else if (old_region == "la") vanguard::region = "na";
                            console::info(Encrypt("Region rotated: ") + old_region + Encrypt(" -> ") + vanguard::region);
                        }
                    }
                    else
                        console::critical(Encrypt("Gateway authentication failed after 3 attempts"));

                    console::info(Encrypt("Refreshing session ticket..."));
                    std::string sid = vanguard::g_session_id.empty() ? vanguard::sid : vanguard::g_session_id;
                    std::vector<uint8_t> ticket = session::refresh_get_ticket(sid, vanguard::extracted_token, vanguard::sid);
                    if (!ticket.empty())
                    {
                        {
                            std::lock_guard<std::mutex> lock(vanguard::g_ticket_mtx);
                            vanguard::g_pending_ticket = std::move(ticket);
                        }
                        console::info(Encrypt("Refresh: ticket stored, will inject on next heartbeat"));
                    }
                    else
                        console::critical(Encrypt("Refresh: failed to get ticket"));

                    console::info(Encrypt("Initializing gateway client (A/B)..."));
                    GatewayClient::init_session();
                    bool gw_ok = GatewayClient::do_gateway_full_auth(
                        vanguard::extracted_token,
                        vanguard::sid,
                        vanguard::region
                    );
                    if (gw_ok)
                    {
                        console::info(Encrypt("Gateway client initialized"));
                        vanguard::g_gateway_hb_active.store(true);
                        std::thread([]()
                        {
                            while (g_Running.load() && vanguard::g_gateway_hb_active.load() && GatewayClient::is_gateway_active())
                            {
                                GatewayClient::do_heartbeat();
                                std::this_thread::sleep_for(std::chrono::seconds(300));
                            }
                        }).detach();
                    }
                    else
                        console::critical(Encrypt("Gateway client init failed"));
                }).detach();


            }
            break;
        }
        default:
        {
            response = create_heartbeat_response(buffer.data(), bytesRead);
            break;
        }
        }

        if (!response.empty()) 
        {
            DWORD written;
            WriteFile(connection, response.data(), (DWORD)response.size(), &written, NULL);
        }

        Sleep(10);
    }

    CloseHandle(connection);
    vanguard::current_connection.store(nullptr);

    console::info(Encrypt("Sending gateway disconnect..."));
    GatewayClient::send_disconnect();
    GatewayClient::shutdown_session();

    console::info(Encrypt("Game disconnected, restarting VGC and waiting for reconnect..."));

    system(Encrypt("sc stop vgc >nul 2>&1"));
    Sleep(500);
    system(Encrypt("sc start vgc >nul 2>&1"));
    Sleep(500);

    HANDLE testPipe = CreateFileW(PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (testPipe != INVALID_HANDLE_VALUE)
    {
        CloseHandle(testPipe);
        console::info(Encrypt("Pipe is available, waiting for game to connect..."));
    }

    vanguard::g_SessionReady.store(false);
}

namespace connection
{

    void create_connection()
    {
        static bool first_run = true;
        static bool last_connected_state = false;

        while (g_Running.load())
        {
            HANDLE connection = CreateNamedPipeW(PIPE_NAME, PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                1, 1048576, 1048576, 500, NULL);

            bool connected = (connection != INVALID_HANDLE_VALUE);

            if (first_run || connected != last_connected_state)
            {
                first_run = false;

                if (connected)
                {
                    console::debug(Encrypt("Vanguard connection exists and is connectable."));
                }
                else
                {
                    DWORD error = GetLastError();

                    if (error == ERROR_FILE_NOT_FOUND)
                    {
                        console::critical(Encrypt("Vanguard connection does not exist, please ensure that Vanguard is running."));
                    }
                    else if (error == ERROR_PIPE_BUSY)
                    {
                        console::critical(Encrypt("Vanguard connection exists but is busy, please ensure that Vanguard is running and not busy."));
                    }
                    else
                    {
                        console::critical(
                            Encrypt("Failed to create connection, error code: ") +
                            std::to_string(error)
                        );
                    }
                }

                last_connected_state = connected;
            }

            if (connected)
            {
                if (ConnectNamedPipe(connection, NULL) ||
                    GetLastError() == ERROR_PIPE_CONNECTED)
                {
                    std::thread(handle_connection, connection).detach();
                }
                else
                {
                    CloseHandle(connection);
                }
            }
        }
    }
}