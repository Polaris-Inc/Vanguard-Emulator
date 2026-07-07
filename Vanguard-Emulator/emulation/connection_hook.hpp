#pragma once

#include <string_view>

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

    bool first_message = true;
    bool gateway_auth_started = false;
    std::vector<unsigned char> last_magic_4_response;

    while (g_Running.load())
    {
        if (!ReadFile(connection, buffer.data(), buffer.size(), &bytesRead, NULL) || bytesRead == 0)
            break;

        VanguardHeader* hdr = reinterpret_cast<VanguardHeader*>(buffer.data());
        std::vector<unsigned char> response;

        std::string jwt = find_longest_jwt(buffer.data(), bytesRead);
        bool has_jwt = !jwt.empty();

        if (first_message)
        {
            response.assign(buffer.data(), buffer.data() + bytesRead);
            first_message = false;
            console::debug(Encrypt("Access Request echoed back (") + std::to_string(bytesRead) + Encrypt(" bytes)"));
        }
        else if (has_jwt)
        {
            vanguard::game_token = jwt;

            unsigned char tuuid_bin[16] = { 0 };
            char tuuid_str[37] = { 0 };
            if (find_last_uuid(buffer.data(), bytesRead, tuuid_bin, tuuid_str))
            {
                vanguard::sid = tuuid_str;
            }

            vanguard::extracted_token = jwt;
            vanguard::g_SessionReady.store(true);

            response.assign(buffer.data(), buffer.data() + bytesRead);

            console::debug(Encrypt("Token Request echoed back"));

            if (!gateway_auth_started)
            {
                gateway_auth_started = true;

                vanguard::region = riotgames::normalize_region(riotgames::get_region());
                console::debug("SID: " + vanguard::sid);
                console::debug("Game Token: " + vanguard::game_token.substr(0, 20) + "...");
                console::debug("Region: " + vanguard::region);

                if (!vanguard::g_authenticated_once.load())
                {
                    std::thread([]()
                    {
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
                        vanguard::g_authenticated_once.store(ok);
                        if (ok)
                            console::info(Encrypt("Gateway authentication succeeded (200 OK)"));
                        else
                            console::critical(Encrypt("Gateway authentication failed after 3 attempts"));
                    }).detach();
                }
                else
                {
                    console::info(Encrypt("Already authenticated in a previous session, skipping re-auth"));
                }

                if (!vanguard::g_auto_refresh_started.exchange(true))
                {
                    std::thread([]()
                    {
                        while (g_Running.load())
                        {
                            std::this_thread::sleep_for(std::chrono::minutes(5));

                            if (!g_Running.load()) break;
                            if (!vanguard::g_SessionReady.load())
                            {
                                console::debug(Encrypt("Game not connected, skipping refresh cycle"));
                                continue;
                            }

                            console::info(Encrypt("Auto-refreshing session ticket..."));

                            std::string sid = vanguard::g_session_id.empty() ? vanguard::sid : vanguard::g_session_id;

                            std::vector<uint8_t> ticket = session::refresh_get_ticket(
                                sid,
                                vanguard::extracted_token,
                                vanguard::sid
                            );

                            if (!ticket.empty())
                            {
                                {
                                    std::lock_guard<std::mutex> lock(vanguard::g_ticket_mtx);
                                    vanguard::g_pending_ticket = std::move(ticket);
                                }
                                console::info(Encrypt("Auto-refresh: ticket stored, will inject on next heartbeat"));
                            }
                            else
                            {
                                console::critical(Encrypt("Auto-refresh: failed to get ticket"));
                            }
                        }
                    }).detach();
                }
            }
        }
        else if (hdr->vMagic == 3)
        {
            bool ticket_injected = false;

            {
                std::lock_guard<std::mutex> lock(vanguard::g_ticket_mtx);
                if (!vanguard::g_pending_ticket.empty())
                {
                    uint32_t ticketLen = (uint32_t)vanguard::g_pending_ticket.size();
                    uint32_t packetLen = 36 + ticketLen;

                    PacketBuilder pb;
                    pb.write<uint32_t>(0x000003E9);
                    pb.write<uint32_t>(packetLen);
                    pb.write<uint32_t>(1);
                    pb.write<uint32_t>(0);
                    pb.write<uint32_t>(0);
                    pb.write<uint32_t>(0);
                    pb.write<uint32_t>(ticketLen);
                    pb.write<uint32_t>(0);
                    pb.write<uint32_t>(0);
                    pb.write_bytes(vanguard::g_pending_ticket.data(), ticketLen);

                    response = std::move(pb.data);
                    vanguard::g_pending_ticket.clear();
                    last_magic_4_response = response;
                    ticket_injected = true;
                    console::info(Encrypt("Injected refresh ticket (") + std::to_string(ticketLen) + Encrypt(" bytes)"));
                }
            }

            if (!ticket_injected)
            {
                if (vanguard::g_GatewaySuccess.load() && !vanguard::g_Sent0x3E9.load())
                {
                    const uint8_t magic_0x3E9_packet[] = {
                        0xE9, 0x03, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00,
                        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00
                    };
                    response.assign(magic_0x3E9_packet, magic_0x3E9_packet + sizeof(magic_0x3E9_packet));
                    vanguard::g_Sent0x3E9.store(true);
                    last_magic_4_response = response;
                    console::debug(Encrypt("Sent one-time 0x3E9 packet (gateway OK)"));
                }
                else
                {
                    response.assign(buffer.data(), buffer.data() + bytesRead);
                    if (response.size() >= sizeof(uint32_t))
                        *reinterpret_cast<uint32_t*>(response.data()) = 4;
                    last_magic_4_response = response;
                    console::debug(Encrypt("Sent heartbeat pong"));
                }
            }
        }
        else
        {
            if (!last_magic_4_response.empty())
            {
                response = last_magic_4_response;
                console::debug(Encrypt("Match start / other message - sent last pong"));
            }
            else
            {
                response.assign(buffer.data(), buffer.data() + bytesRead);
            }
        }

        if (!response.empty()) 
        {
            DWORD written;
            WriteFile(connection, response.data(), response.size(), &written, NULL);
        }

        Sleep(10);
    }

    CloseHandle(connection);
    vanguard::current_connection.store(nullptr);

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