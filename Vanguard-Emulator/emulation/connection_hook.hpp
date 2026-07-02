#pragma once

#include <string_view>

const wchar_t* PIPE_NAME = L"\\\\.\\pipe\\933823D3-C77B-4BAE-89D7-A92B567236BC";

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

            const bool has_jwt = !vanguard::game_token.empty();

            const bool uuid_found = find_last_uuid(
                buffer.data(),
                bytesRead,
                uuid_bin,
                uuid_str
            );

            if (uuid_found)
            {
                vanguard::sid = uuid_str;

                vanguard::g_SessionReady.store(has_jwt);

                response = create_auth_packet(
                    vanguard_header->vMagic,
                    AuthVersion::V5,
                    uuid_bin
                );
            }
            else
            {
                vanguard::g_SessionReady.store(false);

                response = create_auth_packet(
                    vanguard_header->vMagic,
                    AuthVersion::V1,
                    uuid_bin
                );
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
            WriteFile(connection, response.data(), response.size(), &written, NULL);
        }

        Sleep(10);
    }

    CloseHandle(connection);
    vanguard::current_connection.store(nullptr);
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