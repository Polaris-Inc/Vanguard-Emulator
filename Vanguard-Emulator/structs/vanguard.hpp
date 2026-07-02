#pragma once

enum class MessageType : uint32_t
{
    Heartbeat = 1,
    ServerAck = 2,
    AuthAck = 3,
    AuthRequest = 4,
    AuthExtended = 5,
    Unknown = 0
};

enum class AuthVersion : int
{
    V1 = 1,
    V2,
    V3,
    V4,
    V5
};

struct PacketBuilder
{
    std::vector<uint8_t> data;

    template <typename T>
    void write(const T& value)
    {
        const uint8_t* p = reinterpret_cast<const uint8_t*>(&value);
        data.insert(data.end(), p, p + sizeof(T));
    }

    void write_bytes(const uint8_t* p, size_t size)
    {
        data.insert(data.end(), p, p + size);
    }
};

struct VanguardHeader 
{
    uint32_t    vMagic;
    uint32_t    vTotalSize;
    MessageType vMessageType;
    uint8_t     unknown1[12];
    uint32_t    vPayloadSize;
    uint8_t     unknown2[8];
};

namespace vanguard
{
	std::atomic<HANDLE> current_connection(nullptr);

    std::atomic<bool> g_SessionReady(false);

	std::string sid = "";
	std::string game_token = "";
	std::string region = "";
}