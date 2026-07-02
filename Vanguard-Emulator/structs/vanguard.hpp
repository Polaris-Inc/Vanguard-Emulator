#pragma once

struct VanguardHeader 
{
    uint32_t magic;
    uint32_t total_size;
    uint32_t message_type;
    uint8_t  unknown1[12];
    uint32_t payload_size;
    uint8_t  unknown2[8];
};

namespace vanguard
{
	std::atomic<HANDLE> current_connection(nullptr);

	std::string sid = "";
	std::string game_token = "";
	std::string region = "";
}