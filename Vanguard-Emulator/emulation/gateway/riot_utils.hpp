#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace RiotUtils {

std::string emu_patch_config_json(const std::string& body);
std::string emu_riot_get_client_path();
bool emu_riot_is_vanguard_installed();
bool emu_riot_remove_vanguard();
bool emu_riot_run_client(uint16_t config_port);
void emu_riot_kill_services();

}
