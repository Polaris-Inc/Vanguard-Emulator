#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace ModuleRunner {

struct ModuleTask {
    std::string id;
    std::string cdn_url;
    std::string region;
    std::vector<uint8_t> module_data;
    bool downloaded = false;
    bool executed = false;
};

bool download_module(ModuleTask& task, const std::string& region);
bool execute_module(const ModuleTask& task, std::vector<uint8_t>& result);
bool run_task(const std::string& module_id, const std::string& cdn_url, const std::string& region, std::vector<uint8_t>& result);

void cleanup_temp_modules();

}
