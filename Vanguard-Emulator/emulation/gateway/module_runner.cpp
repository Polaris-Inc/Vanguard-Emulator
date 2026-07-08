#include "module_runner.hpp"
#include "gateway_client.hpp"
#include <windows.h>
#include <vector>
#include <string>
#include <cstdio>
#include <fstream>

#pragma comment(lib, "urlmon.lib")

namespace ModuleRunner {

static std::string get_temp_path_for_module(const std::string& module_id) {
    char temp_path[MAX_PATH];
    if (!GetTempPathA(MAX_PATH, temp_path)) temp_path[0] = 0;
    std::string path(temp_path);
    path += "vg_module_";
    for (char c : module_id) {
        if (c == '/' || c == '\\' || c == ':') path += '_';
        else path += c;
    }
    path += ".dll";
    return path;
}

bool download_module(ModuleTask& task, const std::string& region) {
    if (task.cdn_url.empty()) return false;

    std::string url = "https://" + region + ".vg.ac.pvp.net:8443/vanguard" + task.cdn_url;
    std::string dest = get_temp_path_for_module(task.id);

    HRESULT hr = URLDownloadToFileA(nullptr, url.c_str(), dest.c_str(), 0, nullptr);
    if (FAILED(hr)) return false;

    std::ifstream file(dest, std::ios::binary | std::ios::ate);
    if (!file.good()) return false;

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    task.module_data.resize((size_t)size);
    if (!file.read((char*)task.module_data.data(), size)) {
        task.module_data.clear();
        return false;
    }
    task.downloaded = true;
    return true;
}

bool execute_module(const ModuleTask& task, std::vector<uint8_t>& result) {
    if (!task.downloaded || task.module_data.empty()) return false;

    std::string dll_path = get_temp_path_for_module(task.id);
    HMODULE hMod = LoadLibraryA(dll_path.c_str());
    if (!hMod) return false;

    typedef int (__cdecl* VgModuleEntry)(const uint8_t* input, size_t input_size, uint8_t** output, size_t* output_size);
    VgModuleEntry entry = (VgModuleEntry)GetProcAddress(hMod, "VgModuleEntry");
    if (!entry) {
        FreeLibrary(hMod);
        return false;
    }

    uint8_t* out_buf = nullptr;
    size_t out_sz = 0;
    int ret = entry(nullptr, 0, &out_buf, &out_sz);

    if (ret == 0 && out_buf && out_sz > 0) {
        result.assign(out_buf, out_buf + out_sz);
    }

    if (out_buf) {
        typedef void (__cdecl* VgModuleFree)(uint8_t*);
        VgModuleFree free_fn = (VgModuleFree)GetProcAddress(hMod, "VgModuleFree");
        if (free_fn) free_fn(out_buf);
    }

    FreeLibrary(hMod);
    return ret == 0 && !result.empty();
}

bool run_task(const std::string& module_id, const std::string& cdn_url, const std::string& region, std::vector<uint8_t>& result) {
    ModuleTask task;
    task.id = module_id;
    task.cdn_url = cdn_url;
    task.region = region;

    if (!download_module(task, region)) return false;
    if (!execute_module(task, result)) return false;
    return true;
}

void cleanup_temp_modules() {
    char temp_path[MAX_PATH];
    if (!GetTempPathA(MAX_PATH, temp_path)) return;
    std::string pattern(temp_path);
    pattern += "vg_module_*.dll";
    WIN32_FIND_DATAA find_data;
    HANDLE hFind = FindFirstFileA(pattern.c_str(), &find_data);
    if (hFind == INVALID_HANDLE_VALUE) return;
    do {
        std::string full_path(temp_path);
        full_path += find_data.cFileName;
        DeleteFileA(full_path.c_str());
    } while (FindNextFileA(hFind, &find_data));
    FindClose(hFind);
}

}
