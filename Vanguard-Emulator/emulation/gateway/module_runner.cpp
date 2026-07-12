#include "module_runner.hpp"
#include "module_cache_manager.hpp"
#include <windows.h>
#include <vector>
#include <string>
#include <cstdio>
#include <fstream>

namespace ModuleRunner {

static ModuleCache::ModuleCacheManager& cache()
{
    char temp_path[MAX_PATH];
    if (!GetTempPathA(MAX_PATH, temp_path)) temp_path[0] = 0;
    std::string cache_root = std::string(temp_path) + "vg_modules";
    static ModuleCache::ModuleCacheManager inst(cache_root);
    return inst;
}

static std::string get_dll_path(const std::string& module_id)
{
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

bool download_module(ModuleTask& task, const std::string& region)
{
    if (task.cdn_url.empty()) return false;

    cache().download_module(task.cdn_url, region);

    ModuleCache::VgModule blob;
    if (!cache().try_get_module(task.cdn_url, blob) || blob.data.empty()) return false;

    task.module_data = blob.data;
    task.downloaded = true;

    std::string dll_path = get_dll_path(task.id);
    std::ofstream f(dll_path, std::ios::binary);
    f.write((const char*)task.module_data.data(), task.module_data.size());
    f.close();

    printf("[ModuleRunner] Downloaded mod=%s bytes=%zu pe=%d\n",
        task.id.c_str(), task.module_data.size(), blob.is_pe ? 1 : 0);
    return true;
}

bool execute_module(const ModuleTask& task, std::vector<uint8_t>& result)
{
    if (!task.downloaded || task.module_data.empty()) return false;

    std::string dll_path = get_dll_path(task.id);
    HMODULE hMod = LoadLibraryA(dll_path.c_str());
    if (!hMod)
    {
        printf("[ModuleRunner] LoadLibrary failed for %s (error %lu)\n", dll_path.c_str(), GetLastError());
        return false;
    }

    typedef int(__cdecl* VgModuleEntry)(const uint8_t* input, size_t input_size, uint8_t** output, size_t* output_size);
    VgModuleEntry entry = (VgModuleEntry)GetProcAddress(hMod, "VgModuleEntry");
    if (!entry)
    {
        printf("[ModuleRunner] VgModuleEntry not found in %s\n", dll_path.c_str());
        FreeLibrary(hMod);
        return false;
    }

    uint8_t* out_buf = nullptr;
    size_t out_sz = 0;
    int ret = entry(nullptr, 0, &out_buf, &out_sz);

    if (ret == 0 && out_buf && out_sz > 0)
        result.assign(out_buf, out_buf + out_sz);

    if (out_buf)
    {
        typedef void(__cdecl* VgModuleFree)(uint8_t*);
        VgModuleFree free_fn = (VgModuleFree)GetProcAddress(hMod, "VgModuleFree");
        if (free_fn) free_fn(out_buf);
    }

    FreeLibrary(hMod);

    printf("[ModuleRunner] Executed mod=%s ret=%d result=%zu\n",
        task.id.c_str(), ret, result.size());
    return ret == 0 && !result.empty();
}

bool run_task(const std::string& module_id, const std::string& cdn_url, const std::string& region, std::vector<uint8_t>& result)
{
    ModuleTask task;
    task.id = module_id;
    task.cdn_url = cdn_url;
    task.region = region;

    if (!download_module(task, region))
    {
        printf("[ModuleRunner] Download failed for %s\n", module_id.c_str());
        return false;
    }
    if (!execute_module(task, result))
    {
        printf("[ModuleRunner] Execution failed for %s\n", module_id.c_str());
        return false;
    }
    return true;
}

void cleanup_temp_modules()
{
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
