#include "riot_utils.hpp"
#include <windows.h>
#include <winsvc.h>
#include <tlhelp32.h>
#include <regex>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#pragma comment(lib, "advapi32.lib")

namespace RiotUtils {

static bool _emu_is_service_running(const wchar_t* name) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;
    SC_HANDLE svc = OpenServiceW(scm, name, SERVICE_QUERY_STATUS);
    if (!svc) { CloseServiceHandle(scm); return false; }
    SERVICE_STATUS_PROCESS ssp{}; DWORD need = 0;
    BOOL ok = QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO,
        reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &need);
    CloseServiceHandle(svc); CloseServiceHandle(scm);
    return ok && (ssp.dwCurrentState == SERVICE_RUNNING ||
                  ssp.dwCurrentState == SERVICE_START_PENDING);
}

std::string emu_patch_config_json(const std::string& body) {
    std::string r = body;
    auto patch_bool = [&](const char* key, bool v) {
        std::regex re(std::string("(\"") + key + "\"\\s*:\\s*)(true|false)");
        r = std::regex_replace(r, re, std::string("$1") + (v ? "true" : "false"));
    };
    auto patch_str = [&](const char* key, const char* v) {
        std::regex re(std::string("(\"") + key + "\"\\s*:\\s*)\"[^\"]*\"");
        r = std::regex_replace(r, re, std::string("$1\"") + v + "\"");
    };
    patch_bool("anticheat.vanguard.backgroundInstall",                      false);
    patch_bool("anticheat.vanguard.enabled",                                false);
    patch_bool("keystone.client.feature_flags.restart_required.disabled",   true);
    patch_bool("keystone.client.feature_flags.vanguardLaunch.disabled",     true);
    patch_bool("keystone.client.feature_flags.vanguard_attestation.enabled",false);
    patch_bool("lol.client_settings.vanguard.enabled",                      false);
    patch_bool("lol.client_settings.vanguard.enabled_embedded",             false);
    patch_str ("lol.client_settings.vanguard.url",                          "");
    patch_bool("lion.vanguard.required",                                    false);
    patch_bool("lion.vanguard.netrequired",                                 false);
    static const std::regex dep_re(R"(\{\s*[^}]*"id"\s*:\s*"vanguard"[^}]*\},?\s*)");
    r = std::regex_replace(r, dep_re, "");
    return r;
}

std::string emu_riot_get_client_path() {
    char pd[MAX_PATH] = {};
    if (!GetEnvironmentVariableA("PROGRAMDATA", pd, MAX_PATH)) strcpy_s(pd, "C:\\ProgramData");
    std::string installJson = std::string(pd) + "\\Riot Games\\RiotClientInstalls.json";
    std::ifstream f(installJson, std::ios::binary);
    if (!f.is_open()) return {};
    std::string content((std::istreambuf_iterator<char>(f)), {});
    for (const char* key : {"rc_default", "rc_live", "rc_beta"}) {
        std::string needle = std::string("\"") + key + "\"";
        size_t pos = content.find(needle);
        if (pos == std::string::npos) continue;
        size_t vs = content.find('"', pos + needle.size() + 1);
        if (vs == std::string::npos) continue; ++vs;
        size_t ve = content.find('"', vs);
        if (ve == std::string::npos) continue;
        std::string path = content.substr(vs, ve - vs);
        std::string clean;
        for (size_t i = 0; i < path.size(); ++i) {
            if (path[i] == '\\' && i + 1 < path.size() && path[i+1] == '\\') { clean += '\\'; ++i; }
            else clean += path[i];
        }
        if (!clean.empty() && GetFileAttributesA(clean.c_str()) != INVALID_FILE_ATTRIBUTES)
            return clean;
    }
    return {};
}

bool emu_riot_is_vanguard_installed() {
    char pf[MAX_PATH] = {};
    if (!GetEnvironmentVariableA("ProgramW6432", pf, MAX_PATH))
        GetEnvironmentVariableA("PROGRAMFILES", pf, MAX_PATH);
    if (!pf[0]) strcpy_s(pf, "C:\\Program Files");
    std::string vgkPath = std::string(pf) + "\\Riot Vanguard\\installer.exe";
    bool pathExists = GetFileAttributesA(vgkPath.c_str()) != INVALID_FILE_ATTRIBUTES;
    return pathExists || _emu_is_service_running(L"vgc") || _emu_is_service_running(L"vgk");
}

bool emu_riot_remove_vanguard() {
    char pf[MAX_PATH] = {};
    if (!GetEnvironmentVariableA("ProgramW6432", pf, MAX_PATH))
        GetEnvironmentVariableA("PROGRAMFILES", pf, MAX_PATH);
    if (!pf[0]) strcpy_s(pf, "C:\\Program Files");
    std::string vgkExe = std::string(pf) + "\\Riot Vanguard\\installer.exe";
    if (GetFileAttributesA(vgkExe.c_str()) == INVALID_FILE_ATTRIBUTES) {
        printf("[RIOT] Vanguard not installed\n"); return true;
    }
    std::wstring wexe(vgkExe.begin(), vgkExe.end());
    std::wstring cmd = L"\"" + wexe + L"\" --quiet";
    std::vector<wchar_t> cmdBuf(cmd.begin(), cmd.end()); cmdBuf.push_back(L'\0');
    STARTUPINFOW si{}; si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, cmdBuf.data(), nullptr, nullptr, FALSE,
            CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        printf("[RIOT] removeVanguard: CreateProcess failed\n"); return false;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    Sleep(5000);
    for (int i = 0; i < 30; ++i) {
        if (GetFileAttributesA(vgkExe.c_str()) == INVALID_FILE_ATTRIBUTES) {
            printf("[RIOT] Vanguard removed\n"); return true;
        }
        Sleep(1000);
    }
    printf("[RIOT] removeVanguard: installer still present after 30s\n");
    return false;
}

bool emu_riot_run_client(uint16_t config_port) {
    std::string clientPath = emu_riot_get_client_path();
    if (clientPath.empty()) { printf("[RIOT] Riot Client path not found\n"); return false; }
    std::wstring wpath(clientPath.begin(), clientPath.end());
    std::wstring cmd = L"\"" + wpath + L"\" --client-config-url=http://127.0.0.1:" +
                       std::to_wstring(config_port);
    std::vector<wchar_t> cmdBuf(cmd.begin(), cmd.end()); cmdBuf.push_back(L'\0');
    STARTUPINFOW si{}; si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, cmdBuf.data(), nullptr, nullptr, FALSE,
            CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        printf("[RIOT] runRiotClient: CreateProcess failed\n"); return false;
    }
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    printf("[RIOT] Riot Client started (config port %u)\n", config_port);
    return true;
}

void emu_riot_kill_services() {
    const wchar_t* names[] = {
        L"RiotClientServices.exe", L"RiotClient.exe",  L"LeagueClient.exe",
        L"League of Legends.exe",  L"VALORANT.exe",    L"RiotClientUx.exe",
        L"RiotClientCrashHandler.exe"
    };
    for (auto* name : names) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) continue;
        PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe)) {
            do {
                if (_wcsicmp(pe.szExeFile, name) == 0) {
                    HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                    if (hProc) { TerminateProcess(hProc, 0); CloseHandle(hProc); }
                }
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
    }
    printf("[RIOT] Riot services terminated\n");
}

}
