#pragma once

#include <fstream>
#include <string>
#include <sstream>
#include <windows.h>
#include <winhttp.h>
#include <unordered_map>
#include <cstdlib>
#include <regex>

#pragma comment(lib, "winhttp.lib")

namespace riotgames
{
    std::string get_env(const char* name)
    {
        char* value = nullptr;
        size_t len = 0;

        if (_dupenv_s(&value, &len, name) == 0 && value)
        {
            std::string result(value);
            free(value);
            return result;
        }

        return {};
    }

    struct RiotLockfile
    {
        std::string name;
        int pid = 0;
        int port = 0;
        std::string password;
        std::string protocol;
    };

    RiotLockfile get_lockfile()
    {
        RiotLockfile lf;

        std::string appdata = get_env("LOCALAPPDATA");
        if (appdata.empty())
            return lf;

        std::ifstream file(
            appdata + "\\Riot Games\\Riot Client\\Config\\lockfile"
        );

        if (!file.is_open())
            return lf;

        std::string line;
        std::getline(file, line);

        if (line.empty())
            return lf;

        size_t p1 = line.find(':');
        size_t p2 = line.find(':', p1 + 1);
        size_t p3 = line.find(':', p2 + 1);
        size_t p4 = line.find(':', p3 + 1);

        lf.name = line.substr(0, p1);
        lf.pid = std::stoi(line.substr(p1 + 1, p2 - p1 - 1));
        lf.port = std::stoi(line.substr(p2 + 1, p3 - p2 - 1));
        lf.password = line.substr(p3 + 1, p4 - p3 - 1);
        lf.protocol = line.substr(p4 + 1);

        return lf;
    }

    std::string get_riot_userinfo()
    {
        RiotLockfile lf = get_lockfile();

        std::wstring host = L"127.0.0.1";
        int port = lf.port;

        std::wstring auth = L"riot:" + std::wstring(lf.password.begin(), lf.password.end());

        HINTERNET hSession = WinHttpOpen(L"RiotClient",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS, 0);

        HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), port, 0);

        HINTERNET hRequest = WinHttpOpenRequest(
            hConnect,
            L"GET",
            L"/rso-auth/v1/authorization/userinfo",
            NULL,
            WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE
        );

        std::wstring headers = L"Authorization: Basic " + auth;

        WinHttpSendRequest(hRequest,
            headers.c_str(),
            -1,
            WINHTTP_NO_REQUEST_DATA,
            0,
            0,
            0);

        WinHttpReceiveResponse(hRequest, NULL);

        DWORD size = 0;
        WinHttpQueryDataAvailable(hRequest, &size);

        std::string buffer(size, 0);
        DWORD read = 0;

        WinHttpReadData(hRequest, buffer.data(), size, &read);

        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);

        return buffer;
    }

    std::string get_region()
    {
        char localAppData[MAX_PATH] = { 0 };
        if (!GetEnvironmentVariableA("LOCALAPPDATA", localAppData, MAX_PATH))
            return "eu";

        std::string lockfilePath =
            std::string(localAppData) +
            "\\Riot Games\\Riot Client\\Config\\lockfile";

        DWORD attr = GetFileAttributesA(lockfilePath.c_str());
        if (attr == INVALID_FILE_ATTRIBUTES)
            return "eu";

        HANDLE hFile = CreateFileA(
            lockfilePath.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );

        if (hFile == INVALID_HANDLE_VALUE)
            return "eu";

        char buf[256] = { 0 };
        DWORD read = 0;
        ReadFile(hFile, buf, sizeof(buf), &read, NULL);
        CloseHandle(hFile);

        std::string lock(buf);
        std::vector<std::string> parts;
        std::stringstream ss(lock);
        std::string item;
        while (std::getline(ss, item, ':'))
            parts.push_back(item);

        if (parts.size() < 4)
            return "eu";

        int port = 0;
        try { port = std::stoi(parts[2]); }
        catch (...) { return "eu"; }

        std::string password = parts[3];
        std::string auth = "riot:" + password;

        std::string encoded;
        for (size_t i = 0; i < auth.size(); i += 3) {
            unsigned char b1 = auth[i];
            unsigned char b2 = (i + 1 < auth.size()) ? auth[i + 1] : 0;
            unsigned char b3 = (i + 2 < auth.size()) ? auth[i + 2] : 0;
            unsigned char c1 = b1 >> 2;
            unsigned char c2 = ((b1 & 0x03) << 4) | (b2 >> 4);
            unsigned char c3 = ((b2 & 0x0F) << 2) | (b3 >> 6);
            unsigned char c4 = b3 & 0x3F;
            const char* t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            encoded += t[c1];
            encoded += t[c2];
            if (i + 1 < auth.size()) encoded += t[c3]; else encoded += '=';
            if (i + 2 < auth.size()) encoded += t[c4]; else encoded += '=';
        }

        HINTERNET hSession = WinHttpOpen(L"RiotClient",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, nullptr, nullptr, 0);
        if (!hSession) return "eu";

        std::wstring whost = L"127.0.0.1";
        HINTERNET hConnect = WinHttpConnect(hSession, whost.c_str(), (INTERNET_PORT)port, 0);
        if (!hConnect) { WinHttpCloseHandle(hSession); return "eu"; }

        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET",
            L"/chat/v1/session", nullptr, nullptr, nullptr,
            WINHTTP_FLAG_SECURE);
        if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return "eu"; }

        DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
            SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));

        std::wstring wencoded(encoded.begin(), encoded.end());
        std::wstring hdrs = L"Authorization: Basic " + wencoded;
        WinHttpSendRequest(hRequest, hdrs.c_str(), (DWORD)hdrs.length(), nullptr, 0, 0, 0);
        WinHttpReceiveResponse(hRequest, nullptr);

        DWORD size = 0;
        WinHttpQueryDataAvailable(hRequest, &size);
        std::string buffer(size + 1, 0);
        DWORD read_bytes = 0;
        WinHttpReadData(hRequest, buffer.data(), size, &read_bytes);

        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);

        std::regex region_re("\"region\"\\s*:\\s*\"([^\"]+)\"");
        std::smatch match;
        if (std::regex_search(buffer, match, region_re))
            return match[1].str();

        return "eu";
    }

    std::string normalize_region(const std::string& region)
    {
        static const std::unordered_map<std::string, std::string> map =
        {
            {"jp1", "ap"},
            {"ap1", "ap"},
            {"sg2", "ap"},
            {"tw1", "ap"},
            {"tw2", "ap"},
            {"sa1", "ap"},
            {"sa2", "ap"},
            {"sa3", "ap"},
            {"sa4", "ap"},

            {"kr1", "kr"},

            {"na1", "na"},
            {"na2", "na"},

            {"eu1", "eu"},
            {"eu2", "eu"},

            {"br1", "latam"},
            {"la1", "latam"},
            {"la2", "latam"}
        };

        auto it = map.find(region);
        if (it != map.end())
            return it->second;

        return region;
    }

    std::string reformalize_region(const std::string& region)
    {
        static const std::unordered_map<std::string, std::string> map =
        {
            {"na", "latam"},
            {"latam", "na"},

            {"eu", "ap"},
            {"ap", "eu"}
        };

        auto it = map.find(region);
        if (it != map.end())
            return it->second;

        return region;
    }
}