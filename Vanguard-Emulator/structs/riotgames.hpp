#pragma once

#include <fstream>
#include <string>
#include <sstream>
#include <windows.h>
#include <winhttp.h>
#include <unordered_map>
#include <cstdlib>

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

    std::string base64_encode(const std::string& in)
    {
        static const char* table =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz"
            "0123456789+/";

        std::string out;
        out.reserve(((in.size() + 2) / 3) * 4);

        int val = 0;
        int valb = -6;

        for (unsigned char c : in)
        {
            val = (val << 8) | c;
            valb += 8;

            while (valb >= 0)
            {
                out.push_back(table[(val >> valb) & 0x3F]);
                valb -= 6;
            }
        }

        if (valb > -6)
            out.push_back(table[((val << 8) >> (valb + 8)) & 0x3F]);

        while (out.size() % 4)
            out.push_back('=');

        return out;
    }

    std::vector<uint8_t> base64_decode(const std::string& in)
    {
        static const int8_t T[256] =
        {
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
            52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
            -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
            15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
            -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
            41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
        };

        std::vector<uint8_t> out;
        out.reserve((in.size() * 3) / 4);

        int val = 0;
        int valb = -8;

        for (unsigned char c : in)
        {
            int8_t d = T[c];
            if (d == -1)
                continue;

            val = (val << 6) | d;
            valb += 6;

            if (valb >= 0)
            {
                out.push_back((val >> valb) & 0xFF);
                valb -= 8;
            }
        }

        return out;
    }

    std::wstring utf8_to_wstring(const std::string& str)
    {
        if (str.empty())
            return {};

        int size_needed = MultiByteToWideChar(
            CP_UTF8,
            0,
            str.data(),
            static_cast<int>(str.size()),
            nullptr,
            0
        );

        if (size_needed <= 0)
            return {};

        std::wstring result(size_needed, L'\0');

        MultiByteToWideChar(
            CP_UTF8,
            0,
            str.data(),
            static_cast<int>(str.size()),
            &result[0],
            size_needed
        );

        return result;
    }

    std::string get_region()
    {
        char localAppData[MAX_PATH] = { 0 };

        if (!GetEnvironmentVariableA("LOCALAPPDATA", localAppData, MAX_PATH))
            return "[ERROR] Failed to read LOCALAPPDATA environment variable";

        std::string lockfilePath =
            std::string(localAppData) +
            "\\Riot Games\\Riot Client\\Config\\lockfile";

        DWORD attr = GetFileAttributesA(lockfilePath.c_str());
        if (attr == INVALID_FILE_ATTRIBUTES)
            return "[ERROR] Lockfile not found (Riot Client not running or not logged in)";

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
        {
            DWORD err = GetLastError();

            if (err == ERROR_SHARING_VIOLATION)
                return "[ERROR] Lockfile is currently locked by Riot Client (normal state)";

            return "[ERROR] Failed to open lockfile, error: " + std::to_string(err);
        }

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
            return Encrypt("[ERROR] Invalid lockfile format");

        int port = 0;

        try
        {
            port = std::stoi(parts[2]);
        }
        catch (...)
        {
            return Encrypt("[ERROR] Invalid port in lockfile");
        }

        std::string password = parts[3];
        std::string auth = "riot:" + password;

        std::string b64auth = base64_encode(auth);

        std::wstring headers =
            L"Authorization: Basic " +
            utf8_to_wstring(b64auth) +
            L"\r\n";

        auto res = session::perform_http_request(
            L"127.0.0.1",
            port,
            L"/chat/v1/session",
            L"GET",
            "",
            headers
        );

        if (res.first != 200)
            return Encrypt("[ERROR] Riot API request failed, HTTP: ") + std::to_string(res.first);

        std::regex region_re("\"region\"\\s*:\\s*\"([^\"]+)\"");
        std::smatch match;

        if (!std::regex_search(res.second, match, region_re))
            return Encrypt("[ERROR] Region field not found in Riot response");

        return match[1].str();
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
}