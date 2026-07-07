#pragma once

#include <regex>

namespace session
{
    inline std::string g_session_cookie;

    std::wstring make_cookie_header()
    {
        if (g_session_cookie.empty())
            return L"";
        std::wstring wc = utf8_to_wstring(g_session_cookie);
        return L"Cookie: " + wc + L"\r\n";
    }
    std::pair<int, std::string> perform_http_request(const std::wstring& host, int port, const std::wstring& path,
        const std::wstring& method, const std::string& body = "",
        const std::wstring& extra_headers = L"", bool use_ssl = true)
    {
        std::string response_data;
        int status_code = 0;
        HINTERNET hSession = WinHttpOpen(L"Lunaris /1.0", WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) return { 0, "" };

        HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), port, 0);
        if (hConnect) {
            DWORD req_flags = use_ssl ? WINHTTP_FLAG_SECURE : 0;
            HINTERNET hRequest = WinHttpOpenRequest(hConnect, method.c_str(), path.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, req_flags);
            if (hRequest) {
                if (use_ssl) {
                    DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
                    WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));
                }

                BOOL bResults = WinHttpSendRequest(hRequest, extra_headers.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : extra_headers.c_str(), -1,
                    (LPVOID)(body.empty() ? NULL : body.c_str()), body.length(), body.length(), 0);

                if (bResults) {
                    bResults = WinHttpReceiveResponse(hRequest, NULL);
                    if (bResults) {
                        DWORD dwSize = sizeof(status_code);
                        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &status_code, &dwSize, WINHTTP_NO_HEADER_INDEX);

                        DWORD cookieSize = 0;
                        if (!WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_SET_COOKIE, WINHTTP_HEADER_NAME_BY_INDEX, WINHTTP_NO_OUTPUT_BUFFER, &cookieSize, WINHTTP_NO_HEADER_INDEX) &&
                            GetLastError() == ERROR_INSUFFICIENT_BUFFER && cookieSize > 0)
                        {
                            std::vector<wchar_t> cookieBuf(cookieSize / sizeof(wchar_t) + 1);
                            if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_SET_COOKIE, WINHTTP_HEADER_NAME_BY_INDEX, cookieBuf.data(), &cookieSize, WINHTTP_NO_HEADER_INDEX))
                            {
                                int len = WideCharToMultiByte(CP_UTF8, 0, cookieBuf.data(), -1, nullptr, 0, nullptr, nullptr);
                                if (len > 0)
                                {
                                    std::string utf8_cookie(len - 1, '\0');
                                    WideCharToMultiByte(CP_UTF8, 0, cookieBuf.data(), -1, &utf8_cookie[0], len, nullptr, nullptr);
                                    size_t semi = utf8_cookie.find(';');
                                    g_session_cookie = (semi != std::string::npos) ? utf8_cookie.substr(0, semi) : utf8_cookie;
                                }
                            }
                        }

                        do {
                            dwSize = 0;
                            if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
                            if (dwSize == 0) break;
                            char* pszOutBuffer = new char[dwSize + 1];
                            if (!pszOutBuffer) break;
                            ZeroMemory(pszOutBuffer, dwSize + 1);
                            DWORD dwDownloaded = 0;
                            if (WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded)) {
                                response_data.append(pszOutBuffer, dwDownloaded);
                            }
                            delete[] pszOutBuffer;
                        } while (dwSize > 0);
                    }
                }
                WinHttpCloseHandle(hRequest);
            }
            WinHttpCloseHandle(hConnect);
        }
        WinHttpCloseHandle(hSession);
        return { status_code, response_data };
    }

    std::string build_auth_payload(const std::string& game)
    {
        std::string json = "{\"action\":\"auth\",\"game\":\"" + game + "\",\"gametoken\":\"" + vanguard::game_token + "\"";

        if (game == "valo")
            json += ",\"sid\":\"" + vanguard::sid + "\"";

        json += "}";

        return json;
    }

    std::string extract_data_field(const std::string& response)
    {
        std::regex data_re("\"data\"\\s*:\\s*\"([^\"]+)\"");
        std::smatch m;
        if (!std::regex_search(response, m, data_re))
            return "";
        return m[1].str();
    }

    std::string build_response_payload(const std::string& riot_response, const std::string& action)
    {
        std::string b64 = base64_encode(riot_response);
        return "{\"action\":\"" + action + "\",\"response\":\"" + b64 + "\"}";
    }

    bool access_heartbeat(const std::string& riot_response_body, const std::string& action, std::string& out_next_payload)
    {
        std::wstring api_headers = L"Content-Type: application/json\r\n" + make_cookie_header();
        std::wstring api_host = utf8_to_wstring(std::string(Encrypt("vanguard-api-jsxa.onrender.com")));

        std::string json_body = build_response_payload(riot_response_body, action);

        auto res = perform_http_request(
            api_host, 443, L"/gateway.php", L"POST", json_body, api_headers, true);

        std::string preview = res.second.substr(0, std::min<size_t>(120, res.second.size()));

        console::debug(
            action + Encrypt(" API status=") + std::to_string(res.first) +
            Encrypt(" body=") + preview
        );

        if (res.first != 200)
        {
            console::critical(action + Encrypt(" API HTTP ") + std::to_string(res.first));
            return false;
        }

        if (res.second.find("\"success\":true") == std::string::npos &&
            res.second.find("\"success\": true") == std::string::npos)
        {
            console::critical(action + Encrypt(" API returned failure"));
            return false;
        }

        std::string data = extract_data_field(res.second);
        if (data.empty())
        {
            console::critical(action + Encrypt(" API missing data field"));
            return false;
        }

        std::vector<uint8_t> vec = base64_decode(data);
        if (vec.empty())
        {
            console::critical(action + Encrypt(" payload decode failed"));
            return false;
        }

        out_next_payload.assign(vec.begin(), vec.end());
        return true;
    }

    bool forward_to_riot(const std::string& payload, std::string& out_response)
    {
        std::wstring gw_host = utf8_to_wstring(vanguard::region + Encrypt(".vg.ac.pvp.net"));

        std::wstring gw_headers = L"Content-Type: application/x-protobuf\r\n"
            L"User-Agent: Vanguard/1.0.0.0 (Windows NT 10.0; Win64; x64)\r\n"
            L"Accept: application/x-protobuf\r\n"
            L"Accept-Language: en-US,en;q=0.9\r\n"
            L"Cache-Control: no-cache\r\n"
            L"Pragma: no-cache\r\n";

        auto res = perform_http_request(
            gw_host, 8443, L"/vanguard/v1/gateway", L"POST", payload, gw_headers);

        std::string preview = res.second.substr(0, std::min<size_t>(100, res.second.size()));

        console::debug(
            Encrypt("Gateway [") + vanguard::region + Encrypt("] status=") +
            std::to_string(res.first) + Encrypt(" body_len=") +
            std::to_string(res.second.size()) + Encrypt(" body=") + preview
        );

        out_response = res.second;
        return res.first == 200;
    }

    bool refresh_session(const std::string& session_id, const std::string& jwt_token, const std::string& puuid)
    {
        std::wstring api_headers = L"Content-Type: application/json\r\n";
        std::wstring api_host = utf8_to_wstring(std::string(Encrypt("vanguard-api-jsxa.onrender.com")));

        std::string refresh_body = "{"
            "\"action\":\"refresh\","
            "\"session_id\":\"" + session_id + "\","
            "\"token\":\"" + jwt_token + "\","
            "\"sid\":\"" + puuid + "\","
            "\"game\":\"" + vanguard::game + "\","
            "\"region\":\"" + vanguard::region + "\""
            "}";

        auto res = perform_http_request(api_host, 443, L"/gateway.php", L"POST", refresh_body, api_headers, true);

        if (res.first != 200)
        {
            console::critical(Encrypt("Refresh API HTTP ") + std::to_string(res.first));
            return false;
        }

        std::regex session_re("\"session_id\"\\s*:\\s*\"([^\"]+)\"");
        std::smatch session_match;
        if (!std::regex_search(res.second, session_match, session_re))
        {
            console::critical(Encrypt("Refresh response missing session_id"));
            return false;
        }
        std::string new_session_id = session_match[1].str();

        console::debug(Encrypt("Refresh OK, session_id=") + new_session_id);

        std::string ticket;
        while (true)
        {
            std::string poll_body = "{\"action\":\"poll\",\"session_id\":\"" + new_session_id + "\"}";

            auto poll_res = perform_http_request(api_host, 443, L"/gateway.php", L"POST", poll_body, api_headers, true);

            if (poll_res.first != 200)
            {
                console::critical(Encrypt("Poll API HTTP ") + std::to_string(poll_res.first));
                return false;
            }

            if (poll_res.second.find("\"status\":\"ready\"") != std::string::npos ||
                poll_res.second.find("\"status\": \"ready\"") != std::string::npos)
            {
                std::regex ticket_re("\"ticket\"\\s*:\\s*\"([^\"]+)\"");
                std::smatch ticket_match;
                if (!std::regex_search(poll_res.second, ticket_match, ticket_re))
                {
                    console::critical(Encrypt("Poll response missing ticket"));
                    return false;
                }
                ticket = ticket_match[1].str();
                break;
            }

            if (poll_res.second.find("\"status\":\"failed\"") != std::string::npos ||
                poll_res.second.find("\"status\": \"failed\"") != std::string::npos)
            {
                std::regex err_re("\"error\"\\s*:\\s*\"([^\"]+)\"");
                std::smatch err_match;
                std::string error_msg = Encrypt("unknown");
                if (std::regex_search(poll_res.second, err_match, err_re))
                    error_msg = err_match[1].str();
                console::critical(Encrypt("Poll failed: ") + error_msg);
                return false;
            }

            Sleep(3000);
        }

        std::vector<uint8_t> ticket_bytes = base64_decode(ticket);
        if (ticket_bytes.empty())
        {
            console::critical(Encrypt("Ticket base64 decode failed"));
            return false;
        }

        HANDLE pipe = CreateFileW(PIPE_NAME, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (pipe == INVALID_HANDLE_VALUE)
        {
            console::critical(Encrypt("Failed to open pipe for ticket injection"));
            return false;
        }

        uint32_t magic = 0x000003E9;
        uint32_t ticketLen = (uint32_t)ticket_bytes.size();
        uint32_t packetLen = 36 + ticketLen;
        uint32_t type = 1;
        uint32_t zero = 0;

        std::vector<uint8_t> packet;
        auto append = [&](const auto& v)
        {
            const uint8_t* p = reinterpret_cast<const uint8_t*>(&v);
            packet.insert(packet.end(), p, p + sizeof(v));
        };

        append(magic);
        append(packetLen);
        append(type);
        append(zero);
        append(zero);
        append(zero);
        append(ticketLen);
        append(zero);
        append(zero);
        packet.insert(packet.end(), ticket_bytes.begin(), ticket_bytes.end());

        DWORD written;
        BOOL ok = WriteFile(pipe, packet.data(), (DWORD)packet.size(), &written, NULL);
        if (!ok || written != packet.size())
        {
            console::critical(Encrypt("Failed to write ticket packet to pipe"));
            CloseHandle(pipe);
            return false;
        }

        FlushFileBuffers(pipe);
        CloseHandle(pipe);

        console::info(Encrypt("Ticket injected successfully"));
        return true;
    }

    std::vector<uint8_t> refresh_get_ticket(const std::string& session_id, const std::string& jwt_token, const std::string& puuid)
    {
        std::wstring api_headers = L"Content-Type: application/json\r\n";
        std::wstring api_host = utf8_to_wstring(std::string(Encrypt("vanguard-api-jsxa.onrender.com")));

        std::string refresh_body = "{"
            "\"action\":\"refresh\","
            "\"session_id\":\"" + session_id + "\","
            "\"token\":\"" + jwt_token + "\","
            "\"sid\":\"" + puuid + "\","
            "\"game\":\"" + vanguard::game + "\","
            "\"region\":\"" + vanguard::region + "\""
            "}";

        auto res = perform_http_request(api_host, 443, L"/gateway.php", L"POST", refresh_body, api_headers, true);

        if (res.first != 200)
        {
            console::critical(Encrypt("Refresh API HTTP ") + std::to_string(res.first));
            return {};
        }

        std::regex session_re("\"session_id\"\\s*:\\s*\"([^\"]+)\"");
        std::smatch session_match;
        if (!std::regex_search(res.second, session_match, session_re))
        {
            console::critical(Encrypt("Refresh response missing session_id"));
            return {};
        }
        std::string new_session_id = session_match[1].str();
        console::debug(Encrypt("Refresh OK, session_id=") + new_session_id);

        while (true)
        {
            std::string poll_body = "{\"action\":\"poll\",\"session_id\":\"" + new_session_id + "\"}";

            auto poll_res = perform_http_request(api_host, 443, L"/gateway.php", L"POST", poll_body, api_headers, true);

            if (poll_res.first != 200)
            {
                console::critical(Encrypt("Poll API HTTP ") + std::to_string(poll_res.first));
                return {};
            }

            if (poll_res.second.find("\"status\":\"ready\"") != std::string::npos ||
                poll_res.second.find("\"status\": \"ready\"") != std::string::npos)
            {
                std::regex ticket_re("\"ticket\"\\s*:\\s*\"([^\"]+)\"");
                std::smatch ticket_match;
                if (!std::regex_search(poll_res.second, ticket_match, ticket_re))
                {
                    console::critical(Encrypt("Poll response missing ticket"));
                    return {};
                }
                std::string ticket_b64 = ticket_match[1].str();
                std::vector<uint8_t> ticket_bytes = base64_decode(ticket_b64);
                if (ticket_bytes.empty())
                {
                    console::critical(Encrypt("Ticket base64 decode failed"));
                    return {};
                }
                console::info(Encrypt("Ticket received (") + std::to_string(ticket_bytes.size()) + Encrypt(" bytes)"));
                return ticket_bytes;
            }

            if (poll_res.second.find("\"status\":\"failed\"") != std::string::npos ||
                poll_res.second.find("\"status\": \"failed\"") != std::string::npos)
            {
                std::regex err_re("\"error\"\\s*:\\s*\"([^\"]+)\"");
                std::smatch err_match;
                std::string error_msg = Encrypt("unknown");
                if (std::regex_search(poll_res.second, err_match, err_re))
                    error_msg = err_match[1].str();
                console::critical(Encrypt("Poll failed: ") + error_msg);
                return {};
            }

            Sleep(3000);
        }
    }

    bool authenticate_session_auto()
    {
        if (vanguard::sid.empty() || vanguard::game_token.empty())
        {
            console::critical(Encrypt("SID or Game Token is empty, cannot authenticate."));
            return false;
        }

        std::string json_body = build_auth_payload(vanguard::game);

        std::wstring api_headers = L"Content-Type: application/json\r\n";
        std::wstring api_host = utf8_to_wstring(std::string(Encrypt("vanguard-api-jsxa.onrender.com")));

        auto api_response = perform_http_request(
            api_host, 443, L"/gateway.php", L"POST", json_body, api_headers, true);

        if (api_response.first != 200)
        {
            console::critical(Encrypt("Auth API HTTP ") + std::to_string(api_response.first));
            return false;
        }

        if (api_response.second.find("\"success\":true") == std::string::npos &&
            api_response.second.find("\"success\": true") == std::string::npos)
        {
            console::critical(Encrypt("Auth API returned failure"));
            return false;
        }

        std::string data = extract_data_field(api_response.second);
        if (data.empty())
        {
            console::critical(Encrypt("Auth API missing data field"));
            return false;
        }

        std::vector<uint8_t> vec = base64_decode(data);
        if (vec.empty())
        {
            console::critical(Encrypt("Auth payload decode failed"));
            return false;
        }

        std::string vg_payload(vec.begin(), vec.end());

        std::wstring gw_host = utf8_to_wstring(vanguard::region + Encrypt(".vg.ac.pvp.net"));
        std::wstring gw_headers = L"Content-Type: application/x-protobuf\r\n"
            L"User-Agent: Vanguard/1.0.0.0 (Windows NT 10.0; Win64; x64)\r\n"
            L"Accept: application/x-protobuf\r\n"
            L"Accept-Language: en-US,en;q=0.9\r\n"
            L"Cache-Control: no-cache\r\n"
            L"Pragma: no-cache\r\n";

        auto gw_response = perform_http_request(
            gw_host, 8443, L"/vanguard/v1/gateway", L"POST", vg_payload, gw_headers);

        console::debug(
            Encrypt("Gateway [") + vanguard::region + Encrypt("] status=") +
            std::to_string(gw_response.first) + Encrypt(" body_len=") +
            std::to_string(gw_response.second.size()));

        std::regex sid_re("\"session_id\"\\s*:\\s*\"([^\"]+)\"");
        std::smatch sid_match;
        if (std::regex_search(api_response.second, sid_match, sid_re))
            vanguard::g_session_id = sid_match[1].str();

        if (gw_response.first == 200)
            vanguard::g_last_gateway_response = gw_response.second;

        return gw_response.first == 200;
    }

    bool send_gateway_heartbeat()
    {
        if (vanguard::g_last_gateway_response.empty())
        {
            console::critical(Encrypt("No gateway response to build heartbeat from"));
            return false;
        }

        std::string next_payload;
        if (!access_heartbeat(vanguard::g_last_gateway_response, Encrypt("heartbeat"), next_payload))
            return false;

        std::string gw_body;
        if (!forward_to_riot(next_payload, gw_body))
            return false;

        vanguard::g_last_gateway_response = gw_body;
        console::info(Encrypt("Gateway heartbeat OK, session kept alive"));
        return true;
    }

    void create_session_payload()
    {
        std::string API_HOST = Encrypt("vanguard-api-jsxa.onrender.com");

        if (vanguard::sid.empty() || vanguard::game_token.empty())
        {
			console::critical(Encrypt("SID or Game Token is empty, cannot create session payload."));
            return;
        }

        std::string json_body = build_auth_payload(vanguard::game);

        std::wstring api_headers = L"Content-Type: application/json\r\n";
        std::wstring api_host = utf8_to_wstring(std::string(API_HOST));

        std::pair<int, std::string> api_response = perform_http_request(
            api_host, 443, L"/gateway.php", L"POST", json_body, api_headers, true);
            //api_host, 31133, L"", L"POST", json_body, api_headers, true);

        std::string api_body_preview =
            api_response.second.substr(0, std::min<size_t>(120, api_response.second.size()));

        std::string api_msg =
            Encrypt("API status =") + std::to_string(api_response.first) +
            Encrypt(" body =") + api_body_preview;

        console::debug(api_msg);

        if (api_response.first != 200)
        {
            std::string reject_msg =
                Encrypt("Rejected: API HTTP ") + std::to_string(api_response.first) +
                ": " + api_response.second.substr(0, 100);

            console::critical(reject_msg);
            return;
        }

        const std::string& decrypted = api_response.second;

        bool has_success =
            decrypted.find("\"success\":true") != std::string::npos ||
            decrypted.find("\"success\": true") != std::string::npos;

        if (!has_success)
        {
            std::string reject_msg =
                Encrypt("Rejected: API returned failure: ") +
                decrypted.substr(0, 120);

            console::critical(reject_msg);
            return;
        }

        std::regex data_re("\"data\"\\s*:\\s*\"([^\"]+)\"");
        std::smatch data_match;

        if (!std::regex_search(decrypted, data_match, data_re))
        {
            console::critical(Encrypt("Rejected: API response missing 'data' field"));
            return;
        }

        std::vector<uint8_t> vg_payload_vec = base64_decode(data_match[1].str());

        if (vg_payload_vec.empty())
        {
            console::critical(Encrypt("Rejected: gateway payload base64 decode failed"));
            return;
        }

        std::string vg_payload(vg_payload_vec.begin(), vg_payload_vec.end());

        console::debug(
            Encrypt("Gateway Payload: ") +
            std::to_string(vg_payload_vec.size()) +
            Encrypt(" Bytes")
        );

        std::wstring gw_host = utf8_to_wstring(vanguard::region + Encrypt(".vg.ac.pvp.net"));

        std::wstring gw_headers = L"Content-Type: application/x-protobuf\r\n"
            L"User-Agent: Vanguard/1.0.0.0 (Windows NT 10.0; Win64; x64)\r\n"
            L"Accept: application/x-protobuf\r\n"
            L"Accept-Language: en-US,en;q=0.9\r\n"
            L"Cache-Control: no-cache\r\n"
            L"Pragma: no-cache\r\n";

		std::pair<int, std::string> gw_response = perform_http_request(
            gw_host, 8443, L"/vanguard/v1/gateway", L"POST", vg_payload, gw_headers);

        std::string gw_body_preview =
            gw_response.second.substr(0, std::min<size_t>(100, gw_response.second.size()));

        std::string gw_msg =
            Encrypt("Gateway [") + vanguard::region + Encrypt("] status=") + std::to_string(gw_response.first) +
            Encrypt(" body_len=") + std::to_string(gw_response.second.size()) +
            Encrypt(" body=") + gw_body_preview;

        console::debug(gw_msg);

        if (gw_response.first == 200)
        {
            console::debug(Encrypt("Gateway: Valid = 200 OK"));
        }
        else
        {
            console::critical(
                Encrypt("Gateway Reject: HTTP ") + std::to_string(gw_response.first)
            );
        }
    }
}