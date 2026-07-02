#pragma once

namespace session
{
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

    void create_session_payload()
    {
        std::string API_HOST = Encrypt("127.0.0.1");

        if (vanguard::sid.empty() || vanguard::game_token.empty())
        {
			console::critical(Encrypt("SID or Game Token is empty, cannot create session payload."));
            return;
        }

        std::string json_body = build_auth_payload(vanguard::game);

        std::wstring api_headers = L"Content-Type: application/json\r\n";
        std::wstring api_host = utf8_to_wstring(std::string(API_HOST));

        std::pair<int, std::string> api_response = perform_http_request(
            api_host, 31133, L"", L"POST", json_body, api_headers, false);
            //api_host, 31133, L"/val5/create", L"POST", json_body, api_headers, false);

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
            console::critical("Rejected: API response missing 'data' field");
            return;
        }

        std::vector<uint8_t> vg_payload_vec = base64_decode(data_match[1].str());

        if (vg_payload_vec.empty())
        {
            console::critical("Rejected: gateway payload base64 decode failed");
            return;
        }

        std::string vg_payload(vg_payload_vec.begin(), vg_payload_vec.end());

        console::debug(
            "Gateway Payload: " +
            std::to_string(vg_payload_vec.size()) +
            " Bytes"
        );

        std::wstring gw_host = utf8_to_wstring(vanguard::region + ".vg.ac.pvp.net");

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
            "Gateway [" + vanguard::region + "] status=" + std::to_string(gw_response.first) +
            " body_len=" + std::to_string(gw_response.second.size()) +
            " body=" + gw_body_preview;

        console::debug(gw_msg);

        if (gw_response.first == 200)
        {
            console::debug("Gateway: Valid = 200 OK");
        }
        else
        {
            console::critical(
                "Gateway Reject: HTTP " + std::to_string(gw_response.first)
            );
        }
    }
}