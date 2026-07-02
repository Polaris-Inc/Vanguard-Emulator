#pragma once

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
