#pragma once

const wchar_t* PIPE_NAME = Encrypt(L"\\\\.\\pipe\\933823D3-C77B-4BAE-89D7-A92B567236BC");

bool PipeExists()
{
    return WaitNamedPipeW(PIPE_NAME, 0);
}

void handle_connection(HANDLE connection)
{
    vanguard::current_connection.store(connection);
    std::vector<uint8_t> buffer(4096);
    DWORD bytesRead;

    uint8_t uuid_bin[16] = { 0 };
    char uuid_str[37] = { 0 };
    bool uuid_found = false;

    while (g_Running.load())
    {
        if (!ReadFile(connection, buffer.data(), buffer.size(), &bytesRead, NULL) || bytesRead == 0)
            break;

        VanguardHeader* hdr = reinterpret_cast<VanguardHeader*>(buffer.data());


    }
}

void create_connection()
{
    while (g_Running.load())
    {
        HANDLE pipe = CreateNamedPipeW(PIPE_NAME, PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1, 1048576, 1048576, 500, NULL);

        if (pipe != INVALID_HANDLE_VALUE)
        {
            console::debug(Encrypt("Vanguard connection exists and is connectable."));
            CloseHandle(pipe);
        }
        else
        {
            DWORD error = GetLastError();

            if (error == ERROR_FILE_NOT_FOUND)
            {
                console::critical(Encrypt("Vanguard connection does not exist, please ensure that Vanguard is running."));
            }
            else if (error == ERROR_PIPE_BUSY)
            {
                console::critical(Encrypt("Vanguard connection exists but is busy, please ensure that Vanguard is running and not busy."));
            }
            else
            {
                console::critical(Encrypt("Failed to create connection, error code: ") + std::to_string(error));
            }
        }

        if (ConnectNamedPipe(pipe, NULL) || GetLastError() == ERROR_PIPE_CONNECTED)
        {
            std::thread(handle_connection, pipe).detach();
        }
        else
        {
            CloseHandle(pipe);
        }
    }
}