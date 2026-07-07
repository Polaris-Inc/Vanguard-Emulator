#include <iostream>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <TlHelp32.h>
#include <mmsystem.h>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <ctime>
#include <regex>
#include <random>
#include <algorithm>

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")

#include <security/encryption.hpp>

std::atomic<bool> g_Running{ true };
std::atomic<bool> gConnectionFound = false;

#include <structs/vanguard.hpp>

#include <utility/console.hpp>
#include <utility/utilities.hpp>

const wchar_t* PIPE_NAME = L"\\\\.\\pipe\\933823D3-C77B-4BAE-89D7-A92B567236BC";

#include <session/session.hpp>
#include <structs/riotgames.hpp>
#include <emulation/connection_hook.hpp>

std::string console_title = Encrypt("Lunaris");

void keyboard_listener() 
{
	while (g_Running.load())
	{
		if (GetAsyncKeyState(VK_F5) & 0x8000)
		{
			if (vanguard::g_SessionReady)
			{
				console::info(Encrypt("Session active. Auto-refresh runs every 4 minutes."));
			}
			Sleep(1000);
		}
		Sleep(50);
	}
}

int wmain()
{
	if (!EnableDebugPrivilege())
	{
		console::critical(Encrypt("Failed to enable debug privilege, the emulator may not work correctly."));
	}

	if (!IsRunningAsAdmin())
	{
		RelaunchAsAdmin();
		return 0;
	}

	console::CreateConsole(console_title.c_str());

	SetConsoleOutputCP(CP_UTF8);

	print_title();

	printf(Encrypt("\n"));

	if (PipeExists())
	{
		console::critical(Encrypt("Vanguard pipe exists but shows signs of unexpected reinitialization."));
	}

	system(Encrypt("sc stop vgc >nul 2>&1"));
	Sleep(500);
	system(Encrypt("sc start vgc >nul 2>&1"));
	Sleep(500);

	HANDLE pipe = CreateFileW(PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (pipe != INVALID_HANDLE_VALUE) 
	{
		CloseHandle(pipe);
	}

	std::thread(connection::create_connection).detach();
	std::thread(keyboard_listener).detach();

	static bool found_emulation_layer = false;

	while (g_Running.load())
	{
		if (!found_emulation_layer && vanguard::g_SessionReady.load())
		{
			found_emulation_layer = true;
			console::info(Encrypt("Emulation layer is active and ready."));

			vanguard::region = riotgames::normalize_region(riotgames::get_region());

			console::debug("Session ID: " + vanguard::sid);
			console::debug("Game Token: " + vanguard::game_token);
			console::debug("Region: " + vanguard::region);
		}

		std::this_thread::sleep_for(std::chrono::seconds(1));
	}

    return 0;
}
