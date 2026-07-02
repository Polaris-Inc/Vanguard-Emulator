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

#include <emulation/connection_hook.hpp>
#include <session/session.hpp>

std::string console_title = Encrypt("Lunaris");

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

	console::debug(Encrypt("Attempting to restart Vanguard module to ensure proper initialization..."));

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

	while (g_Running.load())
	{
		std::this_thread::sleep_for(std::chrono::seconds(1));
	}

    return 0;
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
