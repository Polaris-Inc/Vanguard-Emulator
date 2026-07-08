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

int amount_before_change = 5;

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
				console::info(Encrypt("Session active. Auto-refresh runs every 5 minutes."));
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

	// Session timer thread - fully independent, never dies
	std::thread([]()
	{
		while (g_Running.load())
		{
			if (vanguard::g_SessionReady.load() && vanguard::g_GatewaySuccess.load())
			{
				auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
					std::chrono::steady_clock::now() - vanguard::g_session_start_time).count();
				vanguard::g_session_active_seconds.store((int)elapsed);
				console::info(Encrypt("Session Active: ") + std::to_string(elapsed) + Encrypt("s"));
				SetConsoleTitleW((L"Lunaris - Session: " + std::to_wstring(elapsed) + L"s").c_str());
			}
			std::this_thread::sleep_for(std::chrono::seconds(30));
		}
	}).detach();

	// Auto-refresh thread - separate so it can never kill the timer
	std::thread([]()
	{
		while (g_Running.load())
		{
			std::this_thread::sleep_for(std::chrono::minutes(5));
			if (!g_Running.load()) break;
			if (!vanguard::g_SessionReady.load()) continue;

			try
			{
				console::info(Encrypt("Authenticating session (refresh)..."));
				bool ok = false;
				for (int i = 0; i < 3 && !ok; i++)
				{
					if (i > 0)
					{
						console::info(Encrypt("Retrying gateway auth (attempt ") + std::to_string(i + 1) + Encrypt("/3)..."));
						Sleep(3000);
					}
					ok = session::authenticate_session_auto();
				}
				vanguard::g_GatewaySuccess.store(ok);
				if (ok)
				{
					console::info(Encrypt("Gateway authentication succeeded (200 OK)"));
					vanguard::g_auth_counter++;
					if (vanguard::g_auth_counter >= 4)
					{
						vanguard::g_auth_counter = 0;
						std::string old_region = vanguard::region;
						if (old_region == "ap") vanguard::region = "eu";
						else if (old_region == "eu") vanguard::region = "ap";
						else if (old_region == "na") vanguard::region = "la";
						else if (old_region == "la") vanguard::region = "na";
						console::info(Encrypt("Region rotated: ") + old_region + Encrypt(" -> ") + vanguard::region);
					}
				}
				else
					console::critical(Encrypt("Gateway authentication failed after 3 attempts"));

				console::info(Encrypt("Refreshing session ticket..."));
				std::string sid = vanguard::g_session_id.empty() ? vanguard::sid : vanguard::g_session_id;
				std::vector<uint8_t> ticket = session::refresh_get_ticket(sid, vanguard::extracted_token, vanguard::sid);
				if (!ticket.empty())
				{
					{
						std::lock_guard<std::mutex> lock(vanguard::g_ticket_mtx);
						vanguard::g_pending_ticket = std::move(ticket);
					}
					console::info(Encrypt("Refresh: ticket stored, will inject on next heartbeat"));
				}
				else
					console::critical(Encrypt("Refresh: failed to get ticket"));

				console::info(Encrypt("Re-initializing gateway client (refresh)..."));
				vanguard::g_gateway_hb_active.store(false);
				GatewayClient::shutdown_session();
				std::this_thread::sleep_for(std::chrono::milliseconds(500));

				bool gw_ok = GatewayClient::do_gateway_full_auth(
					vanguard::extracted_token,
					vanguard::sid,
					vanguard::region
				);
				if (gw_ok)
				{
					vanguard::g_session_start_time = std::chrono::steady_clock::now();
					console::info(Encrypt("Gateway client refreshed"));
					vanguard::g_gateway_hb_active.store(true);
					std::thread([]()
					{
						while (g_Running.load() && vanguard::g_gateway_hb_active.load() && GatewayClient::is_gateway_active())
						{
							GatewayClient::do_heartbeat();
							std::this_thread::sleep_for(std::chrono::seconds(300));
						}
					}).detach();
				}
				else
					console::critical(Encrypt("Gateway client refresh failed"));
			}
			catch (const std::exception& e)
			{
				console::critical(Encrypt("Refresh error: ") + std::string(e.what()));
			}
			catch (...)
			{
				console::critical(Encrypt("Refresh unknown error"));
			}
		}
	}).detach();

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
