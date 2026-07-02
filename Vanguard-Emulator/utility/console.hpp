#pragma once

#include <windows.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <mutex>
#include <chrono>
#include <string>

class console 
{
public:
    enum class level 
    {
        debug,
        info,
        critical
    };

    static void CreateConsole(const char* title = "Console")
    {
        if (!GetConsoleWindow()) {
            AllocConsole();
            freopen_s(&s_out, "CONOUT$", "w", stdout);
            freopen_s(&s_in, "CONIN$", "r", stdin);
        }
        SetConsoleTitleA(title);
        ShowWindow(GetConsoleWindow(), SW_SHOW);
    }

    static void CloseConsole()
    {
        ShowWindow(GetConsoleWindow(), SW_HIDE);
        ClearConsole();
    }

    static void ClearConsole() {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hConsole == INVALID_HANDLE_VALUE) return;

        CONSOLE_SCREEN_BUFFER_INFO csbi;
        DWORD count;
        COORD homeCoords = { 0, 0 };

        if (!GetConsoleScreenBufferInfo(hConsole, &csbi)) return;

        FillConsoleOutputCharacterA(hConsole, ' ', csbi.dwSize.X * csbi.dwSize.Y, homeCoords, &count);
        SetConsoleCursorPosition(hConsole, homeCoords);
    }

    static void debug(const std::string& message)
    {
        log(level::debug, message);
    }

    static void info(const std::string& message)
    {
        log(level::info, message);
    }

    static void critical(const std::string& message)
    {
        log(level::critical, message);
    }

private:
    static inline FILE* s_out = nullptr;
    static inline FILE* s_in = nullptr;
    static inline std::mutex s_mutex;
    static inline std::ofstream s_logFile;

    static void log(level _level, const std::string& message) {
        std::lock_guard<std::mutex> lock(s_mutex);

        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        std::ostringstream oss;

        std::cout << "[";
        setColor(hConsole, 11);
        std::cout << "lunaris";
        resetColor(hConsole);
        std::cout << "] ";

        switch (_level) {
        case level::debug:
            setColor(hConsole, 9);
            oss << "[debug] ";
            std::cout << "[debug] ";
            break;
        case level::info:
            setColor(hConsole, 11);
            oss << "[info] ";
            std::cout << "[info] ";
            break;
        case level::critical:
            setColor(hConsole, 12);
            oss << "[critical] ";
            std::cout << "[critical] ";
            break;
        }

        resetColor(hConsole);
        std::cout << message << std::endl;
        oss << message;
    }

    static void setColor(HANDLE h, int color)
    {
        SetConsoleTextAttribute(h, color);
    }

    static void resetColor(HANDLE h)
    {
        SetConsoleTextAttribute(h, 7);
    }
};


void print_line(const std::string& text, int color)
{
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);

    std::cout << text << "\n";
}

void print_title()
{
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    print_line(Encrypt("╔═╗┌─┐┬  ┌─┐┬─┐┬┌─┐"), 11);
    print_line(Encrypt("╠═╝│ ││  ├─┤├┬┘│└─┐"), 9);
    print_line(Encrypt("╩  └─┘┴─┘┴ ┴┴└─┴└─┘"), 1);

    SetConsoleTextAttribute(hConsole, 15);
}