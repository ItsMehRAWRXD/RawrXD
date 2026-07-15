// ============================================================================
// RawrXD Codex - Unified CLI/GUI Entry Point
// Auto-detects console vs GUI mode, zero bloat, maximum performance
// ============================================================================

#include <Windows.h>
#include <iostream>
#include <string_view>
#include <vector>
#include <fcntl.h>
#include <io.h>
#include "CodexCLI.hpp"
#include "CodexGUI.hpp"
#include "../../include/rawrxd_version.hpp"

using namespace RawrXD::Codex;

// Hide console window if app was launched directly (GUI fallback)
void HideConsoleSession() {
    HWND hConsole = GetConsoleWindow();
    if (hConsole) {
        DWORD dwProcessId;
        GetWindowThreadProcessId(hConsole, &dwProcessId);
        // Only hide if our process owns the console exclusively (double-clicked)
        if (GetCurrentProcessId() == dwProcessId) {
            ShowWindow(hConsole, SW_HIDE);
        }
    }
}

// BindParentConsoleIO - Attach to parent console and redirect streams
// This fixes the -mwindows subsystem trap where stdout is null
void BindParentConsoleIO() {
    // Attempt to attach to the console of the process that launched us
    if (AttachConsole(ATTACH_PARENT_PROCESS)) {
        FILE* fpDummy;
        
        // Reopen low-level standard descriptors to the attached console devices
        freopen_s(&fpDummy, "CONOUT$", "w", stdout);
        freopen_s(&fpDummy, "CONOUT$", "w", stderr);
        freopen_s(&fpDummy, "CONIN$", "r", stdin);
        
        // Clear stream failure states and force synchronization
        std::clog.clear();
        std::cerr.clear();
        std::cout.clear();
        std::cin.clear();
        
        std::wclog.clear();
        std::wcerr.clear();
        std::wcout.clear();
        std::wcin.clear();
        
        std::ios_base::sync_with_stdio(false);
    }
}

int wmain(int argc, wchar_t* argv[]) {
    // Case 1: No arguments -> Launch Native Win32 GUI mode
    if (argc < 2) {
        HideConsoleSession();
        
        // Initialize CLI backend first
        auto cli = std::make_shared<CodexCLI>();
        CodexCLI::Config config;
        // Load config from environment or defaults
        cli->Initialize(config);
        
        // Launch GUI
        CodexGUI gui;
        gui.SetCLI(cli);
        
        if (!gui.Initialize(GetModuleHandle(nullptr), SW_SHOW)) {
            MessageBoxW(nullptr, L"Failed to initialize GUI", L"Error", MB_OK | MB_ICONERROR);
            return -1;
        }
        
        return gui.Run();
    }

    // Case 2: CLI Arguments provided -> Parse and Route
    BindParentConsoleIO(); // Enable console output for CLI mode
    
    std::wstring_view command(argv[1]);

    // Handle commands that don't require initialization first
    if (command == L"help" || command == L"-h" || command == L"--help" || command == L"/?") {
        std::wcout << L"RawrXD Codex - GPT/Codex CLI/GUI Interface\n";
        std::wcout << L"Version: " << RAWRXD_VERSION_STRING << L"\n\n";
        std::wcout << L"Usage:\n";
        std::wcout << L"  rawrxd-codex                    Launch GUI mode\n";
        std::wcout << L"  rawrxd-codex version            Show version\n";
        std::wcout << L"  rawrxd-codex complete \"prompt\"  Single completion\n";
        std::wcout << L"  rawrxd-codex stream \"prompt\"    Streaming completion\n";
        std::wcout << L"  rawrxd-codex repl               Interactive REPL mode\n";
        std::wcout << L"  rawrxd-codex help               Show this help\n\n";
        std::wcout << L"Environment:\n";
        std::wcout << L"  OPENAI_API_KEY    API key for GPT/Codex\n";
        std::wcout << L"  OLLAMA_HOST       Ollama server host (default: localhost:11434)\n";
        std::wcout << L"  OLLAMA_MODEL      Model to use (e.g., gemma3:27b-it-qat)\n";
        return 0;
    }
    
    if (command == L"version" || command == L"-v" || command == L"--version") {
        std::wcout << L"RawrXD Codex Module\n";
        std::wcout << L"Version: " << RAWRXD_VERSION_STRING << L"\n";
        std::wcout << L"Codename: Courageous Rodent\n";
        return 0;
    }
    
    // Initialize CLI for commands that need it
    CodexCLI cli;
    CodexCLI::Config config;
    if (!cli.Initialize(config)) {
        std::wcerr << L"Error: Failed to initialize CLI - " << cli.GetLastError() << L"\n";
        return 1;
    }
    
    if (command == L"repl") {
        cli.RunREPL();
        return 0;
    }
    
    // Commands requiring an explicit prompt argument
    if (argc < 3) {
        std::wcerr << L"Error: Missing prompt text for command '" << command << L"'\n";
        std::wcerr << L"Usage: rawrxd-codex [complete|stream|repl|version] \"your prompt here\"\n";
        return 1;
    }

    // Convert wchar_t to char for CLI (exclude null terminator)
    int len = WideCharToMultiByte(CP_UTF8, 0, argv[2], -1, nullptr, 0, nullptr, nullptr);
    std::string prompt(len - 1, 0);  // -1 to exclude null terminator
    WideCharToMultiByte(CP_UTF8, 0, argv[2], -1, &prompt[0], len, nullptr, nullptr);

    if (command == L"complete") {
        std::string response = cli.Complete(prompt);
        if (!response.empty()) {
            std::cout << response << "\n";
            return 0;
        } else {
            const char* err = cli.GetLastError();
            if (err && *err) {
                std::cerr << "Error: " << err << "\n";
            } else {
                std::cerr << "Error: Empty response or unknown error\n";
            }
            return 1;
        }
    }
    
    if (command == L"stream") {
        bool success = cli.CompleteStreaming(prompt, [](const std::string& chunk, bool isFinal) {
            std::cout << chunk;
            if (isFinal) {
                std::cout << "\n";
            }
        });
        return success ? 0 : 1;
    }

    std::wcerr << L"Unknown command: " << command << L"\n";
    std::wcerr << L"Valid commands: complete, stream, repl, version\n";
    return 1;
}
