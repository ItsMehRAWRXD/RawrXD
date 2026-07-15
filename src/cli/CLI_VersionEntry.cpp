// RawrXD CLI Entry Point - Version 1.1.0
// Zero-allocation, Win32-native command-line interface with version support
// Compile: g++ -std=c++17 -O2 -Wall CLI_VersionEntry.cpp ../core/Version.cpp ../core/UnifiedSessionState.cpp -o rawrxd-cli-v2.exe -lkernel32

#include "../core/Version.hpp"
#include "../core/UnifiedSessionState.hpp"
#include <windows.h>
#include <cstdio>
#include <cstring>

using namespace RawrXD;

// CLI return codes
enum class CLIReturnCode : int {
    Success = 0,
    ErrorGeneral = 1,
    ErrorVersionMismatch = 2,
    ErrorSharedMemory = 3,
    ErrorInvalidArgs = 4
};

// Command-line options
struct CLIOptions {
    bool showVersion = false;
    bool showHelp = false;
    bool verbose = false;
    bool connectToSession = true;  // Try to connect to IDE shared memory
    const wchar_t* command = nullptr;
    int commandArgc = 0;
    const wchar_t** commandArgv = nullptr;
};

// Fast, zero-allocation string comparison for wchar_t
bool WStrEquals(const wchar_t* a, const wchar_t* b) noexcept {
    if (a == nullptr || b == nullptr) return a == b;
    while (*a && *a == *b) { ++a; ++b; }
    return *a == *b;
}

// Parse command-line arguments
CLIOptions ParseArguments(int argc, wchar_t* argv[]) noexcept {
    CLIOptions opts;
    
    for (int i = 1; i < argc; ++i) {
        const wchar_t* arg = argv[i];
        
        // Version flags
        if (WStrEquals(arg, L"--version") || WStrEquals(arg, L"-v")) {
            opts.showVersion = true;
            opts.connectToSession = false;
        }
        // Help flags
        else if (WStrEquals(arg, L"--help") || WStrEquals(arg, L"-h") || WStrEquals(arg, L"/?")) {
            opts.showHelp = true;
            opts.connectToSession = false;
        }
        // Verbose flag
        else if (WStrEquals(arg, L"--verbose") || WStrEquals(arg, L"-V")) {
            opts.verbose = true;
        }
        // No-session flag
        else if (WStrEquals(arg, L"--no-session") || WStrEquals(arg, L"-n")) {
            opts.connectToSession = false;
        }
        // Command separator
        else if (WStrEquals(arg, L"--")) {
            if (i + 1 < argc) {
                opts.command = argv[i + 1];
                opts.commandArgc = argc - i - 2;
                opts.commandArgv = const_cast<const wchar_t**>(&argv[i + 2]);
            }
            break;
        }
        // Unknown flag
        else if (arg[0] == L'-' || arg[0] == L'/') {
            fwprintf(stderr, L"Unknown option: %s\n", arg);
            opts.showHelp = true;
        }
        // Positional argument (command)
        else if (opts.command == nullptr) {
            opts.command = arg;
            opts.commandArgc = argc - i - 1;
            opts.commandArgv = const_cast<const wchar_t**>(&argv[i + 1]);
            break;
        }
    }
    
    return opts;
}

// Print version information
void PrintVersion(bool verbose) noexcept {
    const auto& info = GetVersionInfo();
    
    wprintf(L"RawrXD %hs", info.string);
    
    if (verbose) {
        wprintf(L" (%hs)\n", info.codename);
        wprintf(L"  Protocol: %u\n", info.protocol);
        wprintf(L"  Packed: 0x%08X\n", GetVersionPacked());
        wprintf(L"  Built: %hs\n", info.buildTimestamp);
        if (std::strcmp(info.gitCommit, "unknown") != 0) {
            wprintf(L"  Commit: %hs\n", info.gitCommit);
        }
    } else {
        wprintf(L"\n");
    }
}

// Print help information
void PrintHelp(const wchar_t* programName) noexcept {
    wprintf(L"RawrXD Command-Line Interface\n\n");
    wprintf(L"Usage: %s [options] [--] [command] [args...]\n\n", programName);
    wprintf(L"Options:\n");
    wprintf(L"  -v, --version       Show version information\n");
    wprintf(L"  -V, --verbose       Show verbose output\n");
    wprintf(L"  -n, --no-session    Don't connect to IDE session\n");
    wprintf(L"  -h, --help          Show this help message\n\n");
    wprintf(L"Commands:\n");
    wprintf(L"  status              Show IDE session status\n");
    wprintf(L"  exec <command>      Execute IDE command\n");
    wprintf(L"  model <subcmd>      Model management\n");
    wprintf(L"  file <path>         Open file in IDE\n\n");
    wprintf(L"Examples:\n");
    wprintf(L"  %s --version\n", programName);
    wprintf(L"  %s status\n", programName);
    wprintf(L"  %s -n file main.cpp\n", programName);
}

// Try to connect to IDE session with graceful fallback
struct SessionConnection {
    UnifiedSessionState* session = nullptr;
    bool connected = false;
    bool created = false;
    bool versionMismatch = false;
};

SessionConnection ConnectToSession(bool verbose) noexcept {
    SessionConnection conn;
    
    auto* session = new (std::nothrow) UnifiedSessionState();
    if (!session) {
        if (verbose) {
            fwprintf(stderr, L"Failed to allocate session state\n");
        }
        return conn;
    }
    
    // Try to open existing shared memory first
    if (session->Initialize(false)) {
        conn.session = session;
        conn.connected = true;
        conn.created = false;
        
        // Check protocol compatibility
        if (!session->IsProtocolCompatible()) {
            conn.versionMismatch = true;
            if (verbose) {
                fwprintf(stderr, L"Warning: Protocol version mismatch (expected %u, got %u)\n",
                        GetProtocolVersion(), session->GetProtocolVersion());
            }
        } else if (verbose) {
            wprintf(L"Connected to IDE session (protocol %u)\n", session->GetProtocolVersion());
            wprintf(L"Session version: %hs\n", session->GetRuntimeVersionString().data());
        }
        
        return conn;
    }
    
    // No existing session - create one
    if (session->Initialize(true)) {
        conn.session = session;
        conn.connected = true;
        conn.created = true;
        
        if (verbose) {
            wprintf(L"Created new IDE session\n");
        }
        
        return conn;
    }
    
    // Failed to create session
    delete session;
    if (verbose) {
        fwprintf(stderr, L"Failed to create session\n");
    }
    
    return conn;
}

void DisconnectSession(SessionConnection& conn) noexcept {
    if (conn.session) {
        conn.session->Shutdown();
        delete conn.session;
        conn.session = nullptr;
        conn.connected = false;
    }
}

// Execute CLI command
CLIReturnCode ExecuteCommand(const CLIOptions& opts, SessionConnection& conn) noexcept {
    if (!opts.command) {
        // No command - just show status
        if (conn.connected) {
            wprintf(L"IDE Session: %s\n", conn.created ? L"Created" : L"Connected");
            wprintf(L"Protocol: %u\n", conn.session->GetProtocolVersion());
            wprintf(L"Version: %hs\n", conn.session->GetRuntimeVersionString().data());
            
            auto cwd = conn.session->GetWorkingDirectory();
            auto file = conn.session->GetActiveFilePath();
            
            if (!cwd.empty()) {
                wprintf(L"Working Directory: %s\n", cwd.c_str());
            }
            if (!file.empty()) {
                wprintf(L"Active File: %s\n", file.c_str());
            }
            
            return CLIReturnCode::Success;
        } else {
            wprintf(L"No IDE session available\n");
            return CLIReturnCode::ErrorSharedMemory;
        }
    }
    
    // Handle specific commands
    if (WStrEquals(opts.command, L"status")) {
        if (!conn.connected) {
            fwprintf(stderr, L"Error: Not connected to IDE session\n");
            return CLIReturnCode::ErrorSharedMemory;
        }
        
        wprintf(L"Session Status:\n");
        wprintf(L"  Protocol: %u\n", conn.session->GetProtocolVersion());
        wprintf(L"  Version: %hs\n", conn.session->GetRuntimeVersionString().data());
        wprintf(L"  Mode: %u\n", static_cast<uint32_t>(conn.session->GetExecutionMode()));
        
        return CLIReturnCode::Success;
    }
    
    if (WStrEquals(opts.command, L"version")) {
        PrintVersion(opts.verbose);
        return CLIReturnCode::Success;
    }
    
    // Unknown command
    fwprintf(stderr, L"Unknown command: %s\n", opts.command);
    return CLIReturnCode::ErrorInvalidArgs;
}

// Entry point
int wmain(int argc, wchar_t* argv[]) {
    // Set console output to UTF-8
    SetConsoleOutputCP(CP_UTF8);
    
    // Parse arguments
    CLIOptions opts = ParseArguments(argc, argv);
    
    // Handle --version
    if (opts.showVersion) {
        PrintVersion(opts.verbose);
        return static_cast<int>(CLIReturnCode::Success);
    }
    
    // Handle --help
    if (opts.showHelp) {
        PrintHelp(argv[0]);
        return static_cast<int>(CLIReturnCode::Success);
    }
    
    // Connect to session if requested
    SessionConnection conn;
    if (opts.connectToSession) {
        conn = ConnectToSession(opts.verbose);
        
        if (!conn.connected && !opts.command) {
            // No session and no command - just show version and exit
            PrintVersion(false);
            wprintf(L"\nNo IDE session running. Use --help for usage.\n");
            return static_cast<int>(CLIReturnCode::ErrorSharedMemory);
        }
    }
    
    // Execute command
    CLIReturnCode result = ExecuteCommand(opts, conn);
    
    // Cleanup
    DisconnectSession(conn);
    
    return static_cast<int>(result);
}
