// rawrxd_cli_link_shims.cpp - Link compatibility shims for CLI build
// This file provides link compatibility implementations for CLI build

#include <windows.h>
#include <cstdint>
#include <cstdio>

// Forward declaration to avoid including full header
namespace RawrXD {
    class CommandRegistry {
    public:
        static CommandRegistry& Instance();
        void Initialize();
        void Shutdown();
    };
}

// Link compatibility implementations for CLI
extern "C" {
    // Add any missing symbol implementations here
    // These provide link-time compatibility
}

// CLI entry point shim
namespace RawrXD {
namespace CLI {

    // Initialize CLI subsystem
    int InitializeCLI() {
        // Set up console output
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hOut != INVALID_HANDLE_VALUE) {
            // Enable ANSI escape codes
            DWORD mode = 0;
            if (GetConsoleMode(hOut, &mode)) {
                mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
                SetConsoleMode(hOut, mode);
            }
        }
        
        // Initialize command registry
        CommandRegistry::Instance().Initialize();
        
        return 0;
    }

    // Shutdown CLI subsystem
    void ShutdownCLI() {
        // Flush output
        fflush(stdout);
        fflush(stderr);
        
        // Cleanup command registry
        CommandRegistry::Instance().Shutdown();
    }

} // namespace CLI
} // namespace RawrXD

// Link compatibility exports
#ifdef _WIN32
#pragma comment(linker, "/EXPORT:RawrXD_CLI_Initialize")
#pragma comment(linker, "/EXPORT:RawrXD_CLI_Shutdown")
#endif
