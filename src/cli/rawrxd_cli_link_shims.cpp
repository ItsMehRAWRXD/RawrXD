// rawrxd_cli_link_shims.cpp - Link compatibility shims for CLI build
// This file provides stub implementations for CLI link compatibility

#include <windows.h>
#include <cstdint>

// Stub implementations for CLI link compatibility
extern "C" {
    // Add any missing symbol stubs here
    // These are placeholder implementations for link-time compatibility
}

// CLI entry point shim
namespace RawrXD {
namespace CLI {

    // Placeholder for CLI initialization
    int InitializeCLI() {
        return 0;
    }

    // Placeholder for CLI shutdown
    void ShutdownCLI() {
    }

} // namespace CLI
} // namespace RawrXD

// Link compatibility exports
#ifdef _WIN32
#pragma comment(linker, "/EXPORT:RawrXD_CLI_Initialize")
#pragma comment(linker, "/EXPORT:RawrXD_CLI_Shutdown")
#endif
