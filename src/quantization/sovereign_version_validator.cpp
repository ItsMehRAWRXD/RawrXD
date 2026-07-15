// =============================================================================
// sovereign_version_validator.cpp
// ABI Version Compatibility Checker for Production Deployment
//
// Phase 16A: Prevents "DLL Hell" and incompatible ABI calls
// =============================================================================

#include "sovereign_version_validator.h"
#include <windows.h>
#include <stdio>
#include <string>

// =============================================================================
// Version Constants
// =============================================================================

#define SOVEREIGN_VERSION_MAJOR     1
#define SOVEREIGN_VERSION_MINOR     0
#define SOVEREIGN_VERSION_PATCH     0
#define SOVEREIGN_VERSION_BUILD     0

#define SOVEREIGN_ABI_VERSION       1
#define SOVEREIGN_ABI_MIN_COMPAT    1

// =============================================================================
// Version Structure
// =============================================================================

struct SovereignVersion {
    uint16_t major;
    uint16_t minor;
    uint16_t patch;
    uint16_t build;
    uint16_t abiVersion;
    
    bool IsCompatibleWith(const SovereignVersion& other) const {
        // ABI version must match exactly for now
        // Future: Allow backward compatibility within major version
        return abiVersion == other.abiVersion;
    }
    
    std::string ToString() const {
        char buf[256];
        snprintf(buf, sizeof(buf), "%d.%d.%d.%d (ABI %d)",
                 major, minor, patch, build, abiVersion);
        return std::string(buf);
    }
};

// Current version (compiled into IDE plugin)
static const SovereignVersion IDE_VERSION = {
    SOVEREIGN_VERSION_MAJOR,
    SOVEREIGN_VERSION_MINOR,
    SOVEREIGN_VERSION_PATCH,
    SOVEREIGN_VERSION_BUILD,
    SOVEREIGN_ABI_VERSION
};

// =============================================================================
// Version Query
// =============================================================================

SovereignVersion QueryEngineVersion(const char* enginePath) {
    SovereignVersion version = {0, 0, 0, 0, 0};
    
    // Build command line
    char cmdLine[MAX_PATH + 32];
    snprintf(cmdLine, sizeof(cmdLine), "\"%s\" --version", enginePath);
    
    // Create pipes for stdout capture
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = nullptr;
    
    HANDLE hReadPipe, hWritePipe;
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        return version;
    }
    
    // Set up process
    STARTUPINFOA si = { sizeof(si) };
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;
    
    PROCESS_INFORMATION pi = {};
    
    BOOL created = CreateProcessA(
        nullptr,
        cmdLine,
        nullptr,
        nullptr,
        TRUE,
        CREATE_NO_WINDOW,
        nullptr,
        nullptr,
        &si,
        &pi
    );
    
    if (!created) {
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return version;
    }
    
    // Close write end in parent
    CloseHandle(hWritePipe);
    
    // Read output
    char output[1024];
    DWORD bytesRead;
    std::string versionOutput;
    
    while (ReadFile(hReadPipe, output, sizeof(output) - 1, &bytesRead, nullptr) && bytesRead > 0) {
        output[bytesRead] = '\0';
        versionOutput += output;
    }
    
    // Cleanup
    CloseHandle(hReadPipe);
    WaitForSingleObject(pi.hProcess, 5000);  // 5 second timeout
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    // Parse version string
    // Expected format: "Sovereign Engine v1.0.0.0 (ABI 1)"
    int major, minor, patch, build, abi;
    if (sscanf(versionOutput.c_str(), 
               "Sovereign Engine v%d.%d.%d.%d (ABI %d)",
               &major, &minor, &patch, &build, &abi) == 5) {
        version.major = static_cast<uint16_t>(major);
        version.minor = static_cast<uint16_t>(minor);
        version.patch = static_cast<uint16_t>(patch);
        version.build = static_cast<uint16_t>(build);
        version.abiVersion = static_cast<uint16_t>(abi);
    }
    
    return version;
}

// =============================================================================
// Public API
// =============================================================================

extern "C" {

__declspec(dllexport) bool Sovereign_ValidateVersion(
    const char* enginePath,
    char* errorBuffer,
    size_t errorBufferSize
) {
    if (!enginePath || !errorBuffer || errorBufferSize == 0) {
        return false;
    }
    
    // Query engine version
    SovereignVersion engineVersion = QueryEngineVersion(enginePath);
    
    // Check if query succeeded
    if (engineVersion.major == 0 && engineVersion.abiVersion == 0) {
        snprintf(errorBuffer, errorBufferSize,
                 "Failed to query engine version. Engine may be corrupted or incompatible.");
        return false;
    }
    
    // Check ABI compatibility
    if (!IDE_VERSION.IsCompatibleWith(engineVersion)) {
        snprintf(errorBuffer, errorBufferSize,
                 "ABI version mismatch: IDE requires ABI %d, engine has ABI %d. "
                 "Please update the Sovereign Engine to version %s or compatible.",
                 IDE_VERSION.abiVersion,
                 engineVersion.abiVersion,
                 IDE_VERSION.ToString().c_str());
        return false;
    }
    
    // Check minimum version (optional - for feature requirements)
    if (engineVersion.major < IDE_VERSION.major) {
        snprintf(errorBuffer, errorBufferSize,
                 "Engine version too old: IDE requires %s or newer, engine is %s. "
                 "Please update the Sovereign Engine.",
                 IDE_VERSION.ToString().c_str(),
                 engineVersion.ToString().c_str());
        return false;
    }
    
    // Version is compatible
    return true;
}

__declspec(dllexport) void Sovereign_GetVersionString(char* buffer, size_t bufferSize) {
    if (!buffer || bufferSize == 0) return;
    
    std::string version = IDE_VERSION.ToString();
    strncpy(buffer, version.c_str(), bufferSize - 1);
    buffer[bufferSize - 1] = '\0';
}

__declspec(dllexport) uint16_t Sovereign_GetABIVersion() {
    return SOVEREIGN_ABI_VERSION;
}

__declspec(dllexport) bool Sovereign_IsVersionCompatible(
    uint16_t engineAbiVersion
) {
    return engineAbiVersion == SOVEREIGN_ABI_VERSION;
}

} // extern "C"

// =============================================================================
// Engine-side Version Reporting
// =============================================================================

#ifdef SOVEREIGN_ENGINE_BUILD

// This section compiled into Sovereign_Engine.exe
#include <stdio.h>

int main(int argc, char* argv[]) {
    // Check for --version flag
    if (argc > 1 && strcmp(argv[1], "--version") == 0) {
        printf("Sovereign Engine v%d.%d.%d.%d (ABI %d)\n",
               SOVEREIGN_VERSION_MAJOR,
               SOVEREIGN_VERSION_MINOR,
               SOVEREIGN_VERSION_PATCH,
               SOVEREIGN_VERSION_BUILD,
               SOVEREIGN_ABI_VERSION);
        return 0;
    }
    
    // Normal engine startup...
    return 0;
}

#endif // SOVEREIGN_ENGINE_BUILD
