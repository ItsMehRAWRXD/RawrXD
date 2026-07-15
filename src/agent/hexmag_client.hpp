// hexmag_client.hpp — HexMag CLI ↔ SovereignKernelJIT integration header
#pragma once

#include <string>
#include <functional>

#ifdef __cplusplus
extern "C" {
#endif

// ---------------------------------------------------------------------------
// HexMag JIT Pipeline API
// ---------------------------------------------------------------------------

/// Initialize the JIT buffer with RWX memory.
/// @param capacity Size in bytes for the JIT code buffer.
/// @return 0 on success, -1 on failure.
__declspec(dllexport) int HexMagJIT_Init(size_t capacity);

/// Shutdown and free the JIT buffer.
__declspec(dllexport) void HexMagJIT_Shutdown(void);

/// Emit a simple "exit 42" function into the JIT buffer.
/// @return Number of bytes emitted, or negative on error.
__declspec(dllexport) int HexMagJIT_EmitExit42(void);

/// Execute the emitted JIT code.
/// @return The integer result from JIT execution, or negative on error.
__declspec(dllexport) int HexMagJIT_Execute(void);

/// Full CLI entry point — initializes, emits, executes, and shuts down.
/// @param argc Argument count.
/// @param argv Argument vector.
/// @return 0 if JIT returned 42, 1 otherwise.
__declspec(dllexport) int HexMagCLI_Run(int argc, const char** argv);

/// Legacy stub — kept for backward compatibility.
__declspec(dllexport) void hexmag_connect_stub(void);

#ifdef __cplusplus
}
#endif

// ---------------------------------------------------------------------------
// HexMag Service API (C++ namespace)
// ---------------------------------------------------------------------------

namespace RawrXD {
namespace HexMag {

/// Result structure for ask operations.
struct AskResult {
    bool success = false;
    std::string answer;
    std::string error;
};

/// Result structure for stream operations.
struct StreamResult {
    bool success = false;
    std::string error;
    bool goalSatisfied = false;
};

/// Try to launch the HexMag background service.
/// @return true if service started successfully, false otherwise.
inline bool tryLaunchService() { return false; }

/// Check if the HexMag service is healthy.
/// @return true if service is healthy, false otherwise.
inline bool healthCheck() { return false; }

/// Resolve the base URL for the HexMag service.
/// @return The base URL as a string.
inline std::string resolveBaseUrl() { return "http://localhost:8765"; }

/// Ask with auto-start.
/// @param prompt The prompt to send.
/// @param context Optional code context.
/// @return AskResult with success, answer, and error fields.
inline AskResult askWithAutoStart(const std::string& prompt, const std::string& context) {
    (void)prompt; (void)context;
    AskResult result;
    result.success = false;
    result.error = "HexMag service not implemented";
    return result;
}

/// Stream agent with auto-start.
/// @param prompt The prompt to send.
/// @param onToken Callback for each token received.
/// @param timeoutSeconds Timeout in seconds (default 30.0).
/// @return StreamResult with success, error, and goalSatisfied fields.
inline StreamResult streamAgentWithAutoStart(const std::string& prompt, 
                                              std::function<void(const std::string&)> onToken, 
                                              float timeoutSeconds = 30.0f) {
    (void)prompt; (void)onToken; (void)timeoutSeconds;
    StreamResult result;
    result.success = false;
    result.error = "HexMag service not implemented";
    result.goalSatisfied = false;
    return result;
}

} // namespace HexMag
} // namespace RawrXD
