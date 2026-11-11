// ============================================================================
// Win32IDE_AgentBridge_Init.hpp - AgentBridge Safe Initialization
// ============================================================================
// Provides SEH-protected initialization for the AgentBridge subsystem.
// Prevents IDE crashes if AgentBridge initialization fails.
//
// Usage:
//   if (AgentBridgeInit::InitializeSafe()) {
//       // AgentBridge is ready
//   } else {
//       // Continue without AI bridge
//   }
// ============================================================================

#pragma once

#include <string>

// Forward declaration
class Win32IDE;

namespace RawrXD {
namespace AgentBridgeInit {

// Initialization result codes
enum class InitResult {
    Success = 0,
    AlreadyInitialized,
    ConfigDisabled,
    MissingConfig,
    BackendNotReady,
    ExceptionCaught,
    UnknownError
};

// Safe initialization with SEH protection
// Returns true if AgentBridge is ready to use
bool InitializeSafe(Win32IDE* ide);

// Get detailed result of last initialization attempt
InitResult GetLastResult();
const char* GetLastResultString();

// Check if AgentBridge is currently initialized
bool IsInitialized();

// Shutdown AgentBridge gracefully
void Shutdown();

// Retry initialization (for menu commands)
bool RetryInitialization(Win32IDE* ide);

// Get initialization status for UI
struct InitStatus {
    bool isInitialized;
    bool isEnabled;
    std::string lastError;
    int initAttempts;
    bool canRetry;
};
InitStatus GetStatus();

} // namespace AgentBridgeInit
} // namespace RawrXD

// ============================================================================
// C-compatible API for MASM/plugins
// ============================================================================

extern "C" {
    __declspec(dllexport) int RawrXD_AgentBridge_Initialize(void* ide);
    __declspec(dllexport) int RawrXD_AgentBridge_IsInitialized(void);
    __declspec(dllexport) void RawrXD_AgentBridge_Shutdown(void);
}
