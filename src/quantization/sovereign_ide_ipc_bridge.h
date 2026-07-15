// =============================================================================
// sovereign_ide_ipc_bridge.h
// Named Pipe IPC Bridge Header
// =============================================================================

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// =============================================================================
// Callback Types
// =============================================================================

typedef void (*CompletionTokenCallback)(const char* token, bool isFinal);
typedef void (*CompletionCompleteCallback)(uint32_t totalTokens, float totalTimeMs);
typedef void (*ErrorCallback)(const char* errorMessage);

// =============================================================================
// Core API
// =============================================================================

// Initialize IPC bridge
// asServer: true = Sovereign Engine (server), false = IDE (client)
__declspec(dllexport) bool Sovereign_IPC_Init(bool asServer);

// Shutdown IPC bridge
__declspec(dllexport) void Sovereign_IPC_Shutdown(void);

// Send completion request (IDE → Sovereign)
__declspec(dllexport) bool Sovereign_IPC_SendCompletionRequest(
    const char* file_path,
    const char* content,
    uint32_t cursor_line,
    uint32_t cursor_column,
    const char* language
);

// Send cancel request (IDE → Sovereign)
__declspec(dllexport) bool Sovereign_IPC_SendCancelRequest(void);

// Set callbacks for incoming messages
__declspec(dllexport) void Sovereign_IPC_SetCallbacks(
    CompletionTokenCallback onToken,
    CompletionCompleteCallback onComplete,
    ErrorCallback onError
);

// Poll for incoming messages (call frequently, e.g., every 16ms)
__declspec(dllexport) void Sovereign_IPC_Poll(void);

// Check connection status
__declspec(dllexport) bool Sovereign_IPC_IsConnected(void);

// =============================================================================
// Server-Side Response Helpers
// =============================================================================

// Send token to IDE (Sovereign → IDE)
__declspec(dllexport) bool Sovereign_IPC_SendToken(
    const char* token,
    bool isFinal,
    uint32_t requestId
);

// Send completion done (Sovereign → IDE)
__declspec(dllexport) bool Sovereign_IPC_SendComplete(
    uint32_t totalTokens,
    float totalTimeMs,
    uint32_t requestId
);

// Send error (Sovereign → IDE)
__declspec(dllexport) bool Sovereign_IPC_SendError(
    const char* errorMessage,
    uint32_t requestId
);

// =============================================================================
// Constants
// =============================================================================

#define SOVEREIGN_PIPE_NAME         "\\\\.\\pipe\\SovereignIPC"
#define SOVEREIGN_IPC_VERSION       1
#define SOVEREIGN_IPC_MAGIC           0x534F5645  // 'SOVE'

#ifdef __cplusplus
}
#endif
