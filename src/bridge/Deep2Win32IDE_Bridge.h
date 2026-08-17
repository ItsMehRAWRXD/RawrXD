//==============================================================================
// Deep2Win32IDE_Bridge.h
// C API Header for Deep2-to-Win32IDE Bridge
// Phase 15B: Real Executable Build
//==============================================================================

#pragma once

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

// Initialize the Deep2 bridge
// Call this once at Win32IDE startup
__declspec(dllexport) BOOL Deep2Bridge_Initialize(HWND ideWindow);

// Shutdown the bridge
__declspec(dllexport) void Deep2Bridge_Shutdown();

// Load a GGUF model
__declspec(dllexport) BOOL Deep2Bridge_LoadModel(LPCSTR modelPath);

// Start token generation (cyclonic flow)
__declspec(dllexport) BOOL Deep2Bridge_StartGeneration(
    LPCSTR prompt,
    float temperature,
    float topP,
    int maxTokens,
    HWND targetWindow
);

// Check if generation is active
__declspec(dllexport) BOOL Deep2Bridge_IsGenerating();

// Get current tokens per second
__declspec(dllexport) float Deep2Bridge_GetTokensPerSecond();

// Execute Tib-Bit transition (MASM64)
__declspec(dllexport) ULONG64 Deep2Bridge_ExecuteTibBit(
    ULONG64 tierIndex,
    LPVOID stateContext
);

// Window messages for token streaming
#define WM_USER_DEEP2_TOKEN    (WM_USER + 200)
#define WM_USER_DEEP2_COMPLETE (WM_USER + 201)

#ifdef __cplusplus
}
#endif
