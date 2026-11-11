// ============================================================================
// RawrXD_IDE_Integration.hpp - Complete IDE Integration Header
// ============================================================================
// Production-ready integration of Ghost Text + AI Inference Bridge
// ============================================================================

#pragma once

#include <Windows.h>
#include <string>

// Forward declarations
namespace Deep2 {
    class Deep2Engine;
}

// ============================================================================
// IDE Initialization
// ============================================================================

// Initialize the complete IDE integration
// Call this after creating main window, editor, and status bar
// hMainWindow: Main IDE window handle
// hEditor: Scintilla editor handle
// hStatusBar: Status bar handle (can be nullptr)
bool RawrXD_IDE_Initialize(HWND hMainWindow, HWND hEditor, HWND hStatusBar);

// Shutdown IDE integration
// Call before destroying windows
void RawrXD_IDE_Shutdown();

// Set the Deep2Engine instance for AI completion
// Call this after loading a model
bool RawrXD_IDE_SetEngine(Deep2::Deep2Engine* engine);

// ============================================================================
// Completion Control
// ============================================================================

// Request AI completion at current cursor position
// This will start the inference and stream tokens to ghost text
void RawrXD_IDE_RequestCompletion();

// Cancel current generation
void RawrXD_IDE_CancelGeneration();

// Check if AI is currently generating
bool RawrXD_IDE_IsGenerating();

// ============================================================================
// Accelerator Handling
// ============================================================================

// Process accelerator keys (Ctrl+Space, Ctrl+Break, etc.)
// Call this in your message loop before DispatchMessage
// Returns true if accelerator was processed
bool RawrXD_IDE_ProcessAccel(MSG* pMsg);

// ============================================================================
// Telemetry
// ============================================================================

// Export completion telemetry as JSON string
// Includes: requestId, tokensGenerated, firstTokenLatencyMs, tokensPerSecond, etc.
std::string RawrXD_IDE_ExportTelemetry();

// ============================================================================
// Integration Example
// ============================================================================
/*
// In your WinMain or initialization:
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nCmdShow) {
    // Create windows
    HWND hMainWnd = CreateWindow(...);
    HWND hEditor = CreateWindowEx(..., "Scintilla", ...);
    HWND hStatus = CreateWindow(STATUSCLASSNAME, ...);
    
    // Initialize IDE integration
    if (!RawrXD_IDE_Initialize(hMainWnd, hEditor, hStatus)) {
        MessageBox(hMainWnd, "Failed to initialize IDE", "Error", MB_OK);
        return 1;
    }
    
    // Load model and set engine
    Deep2::Deep2Engine* engine = new Deep2::Deep2Engine();
    if (engine->loadModel("model.gguf")) {
        RawrXD_IDE_SetEngine(engine);
    }
    
    // Message loop with accelerator handling
    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        if (!RawrXD_IDE_ProcessAccel(&msg)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }
    
    // Cleanup
    RawrXD_IDE_Shutdown();
    delete engine;
    return 0;
}
*/
