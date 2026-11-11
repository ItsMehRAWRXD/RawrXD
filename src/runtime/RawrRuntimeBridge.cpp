// d:\rawrxd\src\runtime\RawrRuntimeBridge.cpp
// C-Linkage bridge between MASM entry point (RawrXDMain.asm) and C++ runtime
// Exposes unmangled extern "C" symbols that the assembler can resolve.
//
// This file must be compiled with /EHsc and linked into the final binary.
// It provides the five entry points called from RawrXDMain.asm:
//   RawrXD_InitializePlatform
//   RawrXD_ShutdownPlatform
//   RawrXD_PumpMessageQueue
//   RawrXD_IsPlatformRunning
//   RawrXD_SignalPlatformPanic

#include "RawrRuntime.hpp"
#include "../ui/RawrWindow.hpp"
#include <windows.h>
#include <cstdio>

// ---------------------------------------------------------------------------
// Direct, unmangled external exports matching RawrXDMain.asm parameters
// ---------------------------------------------------------------------------
extern "C" {

void __stdcall RawrXD_InitializePlatform() {
    // Resolve the singleton runtime context
    rawr::RawrRuntime::Get().Initialize();

    // Create the main application window
    rawr::WindowConfig config;
    config.title = "RawrXD Sovereign Runtime";
    config.width = 1280;
    config.height = 800;
    rawr::RawrWindow::Get().Create(config);
}

void __stdcall RawrXD_ShutdownPlatform() {
    rawr::RawrWindow::Get().Destroy();
    rawr::RawrRuntime::Get().Shutdown();
}

void __stdcall RawrXD_PumpMessageQueue() {
    MSG msg;
    while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
}

int __stdcall RawrXD_IsPlatformRunning() {
    return rawr::RawrRuntime::Get().IsInitialized() ? 1 : 0;
}

void __stdcall RawrXD_SignalPlatformPanic(const char* errorText) {
    // Flush any pending diagnostics before showing the error
    rawr::RawrRuntime::Get().Log(rawr::LogLevel::Fatal, errorText);
    MessageBoxA(NULL, errorText, "RawrXD — CRITICAL EXCEPTION FLUSH",
                MB_ICONERROR | MB_OK | MB_SYSTEMMODAL);
}

} // extern "C"
