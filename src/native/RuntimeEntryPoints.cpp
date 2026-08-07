// ============================================================================
// RuntimeEntryPoints.cpp — C Runtime Entry Points for MASM Main
// These are called from RawrXDMain.asm (WinMain PROC)
// ============================================================================

#include "../runtime/RawrRuntime.hpp"
#include "../deep2/Deep2Bridge.hpp"
#include "../ui/RawrWindow.hpp"
#include <cstdio>

// ============================================================================
// InitializeRuntime — Phase 1: bootstrap the runtime core
// ============================================================================
extern "C" __declspec(dllexport) int InitializeRuntime() {
    printf("[RuntimeEntry] InitializeRuntime\n");
    if (!rawr::RawrRuntime::Get().Initialize()) {
        printf("[RuntimeEntry] ERROR: RawrRuntime::Initialize failed\n");
        return 0;
    }
    return 1;
}

// ============================================================================
// InitializeEngine — Phase 2: bootstrap the Deep2 inference engine
// ============================================================================
extern "C" __declspec(dllexport) int InitializeEngine() {
    printf("[RuntimeEntry] InitializeEngine\n");
    rawr::EngineConfig config;
    config.modelPath = "";
    config.modelType = "GGUF";
    config.contextSize = 2048;
    config.temperature = 0.7f;
    config.topK = 40;
    config.topP = 0.95f;
    config.useKVCache = true;
    config.useGPU = true;
    if (!rawr::Deep2Bridge::Get().Initialize(config)) {
        printf("[RuntimeEntry] ERROR: Deep2Bridge::Initialize failed\n");
        return 0;
    }
    return 1;
}

// ============================================================================
// CreateMainWindow — Phase 3: create the application window
// ============================================================================
extern "C" __declspec(dllexport) void* CreateMainWindow(void* hInstance) {
    printf("[RuntimeEntry] CreateMainWindow\n");
    rawr::WindowConfig config;
    config.title = "RawrXD Sovereign Runtime";
    config.width = 1280;
    config.height = 800;
    if (!rawr::RawrWindow::Get().Create(config)) {
        printf("[RuntimeEntry] ERROR: RawrWindow::Create failed\n");
        return nullptr;
    }
    return rawr::RawrWindow::Get().GetHandle();
}

// ============================================================================
// RunMessageLoop — Phase 4: enter the Windows message loop
// ============================================================================
extern "C" __declspec(dllexport) void RunMessageLoop() {
    printf("[RuntimeEntry] RunMessageLoop\n");
    rawr::RawrWindow::Get().Run();
}

// ============================================================================
// ShutdownRuntime — Phase 5: clean shutdown
// ============================================================================
extern "C" __declspec(dllexport) void ShutdownRuntime() {
    printf("[RuntimeEntry] ShutdownRuntime\n");
    rawr::Deep2Bridge::Get().Shutdown();
    rawr::RawrRuntime::Get().Shutdown();
}
