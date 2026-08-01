// src/engine/EngineMain.cpp
// Entry point for RawrXDEngine.exe
// Initializes all subsystems and runs the engine main loop.

#include "Engine.hpp"
#include "Renderer/GpuDevice.hpp"
#include "AIRuntime/AIRuntime.hpp"
#include "../orchestration/BackendManager.hpp"
#include "../metrics/BackendTelemetry.hpp"
#include "../ui/GdiDashboardPainter.hpp"
#include <iostream>
#include <thread>
#include <chrono>

int main() {
    std::cout << "========================================\n";
    std::cout << "  RawrXD Engine v1.0.0\n";
    std::cout << "  Phase 7A — Native Engine Kernel\n";
    std::cout << "========================================\n\n";

    // 1. Initialize Backend Orchestration
    std::cout << "[Init] BackendManager...\n";
    BackendManager backendMgr;
    if (!backendMgr.Initialize()) {
        std::cerr << "[FATAL] BackendManager initialization failed\n";
        return 1;
    }

    // 2. Initialize GPU Device
    std::cout << "[Init] GPU Device...\n";
    IGpuDevice* gpu = CreateGpuDevice();
    if (!gpu->Initialize()) {
        std::cerr << "[FATAL] GPU device initialization failed\n";
        delete gpu;
        return 1;
    }
    auto adapters = gpu->EnumerateAdapters();
    std::cout << "[GPU] Found " << adapters.size() << " adapter(s)\n";
    for (size_t i = 0; i < adapters.size(); i++) {
        std::cout << "  [" << i << "] " << adapters[i].name
                  << " (" << (adapters[i].dedicatedVramBytes / (1024*1024)) << " MB VRAM)\n";
    }

    // 3. Initialize AI Runtime
    std::cout << "[Init] AI Runtime...\n";
    IAIRuntime* ai = nullptr;
    InferenceConfig aiConfig;
    aiConfig.modelPath = "models/sovereign-demo.gguf";
    aiConfig.contextSize = 4096;
    aiConfig.temperature = 0.7f;

    // Check if model file exists before attempting to load
    bool modelExists = false;
    FILE* f = fopen(aiConfig.modelPath.c_str(), "rb");
    if (f) { modelExists = true; fclose(f); }

    if (modelExists) {
        ai = CreateAIRuntime();
        if (!ai->Initialize(aiConfig)) {
            std::cerr << "[WARN] AI Runtime initialization failed (model may be incompatible)\n";
            delete ai;
            ai = nullptr;
        }
    } else {
        std::cout << "[Init] No model file found at '" << aiConfig.modelPath
                  << "' — AI runtime will be inactive\n";
        std::cout << "[Init] Place a GGUF model at that path to enable inference\n";
    }

    // 4. Initialize Telemetry
    std::cout << "[Init] Telemetry...\n";
    BackendTelemetry telemetry;

    // 5. Initialize Engine
    std::cout << "[Init] Engine Main Loop...\n";
    EngineConfig config;
    config.windowTitle = "RawrXD Engine — Sovereign Runtime";
    config.windowWidth = 1280;
    config.windowHeight = 720;
    config.targetFps = 60.0;
    config.enableAI = true;

    Engine engine;
    if (!engine.Initialize(config)) {
        std::cerr << "[FATAL] Engine initialization failed\n";
        delete gpu;
        delete ai;
        return 1;
    }

    // 6. Register callbacks
    engine.SetUpdateCallback([&](const FrameTiming& ft) {
        // Update AI inference rate
        if (ft.frameNumber % 60 == 0) {
            telemetry.SetInferenceVelocity(ai->GetTokensPerSecond());
        }
    });

    engine.SetRenderCallback([&](const FrameTiming& ft) {
        // Print FPS every 120 frames
        if (ft.frameNumber % 120 == 0) {
            std::cout << "[Frame " << ft.frameNumber
                      << "] FPS: " << ft.fps
                      << " | CPU: " << ft.cpuLoadPercent << "%"
                      << " | Tokens/s: " << ai->GetTokensPerSecond()
                      << "\n";
        }
    });

    // 7. Run the demo
    std::cout << "\n=== Engine Main Loop Started ===\n";
    std::cout << "Press Ctrl+C to exit\n\n";

    // Run for 5 seconds in demo mode, then exit
    auto demoStart = std::chrono::steady_clock::now();
    while (engine.IsRunning()) {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - demoStart).count();
        if (elapsed >= 5) {
            std::cout << "\n[Done] Demo completed (5 seconds)\n";
            break;
        }
        engine.FrameTick();
        std::this_thread::sleep_for(std::chrono::milliseconds(16)); // ~60 FPS
    }

    // 8. Shutdown
    engine.Shutdown();
    ai->Shutdown();
    gpu->Shutdown();

    delete ai;
    delete gpu;

    std::cout << "\n=== RawrXD Engine Shutdown Complete ===\n";
    return 0;
}
