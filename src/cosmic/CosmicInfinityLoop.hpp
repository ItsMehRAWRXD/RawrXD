#pragma once

#include <functional>
#include <thread>
#include <atomic>
#include <mutex>
#include <vector>

namespace CosmicInfinity {

// Forward declaration
class CosmicInfinityEngine;

// Loop configuration
struct CosmicInfinityLoopConfig {
    int targetTPS = 60;           // Target ticks per second
    int maxFPS = 60;              // Maximum frames per second
    bool enableFrameLimiting = true;
    bool enableMetrics = true;
    
    CosmicInfinityLoopConfig() = default;
};

// Runtime metrics
struct CosmicInfinityLoopMetrics {
    float currentTPS = 0.0f;
    float currentFPS = 0.0f;
    float averageTickTimeMs = 0.0f;
    float averageFrameTimeMs = 0.0f;
    int64_t totalTicks = 0;
    int64_t totalFrames = 0;
    
    CosmicInfinityLoopMetrics() = default;
};

// Main loop class
class CosmicInfinityLoop {
public:
    // Initialization
    static bool Init(const CosmicInfinityLoopConfig& config = CosmicInfinityLoopConfig());
    static void Shutdown();
    static bool IsInitialized();
    
    // Control
    static void Start();
    static void Stop();
    static bool IsRunning();
    static void Pause();
    static void Resume();
    static bool IsPaused();
    
    // Configuration
    static void SetConfig(const CosmicInfinityLoopConfig& config);
    static CosmicInfinityLoopConfig GetConfig();
    
    // Metrics
    static CosmicInfinityLoopMetrics GetMetrics();
    static float GetCurrentTPS();
    static float GetCurrentFPS();
    static int64_t GetTickCount();
    static int64_t GetFrameCount();
    
    // Callbacks
    using TickCallback = std::function<void(float deltaTime)>;
    using FrameCallback = std::function<void()>;
    using RenderCallback = std::function<void()>;
    using UpdateCallback = std::function<void(float deltaTime)>;
    
    static void RegisterTickCallback(TickCallback callback);
    static void UnregisterTickCallback(TickCallback callback);
    static void RegisterFrameCallback(FrameCallback callback);
    static void UnregisterFrameCallback(FrameCallback callback);
    static void RegisterRenderCallback(RenderCallback callback);
    static void UnregisterRenderCallback(RenderCallback callback);
    static void RegisterUpdateCallback(UpdateCallback callback);
    static void UnregisterUpdateCallback(UpdateCallback callback);
    
    // Manual tick (for testing)
    static void Tick(float deltaTime);
    
private:
    static std::atomic<bool> s_initialized;
    static std::atomic<bool> s_running;
    static std::atomic<bool> s_paused;
    static std::atomic<bool> s_shouldStop;
    
    static CosmicInfinityLoopConfig s_config;
    static CosmicInfinityLoopMetrics s_metrics;
    
    static std::thread s_tickThread;
    static std::thread s_renderThread;
    
    static std::mutex s_tickCallbackMutex;
    static std::mutex s_frameCallbackMutex;
    static std::mutex s_renderCallbackMutex;
    static std::mutex s_updateCallbackMutex;
    static std::mutex s_metricsMutex;
    
    static std::vector<TickCallback> s_tickCallbacks;
    static std::vector<FrameCallback> s_frameCallbacks;
    static std::vector<RenderCallback> s_renderCallbacks;
    static std::vector<UpdateCallback> s_updateCallbacks;
    
    static void TickLoop();
    static void RenderLoop();
    static void UpdateMetrics(float tickTimeMs, float frameTimeMs);
};

} // namespace CosmicInfinity
