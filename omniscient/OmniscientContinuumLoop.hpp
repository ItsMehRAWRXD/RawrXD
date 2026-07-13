#pragma once

#include <functional>
#include <thread>
#include <atomic>
#include <mutex>
#include <vector>

namespace OmniscientContinuum {

// Forward declaration
class OmniscientContinuumEngine;

// Loop configuration
struct OmniscientContinuumLoopConfig {
    int targetTPS = 60;           // Target ticks per second
    int maxFPS = 60;              // Maximum frames per second
    bool enableFrameLimiting = true;
    bool enableMetrics = true;
    bool enableOmnipresentTickPropagation = true;
    bool enableMultiLayerSynchronization = true;
    bool enableCrossLayerResonance = true;
    
    OmniscientContinuumLoopConfig() = default;
};

// Runtime metrics
struct OmniscientContinuumLoopMetrics {
    float currentTPS = 0.0f;
    float currentFPS = 0.0f;
    float averageTickTimeMs = 0.0f;
    float averageFrameTimeMs = 0.0f;
    int64_t totalTicks = 0;
    int64_t totalFrames = 0;
    int64_t synchronizedLayers = 0;
    int64_t resonanceHarmonizations = 0;
    
    OmniscientContinuumLoopMetrics() = default;
};

// Main loop class
class OmniscientContinuumLoop {
public:
    // Initialization
    static bool Init(const OmniscientContinuumLoopConfig& config = OmniscientContinuumLoopConfig());
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
    static void SetConfig(const OmniscientContinuumLoopConfig& config);
    static OmniscientContinuumLoopConfig GetConfig();
    
    // Metrics
    static OmniscientContinuumLoopMetrics GetMetrics();
    static float GetCurrentTPS();
    static float GetCurrentFPS();
    static int64_t GetTickCount();
    static int64_t GetFrameCount();
    static int64_t GetSynchronizedLayers();
    static int64_t GetResonanceHarmonizations();
    
    // Callbacks
    using TickCallback = std::function<void(float deltaTime)>;
    using FrameCallback = std::function<void()>;
    using RenderCallback = std::function<void()>;
    using UpdateCallback = std::function<void(float deltaTime)>;
    using SynchronizationCallback = std::function<void()>;
    using ResonanceCallback = std::function<void()>;
    
    static void RegisterTickCallback(TickCallback callback);
    static void UnregisterTickCallback(TickCallback callback);
    static void RegisterFrameCallback(FrameCallback callback);
    static void UnregisterFrameCallback(FrameCallback callback);
    static void RegisterRenderCallback(RenderCallback callback);
    static void UnregisterRenderCallback(RenderCallback callback);
    static void RegisterUpdateCallback(UpdateCallback callback);
    static void UnregisterUpdateCallback(UpdateCallback callback);
    static void RegisterSynchronizationCallback(SynchronizationCallback callback);
    static void UnregisterSynchronizationCallback(SynchronizationCallback callback);
    static void RegisterResonanceCallback(ResonanceCallback callback);
    static void UnregisterResonanceCallback(ResonanceCallback callback);
    
    // Manual tick (for testing)
    static void Tick(float deltaTime);
    
private:
    static std::atomic<bool> s_initialized;
    static std::atomic<bool> s_running;
    static std::atomic<bool> s_paused;
    static std::atomic<bool> s_shouldStop;
    
    static OmniscientContinuumLoopConfig s_config;
    static OmniscientContinuumLoopMetrics s_metrics;
    
    static std::thread s_tickThread;
    static std::thread s_renderThread;
    static std::thread s_synchronizationThread;
    
    static std::mutex s_tickCallbackMutex;
    static std::mutex s_frameCallbackMutex;
    static std::mutex s_renderCallbackMutex;
    static std::mutex s_updateCallbackMutex;
    static std::mutex s_synchronizationCallbackMutex;
    static std::mutex s_resonanceCallbackMutex;
    static std::mutex s_metricsMutex;
    
    static std::vector<TickCallback> s_tickCallbacks;
    static std::vector<FrameCallback> s_frameCallbacks;
    static std::vector<RenderCallback> s_renderCallbacks;
    static std::vector<UpdateCallback> s_updateCallbacks;
    static std::vector<SynchronizationCallback> s_synchronizationCallbacks;
    static std::vector<ResonanceCallback> s_resonanceCallbacks;
    
    static void TickLoop();
    static void RenderLoop();
    static void SynchronizationLoop();
    static void UpdateMetrics(float tickTimeMs, float frameTimeMs);
    static void SynchronizeLayers();
    static void HarmonizeResonance();
};

} // namespace OmniscientContinuum
