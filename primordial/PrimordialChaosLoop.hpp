#pragma once

#include <functional>
#include <memory>
#include <mutex>
#include <vector>
#include <atomic>
#include <thread>
#include <chrono>

namespace PrimordialChaos {

// Forward declaration
class PrimordialChaosEngine;

// Callback types for different events
using PrimordialChaosTickCallback = std::function<void(int64_t tickCount)>;
using PrimordialChaosUpdateCallback = std::function<void(float deltaTime)>;
using PrimordialChaosRenderCallback = std::function<void()>;

// Loop state enumeration
enum class PrimordialChaosLoopState {
    Stopped,
    Starting,
    Running,
    Paused,
    Stopping
};

// Primordial Chaos Loop - manages async runtime for primordial chaos operations
class PrimordialChaosLoop {
public:
    // Configuration
    struct Config {
        int targetTPS = 60;                    // Target ticks per second
        bool enableFrameLimiting = true;       // Enable frame rate limiting
        int maxFPS = 60;                       // Maximum frames per second
        bool enableMetrics = true;             // Enable metrics collection
        int64_t metricsIntervalMs = 1000;    // Metrics collection interval
    };

    // Initialization
    static void Init(const Config& config = Config{});
    static void Shutdown();
    static bool IsInitialized();
    static bool IsRunning();

    // Loop control
    static void Start();
    static void Stop();
    static void Pause();
    static void Resume();
    static PrimordialChaosLoopState GetState();

    // Callback registration
    static void RegisterTickCallback(const PrimordialChaosTickCallback& callback);
    static void RegisterUpdateCallback(const PrimordialChaosUpdateCallback& callback);
    static void RegisterRenderCallback(const PrimordialChaosRenderCallback& callback);
    static void UnregisterAllCallbacks();

    // Metrics
    static float GetCurrentTPS();
    static float GetCurrentFPS();
    static int64_t GetTickCount();
    static float GetAverageFrameTime();
    static float GetLastFrameTime();

    // Configuration
    static void SetTargetTPS(int tps);
    static int GetTargetTPS();
    static void SetMaxFPS(int fps);
    static int GetMaxFPS();
    static void EnableFrameLimiting(bool enable);
    static bool IsFrameLimitingEnabled();

private:
    static void LoopThreadFunc();
    static void UpdateMetrics(float deltaTime);
    static void NotifyTickCallbacks(int64_t tickCount);
    static void NotifyUpdateCallbacks(float deltaTime);
    static void NotifyRenderCallbacks();

    static bool s_initialized;
    static std::atomic<PrimordialChaosLoopState> s_state;
    static std::unique_ptr<std::thread> s_loopThread;
    static Config s_config;

    // Callbacks
    static std::mutex s_callbackMutex;
    static std::vector<PrimordialChaosTickCallback> s_tickCallbacks;
    static std::vector<PrimordialChaosUpdateCallback> s_updateCallbacks;
    static std::vector<PrimordialChaosRenderCallback> s_renderCallbacks;

    // Metrics
    static std::atomic<int64_t> s_tickCount;
    static std::atomic<float> s_currentTPS;
    static std::atomic<float> s_currentFPS;
    static std::atomic<float> s_averageFrameTime;
    static std::atomic<float> s_lastFrameTime;
    static std::chrono::steady_clock::time_point s_lastTickTime;
    static std::chrono::steady_clock::time_point s_lastFrameTime;
    static std::mutex s_metricsMutex;
};

} // namespace PrimordialChaos
