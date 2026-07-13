#pragma once

#include "CosmicUnityEngine.hpp"
#include <atomic>
#include <thread>
#include <functional>
#include <chrono>

namespace CosmicUnity {

// Runtime metrics structure
struct CosmicUnityMetrics {
    std::atomic<uint64_t> tickCount{0};
    std::atomic<uint64_t> frameCount{0};
    std::atomic<double> currentTPS{0.0};
    std::atomic<double> currentFPS{0.0};
    std::atomic<bool> isRunning{false};
    std::atomic<bool> isPaused{false};
    std::atomic<double> lastSyncTime{0.0};
    std::atomic<double> lastHarmonyTime{0.0};
    std::atomic<uint64_t> syncCount{0};
    std::atomic<uint64_t> harmonyCount{0};

    json ToJson() const {
        return json{
            {"tickCount", tickCount.load()},
            {"frameCount", frameCount.load()},
            {"currentTPS", currentTPS.load()},
            {"currentFPS", currentFPS.load()},
            {"isRunning", isRunning.load()},
            {"isPaused", isPaused.load()},
            {"lastSyncTime", lastSyncTime.load()},
            {"lastHarmonyTime", lastHarmonyTime.load()},
            {"syncCount", syncCount.load()},
            {"harmonyCount", harmonyCount.load()}
        };
    }
};

// Configuration structure
struct CosmicUnityConfig {
    double targetTPS = 60.0;
    double maxFPS = 60.0;
    bool enableFrameLimiting = true;
    bool enableMetrics = true;
    bool enableOmnipresentTickPropagation = true;
    bool enableMultiLayerSynchronization = true;
    bool enableCrossLayerHarmonyHarmonization = true;
    double syncIntervalMs = 100.0;
    double harmonyIntervalMs = 100.0;

    json ToJson() const {
        return json{
            {"targetTPS", targetTPS},
            {"maxFPS", maxFPS},
            {"enableFrameLimiting", enableFrameLimiting},
            {"enableMetrics", enableMetrics},
            {"enableOmnipresentTickPropagation", enableOmnipresentTickPropagation},
            {"enableMultiLayerSynchronization", enableMultiLayerSynchronization},
            {"enableCrossLayerHarmonyHarmonization", enableCrossLayerHarmonyHarmonization},
            {"syncIntervalMs", syncIntervalMs},
            {"harmonyIntervalMs", harmonyIntervalMs}
        };
    }

    static CosmicUnityConfig FromJson(const json& j) {
        CosmicUnityConfig config;
        config.targetTPS = j.value("targetTPS", 60.0);
        config.maxFPS = j.value("maxFPS", 60.0);
        config.enableFrameLimiting = j.value("enableFrameLimiting", true);
        config.enableMetrics = j.value("enableMetrics", true);
        config.enableOmnipresentTickPropagation = j.value("enableOmnipresentTickPropagation", true);
        config.enableMultiLayerSynchronization = j.value("enableMultiLayerSynchronization", true);
        config.enableCrossLayerHarmonyHarmonization = j.value("enableCrossLayerHarmonyHarmonization", true);
        config.syncIntervalMs = j.value("syncIntervalMs", 100.0);
        config.harmonyIntervalMs = j.value("harmonyIntervalMs", 100.0);
        return config;
    }
};

// Tick callback type
using CosmicUnityTickCallback = std::function<void(uint64_t tickCount)>;

// Async runtime loop class
class CosmicUnityLoop {
public:
    static CosmicUnityLoop& GetInstance();

    void Init();
    void Shutdown();

    void Start();
    void Stop();
    void Pause();
    void Resume();

    void SetConfig(const CosmicUnityConfig& config);
    CosmicUnityConfig GetConfig() const;

    CosmicUnityMetrics GetMetrics() const;
    void ResetMetrics();

    void SetTickCallback(CosmicUnityTickCallback callback);
    void RenderFrame();

    bool IsRunning() const { return metrics_.isRunning.load(); }
    bool IsPaused() const { return metrics_.isPaused.load(); }

private:
    CosmicUnityLoop() = default;
    ~CosmicUnityLoop() = default;
    CosmicUnityLoop(const CosmicUnityLoop&) = delete;
    CosmicUnityLoop& operator=(const CosmicUnityLoop&) = delete;

    void TickThreadFunc();
    void SyncThreadFunc();
    void HarmonyThreadFunc();
    void CalculateTPS();
    void CalculateFPS();

    mutable std::mutex mutex_;
    CosmicUnityConfig config_;
    CosmicUnityMetrics metrics_;
    CosmicUnityTickCallback tickCallback_;

    std::atomic<bool> shouldStop_{false};
    std::unique_ptr<std::thread> tickThread_;
    std::unique_ptr<std::thread> syncThread_;
    std::unique_ptr<std::thread> harmonyThread_;

    std::chrono::steady_clock::time_point lastTickTime_;
    std::chrono::steady_clock::time_point lastFrameTime_;
    std::chrono::steady_clock::time_point startTime_;

    std::chrono::duration<double, std::milli> targetFrameDuration_;
};

extern CosmicUnityLoop& g_cosmicUnityLoop;

} // namespace CosmicUnity
