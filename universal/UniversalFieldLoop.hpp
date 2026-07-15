#pragma once

#include "UniversalFieldEngine.hpp"
#include <atomic>
#include <thread>
#include <functional>
#include <chrono>

namespace UniversalField {

// Runtime metrics structure
struct UniversalFieldMetrics {
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
struct UniversalFieldConfig {
    double targetTPS = 60.0;
    double maxFPS = 60.0;
    bool enableFrameLimiting = true;
    bool enableMetrics = true;
    bool enableOmnipresentTickPropagation = true;
    bool enableMultiLayerSynchronization = true;
    bool enableCrossLayerHarmonyHarmonization = true;
    double syncIntervalMs = 100.0;      // 10Hz synchronization
    double harmonyIntervalMs = 100.0;   // 10Hz harmony harmonization

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

    static UniversalFieldConfig FromJson(const json& j) {
        UniversalFieldConfig config;
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
using UniversalFieldTickCallback = std::function<void(uint64_t tickCount)>;

// Async runtime loop class
class UniversalFieldLoop {
public:
    static UniversalFieldLoop& GetInstance();

    // Initialize the loop
    void Init();
    void Shutdown();

    // Control methods
    void Start();
    void Stop();
    void Pause();
    void Resume();

    // Configuration
    void SetConfig(const UniversalFieldConfig& config);
    UniversalFieldConfig GetConfig() const;

    // Metrics
    UniversalFieldMetrics GetMetrics() const;
    void ResetMetrics();

    // Tick callback registration
    void SetTickCallback(UniversalFieldTickCallback callback);

    // Frame rendering (call from main thread)
    void RenderFrame();

    // Check if running
    bool IsRunning() const { return metrics_.isRunning.load(); }
    bool IsPaused() const { return metrics_.isPaused.load(); }

private:
    UniversalFieldLoop() = default;
    ~UniversalFieldLoop() = default;
    UniversalFieldLoop(const UniversalFieldLoop&) = delete;
    UniversalFieldLoop& operator=(const UniversalFieldLoop&) = delete;

    void TickThreadFunc();
    void SyncThreadFunc();
    void HarmonyThreadFunc();
    void CalculateTPS();
    void CalculateFPS();

    mutable std::mutex mutex_;
    UniversalFieldConfig config_;
    UniversalFieldMetrics metrics_;
    UniversalFieldTickCallback tickCallback_;

    std::atomic<bool> shouldStop_{false};
    std::unique_ptr<std::thread> tickThread_;
    std::unique_ptr<std::thread> syncThread_;
    std::unique_ptr<std::thread> harmonyThread_;

    // Timing
    std::chrono::steady_clock::time_point lastTickTime_;
    std::chrono::steady_clock::time_point lastFrameTime_;
    std::chrono::steady_clock::time_point startTime_;

    // Frame limiting
    std::chrono::duration<double, std::milli> targetFrameDuration_;
};

// Global accessor
extern UniversalFieldLoop& g_universalFieldLoop;

} // namespace UniversalField
