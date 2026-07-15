#pragma once

#include "InfiniteSynthesisEngine.hpp"
#include <atomic>
#include <thread>
#include <functional>
#include <chrono>

namespace InfiniteSynthesis {

struct InfiniteSynthesisMetrics {
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
            {"tickCount", tickCount.load()}, {"frameCount", frameCount.load()},
            {"currentTPS", currentTPS.load()}, {"currentFPS", currentFPS.load()},
            {"isRunning", isRunning.load()}, {"isPaused", isPaused.load()},
            {"lastSyncTime", lastSyncTime.load()}, {"lastHarmonyTime", lastHarmonyTime.load()},
            {"syncCount", syncCount.load()}, {"harmonyCount", harmonyCount.load()}
        };
    }
};

struct InfiniteSynthesisConfig {
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
            {"targetTPS", targetTPS}, {"maxFPS", maxFPS}, {"enableFrameLimiting", enableFrameLimiting},
            {"enableMetrics", enableMetrics}, {"enableOmnipresentTickPropagation", enableOmnipresentTickPropagation},
            {"enableMultiLayerSynchronization", enableMultiLayerSynchronization},
            {"enableCrossLayerHarmonyHarmonization", enableCrossLayerHarmonyHarmonization},
            {"syncIntervalMs", syncIntervalMs}, {"harmonyIntervalMs", harmonyIntervalMs}
        };
    }

    static InfiniteSynthesisConfig FromJson(const json& j) {
        InfiniteSynthesisConfig config;
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

using InfiniteSynthesisTickCallback = std::function<void(uint64_t tickCount)>;

class InfiniteSynthesisLoop {
public:
    static InfiniteSynthesisLoop& GetInstance();

    void Init();
    void Shutdown();

    void Start();
    void Stop();
    void Pause();
    void Resume();

    void SetConfig(const InfiniteSynthesisConfig& config);
    InfiniteSynthesisConfig GetConfig() const;

    InfiniteSynthesisMetrics GetMetrics() const;
    void ResetMetrics();

    void SetTickCallback(InfiniteSynthesisTickCallback callback);
    void RenderFrame();

    bool IsRunning() const { return metrics_.isRunning.load(); }
    bool IsPaused() const { return metrics_.isPaused.load(); }

private:
    InfiniteSynthesisLoop() = default;
    ~InfiniteSynthesisLoop() = default;
    InfiniteSynthesisLoop(const InfiniteSynthesisLoop&) = delete;
    InfiniteSynthesisLoop& operator=(const InfiniteSynthesisLoop&) = delete;

    void TickThreadFunc();
    void SyncThreadFunc();
    void HarmonyThreadFunc();
    void CalculateTPS();
    void CalculateFPS();

    mutable std::mutex mutex_;
    InfiniteSynthesisConfig config_;
    InfiniteSynthesisMetrics metrics_;
    InfiniteSynthesisTickCallback tickCallback_;

    std::atomic<bool> shouldStop_{false};
    std::unique_ptr<std::thread> tickThread_;
    std::unique_ptr<std::thread> syncThread_;
    std::unique_ptr<std::thread> harmonyThread_;

    std::chrono::steady_clock::time_point lastTickTime_;
    std::chrono::steady_clock::time_point lastFrameTime_;
    std::chrono::steady_clock::time_point startTime_;

    std::chrono::duration<double, std::milli> targetFrameDuration_;
};

extern InfiniteSynthesisLoop& g_infiniteSynthesisLoop;

} // namespace InfiniteSynthesis
