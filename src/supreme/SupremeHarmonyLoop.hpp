#pragma once

#include "SupremeHarmonyEngine.hpp"
#include <atomic>
#include <thread>
#include <functional>
#include <chrono>

namespace SupremeHarmony {

struct SupremeHarmonyMetrics {
    double supremeHarmonyCount = 0;
    double nodeCount = 0;
    double streamCount = 0;
    double waveCount = 0;
    double matrixCount = 0;
    double tensorCount = 0;
    double clarityCount = 0;
    double averageSupremacy = 0.0;
    double averageUnity = 0.0;
    double averageHarmony = 0.0;
    double averageCoherence = 0.0;
    double averageClarity = 0.0;
    double averageEternity = 0.0;
    double averageOmnipresence = 0.0;
    double averageContinuity = 0.0;
    double totalSupremacy = 0.0;
    double totalStability = 0.0;
    double totalDensity = 0.0;
    double totalPurity = 0.0;
    uint64_t tickCount = 0;
    double currentTPS = 0.0;
    double currentFPS = 0.0;
    double frameTimeMs = 0.0;
    double tickTimeMs = 0.0;
    double lastUpdateTime = 0.0;
    bool isRunning = false;
    bool isPaused = false;
    int targetTPS = 60;
    int targetFPS = 60;
    bool frameLimitingEnabled = true;
    bool multiLayerSyncEnabled = true;
    bool crossLayerHarmonyEnabled = true;
    int activeSyncThreads = 0;
    int activeHarmonyThreads = 0;
    double syncEfficiency = 0.0;
    double harmonyResonance = 0.0;
    double crossLayerConvergence = 0.0;
    double supremeResonance = 0.0;
    double unityResonance = 0.0;
    double convergenceResonance = 0.0;
    double continuityResonance = 0.0;
    double omnipresenceResonance = 0.0;
    double coherenceResonance = 0.0;
    double clarityResonance = 0.0;
    double harmonyResonanceLevel = 0.0;
    double stabilityResonance = 0.0;
    double densityResonance = 0.0;
    double purityResonance = 0.0;
    double eternityResonance = 0.0;
    double supremacyResonance = 0.0;
};

class SupremeHarmonyLoop {
public:
    static SupremeHarmonyLoop& GetInstance();
    
    void Initialize();
    void Start();
    void Stop();
    void Pause();
    void Resume();
    bool IsRunning() const { return isRunning_.load(); }
    bool IsPaused() const { return isPaused_.load(); }
    
    void SetTargetTPS(int tps) { targetTPS_ = tps; }
    void SetTargetFPS(int fps) { targetFPS_ = fps; }
    int GetTargetTPS() const { return targetTPS_; }
    int GetTargetFPS() const { return targetFPS_; }
    
    void SetFrameLimitingEnabled(bool enabled) { frameLimitingEnabled_ = enabled; }
    bool IsFrameLimitingEnabled() const { return frameLimitingEnabled_; }
    
    void SetMultiLayerSyncEnabled(bool enabled) { multiLayerSyncEnabled_ = enabled; }
    bool IsMultiLayerSyncEnabled() const { return multiLayerSyncEnabled_; }
    
    void SetCrossLayerHarmonyEnabled(bool enabled) { crossLayerHarmonyEnabled_ = enabled; }
    bool IsCrossLayerHarmonyEnabled() const { return crossLayerHarmonyEnabled_; }
    
    SupremeHarmonyMetrics GetMetrics() const;
    void ResetMetrics();
    
    void RegisterTickCallback(std::function<void()> callback);
    void RegisterFrameCallback(std::function<void()> callback);
    void RegisterSyncCallback(std::function<void()> callback);
    void RegisterHarmonyCallback(std::function<void()> callback);
    
    void RequestSyncPulse();
    void RequestHarmonyPulse();
    bool IsSyncPulsePending() const { return syncPulsePending_.load(); }
    bool IsHarmonyPulsePending() const { return harmonyPulsePending_.load(); }
    
    void TriggerLayerSync();
    void TriggerCrossLayerHarmonization();
    void TriggerSupremeResonance();
    void TriggerUnityResonance();
    void TriggerConvergenceResonance();
    void TriggerContinuityResonance();
    void TriggerOmnipresenceResonance();
    void TriggerCoherenceResonance();
    void TriggerClarityResonance();
    void TriggerHarmonyResonance();
    void TriggerStabilityResonance();
    void TriggerDensityResonance();
    void TriggerPurityResonance();
    void TriggerEternityResonance();
    void TriggerSupremacyResonance();
    
    double GetSyncEfficiency() const { return syncEfficiency_.load(); }
    double GetHarmonyResonance() const { return harmonyResonance_.load(); }
    double GetCrossLayerConvergence() const { return crossLayerConvergence_.load(); }
    
private:
    SupremeHarmonyLoop() = default;
    ~SupremeHarmonyLoop() { Stop(); }
    
    void TickLoop();
    void FrameLoop();
    void SyncLoop();
    void HarmonyLoop();
    void UpdateMetrics();
    void ProcessSyncPulse();
    void ProcessHarmonyPulse();
    void CalculateResonanceLevels();
    void SynchronizeAllLayers();
    void HarmonizeCrossLayers();
    
    std::atomic<bool> isRunning_{false};
    std::atomic<bool> isPaused_{false};
    std::atomic<bool> shouldStop_{false};
    std::atomic<int> targetTPS_{60};
    std::atomic<int> targetFPS_{60};
    std::atomic<bool> frameLimitingEnabled_{true};
    std::atomic<bool> multiLayerSyncEnabled_{true};
    std::atomic<bool> crossLayerHarmonyEnabled_{true};
    std::atomic<bool> syncPulsePending_{false};
    std::atomic<bool> harmonyPulsePending_{false};
    std::atomic<double> syncEfficiency_{0.0};
    std::atomic<double> harmonyResonance_{0.0};
    std::atomic<double> crossLayerConvergence_{0.0};
    std::atomic<double> supremeResonance_{0.0};
    std::atomic<double> unityResonance_{0.0};
    std::atomic<double> convergenceResonance_{0.0};
    std::atomic<double> continuityResonance_{0.0};
    std::atomic<double> omnipresenceResonance_{0.0};
    std::atomic<double> coherenceResonance_{0.0};
    std::atomic<double> clarityResonance_{0.0};
    std::atomic<double> harmonyResonanceLevel_{0.0};
    std::atomic<double> stabilityResonance_{0.0};
    std::atomic<double> densityResonance_{0.0};
    std::atomic<double> purityResonance_{0.0};
    std::atomic<double> eternityResonance_{0.0};
    std::atomic<double> supremacyResonance_{0.0};
    
    std::thread tickThread_;
    std::thread frameThread_;
    std::thread syncThread_;
    std::thread harmonyThread_;
    
    mutable std::mutex metricsMutex_;
    SupremeHarmonyMetrics metrics_;
    
    std::vector<std::function<void()>> tickCallbacks_;
    std::vector<std::function<void()>> frameCallbacks_;
    std::vector<std::function<void()>> syncCallbacks_;
    std::vector<std::function<void()>> harmonyCallbacks_;
    std::mutex callbackMutex_;
    
    std::chrono::steady_clock::time_point lastTickTime_;
    std::chrono::steady_clock::time_point lastFrameTime_;
    std::chrono::steady_clock::time_point lastSyncTime_;
    std::chrono::steady_clock::time_point lastHarmonyTime_;
    
    uint64_t tickCount_ = 0;
    uint64_t frameCount_ = 0;
    uint64_t syncCount_ = 0;
    uint64_t harmonyCount_ = 0;
};

} // namespace SupremeHarmony
