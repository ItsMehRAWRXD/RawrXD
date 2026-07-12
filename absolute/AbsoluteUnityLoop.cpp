#include "AbsoluteUnityLoop.hpp"
#include <algorithm>

namespace AbsoluteUnity {

AbsoluteUnityLoop& AbsoluteUnityLoop::GetInstance() {
    static AbsoluteUnityLoop instance;
    return instance;
}

void AbsoluteUnityLoop::Initialize() {
    ResetMetrics();
}

void AbsoluteUnityLoop::Start() {
    if (isRunning_.load()) return;
    
    isRunning_ = true;
    shouldStop_ = false;
    isPaused_ = false;
    
    lastTickTime_ = std::chrono::steady_clock::now();
    lastFrameTime_ = std::chrono::steady_clock::now();
    lastSyncTime_ = std::chrono::steady_clock::now();
    lastHarmonyTime_ = std::chrono::steady_clock::now();
    
    tickThread_ = std::thread(&AbsoluteUnityLoop::TickLoop, this);
    frameThread_ = std::thread(&AbsoluteUnityLoop::FrameLoop, this);
    
    if (multiLayerSyncEnabled_.load()) {
        syncThread_ = std::thread(&AbsoluteUnityLoop::SyncLoop, this);
    }
    
    if (crossLayerHarmonyEnabled_.load()) {
        harmonyThread_ = std::thread(&AbsoluteUnityLoop::HarmonyLoop, this);
    }
}

void AbsoluteUnityLoop::Stop() {
    shouldStop_ = true;
    
    if (tickThread_.joinable()) tickThread_.join();
    if (frameThread_.joinable()) frameThread_.join();
    if (syncThread_.joinable()) syncThread_.join();
    if (harmonyThread_.joinable()) harmonyThread_.join();
    
    isRunning_ = false;
    isPaused_ = false;
}

void AbsoluteUnityLoop::Pause() {
    isPaused_ = true;
}

void AbsoluteUnityLoop::Resume() {
    isPaused_ = false;
}

AbsoluteUnityMetrics AbsoluteUnityLoop::GetMetrics() const {
    std::lock_guard<std::mutex> lock(metricsMutex_);
    return metrics_;
}

void AbsoluteUnityLoop::ResetMetrics() {
    std::lock_guard<std::mutex> lock(metricsMutex_);
    metrics_ = AbsoluteUnityMetrics{};
}

void AbsoluteUnityLoop::RegisterTickCallback(std::function<void()> callback) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    tickCallbacks_.push_back(callback);
}

void AbsoluteUnityLoop::RegisterFrameCallback(std::function<void()> callback) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    frameCallbacks_.push_back(callback);
}

void AbsoluteUnityLoop::RegisterSyncCallback(std::function<void()> callback) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    syncCallbacks_.push_back(callback);
}

void AbsoluteUnityLoop::RegisterHarmonyCallback(std::function<void()> callback) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    harmonyCallbacks_.push_back(callback);
}

void AbsoluteUnityLoop::RequestSyncPulse() {
    syncPulsePending_ = true;
}

void AbsoluteUnityLoop::RequestHarmonyPulse() {
    harmonyPulsePending_ = true;
}

void AbsoluteUnityLoop::TriggerLayerSync() {
    syncPulsePending_ = true;
}

void AbsoluteUnityLoop::TriggerCrossLayerHarmonization() {
    harmonyPulsePending_ = true;
}

void AbsoluteUnityLoop::TriggerAbsoluteResonance() {
    absoluteResonance_ = std::min(1.0, absoluteResonance_.load() + 0.1);
}

void AbsoluteUnityLoop::TriggerUnityResonance() {
    unityResonance_ = std::min(1.0, unityResonance_.load() + 0.1);
}

void AbsoluteUnityLoop::TriggerConvergenceResonance() {
    convergenceResonance_ = std::min(1.0, convergenceResonance_.load() + 0.1);
}

void AbsoluteUnityLoop::TriggerContinuityResonance() {
    continuityResonance_ = std::min(1.0, continuityResonance_.load() + 0.1);
}

void AbsoluteUnityLoop::TriggerOmnipresenceResonance() {
    omnipresenceResonance_ = std::min(1.0, omnipresenceResonance_.load() + 0.1);
}

void AbsoluteUnityLoop::TriggerCoherenceResonance() {
    coherenceResonance_ = std::min(1.0, coherenceResonance_.load() + 0.1);
}

void AbsoluteUnityLoop::TriggerClarityResonance() {
    clarityResonance_ = std::min(1.0, clarityResonance_.load() + 0.1);
}

void AbsoluteUnityLoop::TriggerHarmonyResonance() {
    harmonyResonanceLevel_ = std::min(1.0, harmonyResonanceLevel_.load() + 0.1);
}

void AbsoluteUnityLoop::TriggerStabilityResonance() {
    stabilityResonance_ = std::min(1.0, stabilityResonance_.load() + 0.1);
}

void AbsoluteUnityLoop::TriggerDensityResonance() {
    densityResonance_ = std::min(1.0, densityResonance_.load() + 0.1);
}

void AbsoluteUnityLoop::TriggerPurityResonance() {
    purityResonance_ = std::min(1.0, purityResonance_.load() + 0.1);
}

void AbsoluteUnityLoop::TriggerEternityResonance() {
    eternityResonance_ = std::min(1.0, eternityResonance_.load() + 0.1);
}

void AbsoluteUnityLoop::TriggerSupremacyResonance() {
    supremacyResonance_ = std::min(1.0, supremacyResonance_.load() + 0.1);
}

void AbsoluteUnityLoop::TriggerAbsolutenessResonance() {
    absolutenessResonance_ = std::min(1.0, absolutenessResonance_.load() + 0.1);
}

void AbsoluteUnityLoop::TickLoop() {
    while (!shouldStop_.load()) {
        if (isPaused_.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }
        
        auto start = std::chrono::steady_clock::now();
        
        {
            std::lock_guard<std::mutex> lock(callbackMutex_);
            for (auto& callback : tickCallbacks_) {
                if (callback) callback();
            }
        }
        
        tickCount_++;
        
        auto end = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        
        int targetTps = targetTPS_.load();
        if (targetTps > 0) {
            int64_t targetMicros = 1000000 / targetTps;
            int64_t sleepMicros = targetMicros - elapsed;
            if (sleepMicros > 0) {
                std::this_thread::sleep_for(std::chrono::microseconds(sleepMicros));
            }
        }
        
        lastTickTime_ = start;
    }
}

void AbsoluteUnityLoop::FrameLoop() {
    while (!shouldStop_.load()) {
        if (isPaused_.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }
        
        auto start = std::chrono::steady_clock::now();
        
        {
            std::lock_guard<std::mutex> lock(callbackMutex_);
            for (auto& callback : frameCallbacks_) {
                if (callback) callback();
            }
        }
        
        frameCount_++;
        
        auto end = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        
        if (frameLimitingEnabled_.load()) {
            int targetFps = targetFPS_.load();
            if (targetFps > 0) {
                int64_t targetMicros = 1000000 / targetFps;
                int64_t sleepMicros = targetMicros - elapsed;
                if (sleepMicros > 0) {
                    std::this_thread::sleep_for(std::chrono::microseconds(sleepMicros));
                }
            }
        }
        
        lastFrameTime_ = start;
    }
}

void AbsoluteUnityLoop::SyncLoop() {
    while (!shouldStop_.load()) {
        if (isPaused_.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }
        
        auto start = std::chrono::steady_clock::now();
        
        if (syncPulsePending_.load()) {
            ProcessSyncPulse();
            syncPulsePending_ = false;
        }
        
        SynchronizeAllLayers();
        
        {
            std::lock_guard<std::mutex> lock(callbackMutex_);
            for (auto& callback : syncCallbacks_) {
                if (callback) callback();
            }
        }
        
        syncCount_++;
        
        auto end = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        
        int64_t sleepMicros = 16666 - elapsed;
        if (sleepMicros > 0) {
            std::this_thread::sleep_for(std::chrono::microseconds(sleepMicros));
        }
        
        lastSyncTime_ = start;
    }
}

void AbsoluteUnityLoop::HarmonyLoop() {
    while (!shouldStop_.load()) {
        if (isPaused_.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }
        
        auto start = std::chrono::steady_clock::now();
        
        if (harmonyPulsePending_.load()) {
            ProcessHarmonyPulse();
            harmonyPulsePending_ = false;
        }
        
        HarmonizeCrossLayers();
        CalculateResonanceLevels();
        
        {
            std::lock_guard<std::mutex> lock(callbackMutex_);
            for (auto& callback : harmonyCallbacks_) {
                if (callback) callback();
            }
        }
        
        harmonyCount_++;
        
        auto end = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        
        int64_t sleepMicros = 16666 - elapsed;
        if (sleepMicros > 0) {
            std::this_thread::sleep_for(std::chrono::microseconds(sleepMicros));
        }
        
        lastHarmonyTime_ = start;
    }
}

void AbsoluteUnityLoop::UpdateMetrics() {
    std::lock_guard<std::mutex> lock(metricsMutex_);
    
    auto& engine = AbsoluteUnityEngine::GetInstance();
    auto unities = engine.GetAllAbsoluteUnities();
    auto nodes = engine.GetAllUnityNodes();
    auto streams = engine.GetAllAbsoluteStreams();
    auto waves = engine.GetAllUnityWaves();
    auto matrices = engine.GetAllAbsoluteMatrices();
    auto tensors = engine.GetAllAbsoluteTensors();
    auto clarities = engine.GetAllAbsoluteClarities();
    
    metrics_.absoluteUnityCount = static_cast<double>(unities.size());
    metrics_.nodeCount = static_cast<double>(nodes.size());
    metrics_.streamCount = static_cast<double>(streams.size());
    metrics_.waveCount = static_cast<double>(waves.size());
    metrics_.matrixCount = static_cast<double>(matrices.size());
    metrics_.tensorCount = static_cast<double>(tensors.size());
    metrics_.clarityCount = static_cast<double>(clarities.size());
    
    double totalAbsoluteness = 0.0, totalUnity = 0.0, totalHarmony = 0.0, totalCoherence = 0.0;
    double totalClarity = 0.0, totalEternity = 0.0, totalSupremacy = 0.0, totalOmnipresence = 0.0, totalContinuity = 0.0;
    
    for (const auto& u : unities) {
        totalAbsoluteness += u->absoluteness;
        totalUnity += u->unity;
        totalHarmony += u->harmony;
        totalCoherence += u->coherence;
        totalClarity += u->clarity;
        totalEternity += u->eternity;
        totalSupremacy += u->supremacy;
        totalOmnipresence += u->omnipresence;
        totalContinuity += u->continuity;
    }
    
    if (!unities.empty()) {
        metrics_.averageAbsoluteness = totalAbsoluteness / unities.size();
        metrics_.averageUnity = totalUnity / unities.size();
        metrics_.averageHarmony = totalHarmony / unities.size();
        metrics_.averageCoherence = totalCoherence / unities.size();
        metrics_.averageClarity = totalClarity / unities.size();
        metrics_.averageEternity = totalEternity / unities.size();
        metrics_.averageSupremacy = totalSupremacy / unities.size();
        metrics_.averageOmnipresence = totalOmnipresence / unities.size();
        metrics_.averageContinuity = totalContinuity / unities.size();
    }
    
    double totalStability = 0.0, totalDensity = 0.0, totalPurity = 0.0;
    
    for (const auto& m : matrices) totalStability += m->stability;
    for (const auto& t : tensors) totalDensity += t->density;
    for (const auto& c : clarities) totalPurity += c->purity;
    
    metrics_.totalAbsoluteness = totalAbsoluteness;
    metrics_.totalStability = totalStability;
    metrics_.totalDensity = totalDensity;
    metrics_.totalPurity = totalPurity;
    
    metrics_.tickCount = tickCount_;
    metrics_.isRunning = isRunning_.load();
    metrics_.isPaused = isPaused_.load();
    metrics_.targetTPS = targetTPS_.load();
    metrics_.targetFPS = targetFPS_.load();
    metrics_.frameLimitingEnabled = frameLimitingEnabled_.load();
    metrics_.multiLayerSyncEnabled = multiLayerSyncEnabled_.load();
    metrics_.crossLayerHarmonyEnabled = crossLayerHarmonyEnabled_.load();
    
    auto now = std::chrono::steady_clock::now();
    auto tickDuration = std::chrono::duration_cast<std::chrono::milliseconds>(now - lastTickTime_).count();
    auto frameDuration = std::chrono::duration_cast<std::chrono::milliseconds>(now - lastFrameTime_).count();
    
    if (tickDuration > 0) metrics_.currentTPS = 1000.0 / tickDuration;
    if (frameDuration > 0) metrics_.currentFPS = 1000.0 / frameDuration;
    
    metrics_.tickTimeMs = static_cast<double>(tickDuration);
    metrics_.frameTimeMs = static_cast<double>(frameDuration);
    metrics_.lastUpdateTime = std::chrono::system_clock::now().time_since_epoch().count();
    
    metrics_.activeSyncThreads = multiLayerSyncEnabled_.load() ? 1 : 0;
    metrics_.activeHarmonyThreads = crossLayerHarmonyEnabled_.load() ? 1 : 0;
    metrics_.syncEfficiency = syncEfficiency_.load();
    metrics_.harmonyResonance = harmonyResonance_.load();
    metrics_.crossLayerConvergence = crossLayerConvergence_.load();
    
    metrics_.absoluteResonance = absoluteResonance_.load();
    metrics_.unityResonance = unityResonance_.load();
    metrics_.convergenceResonance = convergenceResonance_.load();
    metrics_.continuityResonance = continuityResonance_.load();
    metrics_.omnipresenceResonance = omnipresenceResonance_.load();
    metrics_.coherenceResonance = coherenceResonance_.load();
    metrics_.clarityResonance = clarityResonance_.load();
    metrics_.harmonyResonanceLevel = harmonyResonanceLevel_.load();
    metrics_.stabilityResonance = stabilityResonance_.load();
    metrics_.densityResonance = densityResonance_.load();
    metrics_.purityResonance = purityResonance_.load();
    metrics_.eternityResonance = eternityResonance_.load();
    metrics_.supremacyResonance = supremacyResonance_.load();
    metrics_.absolutenessResonance = absolutenessResonance_.load();
}

void AbsoluteUnityLoop::ProcessSyncPulse() {
    syncEfficiency_ = std::min(1.0, syncEfficiency_.load() + 0.05);
}

void AbsoluteUnityLoop::ProcessHarmonyPulse() {
    harmonyResonance_ = std::min(1.0, harmonyResonance_.load() + 0.05);
}

void AbsoluteUnityLoop::CalculateResonanceLevels() {
    double total = absoluteResonance_.load() + unityResonance_.load() + convergenceResonance_.load() +
                   continuityResonance_.load() + omnipresenceResonance_.load() + coherenceResonance_.load() +
                   clarityResonance_.load() + harmonyResonanceLevel_.load() + stabilityResonance_.load() +
                   densityResonance_.load() + purityResonance_.load() + eternityResonance_.load() +
                   supremacyResonance_.load() + absolutenessResonance_.load();
    crossLayerConvergence_ = total / 14.0;
}

void AbsoluteUnityLoop::SynchronizeAllLayers() {
    syncEfficiency_ = std::min(1.0, syncEfficiency_.load() + 0.01);
}

void AbsoluteUnityLoop::HarmonizeCrossLayers() {
    harmonyResonance_ = std::min(1.0, harmonyResonance_.load() + 0.01);
}

} // namespace AbsoluteUnity
