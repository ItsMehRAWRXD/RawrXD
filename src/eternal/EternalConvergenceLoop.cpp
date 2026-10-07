#include "EternalConvergenceLoop.hpp"
#include <algorithm>

namespace EternalConvergence {

EternalConvergenceLoop& EternalConvergenceLoop::GetInstance() {
    static EternalConvergenceLoop instance;
    return instance;
}

void EternalConvergenceLoop::Initialize() {
    ResetMetrics();
}

void EternalConvergenceLoop::Start() {
    if (isRunning_.load()) return;
    
    isRunning_ = true;
    shouldStop_ = false;
    isPaused_ = false;
    
    lastTickTime_ = std::chrono::steady_clock::now();
    lastFrameTime_ = std::chrono::steady_clock::now();
    lastSyncTime_ = std::chrono::steady_clock::now();
    lastHarmonyTime_ = std::chrono::steady_clock::now();
    
    tickThread_ = std::thread(&EternalConvergenceLoop::TickLoop, this);
    frameThread_ = std::thread(&EternalConvergenceLoop::FrameLoop, this);
    
    if (multiLayerSyncEnabled_.load()) {
        syncThread_ = std::thread(&EternalConvergenceLoop::SyncLoop, this);
    }
    
    if (crossLayerHarmonyEnabled_.load()) {
        harmonyThread_ = std::thread(&EternalConvergenceLoop::HarmonyLoop, this);
    }
}

void EternalConvergenceLoop::Stop() {
    shouldStop_ = true;
    
    if (tickThread_.joinable()) tickThread_.join();
    if (frameThread_.joinable()) frameThread_.join();
    if (syncThread_.joinable()) syncThread_.join();
    if (harmonyThread_.joinable()) harmonyThread_.join();
    
    isRunning_ = false;
    isPaused_ = false;
}

void EternalConvergenceLoop::Pause() {
    isPaused_ = true;
}

void EternalConvergenceLoop::Resume() {
    isPaused_ = false;
}

EternalConvergenceMetrics EternalConvergenceLoop::GetMetrics() const {
    std::lock_guard<std::mutex> lock(metricsMutex_);
    return metrics_;
}

void EternalConvergenceLoop::ResetMetrics() {
    std::lock_guard<std::mutex> lock(metricsMutex_);
    metrics_ = EternalConvergenceMetrics{};
}

void EternalConvergenceLoop::RegisterTickCallback(std::function<void()> callback) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    tickCallbacks_.push_back(callback);
}

void EternalConvergenceLoop::RegisterFrameCallback(std::function<void()> callback) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    frameCallbacks_.push_back(callback);
}

void EternalConvergenceLoop::RegisterSyncCallback(std::function<void()> callback) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    syncCallbacks_.push_back(callback);
}

void EternalConvergenceLoop::RegisterHarmonyCallback(std::function<void()> callback) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    harmonyCallbacks_.push_back(callback);
}

void EternalConvergenceLoop::RequestSyncPulse() {
    syncPulsePending_ = true;
}

void EternalConvergenceLoop::RequestHarmonyPulse() {
    harmonyPulsePending_ = true;
}

void EternalConvergenceLoop::TriggerLayerSync() {
    syncPulsePending_ = true;
}

void EternalConvergenceLoop::TriggerCrossLayerHarmonization() {
    harmonyPulsePending_ = true;
}

void EternalConvergenceLoop::TriggerEternalResonance() {
    eternalResonance_ = std::min(1.0, eternalResonance_.load() + 0.1);
}

void EternalConvergenceLoop::TriggerUnityResonance() {
    unityResonance_ = std::min(1.0, unityResonance_.load() + 0.1);
}

void EternalConvergenceLoop::TriggerConvergenceResonance() {
    convergenceResonance_ = std::min(1.0, convergenceResonance_.load() + 0.1);
}

void EternalConvergenceLoop::TriggerContinuityResonance() {
    continuityResonance_ = std::min(1.0, continuityResonance_.load() + 0.1);
}

void EternalConvergenceLoop::TriggerOmnipresenceResonance() {
    omnipresenceResonance_ = std::min(1.0, omnipresenceResonance_.load() + 0.1);
}

void EternalConvergenceLoop::TriggerCoherenceResonance() {
    coherenceResonance_ = std::min(1.0, coherenceResonance_.load() + 0.1);
}

void EternalConvergenceLoop::TriggerClarityResonance() {
    clarityResonance_ = std::min(1.0, clarityResonance_.load() + 0.1);
}

void EternalConvergenceLoop::TriggerHarmonyResonance() {
    harmonyResonanceLevel_ = std::min(1.0, harmonyResonanceLevel_.load() + 0.1);
}

void EternalConvergenceLoop::TriggerStabilityResonance() {
    stabilityResonance_ = std::min(1.0, stabilityResonance_.load() + 0.1);
}

void EternalConvergenceLoop::TriggerDensityResonance() {
    densityResonance_ = std::min(1.0, densityResonance_.load() + 0.1);
}

void EternalConvergenceLoop::TriggerPurityResonance() {
    purityResonance_ = std::min(1.0, purityResonance_.load() + 0.1);
}

void EternalConvergenceLoop::TriggerEternityResonance() {
    eternityResonance_ = std::min(1.0, eternityResonance_.load() + 0.1);
}

void EternalConvergenceLoop::TickLoop() {
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

void EternalConvergenceLoop::FrameLoop() {
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

void EternalConvergenceLoop::SyncLoop() {
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
        
        int64_t sleepMicros = 16666 - elapsed; // ~60Hz
        if (sleepMicros > 0) {
            std::this_thread::sleep_for(std::chrono::microseconds(sleepMicros));
        }
        
        lastSyncTime_ = start;
    }
}

void EternalConvergenceLoop::HarmonyLoop() {
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
        
        int64_t sleepMicros = 16666 - elapsed; // ~60Hz
        if (sleepMicros > 0) {
            std::this_thread::sleep_for(std::chrono::microseconds(sleepMicros));
        }
        
        lastHarmonyTime_ = start;
    }
}

void EternalConvergenceLoop::UpdateMetrics() {
    std::lock_guard<std::mutex> lock(metricsMutex_);
    
    auto& engine = EternalConvergenceEngine::GetInstance();
    auto eternals = engine.GetAllEternalConvergences();
    auto nodes = engine.GetAllConvergenceNodes();
    auto streams = engine.GetAllEternalStreams();
    auto waves = engine.GetAllConvergenceWaves();
    auto matrices = engine.GetAllUnityMatrices();
    auto tensors = engine.GetAllEternalTensors();
    auto clarities = engine.GetAllEternalClarities();
    
    metrics_.eternalConvergenceCount = static_cast<double>(eternals.size());
    metrics_.nodeCount = static_cast<double>(nodes.size());
    metrics_.streamCount = static_cast<double>(streams.size());
    metrics_.waveCount = static_cast<double>(waves.size());
    metrics_.matrixCount = static_cast<double>(matrices.size());
    metrics_.tensorCount = static_cast<double>(tensors.size());
    metrics_.clarityCount = static_cast<double>(clarities.size());
    
    double totalConvergence = 0.0, totalUnity = 0.0, totalHarmony = 0.0, totalCoherence = 0.0;
    double totalClarity = 0.0, totalOmnipresence = 0.0, totalContinuity = 0.0;
    
    for (const auto& e : eternals) {
        totalConvergence += e->convergence;
        totalUnity += e->unity;
        totalHarmony += e->harmony;
        totalCoherence += e->coherence;
        totalClarity += e->clarity;
        totalOmnipresence += e->omnipresence;
        totalContinuity += e->continuity;
    }
    
    if (!eternals.empty()) {
        metrics_.averageConvergence = totalConvergence / eternals.size();
        metrics_.averageUnity = totalUnity / eternals.size();
        metrics_.averageHarmony = totalHarmony / eternals.size();
        metrics_.averageCoherence = totalCoherence / eternals.size();
        metrics_.averageClarity = totalClarity / eternals.size();
        metrics_.averageOmnipresence = totalOmnipresence / eternals.size();
        metrics_.averageContinuity = totalContinuity / eternals.size();
    }
    
    double totalEternity = 0.0, totalStability = 0.0, totalDensity = 0.0, totalPurity = 0.0;
    
    for (const auto& t : tensors) totalEternity += t->eternity;
    for (const auto& m : matrices) totalStability += m->stability;
    for (const auto& t : tensors) totalDensity += t->density;
    for (const auto& c : clarities) totalPurity += c->purity;
    
    metrics_.totalEternity = totalEternity;
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
    
    metrics_.eternalResonance = eternalResonance_.load();
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
}

void EternalConvergenceLoop::ProcessSyncPulse() {
    syncEfficiency_ = std::min(1.0, syncEfficiency_.load() + 0.05);
}

void EternalConvergenceLoop::ProcessHarmonyPulse() {
    harmonyResonance_ = std::min(1.0, harmonyResonance_.load() + 0.05);
}

void EternalConvergenceLoop::CalculateResonanceLevels() {
    double total = eternalResonance_.load() + unityResonance_.load() + convergenceResonance_.load() +
                   continuityResonance_.load() + omnipresenceResonance_.load() + coherenceResonance_.load() +
                   clarityResonance_.load() + harmonyResonanceLevel_.load() + stabilityResonance_.load() +
                   densityResonance_.load() + purityResonance_.load() + eternityResonance_.load();
    crossLayerConvergence_ = total / 12.0;
}

void EternalConvergenceLoop::SynchronizeAllLayers() {
    syncEfficiency_ = std::min(1.0, syncEfficiency_.load() + 0.01);
}

void EternalConvergenceLoop::HarmonizeCrossLayers() {
    harmonyResonance_ = std::min(1.0, harmonyResonance_.load() + 0.01);
}

} // namespace EternalConvergence
