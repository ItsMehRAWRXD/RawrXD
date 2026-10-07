#include "SupremeHarmonyLoop.hpp"
#include <algorithm>

namespace SupremeHarmony {

SupremeHarmonyLoop& SupremeHarmonyLoop::GetInstance() {
    static SupremeHarmonyLoop instance;
    return instance;
}

void SupremeHarmonyLoop::Initialize() {
    ResetMetrics();
}

void SupremeHarmonyLoop::Start() {
    if (isRunning_.load()) return;
    
    isRunning_ = true;
    shouldStop_ = false;
    isPaused_ = false;
    
    lastTickTime_ = std::chrono::steady_clock::now();
    lastFrameTime_ = std::chrono::steady_clock::now();
    lastSyncTime_ = std::chrono::steady_clock::now();
    lastHarmonyTime_ = std::chrono::steady_clock::now();
    
    tickThread_ = std::thread(&SupremeHarmonyLoop::TickLoop, this);
    frameThread_ = std::thread(&SupremeHarmonyLoop::FrameLoop, this);
    
    if (multiLayerSyncEnabled_.load()) {
        syncThread_ = std::thread(&SupremeHarmonyLoop::SyncLoop, this);
    }
    
    if (crossLayerHarmonyEnabled_.load()) {
        harmonyThread_ = std::thread(&SupremeHarmonyLoop::HarmonyLoop, this);
    }
}

void SupremeHarmonyLoop::Stop() {
    shouldStop_ = true;
    
    if (tickThread_.joinable()) tickThread_.join();
    if (frameThread_.joinable()) frameThread_.join();
    if (syncThread_.joinable()) syncThread_.join();
    if (harmonyThread_.joinable()) harmonyThread_.join();
    
    isRunning_ = false;
    isPaused_ = false;
}

void SupremeHarmonyLoop::Pause() {
    isPaused_ = true;
}

void SupremeHarmonyLoop::Resume() {
    isPaused_ = false;
}

SupremeHarmonyMetrics SupremeHarmonyLoop::GetMetrics() const {
    std::lock_guard<std::mutex> lock(metricsMutex_);
    return metrics_;
}

void SupremeHarmonyLoop::ResetMetrics() {
    std::lock_guard<std::mutex> lock(metricsMutex_);
    metrics_ = SupremeHarmonyMetrics{};
}

void SupremeHarmonyLoop::RegisterTickCallback(std::function<void()> callback) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    tickCallbacks_.push_back(callback);
}

void SupremeHarmonyLoop::RegisterFrameCallback(std::function<void()> callback) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    frameCallbacks_.push_back(callback);
}

void SupremeHarmonyLoop::RegisterSyncCallback(std::function<void()> callback) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    syncCallbacks_.push_back(callback);
}

void SupremeHarmonyLoop::RegisterHarmonyCallback(std::function<void()> callback) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    harmonyCallbacks_.push_back(callback);
}

void SupremeHarmonyLoop::RequestSyncPulse() {
    syncPulsePending_ = true;
}

void SupremeHarmonyLoop::RequestHarmonyPulse() {
    harmonyPulsePending_ = true;
}

void SupremeHarmonyLoop::TriggerLayerSync() {
    syncPulsePending_ = true;
}

void SupremeHarmonyLoop::TriggerCrossLayerHarmonization() {
    harmonyPulsePending_ = true;
}

void SupremeHarmonyLoop::TriggerSupremeResonance() {
    supremeResonance_ = std::min(1.0, supremeResonance_.load() + 0.1);
}

void SupremeHarmonyLoop::TriggerUnityResonance() {
    unityResonance_ = std::min(1.0, unityResonance_.load() + 0.1);
}

void SupremeHarmonyLoop::TriggerConvergenceResonance() {
    convergenceResonance_ = std::min(1.0, convergenceResonance_.load() + 0.1);
}

void SupremeHarmonyLoop::TriggerContinuityResonance() {
    continuityResonance_ = std::min(1.0, continuityResonance_.load() + 0.1);
}

void SupremeHarmonyLoop::TriggerOmnipresenceResonance() {
    omnipresenceResonance_ = std::min(1.0, omnipresenceResonance_.load() + 0.1);
}

void SupremeHarmonyLoop::TriggerCoherenceResonance() {
    coherenceResonance_ = std::min(1.0, coherenceResonance_.load() + 0.1);
}

void SupremeHarmonyLoop::TriggerClarityResonance() {
    clarityResonance_ = std::min(1.0, clarityResonance_.load() + 0.1);
}

void SupremeHarmonyLoop::TriggerHarmonyResonance() {
    harmonyResonanceLevel_ = std::min(1.0, harmonyResonanceLevel_.load() + 0.1);
}

void SupremeHarmonyLoop::TriggerStabilityResonance() {
    stabilityResonance_ = std::min(1.0, stabilityResonance_.load() + 0.1);
}

void SupremeHarmonyLoop::TriggerDensityResonance() {
    densityResonance_ = std::min(1.0, densityResonance_.load() + 0.1);
}

void SupremeHarmonyLoop::TriggerPurityResonance() {
    purityResonance_ = std::min(1.0, purityResonance_.load() + 0.1);
}

void SupremeHarmonyLoop::TriggerEternityResonance() {
    eternityResonance_ = std::min(1.0, eternityResonance_.load() + 0.1);
}

void SupremeHarmonyLoop::TriggerSupremacyResonance() {
    supremacyResonance_ = std::min(1.0, supremacyResonance_.load() + 0.1);
}

void SupremeHarmonyLoop::TickLoop() {
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

void SupremeHarmonyLoop::FrameLoop() {
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

void SupremeHarmonyLoop::SyncLoop() {
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

void SupremeHarmonyLoop::HarmonyLoop() {
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

void SupremeHarmonyLoop::UpdateMetrics() {
    std::lock_guard<std::mutex> lock(metricsMutex_);
    
    auto& engine = SupremeHarmonyEngine::GetInstance();
    auto harmonies = engine.GetAllSupremeHarmonies();
    auto nodes = engine.GetAllHarmonyNodes();
    auto streams = engine.GetAllSupremeStreams();
    auto waves = engine.GetAllHarmonyWaves();
    auto matrices = engine.GetAllSupremeMatrices();
    auto tensors = engine.GetAllSupremeTensors();
    auto clarities = engine.GetAllSupremeClarities();
    
    metrics_.supremeHarmonyCount = static_cast<double>(harmonies.size());
    metrics_.nodeCount = static_cast<double>(nodes.size());
    metrics_.streamCount = static_cast<double>(streams.size());
    metrics_.waveCount = static_cast<double>(waves.size());
    metrics_.matrixCount = static_cast<double>(matrices.size());
    metrics_.tensorCount = static_cast<double>(tensors.size());
    metrics_.clarityCount = static_cast<double>(clarities.size());
    
    double totalSupremacy = 0.0, totalUnity = 0.0, totalHarmony = 0.0, totalCoherence = 0.0;
    double totalClarity = 0.0, totalEternity = 0.0, totalOmnipresence = 0.0, totalContinuity = 0.0;
    
    for (const auto& h : harmonies) {
        totalSupremacy += h->supremacy;
        totalUnity += h->unity;
        totalHarmony += h->harmony;
        totalCoherence += h->coherence;
        totalClarity += h->clarity;
        totalEternity += h->eternity;
        totalOmnipresence += h->omnipresence;
        totalContinuity += h->continuity;
    }
    
    if (!harmonies.empty()) {
        metrics_.averageSupremacy = totalSupremacy / harmonies.size();
        metrics_.averageUnity = totalUnity / harmonies.size();
        metrics_.averageHarmony = totalHarmony / harmonies.size();
        metrics_.averageCoherence = totalCoherence / harmonies.size();
        metrics_.averageClarity = totalClarity / harmonies.size();
        metrics_.averageEternity = totalEternity / harmonies.size();
        metrics_.averageOmnipresence = totalOmnipresence / harmonies.size();
        metrics_.averageContinuity = totalContinuity / harmonies.size();
    }
    
    double totalStability = 0.0, totalDensity = 0.0, totalPurity = 0.0;
    
    for (const auto& m : matrices) totalStability += m->stability;
    for (const auto& t : tensors) totalDensity += t->density;
    for (const auto& c : clarities) totalPurity += c->purity;
    
    metrics_.totalSupremacy = totalSupremacy;
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
    
    metrics_.supremeResonance = supremeResonance_.load();
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
}

void SupremeHarmonyLoop::ProcessSyncPulse() {
    syncEfficiency_ = std::min(1.0, syncEfficiency_.load() + 0.05);
}

void SupremeHarmonyLoop::ProcessHarmonyPulse() {
    harmonyResonance_ = std::min(1.0, harmonyResonance_.load() + 0.05);
}

void SupremeHarmonyLoop::CalculateResonanceLevels() {
    double total = supremeResonance_.load() + unityResonance_.load() + convergenceResonance_.load() +
                   continuityResonance_.load() + omnipresenceResonance_.load() + coherenceResonance_.load() +
                   clarityResonance_.load() + harmonyResonanceLevel_.load() + stabilityResonance_.load() +
                   densityResonance_.load() + purityResonance_.load() + eternityResonance_.load() +
                   supremacyResonance_.load();
    crossLayerConvergence_ = total / 13.0;
}

void SupremeHarmonyLoop::SynchronizeAllLayers() {
    syncEfficiency_ = std::min(1.0, syncEfficiency_.load() + 0.01);
}

void SupremeHarmonyLoop::HarmonizeCrossLayers() {
    harmonyResonance_ = std::min(1.0, harmonyResonance_.load() + 0.01);
}

} // namespace SupremeHarmony
