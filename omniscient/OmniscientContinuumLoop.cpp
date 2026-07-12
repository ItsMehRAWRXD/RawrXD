#include "OmniscientContinuumLoop.hpp"
#include "OmniscientContinuumEngine.hpp"
#include <chrono>
#include <cmath>

namespace OmniscientContinuum {

// Static member definitions
std::atomic<bool> OmniscientContinuumLoop::s_initialized{false};
std::atomic<bool> OmniscientContinuumLoop::s_running{false};
std::atomic<bool> OmniscientContinuumLoop::s_paused{false};
std::atomic<bool> OmniscientContinuumLoop::s_shouldStop{false};

OmniscientContinuumLoopConfig OmniscientContinuumLoop::s_config;
OmniscientContinuumLoopMetrics OmniscientContinuumLoop::s_metrics;

std::thread OmniscientContinuumLoop::s_tickThread;
std::thread OmniscientContinuumLoop::s_renderThread;
std::thread OmniscientContinuumLoop::s_synchronizationThread;

std::mutex OmniscientContinuumLoop::s_tickCallbackMutex;
std::mutex OmniscientContinuumLoop::s_frameCallbackMutex;
std::mutex OmniscientContinuumLoop::s_renderCallbackMutex;
std::mutex OmniscientContinuumLoop::s_updateCallbackMutex;
std::mutex OmniscientContinuumLoop::s_synchronizationCallbackMutex;
std::mutex OmniscientContinuumLoop::s_resonanceCallbackMutex;
std::mutex OmniscientContinuumLoop::s_metricsMutex;

std::vector<OmniscientContinuumLoop::TickCallback> OmniscientContinuumLoop::s_tickCallbacks;
std::vector<OmniscientContinuumLoop::FrameCallback> OmniscientContinuumLoop::s_frameCallbacks;
std::vector<OmniscientContinuumLoop::RenderCallback> OmniscientContinuumLoop::s_renderCallbacks;
std::vector<OmniscientContinuumLoop::UpdateCallback> OmniscientContinuumLoop::s_updateCallbacks;
std::vector<OmniscientContinuumLoop::SynchronizationCallback> OmniscientContinuumLoop::s_synchronizationCallbacks;
std::vector<OmniscientContinuumLoop::ResonanceCallback> OmniscientContinuumLoop::s_resonanceCallbacks;

bool OmniscientContinuumLoop::Init(const OmniscientContinuumLoopConfig& config) {
    if (s_initialized.load()) return true;
    
    s_config = config;
    s_initialized.store(true);
    return true;
}

void OmniscientContinuumLoop::Shutdown() {
    if (!s_initialized.load()) return;
    
    Stop();
    
    std::lock_guard<std::mutex> lock1(s_tickCallbackMutex);
    std::lock_guard<std::mutex> lock2(s_frameCallbackMutex);
    std::lock_guard<std::mutex> lock3(s_renderCallbackMutex);
    std::lock_guard<std::mutex> lock4(s_updateCallbackMutex);
    std::lock_guard<std::mutex> lock5(s_synchronizationCallbackMutex);
    std::lock_guard<std::mutex> lock6(s_resonanceCallbackMutex);
    
    s_tickCallbacks.clear();
    s_frameCallbacks.clear();
    s_renderCallbacks.clear();
    s_updateCallbacks.clear();
    s_synchronizationCallbacks.clear();
    s_resonanceCallbacks.clear();
    
    s_initialized.store(false);
}

bool OmniscientContinuumLoop::IsInitialized() {
    return s_initialized.load();
}

void OmniscientContinuumLoop::Start() {
    if (s_running.load()) return;
    
    s_shouldStop.store(false);
    s_running.store(true);
    
    s_tickThread = std::thread(TickLoop);
    s_renderThread = std::thread(RenderLoop);
    
    if (s_config.enableMultiLayerSynchronization) {
        s_synchronizationThread = std::thread(SynchronizationLoop);
    }
}

void OmniscientContinuumLoop::Stop() {
    if (!s_running.load()) return;
    
    s_shouldStop.store(true);
    s_running.store(false);
    
    if (s_tickThread.joinable()) {
        s_tickThread.join();
    }
    if (s_renderThread.joinable()) {
        s_renderThread.join();
    }
    if (s_synchronizationThread.joinable()) {
        s_synchronizationThread.join();
    }
}

bool OmniscientContinuumLoop::IsRunning() {
    return s_running.load();
}

void OmniscientContinuumLoop::Pause() {
    s_paused.store(true);
}

void OmniscientContinuumLoop::Resume() {
    s_paused.store(false);
}

bool OmniscientContinuumLoop::IsPaused() {
    return s_paused.load();
}

void OmniscientContinuumLoop::SetConfig(const OmniscientContinuumLoopConfig& config) {
    s_config = config;
}

OmniscientContinuumLoopConfig OmniscientContinuumLoop::GetConfig() {
    return s_config;
}

OmniscientContinuumLoopMetrics OmniscientContinuumLoop::GetMetrics() {
    std::lock_guard<std::mutex> lock(s_metricsMutex);
    return s_metrics;
}

float OmniscientContinuumLoop::GetCurrentTPS() {
    std::lock_guard<std::mutex> lock(s_metricsMutex);
    return s_metrics.currentTPS;
}

float OmniscientContinuumLoop::GetCurrentFPS() {
    std::lock_guard<std::mutex> lock(s_metricsMutex);
    return s_metrics.currentFPS;
}

int64_t OmniscientContinuumLoop::GetTickCount() {
    std::lock_guard<std::mutex> lock(s_metricsMutex);
    return s_metrics.totalTicks;
}

int64_t OmniscientContinuumLoop::GetFrameCount() {
    std::lock_guard<std::mutex> lock(s_metricsMutex);
    return s_metrics.totalFrames;
}

int64_t OmniscientContinuumLoop::GetSynchronizedLayers() {
    std::lock_guard<std::mutex> lock(s_metricsMutex);
    return s_metrics.synchronizedLayers;
}

int64_t OmniscientContinuumLoop::GetResonanceHarmonizations() {
    std::lock_guard<std::mutex> lock(s_metricsMutex);
    return s_metrics.resonanceHarmonizations;
}

void OmniscientContinuumLoop::RegisterTickCallback(TickCallback callback) {
    std::lock_guard<std::mutex> lock(s_tickCallbackMutex);
    s_tickCallbacks.push_back(callback);
}

void OmniscientContinuumLoop::UnregisterTickCallback(TickCallback callback) {
    std::lock_guard<std::mutex> lock(s_tickCallbackMutex);
}

void OmniscientContinuumLoop::RegisterFrameCallback(FrameCallback callback) {
    std::lock_guard<std::mutex> lock(s_frameCallbackMutex);
    s_frameCallbacks.push_back(callback);
}

void OmniscientContinuumLoop::UnregisterFrameCallback(FrameCallback callback) {
    std::lock_guard<std::mutex> lock(s_frameCallbackMutex);
}

void OmniscientContinuumLoop::RegisterRenderCallback(RenderCallback callback) {
    std::lock_guard<std::mutex> lock(s_renderCallbackMutex);
    s_renderCallbacks.push_back(callback);
}

void OmniscientContinuumLoop::UnregisterRenderCallback(RenderCallback callback) {
    std::lock_guard<std::mutex> lock(s_renderCallbackMutex);
}

void OmniscientContinuumLoop::RegisterUpdateCallback(UpdateCallback callback) {
    std::lock_guard<std::mutex> lock(s_updateCallbackMutex);
    s_updateCallbacks.push_back(callback);
}

void OmniscientContinuumLoop::UnregisterUpdateCallback(UpdateCallback callback) {
    std::lock_guard<std::mutex> lock(s_updateCallbackMutex);
}

void OmniscientContinuumLoop::RegisterSynchronizationCallback(SynchronizationCallback callback) {
    std::lock_guard<std::mutex> lock(s_synchronizationCallbackMutex);
    s_synchronizationCallbacks.push_back(callback);
}

void OmniscientContinuumLoop::UnregisterSynchronizationCallback(SynchronizationCallback callback) {
    std::lock_guard<std::mutex> lock(s_synchronizationCallbackMutex);
}

void OmniscientContinuumLoop::RegisterResonanceCallback(ResonanceCallback callback) {
    std::lock_guard<std::mutex> lock(s_resonanceCallbackMutex);
    s_resonanceCallbacks.push_back(callback);
}

void OmniscientContinuumLoop::UnregisterResonanceCallback(ResonanceCallback callback) {
    std::lock_guard<std::mutex> lock(s_resonanceCallbackMutex);
}

void OmniscientContinuumLoop::Tick(float deltaTime) {
    {
        std::lock_guard<std::mutex> lock(s_tickCallbackMutex);
        for (auto& callback : s_tickCallbacks) {
            callback(deltaTime);
        }
    }
    
    {
        std::lock_guard<std::mutex> lock(s_updateCallbackMutex);
        for (auto& callback : s_updateCallbacks) {
            callback(deltaTime);
        }
    }
}

void OmniscientContinuumLoop::TickLoop() {
    using namespace std::chrono;
    
    auto lastTickTime = steady_clock::now();
    float tickAccumulator = 0.0f;
    const float targetTickInterval = 1000.0f / s_config.targetTPS;
    
    while (!s_shouldStop.load()) {
        auto currentTime = steady_clock::now();
        float deltaTime = duration<float, std::milli>(currentTime - lastTickTime).count();
        lastTickTime = currentTime;
        
        tickAccumulator += deltaTime;
        
        if (!s_paused.load()) {
            while (tickAccumulator >= targetTickInterval) {
                float tickDelta = targetTickInterval / 1000.0f;
                
                auto tickStart = steady_clock::now();
                Tick(tickDelta);
                auto tickEnd = steady_clock::now();
                float tickTimeMs = duration<float, std::milli>(tickEnd - tickStart).count();
                
                {
                    std::lock_guard<std::mutex> lock(s_metricsMutex);
                    s_metrics.totalTicks++;
                    s_metrics.averageTickTimeMs = s_metrics.averageTickTimeMs * 0.95f + tickTimeMs * 0.05f;
                    s_metrics.currentTPS = 1000.0f / targetTickInterval;
                }
                
                tickAccumulator -= targetTickInterval;
            }
        }
        
        std::this_thread::sleep_for(milliseconds(1));
    }
}

void OmniscientContinuumLoop::RenderLoop() {
    using namespace std::chrono;
    
    auto lastFrameTime = steady_clock::now();
    const float targetFrameInterval = 1000.0f / s_config.maxFPS;
    
    while (!s_shouldStop.load()) {
        auto currentTime = steady_clock::now();
        float deltaTime = duration<float, std::milli>(currentTime - lastFrameTime).count();
        
        if (s_config.enableFrameLimiting && deltaTime < targetFrameInterval) {
            std::this_thread::sleep_for(
                milliseconds(static_cast<long>(targetFrameInterval - deltaTime)));
            continue;
        }
        
        lastFrameTime = currentTime;
        
        if (!s_paused.load()) {
            auto frameStart = steady_clock::now();
            
            {
                std::lock_guard<std::mutex> lock(s_frameCallbackMutex);
                for (auto& callback : s_frameCallbacks) {
                    callback();
                }
            }
            
            {
                std::lock_guard<std::mutex> lock(s_renderCallbackMutex);
                for (auto& callback : s_renderCallbacks) {
                    callback();
                }
            }
            
            auto frameEnd = steady_clock::now();
            float frameTimeMs = duration<float, std::milli>(frameEnd - frameStart).count();
            
            {
                std::lock_guard<std::mutex> lock(s_metricsMutex);
                s_metrics.totalFrames++;
                s_metrics.averageFrameTimeMs = s_metrics.averageFrameTimeMs * 0.95f + frameTimeMs * 0.05f;
                s_metrics.currentFPS = 1000.0f / deltaTime;
            }
        }
    }
}

void OmniscientContinuumLoop::SynchronizationLoop() {
    using namespace std::chrono;
    
    while (!s_shouldStop.load()) {
        if (!s_paused.load()) {
            if (s_config.enableMultiLayerSynchronization) {
                SynchronizeLayers();
            }
            
            if (s_config.enableCrossLayerResonance) {
                HarmonizeResonance();
            }
        }
        
        std::this_thread::sleep_for(milliseconds(100));
    }
}

void OmniscientContinuumLoop::SynchronizeLayers() {
    {
        std::lock_guard<std::mutex> lock(s_synchronizationCallbackMutex);
        for (auto& callback : s_synchronizationCallbacks) {
            callback();
        }
    }
    
    std::lock_guard<std::mutex> lock(s_metricsMutex);
    s_metrics.synchronizedLayers++;
}

void OmniscientContinuumLoop::HarmonizeResonance() {
    {
        std::lock_guard<std::mutex> lock(s_resonanceCallbackMutex);
        for (auto& callback : s_resonanceCallbacks) {
            callback();
        }
    }
    
    std::lock_guard<std::mutex> lock(s_metricsMutex);
    s_metrics.resonanceHarmonizations++;
}

void OmniscientContinuumLoop::UpdateMetrics(float tickTimeMs, float frameTimeMs) {
    std::lock_guard<std::mutex> lock(s_metricsMutex);
    s_metrics.averageTickTimeMs = s_metrics.averageTickTimeMs * 0.95f + tickTimeMs * 0.05f;
    s_metrics.averageFrameTimeMs = s_metrics.averageFrameTimeMs * 0.95f + frameTimeMs * 0.05f;
}

} // namespace OmniscientContinuum
