#include "SupremeConsciousnessLoop.hpp"
#include "SupremeConsciousnessEngine.hpp"
#include <chrono>
#include <cmath>

namespace SupremeConsciousness {

// Static member definitions
std::atomic<bool> SupremeConsciousnessLoop::s_initialized{false};
std::atomic<bool> SupremeConsciousnessLoop::s_running{false};
std::atomic<bool> SupremeConsciousnessLoop::s_paused{false};
std::atomic<bool> SupremeConsciousnessLoop::s_shouldStop{false};

SupremeConsciousnessLoopConfig SupremeConsciousnessLoop::s_config;
SupremeConsciousnessLoopMetrics SupremeConsciousnessLoop::s_metrics;

std::thread SupremeConsciousnessLoop::s_tickThread;
std::thread SupremeConsciousnessLoop::s_renderThread;

std::mutex SupremeConsciousnessLoop::s_tickCallbackMutex;
std::mutex SupremeConsciousnessLoop::s_frameCallbackMutex;
std::mutex SupremeConsciousnessLoop::s_renderCallbackMutex;
std::mutex SupremeConsciousnessLoop::s_updateCallbackMutex;
std::mutex SupremeConsciousnessLoop::s_metricsMutex;

std::vector<SupremeConsciousnessLoop::TickCallback> SupremeConsciousnessLoop::s_tickCallbacks;
std::vector<SupremeConsciousnessLoop::FrameCallback> SupremeConsciousnessLoop::s_frameCallbacks;
std::vector<SupremeConsciousnessLoop::RenderCallback> SupremeConsciousnessLoop::s_renderCallbacks;
std::vector<SupremeConsciousnessLoop::UpdateCallback> SupremeConsciousnessLoop::s_updateCallbacks;

bool SupremeConsciousnessLoop::Init(const SupremeConsciousnessLoopConfig& config) {
    if (s_initialized.load()) return true;
    
    s_config = config;
    s_initialized.store(true);
    return true;
}

void SupremeConsciousnessLoop::Shutdown() {
    if (!s_initialized.load()) return;
    
    Stop();
    
    std::lock_guard<std::mutex> lock1(s_tickCallbackMutex);
    std::lock_guard<std::mutex> lock2(s_frameCallbackMutex);
    std::lock_guard<std::mutex> lock3(s_renderCallbackMutex);
    std::lock_guard<std::mutex> lock4(s_updateCallbackMutex);
    
    s_tickCallbacks.clear();
    s_frameCallbacks.clear();
    s_renderCallbacks.clear();
    s_updateCallbacks.clear();
    
    s_initialized.store(false);
}

bool SupremeConsciousnessLoop::IsInitialized() {
    return s_initialized.load();
}

void SupremeConsciousnessLoop::Start() {
    if (s_running.load()) return;
    
    s_shouldStop.store(false);
    s_running.store(true);
    
    s_tickThread = std::thread(TickLoop);
    s_renderThread = std::thread(RenderLoop);
}

void SupremeConsciousnessLoop::Stop() {
    if (!s_running.load()) return;
    
    s_shouldStop.store(true);
    s_running.store(false);
    
    if (s_tickThread.joinable()) {
        s_tickThread.join();
    }
    if (s_renderThread.joinable()) {
        s_renderThread.join();
    }
}

bool SupremeConsciousnessLoop::IsRunning() {
    return s_running.load();
}

void SupremeConsciousnessLoop::Pause() {
    s_paused.store(true);
}

void SupremeConsciousnessLoop::Resume() {
    s_paused.store(false);
}

bool SupremeConsciousnessLoop::IsPaused() {
    return s_paused.load();
}

void SupremeConsciousnessLoop::SetConfig(const SupremeConsciousnessLoopConfig& config) {
    s_config = config;
}

SupremeConsciousnessLoopConfig SupremeConsciousnessLoop::GetConfig() {
    return s_config;
}

SupremeConsciousnessLoopMetrics SupremeConsciousnessLoop::GetMetrics() {
    std::lock_guard<std::mutex> lock(s_metricsMutex);
    return s_metrics;
}

float SupremeConsciousnessLoop::GetCurrentTPS() {
    std::lock_guard<std::mutex> lock(s_metricsMutex);
    return s_metrics.currentTPS;
}

float SupremeConsciousnessLoop::GetCurrentFPS() {
    std::lock_guard<std::mutex> lock(s_metricsMutex);
    return s_metrics.currentFPS;
}

int64_t SupremeConsciousnessLoop::GetTickCount() {
    std::lock_guard<std::mutex> lock(s_metricsMutex);
    return s_metrics.totalTicks;
}

int64_t SupremeConsciousnessLoop::GetFrameCount() {
    std::lock_guard<std::mutex> lock(s_metricsMutex);
    return s_metrics.totalFrames;
}

void SupremeConsciousnessLoop::RegisterTickCallback(TickCallback callback) {
    std::lock_guard<std::mutex> lock(s_tickCallbackMutex);
    s_tickCallbacks.push_back(callback);
}

void SupremeConsciousnessLoop::UnregisterTickCallback(TickCallback callback) {
    std::lock_guard<std::mutex> lock(s_tickCallbackMutex);
    // Note: Cannot reliably compare std::function instances
}

void SupremeConsciousnessLoop::RegisterFrameCallback(FrameCallback callback) {
    std::lock_guard<std::mutex> lock(s_frameCallbackMutex);
    s_frameCallbacks.push_back(callback);
}

void SupremeConsciousnessLoop::UnregisterFrameCallback(FrameCallback callback) {
    std::lock_guard<std::mutex> lock(s_frameCallbackMutex);
    // Note: Cannot reliably compare std::function instances
}

void SupremeConsciousnessLoop::RegisterRenderCallback(RenderCallback callback) {
    std::lock_guard<std::mutex> lock(s_renderCallbackMutex);
    s_renderCallbacks.push_back(callback);
}

void SupremeConsciousnessLoop::UnregisterRenderCallback(RenderCallback callback) {
    std::lock_guard<std::mutex> lock(s_renderCallbackMutex);
    // Note: Cannot reliably compare std::function instances
}

void SupremeConsciousnessLoop::RegisterUpdateCallback(UpdateCallback callback) {
    std::lock_guard<std::mutex> lock(s_updateCallbackMutex);
    s_updateCallbacks.push_back(callback);
}

void SupremeConsciousnessLoop::UnregisterUpdateCallback(UpdateCallback callback) {
    std::lock_guard<std::mutex> lock(s_updateCallbackMutex);
    // Note: Cannot reliably compare std::function instances
}

void SupremeConsciousnessLoop::Tick(float deltaTime) {
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

void SupremeConsciousnessLoop::TickLoop() {
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

void SupremeConsciousnessLoop::RenderLoop() {
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

void SupremeConsciousnessLoop::UpdateMetrics(float tickTimeMs, float frameTimeMs) {
    std::lock_guard<std::mutex> lock(s_metricsMutex);
    s_metrics.averageTickTimeMs = s_metrics.averageTickTimeMs * 0.95f + tickTimeMs * 0.05f;
    s_metrics.averageFrameTimeMs = s_metrics.averageFrameTimeMs * 0.95f + frameTimeMs * 0.05f;
}

} // namespace SupremeConsciousness
