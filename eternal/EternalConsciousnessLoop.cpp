#include "EternalConsciousnessLoop.hpp"
#include "EternalConsciousnessEngine.hpp"
#include <chrono>
#include <thread>
#include <algorithm>

namespace EternalConsciousness {

// Static member definitions
std::atomic<bool> EternalConsciousnessLoop::s_initialized{false};
std::atomic<bool> EternalConsciousnessLoop::s_running{false};
std::atomic<bool> EternalConsciousnessLoop::s_paused{false};
std::atomic<bool> EternalConsciousnessLoop::s_shouldStop{false};

EternalConsciousnessLoopConfig EternalConsciousnessLoop::s_config;
EternalConsciousnessLoopMetrics EternalConsciousnessLoop::s_metrics;

std::thread EternalConsciousnessLoop::s_tickThread;
std::thread EternalConsciousnessLoop::s_renderThread;

std::mutex EternalConsciousnessLoop::s_tickCallbackMutex;
std::mutex EternalConsciousnessLoop::s_frameCallbackMutex;
std::mutex EternalConsciousnessLoop::s_renderCallbackMutex;
std::mutex EternalConsciousnessLoop::s_updateCallbackMutex;
std::mutex EternalConsciousnessLoop::s_metricsMutex;

std::vector<EternalConsciousnessLoop::TickCallback> EternalConsciousnessLoop::s_tickCallbacks;
std::vector<EternalConsciousnessLoop::FrameCallback> EternalConsciousnessLoop::s_frameCallbacks;
std::vector<EternalConsciousnessLoop::RenderCallback> EternalConsciousnessLoop::s_renderCallbacks;
std::vector<EternalConsciousnessLoop::UpdateCallback> EternalConsciousnessLoop::s_updateCallbacks;

bool EternalConsciousnessLoop::Init(const EternalConsciousnessLoopConfig& config) {
    if (s_initialized.load()) return true;
    
    s_config = config;
    
    // Initialize engine if not already done
    if (!EternalConsciousnessEngine::IsInitialized()) {
        EternalConsciousnessEngine::Init();
    }
    
    s_initialized.store(true);
    return true;
}

void EternalConsciousnessLoop::Shutdown() {
    if (!s_initialized.load()) return;
    
    Stop();
    
    if (s_tickThread.joinable()) {
        s_tickThread.join();
    }
    if (s_renderThread.joinable()) {
        s_renderThread.join();
    }
    
    s_initialized.store(false);
}

bool EternalConsciousnessLoop::IsInitialized() {
    return s_initialized.load();
}

void EternalConsciousnessLoop::Start() {
    if (s_running.load()) return;
    
    s_shouldStop.store(false);
    s_running.store(true);
    
    s_tickThread = std::thread(TickLoop);
    s_renderThread = std::thread(RenderLoop);
}

void EternalConsciousnessLoop::Stop() {
    s_shouldStop.store(true);
    s_running.store(false);
}

bool EternalConsciousnessLoop::IsRunning() {
    return s_running.load();
}

void EternalConsciousnessLoop::Pause() {
    s_paused.store(true);
}

void EternalConsciousnessLoop::Resume() {
    s_paused.store(false);
}

bool EternalConsciousnessLoop::IsPaused() {
    return s_paused.load();
}

void EternalConsciousnessLoop::SetConfig(const EternalConsciousnessLoopConfig& config) {
    s_config = config;
}

EternalConsciousnessLoopConfig EternalConsciousnessLoop::GetConfig() {
    return s_config;
}

EternalConsciousnessLoopMetrics EternalConsciousnessLoop::GetMetrics() {
    std::lock_guard<std::mutex> lock(s_metricsMutex);
    return s_metrics;
}

float EternalConsciousnessLoop::GetCurrentTPS() {
    std::lock_guard<std::mutex> lock(s_metricsMutex);
    return s_metrics.currentTPS;
}

float EternalConsciousnessLoop::GetCurrentFPS() {
    std::lock_guard<std::mutex> lock(s_metricsMutex);
    return s_metrics.currentFPS;
}

int64_t EternalConsciousnessLoop::GetTickCount() {
    std::lock_guard<std::mutex> lock(s_metricsMutex);
    return s_metrics.totalTicks;
}

int64_t EternalConsciousnessLoop::GetFrameCount() {
    std::lock_guard<std::mutex> lock(s_metricsMutex);
    return s_metrics.totalFrames;
}

void EternalConsciousnessLoop::RegisterTickCallback(TickCallback callback) {
    std::lock_guard<std::mutex> lock(s_tickCallbackMutex);
    s_tickCallbacks.push_back(callback);
}

void EternalConsciousnessLoop::UnregisterTickCallback(TickCallback callback) {
    std::lock_guard<std::mutex> lock(s_tickCallbackMutex);
    s_tickCallbacks.erase(
        std::remove_if(s_tickCallbacks.begin(), s_tickCallbacks.end(),
            [&callback](const TickCallback& cb) {
                return cb.target_type() == callback.target_type();
            }), s_tickCallbacks.end());
}

void EternalConsciousnessLoop::RegisterFrameCallback(FrameCallback callback) {
    std::lock_guard<std::mutex> lock(s_frameCallbackMutex);
    s_frameCallbacks.push_back(callback);
}

void EternalConsciousnessLoop::UnregisterFrameCallback(FrameCallback callback) {
    std::lock_guard<std::mutex> lock(s_frameCallbackMutex);
    s_frameCallbacks.erase(
        std::remove_if(s_frameCallbacks.begin(), s_frameCallbacks.end(),
            [&callback](const FrameCallback& cb) {
                return cb.target_type() == callback.target_type();
            }), s_frameCallbacks.end());
}

void EternalConsciousnessLoop::RegisterRenderCallback(RenderCallback callback) {
    std::lock_guard<std::mutex> lock(s_renderCallbackMutex);
    s_renderCallbacks.push_back(callback);
}

void EternalConsciousnessLoop::UnregisterRenderCallback(RenderCallback callback) {
    std::lock_guard<std::mutex> lock(s_renderCallbackMutex);
    s_renderCallbacks.erase(
        std::remove_if(s_renderCallbacks.begin(), s_renderCallbacks.end(),
            [&callback](const RenderCallback& cb) {
                return cb.target_type() == callback.target_type();
            }), s_renderCallbacks.end());
}

void EternalConsciousnessLoop::RegisterUpdateCallback(UpdateCallback callback) {
    std::lock_guard<std::mutex> lock(s_updateCallbackMutex);
    s_updateCallbacks.push_back(callback);
}

void EternalConsciousnessLoop::UnregisterUpdateCallback(UpdateCallback callback) {
    std::lock_guard<std::mutex> lock(s_updateCallbackMutex);
    s_updateCallbacks.erase(
        std::remove_if(s_updateCallbacks.begin(), s_updateCallbacks.end(),
            [&callback](const UpdateCallback& cb) {
                return cb.target_type() == callback.target_type();
            }), s_updateCallbacks.end());
}

void EternalConsciousnessLoop::Tick(float deltaTime) {
    // Execute tick callbacks
    std::vector<TickCallback> callbacks;
    {
        std::lock_guard<std::mutex> lock(s_tickCallbackMutex);
        callbacks = s_tickCallbacks;
    }
    
    for (auto& callback : callbacks) {
        callback(deltaTime);
    }
    
    // Execute update callbacks
    std::vector<UpdateCallback> updateCallbacks;
    {
        std::lock_guard<std::mutex> lock(s_updateCallbackMutex);
        updateCallbacks = s_updateCallbacks;
    }
    
    for (auto& callback : updateCallbacks) {
        callback(deltaTime);
    }
}

void EternalConsciousnessLoop::TickLoop() {
    using namespace std::chrono;
    
    auto lastTickTime = steady_clock::now();
    const float targetTickInterval = 1000.0f / s_config.targetTPS; // ms
    
    while (!s_shouldStop.load()) {
        if (s_paused.load()) {
            std::this_thread::sleep_for(milliseconds(10));
            continue;
        }
        
        auto currentTime = steady_clock::now();
        float deltaTime = duration<float, std::milli>(currentTime - lastTickTime).count();
        
        if (deltaTime >= targetTickInterval) {
            auto tickStart = steady_clock::now();
            
            Tick(deltaTime / 1000.0f); // Convert to seconds
            
            auto tickEnd = steady_clock::now();
            float tickTimeMs = duration<float, std::milli>(tickEnd - tickStart).count();
            
            {
                std::lock_guard<std::mutex> lock(s_metricsMutex);
                s_metrics.totalTicks++;
                s_metrics.averageTickTimeMs = 
                    (s_metrics.averageTickTimeMs * (s_metrics.totalTicks - 1) + tickTimeMs) / s_metrics.totalTicks;
                s_metrics.currentTPS = 1000.0f / deltaTime;
            }
            
            lastTickTime = currentTime;
        } else {
            // Sleep to prevent busy waiting
            std::this_thread::sleep_for(microseconds(100));
        }
    }
}

void EternalConsciousnessLoop::RenderLoop() {
    using namespace std::chrono;
    
    auto lastFrameTime = steady_clock::now();
    const float targetFrameInterval = 1000.0f / s_config.maxFPS; // ms
    
    while (!s_shouldStop.load()) {
        if (s_paused.load()) {
            std::this_thread::sleep_for(milliseconds(10));
            continue;
        }
        
        auto currentTime = steady_clock::now();
        float deltaTime = duration<float, std::milli>(currentTime - lastFrameTime).count();
        
        if (!s_config.enableFrameLimiting || deltaTime >= targetFrameInterval) {
            auto frameStart = steady_clock::now();
            
            // Execute frame callbacks
            std::vector<FrameCallback> callbacks;
            {
                std::lock_guard<std::mutex> lock(s_frameCallbackMutex);
                callbacks = s_frameCallbacks;
            }
            
            for (auto& callback : callbacks) {
                callback();
            }
            
            // Execute render callbacks
            std::vector<RenderCallback> renderCallbacks;
            {
                std::lock_guard<std::mutex> lock(s_renderCallbackMutex);
                renderCallbacks = s_renderCallbacks;
            }
            
            for (auto& callback : renderCallbacks) {
                callback();
            }
            
            auto frameEnd = steady_clock::now();
            float frameTimeMs = duration<float, std::milli>(frameEnd - frameStart).count();
            
            {
                std::lock_guard<std::mutex> lock(s_metricsMutex);
                s_metrics.totalFrames++;
                s_metrics.averageFrameTimeMs = 
                    (s_metrics.averageFrameTimeMs * (s_metrics.totalFrames - 1) + frameTimeMs) / s_metrics.totalFrames;
                s_metrics.currentFPS = 1000.0f / deltaTime;
            }
            
            lastFrameTime = currentTime;
        } else {
            // Sleep to prevent busy waiting
            std::this_thread::sleep_for(microseconds(100));
        }
    }
}

} // namespace EternalConsciousness
