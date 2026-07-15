#include "SupremeBeingLoop.hpp"
#include "SupremeBeingEngine.hpp"
#include <chrono>
#include <thread>
#include <algorithm>

namespace SupremeBeing {

// Static member definitions
std::atomic<bool> SupremeBeingLoop::s_initialized{false};
std::atomic<bool> SupremeBeingLoop::s_running{false};
std::atomic<bool> SupremeBeingLoop::s_paused{false};
std::atomic<bool> SupremeBeingLoop::s_shouldStop{false};

SupremeBeingLoopConfig SupremeBeingLoop::s_config;
SupremeBeingLoopMetrics SupremeBeingLoop::s_metrics;

std::thread SupremeBeingLoop::s_tickThread;
std::thread SupremeBeingLoop::s_renderThread;

std::mutex SupremeBeingLoop::s_tickCallbackMutex;
std::mutex SupremeBeingLoop::s_frameCallbackMutex;
std::mutex SupremeBeingLoop::s_renderCallbackMutex;
std::mutex SupremeBeingLoop::s_updateCallbackMutex;
std::mutex SupremeBeingLoop::s_metricsMutex;

std::vector<SupremeBeingLoop::TickCallback> SupremeBeingLoop::s_tickCallbacks;
std::vector<SupremeBeingLoop::FrameCallback> SupremeBeingLoop::s_frameCallbacks;
std::vector<SupremeBeingLoop::RenderCallback> SupremeBeingLoop::s_renderCallbacks;
std::vector<SupremeBeingLoop::UpdateCallback> SupremeBeingLoop::s_updateCallbacks;

bool SupremeBeingLoop::Init(const SupremeBeingLoopConfig& config) {
    if (s_initialized.load()) return true;
    
    s_config = config;
    
    // Initialize engine if not already done
    if (!SupremeBeingEngine::IsInitialized()) {
        SupremeBeingEngine::Init();
    }
    
    s_initialized.store(true);
    return true;
}

void SupremeBeingLoop::Shutdown() {
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

bool SupremeBeingLoop::IsInitialized() {
    return s_initialized.load();
}

void SupremeBeingLoop::Start() {
    if (s_running.load()) return;
    
    s_shouldStop.store(false);
    s_running.store(true);
    
    s_tickThread = std::thread(TickLoop);
    s_renderThread = std::thread(RenderLoop);
}

void SupremeBeingLoop::Stop() {
    s_shouldStop.store(true);
    s_running.store(false);
}

bool SupremeBeingLoop::IsRunning() {
    return s_running.load();
}

void SupremeBeingLoop::Pause() {
    s_paused.store(true);
}

void SupremeBeingLoop::Resume() {
    s_paused.store(false);
}

bool SupremeBeingLoop::IsPaused() {
    return s_paused.load();
}

void SupremeBeingLoop::SetConfig(const SupremeBeingLoopConfig& config) {
    s_config = config;
}

SupremeBeingLoopConfig SupremeBeingLoop::GetConfig() {
    return s_config;
}

SupremeBeingLoopMetrics SupremeBeingLoop::GetMetrics() {
    std::lock_guard<std::mutex> lock(s_metricsMutex);
    return s_metrics;
}

float SupremeBeingLoop::GetCurrentTPS() {
    std::lock_guard<std::mutex> lock(s_metricsMutex);
    return s_metrics.currentTPS;
}

float SupremeBeingLoop::GetCurrentFPS() {
    std::lock_guard<std::mutex> lock(s_metricsMutex);
    return s_metrics.currentFPS;
}

int64_t SupremeBeingLoop::GetTickCount() {
    std::lock_guard<std::mutex> lock(s_metricsMutex);
    return s_metrics.totalTicks;
}

int64_t SupremeBeingLoop::GetFrameCount() {
    std::lock_guard<std::mutex> lock(s_metricsMutex);
    return s_metrics.totalFrames;
}

void SupremeBeingLoop::RegisterTickCallback(TickCallback callback) {
    std::lock_guard<std::mutex> lock(s_tickCallbackMutex);
    s_tickCallbacks.push_back(callback);
}

void SupremeBeingLoop::UnregisterTickCallback(TickCallback callback) {
    std::lock_guard<std::mutex> lock(s_tickCallbackMutex);
    s_tickCallbacks.erase(
        std::remove_if(s_tickCallbacks.begin(), s_tickCallbacks.end(),
            [&callback](const TickCallback& cb) {
                return cb.target_type() == callback.target_type();
            }), s_tickCallbacks.end());
}

void SupremeBeingLoop::RegisterFrameCallback(FrameCallback callback) {
    std::lock_guard<std::mutex> lock(s_frameCallbackMutex);
    s_frameCallbacks.push_back(callback);
}

void SupremeBeingLoop::UnregisterFrameCallback(FrameCallback callback) {
    std::lock_guard<std::mutex> lock(s_frameCallbackMutex);
    s_frameCallbacks.erase(
        std::remove_if(s_frameCallbacks.begin(), s_frameCallbacks.end(),
            [&callback](const FrameCallback& cb) {
                return cb.target_type() == callback.target_type();
            }), s_frameCallbacks.end());
}

void SupremeBeingLoop::RegisterRenderCallback(RenderCallback callback) {
    std::lock_guard<std::mutex> lock(s_renderCallbackMutex);
    s_renderCallbacks.push_back(callback);
}

void SupremeBeingLoop::UnregisterRenderCallback(RenderCallback callback) {
    std::lock_guard<std::mutex> lock(s_renderCallbackMutex);
    s_renderCallbacks.erase(
        std::remove_if(s_renderCallbacks.begin(), s_renderCallbacks.end(),
            [&callback](const RenderCallback& cb) {
                return cb.target_type() == callback.target_type();
            }), s_renderCallbacks.end());
}

void SupremeBeingLoop::RegisterUpdateCallback(UpdateCallback callback) {
    std::lock_guard<std::mutex> lock(s_updateCallbackMutex);
    s_updateCallbacks.push_back(callback);
}

void SupremeBeingLoop::UnregisterUpdateCallback(UpdateCallback callback) {
    std::lock_guard<std::mutex> lock(s_updateCallbackMutex);
    s_updateCallbacks.erase(
        std::remove_if(s_updateCallbacks.begin(), s_updateCallbacks.end(),
            [&callback](const UpdateCallback& cb) {
                return cb.target_type() == callback.target_type();
            }), s_updateCallbacks.end());
}

void SupremeBeingLoop::Tick(float deltaTime) {
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

void SupremeBeingLoop::TickLoop() {
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

void SupremeBeingLoop::RenderLoop() {
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

} // namespace SupremeBeing
