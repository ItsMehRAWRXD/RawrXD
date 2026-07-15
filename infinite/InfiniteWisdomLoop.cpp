#include "InfiniteWisdomLoop.hpp"
#include "InfiniteWisdomEngine.hpp"
#include <chrono>
#include <thread>
#include <algorithm>

namespace InfiniteWisdom {

// Static member definitions
std::atomic<bool> InfiniteWisdomLoop::s_initialized{false};
std::atomic<bool> InfiniteWisdomLoop::s_running{false};
std::atomic<bool> InfiniteWisdomLoop::s_paused{false};
std::atomic<bool> InfiniteWisdomLoop::s_shouldStop{false};

InfiniteWisdomLoopConfig InfiniteWisdomLoop::s_config;
InfiniteWisdomLoopMetrics InfiniteWisdomLoop::s_metrics;

std::thread InfiniteWisdomLoop::s_tickThread;
std::thread InfiniteWisdomLoop::s_renderThread;

std::mutex InfiniteWisdomLoop::s_tickCallbackMutex;
std::mutex InfiniteWisdomLoop::s_frameCallbackMutex;
std::mutex InfiniteWisdomLoop::s_renderCallbackMutex;
std::mutex InfiniteWisdomLoop::s_updateCallbackMutex;
std::mutex InfiniteWisdomLoop::s_metricsMutex;

std::vector<InfiniteWisdomLoop::TickCallback> InfiniteWisdomLoop::s_tickCallbacks;
std::vector<InfiniteWisdomLoop::FrameCallback> InfiniteWisdomLoop::s_frameCallbacks;
std::vector<InfiniteWisdomLoop::RenderCallback> InfiniteWisdomLoop::s_renderCallbacks;
std::vector<InfiniteWisdomLoop::UpdateCallback> InfiniteWisdomLoop::s_updateCallbacks;

bool InfiniteWisdomLoop::Init(const InfiniteWisdomLoopConfig& config) {
    if (s_initialized.load()) return true;
    
    s_config = config;
    
    // Initialize engine if not already done
    if (!InfiniteWisdomEngine::IsInitialized()) {
        InfiniteWisdomEngine::Init();
    }
    
    s_initialized.store(true);
    return true;
}

void InfiniteWisdomLoop::Shutdown() {
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

bool InfiniteWisdomLoop::IsInitialized() {
    return s_initialized.load();
}

void InfiniteWisdomLoop::Start() {
    if (s_running.load()) return;
    
    s_shouldStop.store(false);
    s_running.store(true);
    
    s_tickThread = std::thread(TickLoop);
    s_renderThread = std::thread(RenderLoop);
}

void InfiniteWisdomLoop::Stop() {
    s_shouldStop.store(true);
    s_running.store(false);
}

bool InfiniteWisdomLoop::IsRunning() {
    return s_running.load();
}

void InfiniteWisdomLoop::Pause() {
    s_paused.store(true);
}

void InfiniteWisdomLoop::Resume() {
    s_paused.store(false);
}

bool InfiniteWisdomLoop::IsPaused() {
    return s_paused.load();
}

void InfiniteWisdomLoop::SetConfig(const InfiniteWisdomLoopConfig& config) {
    s_config = config;
}

InfiniteWisdomLoopConfig InfiniteWisdomLoop::GetConfig() {
    return s_config;
}

InfiniteWisdomLoopMetrics InfiniteWisdomLoop::GetMetrics() {
    std::lock_guard<std::mutex> lock(s_metricsMutex);
    return s_metrics;
}

float InfiniteWisdomLoop::GetCurrentTPS() {
    std::lock_guard<std::mutex> lock(s_metricsMutex);
    return s_metrics.currentTPS;
}

float InfiniteWisdomLoop::GetCurrentFPS() {
    std::lock_guard<std::mutex> lock(s_metricsMutex);
    return s_metrics.currentFPS;
}

int64_t InfiniteWisdomLoop::GetTickCount() {
    std::lock_guard<std::mutex> lock(s_metricsMutex);
    return s_metrics.totalTicks;
}

int64_t InfiniteWisdomLoop::GetFrameCount() {
    std::lock_guard<std::mutex> lock(s_metricsMutex);
    return s_metrics.totalFrames;
}

void InfiniteWisdomLoop::RegisterTickCallback(TickCallback callback) {
    std::lock_guard<std::mutex> lock(s_tickCallbackMutex);
    s_tickCallbacks.push_back(callback);
}

void InfiniteWisdomLoop::UnregisterTickCallback(TickCallback callback) {
    std::lock_guard<std::mutex> lock(s_tickCallbackMutex);
    s_tickCallbacks.erase(
        std::remove_if(s_tickCallbacks.begin(), s_tickCallbacks.end(),
            [&callback](const TickCallback& cb) {
                return cb.target_type() == callback.target_type();
            }), s_tickCallbacks.end());
}

void InfiniteWisdomLoop::RegisterFrameCallback(FrameCallback callback) {
    std::lock_guard<std::mutex> lock(s_frameCallbackMutex);
    s_frameCallbacks.push_back(callback);
}

void InfiniteWisdomLoop::UnregisterFrameCallback(FrameCallback callback) {
    std::lock_guard<std::mutex> lock(s_frameCallbackMutex);
    s_frameCallbacks.erase(
        std::remove_if(s_frameCallbacks.begin(), s_frameCallbacks.end(),
            [&callback](const FrameCallback& cb) {
                return cb.target_type() == callback.target_type();
            }), s_frameCallbacks.end());
}

void InfiniteWisdomLoop::RegisterRenderCallback(RenderCallback callback) {
    std::lock_guard<std::mutex> lock(s_renderCallbackMutex);
    s_renderCallbacks.push_back(callback);
}

void InfiniteWisdomLoop::UnregisterRenderCallback(RenderCallback callback) {
    std::lock_guard<std::mutex> lock(s_renderCallbackMutex);
    s_renderCallbacks.erase(
        std::remove_if(s_renderCallbacks.begin(), s_renderCallbacks.end(),
            [&callback](const RenderCallback& cb) {
                return cb.target_type() == callback.target_type();
            }), s_renderCallbacks.end());
}

void InfiniteWisdomLoop::RegisterUpdateCallback(UpdateCallback callback) {
    std::lock_guard<std::mutex> lock(s_updateCallbackMutex);
    s_updateCallbacks.push_back(callback);
}

void InfiniteWisdomLoop::UnregisterUpdateCallback(UpdateCallback callback) {
    std::lock_guard<std::mutex> lock(s_updateCallbackMutex);
    s_updateCallbacks.erase(
        std::remove_if(s_updateCallbacks.begin(), s_updateCallbacks.end(),
            [&callback](const UpdateCallback& cb) {
                return cb.target_type() == callback.target_type();
            }), s_updateCallbacks.end());
}

void InfiniteWisdomLoop::Tick(float deltaTime) {
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

void InfiniteWisdomLoop::TickLoop() {
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

void InfiniteWisdomLoop::RenderLoop() {
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

} // namespace InfiniteWisdom
