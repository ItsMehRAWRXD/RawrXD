#include "AbsoluteTruthLoop.hpp"
#include "AbsoluteTruthEngine.hpp"
#include <chrono>
#include <cmath>

namespace AbsoluteTruth {

// Static member definitions
std::atomic<bool> AbsoluteTruthLoop::s_initialized{false};
std::atomic<bool> AbsoluteTruthLoop::s_running{false};
std::atomic<bool> AbsoluteTruthLoop::s_paused{false};
std::atomic<bool> AbsoluteTruthLoop::s_shouldStop{false};

AbsoluteTruthLoopConfig AbsoluteTruthLoop::s_config;
AbsoluteTruthLoopMetrics AbsoluteTruthLoop::s_metrics;

std::thread AbsoluteTruthLoop::s_tickThread;
std::thread AbsoluteTruthLoop::s_renderThread;

std::mutex AbsoluteTruthLoop::s_tickCallbackMutex;
std::mutex AbsoluteTruthLoop::s_frameCallbackMutex;
std::mutex AbsoluteTruthLoop::s_renderCallbackMutex;
std::mutex AbsoluteTruthLoop::s_updateCallbackMutex;
std::mutex AbsoluteTruthLoop::s_metricsMutex;

std::vector<AbsoluteTruthLoop::TickCallback> AbsoluteTruthLoop::s_tickCallbacks;
std::vector<AbsoluteTruthLoop::FrameCallback> AbsoluteTruthLoop::s_frameCallbacks;
std::vector<AbsoluteTruthLoop::RenderCallback> AbsoluteTruthLoop::s_renderCallbacks;
std::vector<AbsoluteTruthLoop::UpdateCallback> AbsoluteTruthLoop::s_updateCallbacks;

bool AbsoluteTruthLoop::Init(const AbsoluteTruthLoopConfig& config) {
    if (s_initialized.load()) return true;
    
    s_config = config;
    s_initialized.store(true);
    return true;
}

void AbsoluteTruthLoop::Shutdown() {
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

bool AbsoluteTruthLoop::IsInitialized() {
    return s_initialized.load();
}

void AbsoluteTruthLoop::Start() {
    if (s_running.load()) return;
    
    s_shouldStop.store(false);
    s_running.store(true);
    
    s_tickThread = std::thread(TickLoop);
    s_renderThread = std::thread(RenderLoop);
}

void AbsoluteTruthLoop::Stop() {
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

bool AbsoluteTruthLoop::IsRunning() {
    return s_running.load();
}

void AbsoluteTruthLoop::Pause() {
    s_paused.store(true);
}

void AbsoluteTruthLoop::Resume() {
    s_paused.store(false);
}

bool AbsoluteTruthLoop::IsPaused() {
    return s_paused.load();
}

void AbsoluteTruthLoop::SetConfig(const AbsoluteTruthLoopConfig& config) {
    s_config = config;
}

AbsoluteTruthLoopConfig AbsoluteTruthLoop::GetConfig() {
    return s_config;
}

AbsoluteTruthLoopMetrics AbsoluteTruthLoop::GetMetrics() {
    std::lock_guard<std::mutex> lock(s_metricsMutex);
    return s_metrics;
}

float AbsoluteTruthLoop::GetCurrentTPS() {
    std::lock_guard<std::mutex> lock(s_metricsMutex);
    return s_metrics.currentTPS;
}

float AbsoluteTruthLoop::GetCurrentFPS() {
    std::lock_guard<std::mutex> lock(s_metricsMutex);
    return s_metrics.currentFPS;
}

int64_t AbsoluteTruthLoop::GetTickCount() {
    std::lock_guard<std::mutex> lock(s_metricsMutex);
    return s_metrics.totalTicks;
}

int64_t AbsoluteTruthLoop::GetFrameCount() {
    std::lock_guard<std::mutex> lock(s_metricsMutex);
    return s_metrics.totalFrames;
}

void AbsoluteTruthLoop::RegisterTickCallback(TickCallback callback) {
    std::lock_guard<std::mutex> lock(s_tickCallbackMutex);
    s_tickCallbacks.push_back(callback);
}

void AbsoluteTruthLoop::UnregisterTickCallback(TickCallback callback) {
    std::lock_guard<std::mutex> lock(s_tickCallbackMutex);
    // Note: Cannot reliably compare std::function instances
}

void AbsoluteTruthLoop::RegisterFrameCallback(FrameCallback callback) {
    std::lock_guard<std::mutex> lock(s_frameCallbackMutex);
    s_frameCallbacks.push_back(callback);
}

void AbsoluteTruthLoop::UnregisterFrameCallback(FrameCallback callback) {
    std::lock_guard<std::mutex> lock(s_frameCallbackMutex);
    // Note: Cannot reliably compare std::function instances
}

void AbsoluteTruthLoop::RegisterRenderCallback(RenderCallback callback) {
    std::lock_guard<std::mutex> lock(s_renderCallbackMutex);
    s_renderCallbacks.push_back(callback);
}

void AbsoluteTruthLoop::UnregisterRenderCallback(RenderCallback callback) {
    std::lock_guard<std::mutex> lock(s_renderCallbackMutex);
    // Note: Cannot reliably compare std::function instances
}

void AbsoluteTruthLoop::RegisterUpdateCallback(UpdateCallback callback) {
    std::lock_guard<std::mutex> lock(s_updateCallbackMutex);
    s_updateCallbacks.push_back(callback);
}

void AbsoluteTruthLoop::UnregisterUpdateCallback(UpdateCallback callback) {
    std::lock_guard<std::mutex> lock(s_updateCallbackMutex);
    // Note: Cannot reliably compare std::function instances
}

void AbsoluteTruthLoop::Tick(float deltaTime) {
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

void AbsoluteTruthLoop::TickLoop() {
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

void AbsoluteTruthLoop::RenderLoop() {
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

void AbsoluteTruthLoop::UpdateMetrics(float tickTimeMs, float frameTimeMs) {
    std::lock_guard<std::mutex> lock(s_metricsMutex);
    s_metrics.averageTickTimeMs = s_metrics.averageTickTimeMs * 0.95f + tickTimeMs * 0.05f;
    s_metrics.averageFrameTimeMs = s_metrics.averageFrameTimeMs * 0.95f + frameTimeMs * 0.05f;
}

} // namespace AbsoluteTruth
