#include "DivineUnityLoop.hpp"
#include <algorithm>
#include <thread>

namespace DivineUnity {

// Static member definitions
bool DivineUnityLoop::s_initialized = false;
std::atomic<DivineUnityLoopState> DivineUnityLoop::s_state{DivineUnityLoopState::Stopped};
std::unique_ptr<std::thread> DivineUnityLoop::s_loopThread;
DivineUnityLoop::Config DivineUnityLoop::s_config;

std::mutex DivineUnityLoop::s_callbackMutex;
std::vector<DivineUnityTickCallback> DivineUnityLoop::s_tickCallbacks;
std::vector<DivineUnityUpdateCallback> DivineUnityLoop::s_updateCallbacks;
std::vector<DivineUnityRenderCallback> DivineUnityLoop::s_renderCallbacks;

std::atomic<int64_t> DivineUnityLoop::s_tickCount{0};
std::atomic<float> DivineUnityLoop::s_currentTPS{0.0f};
std::atomic<float> DivineUnityLoop::s_currentFPS{0.0f};
std::atomic<float> DivineUnityLoop::s_averageFrameTime{0.0f};
std::atomic<float> DivineUnityLoop::s_lastFrameTime{0.0f};
std::chrono::steady_clock::time_point DivineUnityLoop::s_lastTickTime;
std::chrono::steady_clock::time_point DivineUnityLoop::s_lastFrameTime;
std::mutex DivineUnityLoop::s_metricsMutex;

void DivineUnityLoop::Init(const Config& config) {
    if (s_initialized) return;
    s_config = config;
    s_initialized = true;
    s_state = DivineUnityLoopState::Stopped;
}

void DivineUnityLoop::Shutdown() {
    if (!s_initialized) return;
    Stop();
    UnregisterAllCallbacks();
    s_initialized = false;
}

bool DivineUnityLoop::IsInitialized() {
    return s_initialized;
}

bool DivineUnityLoop::IsRunning() {
    return s_state == DivineUnityLoopState::Running;
}

void DivineUnityLoop::Start() {
    if (!s_initialized || s_state != DivineUnityLoopState::Stopped) return;
    
    s_state = DivineUnityLoopState::Starting;
    s_tickCount = 0;
    s_lastTickTime = std::chrono::steady_clock::now();
    s_lastFrameTime = s_lastTickTime;
    
    s_loopThread = std::make_unique<std::thread>(LoopThreadFunc);
    s_state = DivineUnityLoopState::Running;
}

void DivineUnityLoop::Stop() {
    if (!s_initialized || s_state == DivineUnityLoopState::Stopped) return;
    
    s_state = DivineUnityLoopState::Stopping;
    if (s_loopThread && s_loopThread->joinable()) {
        s_loopThread->join();
    }
    s_loopThread.reset();
    s_state = DivineUnityLoopState::Stopped;
}

void DivineUnityLoop::Pause() {
    if (s_state == DivineUnityLoopState::Running) {
        s_state = DivineUnityLoopState::Paused;
    }
}

void DivineUnityLoop::Resume() {
    if (s_state == DivineUnityLoopState::Paused) {
        s_state = DivineUnityLoopState::Running;
        s_lastTickTime = std::chrono::steady_clock::now();
        s_lastFrameTime = s_lastTickTime;
    }
}

DivineUnityLoopState DivineUnityLoop::GetState() {
    return s_state;
}

void DivineUnityLoop::RegisterTickCallback(const DivineUnityTickCallback& callback) {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    s_tickCallbacks.push_back(callback);
}

void DivineUnityLoop::RegisterUpdateCallback(const DivineUnityUpdateCallback& callback) {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    s_updateCallbacks.push_back(callback);
}

void DivineUnityLoop::RegisterRenderCallback(const DivineUnityRenderCallback& callback) {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    s_renderCallbacks.push_back(callback);
}

void DivineUnityLoop::UnregisterAllCallbacks() {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    s_tickCallbacks.clear();
    s_updateCallbacks.clear();
    s_renderCallbacks.clear();
}

float DivineUnityLoop::GetCurrentTPS() {
    return s_currentTPS.load();
}

float DivineUnityLoop::GetCurrentFPS() {
    return s_currentFPS.load();
}

int64_t DivineUnityLoop::GetTickCount() {
    return s_tickCount.load();
}

float DivineUnityLoop::GetAverageFrameTime() {
    return s_averageFrameTime.load();
}

float DivineUnityLoop::GetLastFrameTime() {
    return s_lastFrameTime.load();
}

void DivineUnityLoop::SetTargetTPS(int tps) {
    s_config.targetTPS = std::max(1, tps);
}

int DivineUnityLoop::GetTargetTPS() {
    return s_config.targetTPS;
}

void DivineUnityLoop::SetMaxFPS(int fps) {
    s_config.maxFPS = std::max(1, fps);
}

int DivineUnityLoop::GetMaxFPS() {
    return s_config.maxFPS;
}

void DivineUnityLoop::EnableFrameLimiting(bool enable) {
    s_config.enableFrameLimiting = enable;
}

bool DivineUnityLoop::IsFrameLimitingEnabled() {
    return s_config.enableFrameLimiting;
}

void DivineUnityLoop::LoopThreadFunc() {
    using namespace std::chrono;
    
    const auto tickInterval = duration<double>(1.0 / s_config.targetTPS);
    auto lastTick = steady_clock::now();
    auto lastFrame = lastTick;
    auto lastMetricsUpdate = lastTick;
    
    int tickCountThisSecond = 0;
    int frameCountThisSecond = 0;
    
    while (s_state != DivineUnityLoopState::Stopping) {
        if (s_state == DivineUnityLoopState::Paused) {
            std::this_thread::sleep_for(milliseconds(10));
            continue;
        }
        
        auto now = steady_clock::now();
        
        // Tick processing
        if (now - lastTick >= tickInterval) {
            auto deltaTime = duration<float>(now - lastTick).count();
            lastTick = now;
            
            s_tickCount++;
            tickCountThisSecond++;
            
            NotifyTickCallbacks(s_tickCount.load());
            NotifyUpdateCallbacks(deltaTime);
            
            // Frame limiting
            if (s_config.enableFrameLimiting) {
                auto frameInterval = duration<double>(1.0 / s_config.maxFPS);
                if (now - lastFrame < frameInterval) {
                    std::this_thread::sleep_for(frameInterval - (now - lastFrame));
                    now = steady_clock::now();
                }
            }
            
            NotifyRenderCallbacks();
            frameCountThisSecond++;
            lastFrame = now;
            
            // Metrics update
            if (s_config.enableMetrics && now - lastMetricsUpdate >= seconds(1)) {
                s_currentTPS = static_cast<float>(tickCountThisSecond);
                s_currentFPS = static_cast<float>(frameCountThisSecond);
                tickCountThisSecond = 0;
                frameCountThisSecond = 0;
                lastMetricsUpdate = now;
            }
        }
        
        // Small sleep to prevent busy-waiting
        std::this_thread::sleep_for(microseconds(100));
    }
}

void DivineUnityLoop::NotifyTickCallbacks(int64_t tickCount) {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    for (auto& callback : s_tickCallbacks) {
        if (callback) callback(tickCount);
    }
}

void DivineUnityLoop::NotifyUpdateCallbacks(float deltaTime) {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    for (auto& callback : s_updateCallbacks) {
        if (callback) callback(deltaTime);
    }
}

void DivineUnityLoop::NotifyRenderCallbacks() {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    for (auto& callback : s_renderCallbacks) {
        if (callback) callback();
    }
}

} // namespace DivineUnity
