#include "PrimordialChaosLoop.hpp"
#include <algorithm>
#include <thread>

namespace PrimordialChaos {

// Static member definitions
bool PrimordialChaosLoop::s_initialized = false;
std::atomic<PrimordialChaosLoopState> PrimordialChaosLoop::s_state{PrimordialChaosLoopState::Stopped};
std::unique_ptr<std::thread> PrimordialChaosLoop::s_loopThread;
PrimordialChaosLoop::Config PrimordialChaosLoop::s_config;

std::mutex PrimordialChaosLoop::s_callbackMutex;
std::vector<PrimordialChaosTickCallback> PrimordialChaosLoop::s_tickCallbacks;
std::vector<PrimordialChaosUpdateCallback> PrimordialChaosLoop::s_updateCallbacks;
std::vector<PrimordialChaosRenderCallback> PrimordialChaosLoop::s_renderCallbacks;

std::atomic<int64_t> PrimordialChaosLoop::s_tickCount{0};
std::atomic<float> PrimordialChaosLoop::s_currentTPS{0.0f};
std::atomic<float> PrimordialChaosLoop::s_currentFPS{0.0f};
std::atomic<float> PrimordialChaosLoop::s_averageFrameTime{0.0f};
std::atomic<float> PrimordialChaosLoop::s_lastFrameTime{0.0f};
std::chrono::steady_clock::time_point PrimordialChaosLoop::s_lastTickTime;
std::chrono::steady_clock::time_point PrimordialChaosLoop::s_lastFrameTime;
std::mutex PrimordialChaosLoop::s_metricsMutex;

void PrimordialChaosLoop::Init(const Config& config) {
    if (s_initialized) return;
    s_config = config;
    s_initialized = true;
    s_state = PrimordialChaosLoopState::Stopped;
}

void PrimordialChaosLoop::Shutdown() {
    if (!s_initialized) return;
    Stop();
    UnregisterAllCallbacks();
    s_initialized = false;
}

bool PrimordialChaosLoop::IsInitialized() {
    return s_initialized;
}

bool PrimordialChaosLoop::IsRunning() {
    return s_state == PrimordialChaosLoopState::Running;
}

void PrimordialChaosLoop::Start() {
    if (!s_initialized || s_state != PrimordialChaosLoopState::Stopped) return;
    
    s_state = PrimordialChaosLoopState::Starting;
    s_tickCount = 0;
    s_lastTickTime = std::chrono::steady_clock::now();
    s_lastFrameTime = s_lastTickTime;
    
    s_loopThread = std::make_unique<std::thread>(LoopThreadFunc);
    s_state = PrimordialChaosLoopState::Running;
}

void PrimordialChaosLoop::Stop() {
    if (!s_initialized || s_state == PrimordialChaosLoopState::Stopped) return;
    
    s_state = PrimordialChaosLoopState::Stopping;
    if (s_loopThread && s_loopThread->joinable()) {
        s_loopThread->join();
    }
    s_loopThread.reset();
    s_state = PrimordialChaosLoopState::Stopped;
}

void PrimordialChaosLoop::Pause() {
    if (s_state == PrimordialChaosLoopState::Running) {
        s_state = PrimordialChaosLoopState::Paused;
    }
}

void PrimordialChaosLoop::Resume() {
    if (s_state == PrimordialChaosLoopState::Paused) {
        s_state = PrimordialChaosLoopState::Running;
        s_lastTickTime = std::chrono::steady_clock::now();
        s_lastFrameTime = s_lastTickTime;
    }
}

PrimordialChaosLoopState PrimordialChaosLoop::GetState() {
    return s_state;
}

void PrimordialChaosLoop::RegisterTickCallback(const PrimordialChaosTickCallback& callback) {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    s_tickCallbacks.push_back(callback);
}

void PrimordialChaosLoop::RegisterUpdateCallback(const PrimordialChaosUpdateCallback& callback) {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    s_updateCallbacks.push_back(callback);
}

void PrimordialChaosLoop::RegisterRenderCallback(const PrimordialChaosRenderCallback& callback) {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    s_renderCallbacks.push_back(callback);
}

void PrimordialChaosLoop::UnregisterAllCallbacks() {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    s_tickCallbacks.clear();
    s_updateCallbacks.clear();
    s_renderCallbacks.clear();
}

float PrimordialChaosLoop::GetCurrentTPS() {
    return s_currentTPS.load();
}

float PrimordialChaosLoop::GetCurrentFPS() {
    return s_currentFPS.load();
}

int64_t PrimordialChaosLoop::GetTickCount() {
    return s_tickCount.load();
}

float PrimordialChaosLoop::GetAverageFrameTime() {
    return s_averageFrameTime.load();
}

float PrimordialChaosLoop::GetLastFrameTime() {
    return s_lastFrameTime.load();
}

void PrimordialChaosLoop::SetTargetTPS(int tps) {
    s_config.targetTPS = std::max(1, tps);
}

int PrimordialChaosLoop::GetTargetTPS() {
    return s_config.targetTPS;
}

void PrimordialChaosLoop::SetMaxFPS(int fps) {
    s_config.maxFPS = std::max(1, fps);
}

int PrimordialChaosLoop::GetMaxFPS() {
    return s_config.maxFPS;
}

void PrimordialChaosLoop::EnableFrameLimiting(bool enable) {
    s_config.enableFrameLimiting = enable;
}

bool PrimordialChaosLoop::IsFrameLimitingEnabled() {
    return s_config.enableFrameLimiting;
}

void PrimordialChaosLoop::LoopThreadFunc() {
    using namespace std::chrono;
    
    const auto tickInterval = duration<double>(1.0 / s_config.targetTPS);
    auto lastTick = steady_clock::now();
    auto lastFrame = lastTick;
    auto lastMetricsUpdate = lastTick;
    
    int tickCountThisSecond = 0;
    int frameCountThisSecond = 0;
    
    while (s_state != PrimordialChaosLoopState::Stopping) {
        if (s_state == PrimordialChaosLoopState::Paused) {
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

void PrimordialChaosLoop::NotifyTickCallbacks(int64_t tickCount) {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    for (auto& callback : s_tickCallbacks) {
        if (callback) callback(tickCount);
    }
}

void PrimordialChaosLoop::NotifyUpdateCallbacks(float deltaTime) {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    for (auto& callback : s_updateCallbacks) {
        if (callback) callback(deltaTime);
    }
}

void PrimordialChaosLoop::NotifyRenderCallbacks() {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    for (auto& callback : s_renderCallbacks) {
        if (callback) callback();
    }
}

} // namespace PrimordialChaos
