#include "OmniGenesisLoop.hpp"
#include <algorithm>
#include <thread>

namespace OmniGenesis {

// Static member definitions
bool OmniGenesisLoop::s_initialized = false;
std::atomic<OmniGenesisLoopState> OmniGenesisLoop::s_state{OmniGenesisLoopState::Stopped};
std::unique_ptr<std::thread> OmniGenesisLoop::s_loopThread;
OmniGenesisLoop::Config OmniGenesisLoop::s_config;

std::mutex OmniGenesisLoop::s_callbackMutex;
std::vector<OmniGenesisTickCallback> OmniGenesisLoop::s_tickCallbacks;
std::vector<OmniGenesisUpdateCallback> OmniGenesisLoop::s_updateCallbacks;
std::vector<OmniGenesisRenderCallback> OmniGenesisLoop::s_renderCallbacks;

std::atomic<int64_t> OmniGenesisLoop::s_tickCount{0};
std::atomic<float> OmniGenesisLoop::s_currentTPS{0.0f};
std::atomic<float> OmniGenesisLoop::s_currentFPS{0.0f};
std::atomic<float> OmniGenesisLoop::s_averageFrameTime{0.0f};
std::atomic<float> OmniGenesisLoop::s_lastFrameTime{0.0f};
std::chrono::steady_clock::time_point OmniGenesisLoop::s_lastTickTime;
std::chrono::steady_clock::time_point OmniGenesisLoop::s_lastFrameTime;
std::mutex OmniGenesisLoop::s_metricsMutex;

void OmniGenesisLoop::Init(const Config& config) {
    if (s_initialized) return;
    s_config = config;
    s_initialized = true;
    s_state = OmniGenesisLoopState::Stopped;
}

void OmniGenesisLoop::Shutdown() {
    if (!s_initialized) return;
    Stop();
    UnregisterAllCallbacks();
    s_initialized = false;
}

bool OmniGenesisLoop::IsInitialized() {
    return s_initialized;
}

bool OmniGenesisLoop::IsRunning() {
    return s_state == OmniGenesisLoopState::Running;
}

void OmniGenesisLoop::Start() {
    if (!s_initialized || s_state != OmniGenesisLoopState::Stopped) return;
    
    s_state = OmniGenesisLoopState::Starting;
    s_tickCount = 0;
    s_lastTickTime = std::chrono::steady_clock::now();
    s_lastFrameTime = s_lastTickTime;
    
    s_loopThread = std::make_unique<std::thread>(LoopThreadFunc);
    s_state = OmniGenesisLoopState::Running;
}

void OmniGenesisLoop::Stop() {
    if (!s_initialized || s_state == OmniGenesisLoopState::Stopped) return;
    
    s_state = OmniGenesisLoopState::Stopping;
    if (s_loopThread && s_loopThread->joinable()) {
        s_loopThread->join();
    }
    s_loopThread.reset();
    s_state = OmniGenesisLoopState::Stopped;
}

void OmniGenesisLoop::Pause() {
    if (s_state == OmniGenesisLoopState::Running) {
        s_state = OmniGenesisLoopState::Paused;
    }
}

void OmniGenesisLoop::Resume() {
    if (s_state == OmniGenesisLoopState::Paused) {
        s_state = OmniGenesisLoopState::Running;
        s_lastTickTime = std::chrono::steady_clock::now();
        s_lastFrameTime = s_lastTickTime;
    }
}

OmniGenesisLoopState OmniGenesisLoop::GetState() {
    return s_state;
}

void OmniGenesisLoop::RegisterTickCallback(const OmniGenesisTickCallback& callback) {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    s_tickCallbacks.push_back(callback);
}

void OmniGenesisLoop::RegisterUpdateCallback(const OmniGenesisUpdateCallback& callback) {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    s_updateCallbacks.push_back(callback);
}

void OmniGenesisLoop::RegisterRenderCallback(const OmniGenesisRenderCallback& callback) {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    s_renderCallbacks.push_back(callback);
}

void OmniGenesisLoop::UnregisterAllCallbacks() {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    s_tickCallbacks.clear();
    s_updateCallbacks.clear();
    s_renderCallbacks.clear();
}

float OmniGenesisLoop::GetCurrentTPS() {
    return s_currentTPS.load();
}

float OmniGenesisLoop::GetCurrentFPS() {
    return s_currentFPS.load();
}

int64_t OmniGenesisLoop::GetTickCount() {
    return s_tickCount.load();
}

float OmniGenesisLoop::GetAverageFrameTime() {
    return s_averageFrameTime.load();
}

float OmniGenesisLoop::GetLastFrameTime() {
    return s_lastFrameTime.load();
}

void OmniGenesisLoop::SetTargetTPS(int tps) {
    s_config.targetTPS = std::max(1, tps);
}

int OmniGenesisLoop::GetTargetTPS() {
    return s_config.targetTPS;
}

void OmniGenesisLoop::SetMaxFPS(int fps) {
    s_config.maxFPS = std::max(1, fps);
}

int OmniGenesisLoop::GetMaxFPS() {
    return s_config.maxFPS;
}

void OmniGenesisLoop::EnableFrameLimiting(bool enable) {
    s_config.enableFrameLimiting = enable;
}

bool OmniGenesisLoop::IsFrameLimitingEnabled() {
    return s_config.enableFrameLimiting;
}

void OmniGenesisLoop::LoopThreadFunc() {
    using namespace std::chrono;
    
    const auto tickInterval = duration<double>(1.0 / s_config.targetTPS);
    auto lastTick = steady_clock::now();
    auto lastFrame = lastTick;
    auto lastMetricsUpdate = lastTick;
    
    int tickCountThisSecond = 0;
    int frameCountThisSecond = 0;
    
    while (s_state != OmniGenesisLoopState::Stopping) {
        if (s_state == OmniGenesisLoopState::Paused) {
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

void OmniGenesisLoop::NotifyTickCallbacks(int64_t tickCount) {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    for (auto& callback : s_tickCallbacks) {
        if (callback) callback(tickCount);
    }
}

void OmniGenesisLoop::NotifyUpdateCallbacks(float deltaTime) {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    for (auto& callback : s_updateCallbacks) {
        if (callback) callback(deltaTime);
    }
}

void OmniGenesisLoop::NotifyRenderCallbacks() {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    for (auto& callback : s_renderCallbacks) {
        if (callback) callback();
    }
}

} // namespace OmniGenesis
