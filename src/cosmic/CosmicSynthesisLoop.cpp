#include "CosmicSynthesisLoop.hpp"
#include <algorithm>
#include <thread>

namespace CosmicSynthesis {

// Static member definitions
bool CosmicSynthesisLoop::s_initialized = false;
std::atomic<CosmicSynthesisLoopState> CosmicSynthesisLoop::s_state{CosmicSynthesisLoopState::Stopped};
std::unique_ptr<std::thread> CosmicSynthesisLoop::s_loopThread;
CosmicSynthesisLoop::Config CosmicSynthesisLoop::s_config;

std::mutex CosmicSynthesisLoop::s_callbackMutex;
std::vector<CosmicSynthesisTickCallback> CosmicSynthesisLoop::s_tickCallbacks;
std::vector<CosmicSynthesisUpdateCallback> CosmicSynthesisLoop::s_updateCallbacks;
std::vector<CosmicSynthesisRenderCallback> CosmicSynthesisLoop::s_renderCallbacks;

std::atomic<int64_t> CosmicSynthesisLoop::s_tickCount{0};
std::atomic<float> CosmicSynthesisLoop::s_currentTPS{0.0f};
std::atomic<float> CosmicSynthesisLoop::s_currentFPS{0.0f};
std::atomic<float> CosmicSynthesisLoop::s_averageFrameTime{0.0f};
std::atomic<float> CosmicSynthesisLoop::s_lastFrameTime{0.0f};
std::chrono::steady_clock::time_point CosmicSynthesisLoop::s_lastTickTime;
std::chrono::steady_clock::time_point CosmicSynthesisLoop::s_lastFrameTime;
std::mutex CosmicSynthesisLoop::s_metricsMutex;

void CosmicSynthesisLoop::Init(const Config& config) {
    if (s_initialized) return;
    s_config = config;
    s_initialized = true;
    s_state = CosmicSynthesisLoopState::Stopped;
}

void CosmicSynthesisLoop::Shutdown() {
    if (!s_initialized) return;
    Stop();
    UnregisterAllCallbacks();
    s_initialized = false;
}

bool CosmicSynthesisLoop::IsInitialized() {
    return s_initialized;
}

bool CosmicSynthesisLoop::IsRunning() {
    return s_state == CosmicSynthesisLoopState::Running;
}

void CosmicSynthesisLoop::Start() {
    if (!s_initialized || s_state != CosmicSynthesisLoopState::Stopped) return;
    
    s_state = CosmicSynthesisLoopState::Starting;
    s_tickCount = 0;
    s_lastTickTime = std::chrono::steady_clock::now();
    s_lastFrameTime = s_lastTickTime;
    
    s_loopThread = std::make_unique<std::thread>(LoopThreadFunc);
    s_state = CosmicSynthesisLoopState::Running;
}

void CosmicSynthesisLoop::Stop() {
    if (!s_initialized || s_state == CosmicSynthesisLoopState::Stopped) return;
    
    s_state = CosmicSynthesisLoopState::Stopping;
    if (s_loopThread && s_loopThread->joinable()) {
        s_loopThread->join();
    }
    s_loopThread.reset();
    s_state = CosmicSynthesisLoopState::Stopped;
}

void CosmicSynthesisLoop::Pause() {
    if (s_state == CosmicSynthesisLoopState::Running) {
        s_state = CosmicSynthesisLoopState::Paused;
    }
}

void CosmicSynthesisLoop::Resume() {
    if (s_state == CosmicSynthesisLoopState::Paused) {
        s_state = CosmicSynthesisLoopState::Running;
        s_lastTickTime = std::chrono::steady_clock::now();
        s_lastFrameTime = s_lastTickTime;
    }
}

CosmicSynthesisLoopState CosmicSynthesisLoop::GetState() {
    return s_state;
}

void CosmicSynthesisLoop::RegisterTickCallback(const CosmicSynthesisTickCallback& callback) {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    s_tickCallbacks.push_back(callback);
}

void CosmicSynthesisLoop::RegisterUpdateCallback(const CosmicSynthesisUpdateCallback& callback) {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    s_updateCallbacks.push_back(callback);
}

void CosmicSynthesisLoop::RegisterRenderCallback(const CosmicSynthesisRenderCallback& callback) {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    s_renderCallbacks.push_back(callback);
}

void CosmicSynthesisLoop::UnregisterAllCallbacks() {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    s_tickCallbacks.clear();
    s_updateCallbacks.clear();
    s_renderCallbacks.clear();
}

float CosmicSynthesisLoop::GetCurrentTPS() {
    return s_currentTPS.load();
}

float CosmicSynthesisLoop::GetCurrentFPS() {
    return s_currentFPS.load();
}

int64_t CosmicSynthesisLoop::GetTickCount() {
    return s_tickCount.load();
}

float CosmicSynthesisLoop::GetAverageFrameTime() {
    return s_averageFrameTime.load();
}

float CosmicSynthesisLoop::GetLastFrameTime() {
    return s_lastFrameTime.load();
}

void CosmicSynthesisLoop::SetTargetTPS(int tps) {
    s_config.targetTPS = std::max(1, tps);
}

int CosmicSynthesisLoop::GetTargetTPS() {
    return s_config.targetTPS;
}

void CosmicSynthesisLoop::SetMaxFPS(int fps) {
    s_config.maxFPS = std::max(1, fps);
}

int CosmicSynthesisLoop::GetMaxFPS() {
    return s_config.maxFPS;
}

void CosmicSynthesisLoop::EnableFrameLimiting(bool enable) {
    s_config.enableFrameLimiting = enable;
}

bool CosmicSynthesisLoop::IsFrameLimitingEnabled() {
    return s_config.enableFrameLimiting;
}

void CosmicSynthesisLoop::LoopThreadFunc() {
    using namespace std::chrono;
    
    const auto tickInterval = duration<double>(1.0 / s_config.targetTPS);
    auto lastTick = steady_clock::now();
    auto lastFrame = lastTick;
    auto lastMetricsUpdate = lastTick;
    
    int tickCountThisSecond = 0;
    int frameCountThisSecond = 0;
    
    while (s_state != CosmicSynthesisLoopState::Stopping) {
        if (s_state == CosmicSynthesisLoopState::Paused) {
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

void CosmicSynthesisLoop::NotifyTickCallbacks(int64_t tickCount) {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    for (auto& callback : s_tickCallbacks) {
        if (callback) callback(tickCount);
    }
}

void CosmicSynthesisLoop::NotifyUpdateCallbacks(float deltaTime) {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    for (auto& callback : s_updateCallbacks) {
        if (callback) callback(deltaTime);
    }
}

void CosmicSynthesisLoop::NotifyRenderCallbacks() {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    for (auto& callback : s_renderCallbacks) {
        if (callback) callback();
    }
}

} // namespace CosmicSynthesis
