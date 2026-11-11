#include "holy/HolySovereigntyLoop.hpp"
#include <chrono>
#include <thread>
#include <algorithm>

namespace HolySovereignty {

bool HolySovereigntyLoop::s_initialized = false;
std::atomic<bool> HolySovereigntyLoop::s_running(false);
std::thread HolySovereigntyLoop::s_loopThread;
std::mutex HolySovereigntyLoop::s_callbackMutex;
std::vector<HolySovereigntyLoop::TickCallback> HolySovereigntyLoop::s_tickCallbacks;
std::atomic<int64_t> HolySovereigntyLoop::s_tickCount(0);
std::atomic<float> HolySovereigntyLoop::s_currentFPS(0.0f);
int HolySovereigntyLoop::s_targetTPS = 60;

void HolySovereigntyLoop::Init() {
    if (s_initialized) return;
    s_initialized = true;
    s_tickCount = 0;
    s_currentFPS = 0.0f;
    s_targetTPS = 60;
}

void HolySovereigntyLoop::Shutdown() {
    if (!s_initialized) return;
    Stop();
    ClearTickCallbacks();
    s_initialized = false;
}

void HolySovereigntyLoop::Start() {
    if (!s_initialized) Init();
    if (s_running) return;
    s_running = true;
    s_loopThread = std::thread(LoopThread);
}

void HolySovereigntyLoop::Stop() {
    if (!s_running) return;
    s_running = false;
    if (s_loopThread.joinable()) {
        s_loopThread.join();
    }
}

bool HolySovereigntyLoop::IsRunning() {
    return s_running;
}

bool HolySovereigntyLoop::IsInitialized() {
    return s_initialized;
}

void HolySovereigntyLoop::RegisterTickCallback(TickCallback callback) {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    s_tickCallbacks.push_back(callback);
}

void HolySovereigntyLoop::UnregisterTickCallback(TickCallback callback) {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    s_tickCallbacks.erase(
        std::remove_if(s_tickCallbacks.begin(), s_tickCallbacks.end(),
            [&callback](const TickCallback& cb) {
                return cb.target<void()>() == callback.target<void()>();
            }),
        s_tickCallbacks.end());
}

void HolySovereigntyLoop::ClearTickCallbacks() {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    s_tickCallbacks.clear();
}

int64_t HolySovereigntyLoop::GetTickCount() {
    return s_tickCount;
}

float HolySovereigntyLoop::GetCurrentFPS() {
    return s_currentFPS;
}

void HolySovereigntyLoop::SetTargetTPS(int tps) {
    s_targetTPS = tps;
}

int HolySovereigntyLoop::GetTargetTPS() {
    return s_targetTPS;
}

void HolySovereigntyLoop::LoopThread() {
    using namespace std::chrono;
    auto lastTime = steady_clock::now();
    int frameCount = 0;
    auto lastFPSUpdate = lastTime;
    
    const auto targetFrameTime = milliseconds(1000 / s_targetTPS);
    
    while (s_running) {
        auto frameStart = steady_clock::now();
        
        ProcessTick();
        s_tickCount++;
        frameCount++;
        
        // Update FPS every second
        auto now = steady_clock::now();
        if (duration_cast<seconds>(now - lastFPSUpdate).count() >= 1) {
            s_currentFPS = static_cast<float>(frameCount);
            frameCount = 0;
            lastFPSUpdate = now;
        }
        
        // Frame limiting
        auto frameEnd = steady_clock::now();
        auto frameDuration = duration_cast<milliseconds>(frameEnd - frameStart);
        if (frameDuration < targetFrameTime) {
            std::this_thread::sleep_for(targetFrameTime - frameDuration);
        }
    }
}

void HolySovereigntyLoop::ProcessTick() {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    for (auto& callback : s_tickCallbacks) {
        if (callback) {
            callback();
        }
    }
}

} // namespace HolySovereignty
