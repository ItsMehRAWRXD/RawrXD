#include "sacred/SacredSovereigntyLoop.hpp"
#include <chrono>
#include <thread>
#include <algorithm>

namespace SacredSovereignty {

bool SacredSovereigntyLoop::s_initialized = false;
std::atomic<bool> SacredSovereigntyLoop::s_running(false);
std::thread SacredSovereigntyLoop::s_loopThread;
std::mutex SacredSovereigntyLoop::s_callbackMutex;
std::vector<SacredSovereigntyLoop::TickCallback> SacredSovereigntyLoop::s_tickCallbacks;
std::atomic<int64_t> SacredSovereigntyLoop::s_tickCount(0);
std::atomic<float> SacredSovereigntyLoop::s_currentFPS(0.0f);
int SacredSovereigntyLoop::s_targetTPS = 60;

void SacredSovereigntyLoop::Init() {
    if (s_initialized) return;
    s_initialized = true;
    s_tickCount = 0;
    s_currentFPS = 0.0f;
    s_targetTPS = 60;
}

void SacredSovereigntyLoop::Shutdown() {
    if (!s_initialized) return;
    Stop();
    ClearTickCallbacks();
    s_initialized = false;
}

void SacredSovereigntyLoop::Start() {
    if (!s_initialized) Init();
    if (s_running) return;
    s_running = true;
    s_loopThread = std::thread(LoopThread);
}

void SacredSovereigntyLoop::Stop() {
    if (!s_running) return;
    s_running = false;
    if (s_loopThread.joinable()) {
        s_loopThread.join();
    }
}

bool SacredSovereigntyLoop::IsRunning() {
    return s_running;
}

bool SacredSovereigntyLoop::IsInitialized() {
    return s_initialized;
}

void SacredSovereigntyLoop::RegisterTickCallback(TickCallback callback) {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    s_tickCallbacks.push_back(callback);
}

void SacredSovereigntyLoop::UnregisterTickCallback(TickCallback callback) {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    s_tickCallbacks.erase(
        std::remove_if(s_tickCallbacks.begin(), s_tickCallbacks.end(),
            [&callback](const TickCallback& cb) {
                return cb.target<void()>() == callback.target<void()>();
            }),
        s_tickCallbacks.end());
}

void SacredSovereigntyLoop::ClearTickCallbacks() {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    s_tickCallbacks.clear();
}

int64_t SacredSovereigntyLoop::GetTickCount() {
    return s_tickCount;
}

float SacredSovereigntyLoop::GetCurrentFPS() {
    return s_currentFPS;
}

void SacredSovereigntyLoop::SetTargetTPS(int tps) {
    s_targetTPS = tps;
}

int SacredSovereigntyLoop::GetTargetTPS() {
    return s_targetTPS;
}

void SacredSovereigntyLoop::LoopThread() {
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

void SacredSovereigntyLoop::ProcessTick() {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    for (auto& callback : s_tickCallbacks) {
        if (callback) {
            callback();
        }
    }
}

} // namespace SacredSovereignty
