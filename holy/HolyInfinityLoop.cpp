#include "holy/HolyInfinityLoop.hpp"
#include <chrono>
#include <thread>
#include <algorithm>

namespace HolyInfinity {

bool HolyInfinityLoop::s_initialized = false;
std::atomic<bool> HolyInfinityLoop::s_running(false);
std::thread HolyInfinityLoop::s_loopThread;
std::mutex HolyInfinityLoop::s_callbackMutex;
std::vector<HolyInfinityLoop::TickCallback> HolyInfinityLoop::s_tickCallbacks;
std::atomic<int64_t> HolyInfinityLoop::s_tickCount(0);
std::atomic<float> HolyInfinityLoop::s_currentFPS(0.0f);
int HolyInfinityLoop::s_targetTPS = 60;

void HolyInfinityLoop::Init() {
    if (s_initialized) return;
    s_initialized = true;
    s_tickCount = 0;
    s_currentFPS = 0.0f;
    s_targetTPS = 60;
}

void HolyInfinityLoop::Shutdown() {
    if (!s_initialized) return;
    Stop();
    ClearTickCallbacks();
    s_initialized = false;
}

void HolyInfinityLoop::Start() {
    if (!s_initialized) Init();
    if (s_running) return;
    s_running = true;
    s_loopThread = std::thread(LoopThread);
}

void HolyInfinityLoop::Stop() {
    if (!s_running) return;
    s_running = false;
    if (s_loopThread.joinable()) {
        s_loopThread.join();
    }
}

bool HolyInfinityLoop::IsRunning() {
    return s_running;
}

bool HolyInfinityLoop::IsInitialized() {
    return s_initialized;
}

void HolyInfinityLoop::RegisterTickCallback(TickCallback callback) {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    s_tickCallbacks.push_back(callback);
}

void HolyInfinityLoop::UnregisterTickCallback(TickCallback callback) {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    s_tickCallbacks.erase(
        std::remove_if(s_tickCallbacks.begin(), s_tickCallbacks.end(),
            [&callback](const TickCallback& cb) {
                return cb.target<void()>() == callback.target<void()>();
            }),
        s_tickCallbacks.end());
}

void HolyInfinityLoop::ClearTickCallbacks() {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    s_tickCallbacks.clear();
}

int64_t HolyInfinityLoop::GetTickCount() {
    return s_tickCount;
}

float HolyInfinityLoop::GetCurrentFPS() {
    return s_currentFPS;
}

void HolyInfinityLoop::SetTargetTPS(int tps) {
    s_targetTPS = tps;
}

int HolyInfinityLoop::GetTargetTPS() {
    return s_targetTPS;
}

void HolyInfinityLoop::LoopThread() {
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

void HolyInfinityLoop::ProcessTick() {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    for (auto& callback : s_tickCallbacks) {
        if (callback) {
            callback();
        }
    }
}

} // namespace HolyInfinity
