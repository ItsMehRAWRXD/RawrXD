#include "blessed/BlessedInfinityLoop.hpp"
#include <chrono>
#include <thread>
#include <algorithm>

namespace BlessedInfinity {

bool BlessedInfinityLoop::s_initialized = false;
std::atomic<bool> BlessedInfinityLoop::s_running(false);
std::thread BlessedInfinityLoop::s_loopThread;
std::mutex BlessedInfinityLoop::s_callbackMutex;
std::vector<BlessedInfinityLoop::TickCallback> BlessedInfinityLoop::s_tickCallbacks;
std::atomic<int64_t> BlessedInfinityLoop::s_tickCount(0);
std::atomic<float> BlessedInfinityLoop::s_currentFPS(0.0f);
int BlessedInfinityLoop::s_targetTPS = 60;

void BlessedInfinityLoop::Init() {
    if (s_initialized) return;
    s_initialized = true;
    s_tickCount = 0;
    s_currentFPS = 0.0f;
    s_targetTPS = 60;
}

void BlessedInfinityLoop::Shutdown() {
    if (!s_initialized) return;
    Stop();
    ClearTickCallbacks();
    s_initialized = false;
}

void BlessedInfinityLoop::Start() {
    if (!s_initialized) Init();
    if (s_running) return;
    s_running = true;
    s_loopThread = std::thread(LoopThread);
}

void BlessedInfinityLoop::Stop() {
    if (!s_running) return;
    s_running = false;
    if (s_loopThread.joinable()) {
        s_loopThread.join();
    }
}

bool BlessedInfinityLoop::IsRunning() {
    return s_running;
}

bool BlessedInfinityLoop::IsInitialized() {
    return s_initialized;
}

void BlessedInfinityLoop::RegisterTickCallback(TickCallback callback) {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    s_tickCallbacks.push_back(callback);
}

void BlessedInfinityLoop::UnregisterTickCallback(TickCallback callback) {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    s_tickCallbacks.erase(
        std::remove_if(s_tickCallbacks.begin(), s_tickCallbacks.end(),
            [&callback](const TickCallback& cb) {
                return cb.target<void()>() == callback.target<void()>();
            }),
        s_tickCallbacks.end());
}

void BlessedInfinityLoop::ClearTickCallbacks() {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    s_tickCallbacks.clear();
}

int64_t BlessedInfinityLoop::GetTickCount() {
    return s_tickCount;
}

float BlessedInfinityLoop::GetCurrentFPS() {
    return s_currentFPS;
}

void BlessedInfinityLoop::SetTargetTPS(int tps) {
    s_targetTPS = tps;
}

int BlessedInfinityLoop::GetTargetTPS() {
    return s_targetTPS;
}

void BlessedInfinityLoop::LoopThread() {
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

void BlessedInfinityLoop::ProcessTick() {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    for (auto& callback : s_tickCallbacks) {
        if (callback) {
            callback();
        }
    }
}

} // namespace BlessedInfinity
