#include "transcendent/TranscendentUnityLoop.hpp"
#include <chrono>
#include <thread>
#include <algorithm>

namespace TranscendentUnity {

bool TranscendentUnityLoop::s_initialized = false;
std::atomic<bool> TranscendentUnityLoop::s_running(false);
std::thread TranscendentUnityLoop::s_loopThread;
std::mutex TranscendentUnityLoop::s_callbackMutex;
std::vector<TranscendentUnityLoop::TickCallback> TranscendentUnityLoop::s_tickCallbacks;
std::atomic<int64_t> TranscendentUnityLoop::s_tickCount(0);
std::atomic<float> TranscendentUnityLoop::s_currentFPS(0.0f);
int TranscendentUnityLoop::s_targetTPS = 60;

void TranscendentUnityLoop::Init() {
    if (s_initialized) return;
    s_initialized = true;
    s_tickCount = 0;
    s_currentFPS = 0.0f;
    s_targetTPS = 60;
}

void TranscendentUnityLoop::Shutdown() {
    if (!s_initialized) return;
    Stop();
    ClearTickCallbacks();
    s_initialized = false;
}

void TranscendentUnityLoop::Start() {
    if (!s_initialized) Init();
    if (s_running) return;
    s_running = true;
    s_loopThread = std::thread(LoopThread);
}

void TranscendentUnityLoop::Stop() {
    if (!s_running) return;
    s_running = false;
    if (s_loopThread.joinable()) {
        s_loopThread.join();
    }
}

bool TranscendentUnityLoop::IsRunning() {
    return s_running;
}

bool TranscendentUnityLoop::IsInitialized() {
    return s_initialized;
}

void TranscendentUnityLoop::RegisterTickCallback(TickCallback callback) {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    s_tickCallbacks.push_back(callback);
}

void TranscendentUnityLoop::UnregisterTickCallback(TickCallback callback) {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    s_tickCallbacks.erase(
        std::remove_if(s_tickCallbacks.begin(), s_tickCallbacks.end(),
            [&callback](const TickCallback& cb) {
                return cb.target<void()>() == callback.target<void()>();
            }),
        s_tickCallbacks.end());
}

void TranscendentUnityLoop::ClearTickCallbacks() {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    s_tickCallbacks.clear();
}

int64_t TranscendentUnityLoop::GetTickCount() {
    return s_tickCount;
}

float TranscendentUnityLoop::GetCurrentFPS() {
    return s_currentFPS;
}

void TranscendentUnityLoop::SetTargetTPS(int tps) {
    s_targetTPS = tps;
}

int TranscendentUnityLoop::GetTargetTPS() {
    return s_targetTPS;
}

void TranscendentUnityLoop::LoopThread() {
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

void TranscendentUnityLoop::ProcessTick() {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    for (auto& callback : s_tickCallbacks) {
        if (callback) {
            callback();
        }
    }
}

} // namespace TranscendentUnity
