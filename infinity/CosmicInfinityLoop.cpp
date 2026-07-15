#include "infinity/CosmicInfinityLoop.hpp"
#include "infinity/CosmicInfinityEngine.hpp"
#include <chrono>
#include <thread>

namespace Infinity {

std::atomic<bool> CosmicInfinityLoop::s_running(false);
std::atomic<bool> CosmicInfinityLoop::s_initialized(false);
std::thread CosmicInfinityLoop::s_loopThread;
std::vector<std::function<void()>> CosmicInfinityLoop::s_tickCallbacks;
std::atomic<int> CosmicInfinityLoop::s_tickRate(60);
std::atomic<int64_t> CosmicInfinityLoop::s_tickCount(0);
std::atomic<float> CosmicInfinityLoop::s_currentFPS(0.0f);
std::mutex CosmicInfinityLoop::s_callbackMutex;

void CosmicInfinityLoop::Init() {
    if (s_initialized.exchange(true)) return;
    s_running = false;
    s_tickCount = 0;
    s_currentFPS = 0.0f;
}

void CosmicInfinityLoop::Shutdown() {
    if (!s_initialized.exchange(false)) return;
    Stop();
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    s_tickCallbacks.clear();
}

void CosmicInfinityLoop::Start() {
    if (!s_initialized || s_running.exchange(true)) return;
    s_loopThread = std::thread(LoopThread);
}

void CosmicInfinityLoop::Stop() {
    if (!s_running.exchange(false)) return;
    if (s_loopThread.joinable()) {
        s_loopThread.join();
    }
}

bool CosmicInfinityLoop::IsRunning() {
    return s_running.load();
}

void CosmicInfinityLoop::RegisterTickCallback(std::function<void()> callback) {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    s_tickCallbacks.push_back(callback);
}

void CosmicInfinityLoop::SetTickRate(int ticksPerSecond) {
    s_tickRate.store(std::max(1, ticksPerSecond));
}

int CosmicInfinityLoop::GetTickRate() {
    return s_tickRate.load();
}

int64_t CosmicInfinityLoop::GetTickCount() {
    return s_tickCount.load();
}

float CosmicInfinityLoop::GetCurrentFPS() {
    return s_currentFPS.load();
}

void CosmicInfinityLoop::LoopThread() {
    using namespace std::chrono;
    
    auto lastTime = steady_clock::now();
    int frameCount = 0;
    auto fpsTime = lastTime;
    
    while (s_running.load()) {
        auto currentTime = steady_clock::now();
        auto deltaTime = duration<float>(currentTime - lastTime).count();
        lastTime = currentTime;
        
        CosmicInfinityEngine::OnTick();
        
        {
            std::lock_guard<std::mutex> lock(s_callbackMutex);
            for (auto& callback : s_tickCallbacks) {
                if (callback) callback();
            }
        }
        
        s_tickCount++;
        frameCount++;
        
        auto now = steady_clock::now();
        if (duration<float>(now - fpsTime).count() >= 1.0f) {
            s_currentFPS.store(static_cast<float>(frameCount));
            frameCount = 0;
            fpsTime = now;
        }
        
        int tickRate = s_tickRate.load();
        auto targetDuration = milliseconds(1000 / tickRate);
        auto elapsed = steady_clock::now() - currentTime;
        if (elapsed < targetDuration) {
            std::this_thread::sleep_for(targetDuration - elapsed);
        }
    }
}

} // namespace Infinity
