#include "eternity/UltimateEternityLoop.hpp"
#include "eternity/UltimateEternityEngine.hpp"
#include <chrono>
#include <thread>

namespace Eternity {

std::atomic<bool> UltimateEternityLoop::s_running(false);
std::atomic<bool> UltimateEternityLoop::s_initialized(false);
std::thread UltimateEternityLoop::s_loopThread;
std::vector<std::function<void()>> UltimateEternityLoop::s_tickCallbacks;
std::atomic<int> UltimateEternityLoop::s_tickRate(60);
std::atomic<int64_t> UltimateEternityLoop::s_tickCount(0);
std::atomic<float> UltimateEternityLoop::s_currentFPS(0.0f);
std::mutex UltimateEternityLoop::s_callbackMutex;

void UltimateEternityLoop::Init() {
    if (s_initialized.exchange(true)) return;
    s_running = false;
    s_tickCount = 0;
    s_currentFPS = 0.0f;
}

void UltimateEternityLoop::Shutdown() {
    if (!s_initialized.exchange(false)) return;
    Stop();
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    s_tickCallbacks.clear();
}

void UltimateEternityLoop::Start() {
    if (!s_initialized || s_running.exchange(true)) return;
    s_loopThread = std::thread(LoopThread);
}

void UltimateEternityLoop::Stop() {
    if (!s_running.exchange(false)) return;
    if (s_loopThread.joinable()) {
        s_loopThread.join();
    }
}

bool UltimateEternityLoop::IsRunning() {
    return s_running.load();
}

void UltimateEternityLoop::RegisterTickCallback(std::function<void()> callback) {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    s_tickCallbacks.push_back(callback);
}

void UltimateEternityLoop::SetTickRate(int ticksPerSecond) {
    s_tickRate.store(std::max(1, ticksPerSecond));
}

int UltimateEternityLoop::GetTickRate() {
    return s_tickRate.load();
}

int64_t UltimateEternityLoop::GetTickCount() {
    return s_tickCount.load();
}

float UltimateEternityLoop::GetCurrentFPS() {
    return s_currentFPS.load();
}

void UltimateEternityLoop::LoopThread() {
    using namespace std::chrono;
    
    auto lastTime = steady_clock::now();
    int frameCount = 0;
    auto fpsTime = lastTime;
    
    while (s_running.load()) {
        auto currentTime = steady_clock::now();
        auto deltaTime = duration<float>(currentTime - lastTime).count();
        lastTime = currentTime;
        
        UltimateEternityEngine::OnTick();
        
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

} // namespace Eternity
