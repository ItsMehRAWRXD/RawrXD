#include "divine/DivineDominionLoop.hpp"
#include "divine/DivineDominionEngine.hpp"
#include <chrono>
#include <thread>

namespace DivineDominion {

std::atomic<bool> DivineDominionLoop::s_running(false);
std::atomic<bool> DivineDominionLoop::s_initialized(false);
std::thread DivineDominionLoop::s_loopThread;
std::vector<std::function<void()>> DivineDominionLoop::s_tickCallbacks;
std::atomic<int> DivineDominionLoop::s_tickRate(60);
std::atomic<int64_t> DivineDominionLoop::s_tickCount(0);
std::atomic<float> DivineDominionLoop::s_currentFPS(0.0f);
std::mutex DivineDominionLoop::s_callbackMutex;

void DivineDominionLoop::Init() {
    if (s_initialized.exchange(true)) return;
    s_running = false;
    s_tickCount = 0;
    s_currentFPS = 0.0f;
}

void DivineDominionLoop::Shutdown() {
    if (!s_initialized.exchange(false)) return;
    Stop();
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    s_tickCallbacks.clear();
}

void DivineDominionLoop::Start() {
    if (!s_initialized || s_running.exchange(true)) return;
    s_loopThread = std::thread(LoopThread);
}

void DivineDominionLoop::Stop() {
    if (!s_running.exchange(false)) return;
    if (s_loopThread.joinable()) {
        s_loopThread.join();
    }
}

bool DivineDominionLoop::IsRunning() {
    return s_running.load();
}

void DivineDominionLoop::RegisterTickCallback(std::function<void()> callback) {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    s_tickCallbacks.push_back(callback);
}

void DivineDominionLoop::SetTickRate(int ticksPerSecond) {
    s_tickRate.store(std::max(1, ticksPerSecond));
}

int DivineDominionLoop::GetTickRate() {
    return s_tickRate.load();
}

int64_t DivineDominionLoop::GetTickCount() {
    return s_tickCount.load();
}

float DivineDominionLoop::GetCurrentFPS() {
    return s_currentFPS.load();
}

void DivineDominionLoop::LoopThread() {
    using namespace std::chrono;
    
    auto lastTime = steady_clock::now();
    int frameCount = 0;
    auto fpsTime = lastTime;
    
    while (s_running.load()) {
        auto currentTime = steady_clock::now();
        auto deltaTime = duration<float>(currentTime - lastTime).count();
        lastTime = currentTime;
        
        DivineDominionEngine::OnTick();
        
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

} // namespace DivineDominion
