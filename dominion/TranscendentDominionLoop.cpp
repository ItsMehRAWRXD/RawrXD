#include "dominion/TranscendentDominionLoop.hpp"
#include "dominion/TranscendentDominionEngine.hpp"
#include <chrono>
#include <thread>

namespace Dominion {

std::atomic<bool> TranscendentDominionLoop::s_running(false);
std::atomic<bool> TranscendentDominionLoop::s_initialized(false);
std::thread TranscendentDominionLoop::s_loopThread;
std::vector<std::function<void()>> TranscendentDominionLoop::s_tickCallbacks;
std::atomic<int> TranscendentDominionLoop::s_tickRate(60);
std::atomic<int64_t> TranscendentDominionLoop::s_tickCount(0);
std::atomic<float> TranscendentDominionLoop::s_currentFPS(0.0f);
std::mutex TranscendentDominionLoop::s_callbackMutex;

void TranscendentDominionLoop::Init() {
    if (s_initialized.exchange(true)) return;
    s_running = false;
    s_tickCount = 0;
    s_currentFPS = 0.0f;
}

void TranscendentDominionLoop::Shutdown() {
    if (!s_initialized.exchange(false)) return;
    Stop();
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    s_tickCallbacks.clear();
}

void TranscendentDominionLoop::Start() {
    if (!s_initialized || s_running.exchange(true)) return;
    s_loopThread = std::thread(LoopThread);
}

void TranscendentDominionLoop::Stop() {
    if (!s_running.exchange(false)) return;
    if (s_loopThread.joinable()) {
        s_loopThread.join();
    }
}

bool TranscendentDominionLoop::IsRunning() {
    return s_running.load();
}

void TranscendentDominionLoop::RegisterTickCallback(std::function<void()> callback) {
    std::lock_guard<std::mutex> lock(s_callbackMutex);
    s_tickCallbacks.push_back(callback);
}

void TranscendentDominionLoop::SetTickRate(int ticksPerSecond) {
    s_tickRate.store(std::max(1, ticksPerSecond));
}

int TranscendentDominionLoop::GetTickRate() {
    return s_tickRate.load();
}

int64_t TranscendentDominionLoop::GetTickCount() {
    return s_tickCount.load();
}

float TranscendentDominionLoop::GetCurrentFPS() {
    return s_currentFPS.load();
}

void TranscendentDominionLoop::LoopThread() {
    using namespace std::chrono;
    
    auto lastTime = steady_clock::now();
    int frameCount = 0;
    auto fpsTime = lastTime;
    
    while (s_running.load()) {
        auto currentTime = steady_clock::now();
        auto deltaTime = duration<float>(currentTime - lastTime).count();
        lastTime = currentTime;
        
        TranscendentDominionEngine::OnTick();
        
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

} // namespace Dominion
