#include "transcendent/TranscendentObservatoryLoop.hpp"
#include "transcendent/TranscendentObservatoryEngine.hpp"
#include <chrono>
#include <thread>

namespace Transcendent {

std::atomic<bool> TranscendentObservatoryLoop::s_running(false);
std::atomic<bool> TranscendentObservatoryLoop::s_initialized(false);
std::atomic<int64_t> TranscendentObservatoryLoop::s_tickCount(0);
std::atomic<int> TranscendentObservatoryLoop::s_tickRate(60);
std::unique_ptr<std::thread> TranscendentObservatoryLoop::s_thread;

void TranscendentObservatoryLoop::Init() {
    if (s_initialized.exchange(true)) return;
    TranscendentObservatoryEngine::Init();
}

void TranscendentObservatoryLoop::Shutdown() {
    Stop();
    TranscendentObservatoryEngine::Shutdown();
    s_initialized = false;
}

void TranscendentObservatoryLoop::Start() {
    if (s_running.exchange(true)) return;
    s_thread = std::make_unique<std::thread>(RunLoop);
}

void TranscendentObservatoryLoop::Stop() {
    s_running = false;
    if (s_thread && s_thread->joinable()) {
        s_thread->join();
    }
    s_thread.reset();
}

bool TranscendentObservatoryLoop::IsRunning() {
    return s_running;
}

void TranscendentObservatoryLoop::Tick() {
    TranscendentObservatoryEngine::OnTick();
    s_tickCount++;
}

int64_t TranscendentObservatoryLoop::GetTickCount() {
    return s_tickCount;
}

void TranscendentObservatoryLoop::SetTickRate(int ticksPerSecond) {
    s_tickRate = ticksPerSecond;
}

void TranscendentObservatoryLoop::RunLoop() {
    while (s_running) {
        Tick();
        std::this_thread::sleep_for(
            std::chrono::milliseconds(1000 / s_tickRate.load()));
    }
}

} // namespace Transcendent
