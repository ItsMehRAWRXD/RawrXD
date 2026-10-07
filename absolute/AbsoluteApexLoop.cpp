#include "absolute/AbsoluteApexLoop.hpp"
#include "absolute/AbsoluteApexEngine.hpp"
#include <chrono>
#include <thread>

namespace Absolute {

std::atomic<bool> AbsoluteApexLoop::s_running(false);
std::atomic<bool> AbsoluteApexLoop::s_initialized(false);
std::atomic<int64_t> AbsoluteApexLoop::s_tickCount(0);
std::atomic<int> AbsoluteApexLoop::s_tickRate(60);
std::unique_ptr<std::thread> AbsoluteApexLoop::s_thread;

void AbsoluteApexLoop::Init() {
    if (s_initialized.exchange(true)) return;
    AbsoluteApexEngine::Init();
}

void AbsoluteApexLoop::Shutdown() {
    Stop();
    AbsoluteApexEngine::Shutdown();
    s_initialized = false;
}

void AbsoluteApexLoop::Start() {
    if (s_running.exchange(true)) return;
    s_thread = std::make_unique<std::thread>(RunLoop);
}

void AbsoluteApexLoop::Stop() {
    s_running = false;
    if (s_thread && s_thread->joinable()) {
        s_thread->join();
    }
    s_thread.reset();
}

bool AbsoluteApexLoop::IsRunning() {
    return s_running;
}

void AbsoluteApexLoop::Tick() {
    AbsoluteApexEngine::OnTick();
    s_tickCount++;
}

int64_t AbsoluteApexLoop::GetTickCount() {
    return s_tickCount;
}

void AbsoluteApexLoop::SetTickRate(int ticksPerSecond) {
    s_tickRate = ticksPerSecond;
}

void AbsoluteApexLoop::RunLoop() {
    while (s_running) {
        Tick();
        std::this_thread::sleep_for(
            std::chrono::milliseconds(1000 / s_tickRate.load()));
    }
}

} // namespace Absolute
