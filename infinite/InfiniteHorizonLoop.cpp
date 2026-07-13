#include "infinite/InfiniteHorizonLoop.hpp"
#include "infinite/InfiniteHorizonEngine.hpp"
#include <chrono>
#include <thread>

namespace Infinite {

std::atomic<bool> InfiniteHorizonLoop::s_running(false);
std::atomic<bool> InfiniteHorizonLoop::s_initialized(false);
std::atomic<int64_t> InfiniteHorizonLoop::s_tickCount(0);
std::atomic<int> InfiniteHorizonLoop::s_tickRate(60);
std::unique_ptr<std::thread> InfiniteHorizonLoop::s_thread;

void InfiniteHorizonLoop::Init() {
    if (s_initialized.exchange(true)) return;
    InfiniteHorizonEngine::Init();
}

void InfiniteHorizonLoop::Shutdown() {
    Stop();
    InfiniteHorizonEngine::Shutdown();
    s_initialized = false;
}

void InfiniteHorizonLoop::Start() {
    if (s_running.exchange(true)) return;
    s_thread = std::make_unique<std::thread>(RunLoop);
}

void InfiniteHorizonLoop::Stop() {
    s_running = false;
    if (s_thread && s_thread->joinable()) {
        s_thread->join();
    }
    s_thread.reset();
}

bool InfiniteHorizonLoop::IsRunning() {
    return s_running;
}

void InfiniteHorizonLoop::Tick() {
    InfiniteHorizonEngine::OnTick();
    s_tickCount++;
}

int64_t InfiniteHorizonLoop::GetTickCount() {
    return s_tickCount;
}

void InfiniteHorizonLoop::SetTickRate(int ticksPerSecond) {
    s_tickRate = ticksPerSecond;
}

void InfiniteHorizonLoop::RunLoop() {
    while (s_running) {
        Tick();
        std::this_thread::sleep_for(
            std::chrono::milliseconds(1000 / s_tickRate.load()));
    }
}

} // namespace Infinite
