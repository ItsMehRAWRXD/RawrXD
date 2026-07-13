#include "universal/UniversalCouncilLoop.hpp"
#include "universal/UniversalCouncilEngine.hpp"
#include <chrono>
#include <thread>

namespace Universal {

std::atomic<bool> UniversalCouncilLoop::s_running(false);
std::atomic<bool> UniversalCouncilLoop::s_initialized(false);
std::atomic<int64_t> UniversalCouncilLoop::s_tickCount(0);
std::atomic<int> UniversalCouncilLoop::s_tickRate(60);
std::unique_ptr<std::thread> UniversalCouncilLoop::s_thread;

void UniversalCouncilLoop::Init() {
    if (s_initialized.exchange(true)) return;
    UniversalCouncilEngine::Init();
}

void UniversalCouncilLoop::Shutdown() {
    Stop();
    UniversalCouncilEngine::Shutdown();
    s_initialized = false;
}

void UniversalCouncilLoop::Start() {
    if (s_running.exchange(true)) return;
    s_thread = std::make_unique<std::thread>(RunLoop);
}

void UniversalCouncilLoop::Stop() {
    s_running = false;
    if (s_thread && s_thread->joinable()) {
        s_thread->join();
    }
    s_thread.reset();
}

bool UniversalCouncilLoop::IsRunning() {
    return s_running;
}

void UniversalCouncilLoop::Tick() {
    UniversalCouncilEngine::OnTick();
    s_tickCount++;
}

int64_t UniversalCouncilLoop::GetTickCount() {
    return s_tickCount;
}

void UniversalCouncilLoop::SetTickRate(int ticksPerSecond) {
    s_tickRate = ticksPerSecond;
}

void UniversalCouncilLoop::RunLoop() {
    while (s_running) {
        Tick();
        std::this_thread::sleep_for(
            std::chrono::milliseconds(1000 / s_tickRate.load()));
    }
}

} // namespace Universal
