#include "eternal/EternalSanctuaryLoop.hpp"
#include "eternal/EternalSanctuaryEngine.hpp"
#include <chrono>
#include <thread>

namespace Eternal {

std::atomic<bool> EternalSanctuaryLoop::s_running(false);
std::atomic<bool> EternalSanctuaryLoop::s_initialized(false);
std::atomic<int64_t> EternalSanctuaryLoop::s_tickCount(0);
std::atomic<int> EternalSanctuaryLoop::s_tickRate(60);
std::unique_ptr<std::thread> EternalSanctuaryLoop::s_thread;

void EternalSanctuaryLoop::Init() {
    if (s_initialized.exchange(true)) return;
    EternalSanctuaryEngine::Init();
}

void EternalSanctuaryLoop::Shutdown() {
    Stop();
    EternalSanctuaryEngine::Shutdown();
    s_initialized = false;
}

void EternalSanctuaryLoop::Start() {
    if (s_running.exchange(true)) return;
    s_thread = std::make_unique<std::thread>(RunLoop);
}

void EternalSanctuaryLoop::Stop() {
    s_running = false;
    if (s_thread && s_thread->joinable()) {
        s_thread->join();
    }
    s_thread.reset();
}

bool EternalSanctuaryLoop::IsRunning() {
    return s_running;
}

void EternalSanctuaryLoop::Tick() {
    EternalSanctuaryEngine::OnTick();
    s_tickCount++;
}

int64_t EternalSanctuaryLoop::GetTickCount() {
    return s_tickCount;
}

void EternalSanctuaryLoop::SetTickRate(int ticksPerSecond) {
    s_tickRate = ticksPerSecond;
}

void EternalSanctuaryLoop::RunLoop() {
    while (s_running) {
        Tick();
        std::this_thread::sleep_for(
            std::chrono::milliseconds(1000 / s_tickRate.load()));
    }
}

} // namespace Eternal
