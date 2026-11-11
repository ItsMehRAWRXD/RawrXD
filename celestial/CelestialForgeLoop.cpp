#include "celestial/CelestialForgeLoop.hpp"
#include "celestial/CelestialForgeEngine.hpp"
#include <chrono>
#include <thread>

namespace Celestial {

std::atomic<bool> CelestialForgeLoop::s_running(false);
std::atomic<bool> CelestialForgeLoop::s_initialized(false);
std::atomic<int64_t> CelestialForgeLoop::s_tickCount(0);
std::atomic<int> CelestialForgeLoop::s_tickRate(60);
std::unique_ptr<std::thread> CelestialForgeLoop::s_thread;

void CelestialForgeLoop::Init() {
    if (s_initialized.exchange(true)) return;
    CelestialForgeEngine::Init();
}

void CelestialForgeLoop::Shutdown() {
    Stop();
    CelestialForgeEngine::Shutdown();
    s_initialized = false;
}

void CelestialForgeLoop::Start() {
    if (s_running.exchange(true)) return;
    s_thread = std::make_unique<std::thread>(RunLoop);
}

void CelestialForgeLoop::Stop() {
    s_running = false;
    if (s_thread && s_thread->joinable()) {
        s_thread->join();
    }
    s_thread.reset();
}

bool CelestialForgeLoop::IsRunning() {
    return s_running;
}

void CelestialForgeLoop::Tick() {
    CelestialForgeEngine::OnTick();
    s_tickCount++;
}

int64_t CelestialForgeLoop::GetTickCount() {
    return s_tickCount;
}

void CelestialForgeLoop::SetTickRate(int ticksPerSecond) {
    s_tickRate = ticksPerSecond;
}

void CelestialForgeLoop::RunLoop() {
    while (s_running) {
        Tick();
        std::this_thread::sleep_for(
            std::chrono::milliseconds(1000 / s_tickRate.load()));
    }
}

} // namespace Celestial
