#include "integration/SovereignIntegrationLoop.hpp"
#include "integration/SovereignIntegrationEngine.hpp"
#include <chrono>
#include <thread>

namespace Integration {

std::atomic<bool> SovereignIntegrationLoop::s_running(false);
std::atomic<bool> SovereignIntegrationLoop::s_initialized(false);
std::atomic<int64_t> SovereignIntegrationLoop::s_tickCount(0);
std::atomic<int> SovereignIntegrationLoop::s_tickRate(60);
std::unique_ptr<std::thread> SovereignIntegrationLoop::s_thread;

void SovereignIntegrationLoop::Init() {
    if (s_initialized.exchange(true)) return;
    SovereignIntegrationEngine::Init();
}

void SovereignIntegrationLoop::Shutdown() {
    Stop();
    SovereignIntegrationEngine::Shutdown();
    s_initialized = false;
}

void SovereignIntegrationLoop::Start() {
    if (s_running.exchange(true)) return;
    s_thread = std::make_unique<std::thread>(RunLoop);
}

void SovereignIntegrationLoop::Stop() {
    s_running = false;
    if (s_thread && s_thread->joinable()) {
        s_thread->join();
    }
    s_thread.reset();
}

bool SovereignIntegrationLoop::IsRunning() {
    return s_running;
}

void SovereignIntegrationLoop::Tick() {
    SovereignIntegrationEngine::OnTick();
    s_tickCount++;
}

int64_t SovereignIntegrationLoop::GetTickCount() {
    return s_tickCount;
}

void SovereignIntegrationLoop::SetTickRate(int ticksPerSecond) {
    s_tickRate = ticksPerSecond;
}

void SovereignIntegrationLoop::RunLoop() {
    while (s_running) {
        Tick();
        std::this_thread::sleep_for(
            std::chrono::milliseconds(1000 / s_tickRate.load()));
    }
}

} // namespace Integration
