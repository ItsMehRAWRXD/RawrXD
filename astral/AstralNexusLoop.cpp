#include "astral/AstralNexusLoop.hpp"
#include "astral/AstralNexusEngine.hpp"
#include <chrono>
#include <thread>

namespace Astral {

std::atomic<bool> AstralNexusLoop::s_running(false);
std::atomic<bool> AstralNexusLoop::s_initialized(false);
std::atomic<int64_t> AstralNexusLoop::s_tickCount(0);
std::atomic<int> AstralNexusLoop::s_tickRate(60);
std::unique_ptr<std::thread> AstralNexusLoop::s_thread;

void AstralNexusLoop::Init() {
    if (s_initialized.exchange(true)) return;
    AstralNexusEngine::Init();
}

void AstralNexusLoop::Shutdown() {
    Stop();
    AstralNexusEngine::Shutdown();
    s_initialized = false;
}

void AstralNexusLoop::Start() {
    if (s_running.exchange(true)) return;
    s_thread = std::make_unique<std::thread>(RunLoop);
}

void AstralNexusLoop::Stop() {
    s_running = false;
    if (s_thread && s_thread->joinable()) {
        s_thread->join();
    }
    s_thread.reset();
}

bool AstralNexusLoop::IsRunning() {
    return s_running;
}

void AstralNexusLoop::Tick() {
    AstralNexusEngine::OnTick();
    s_tickCount++;
}

int64_t AstralNexusLoop::GetTickCount() {
    return s_tickCount;
}

void AstralNexusLoop::SetTickRate(int ticksPerSecond) {
    s_tickRate = ticksPerSecond;
}

void AstralNexusLoop::RunLoop() {
    while (s_running) {
        Tick();
        std::this_thread::sleep_for(
            std::chrono::milliseconds(1000 / s_tickRate.load()));
    }
}

} // namespace Astral
