#include "omniversal/OmniversalTribunalLoop.hpp"
#include "omniversal/OmniversalTribunalEngine.hpp"
#include <chrono>
#include <thread>

namespace Omniversal {

std::atomic<bool> OmniversalTribunalLoop::s_running(false);
std::atomic<bool> OmniversalTribunalLoop::s_initialized(false);
std::atomic<int64_t> OmniversalTribunalLoop::s_tickCount(0);
std::atomic<int> OmniversalTribunalLoop::s_tickRate(60);
std::unique_ptr<std::thread> OmniversalTribunalLoop::s_thread;

void OmniversalTribunalLoop::Init() {
    if (s_initialized.exchange(true)) return;
    OmniversalTribunalEngine::Init();
}

void OmniversalTribunalLoop::Shutdown() {
    Stop();
    OmniversalTribunalEngine::Shutdown();
    s_initialized = false;
}

void OmniversalTribunalLoop::Start() {
    if (s_running.exchange(true)) return;
    s_thread = std::make_unique<std::thread>(RunLoop);
}

void OmniversalTribunalLoop::Stop() {
    s_running = false;
    if (s_thread && s_thread->joinable()) {
        s_thread->join();
    }
    s_thread.reset();
}

bool OmniversalTribunalLoop::IsRunning() {
    return s_running;
}

void OmniversalTribunalLoop::Tick() {
    OmniversalTribunalEngine::OnTick();
    s_tickCount++;
}

int64_t OmniversalTribunalLoop::GetTickCount() {
    return s_tickCount;
}

void OmniversalTribunalLoop::SetTickRate(int ticksPerSecond) {
    s_tickRate = ticksPerSecond;
}

void OmniversalTribunalLoop::RunLoop() {
    while (s_running) {
        Tick();
        std::this_thread::sleep_for(
            std::chrono::milliseconds(1000 / s_tickRate.load()));
    }
}

} // namespace Omniversal
