#include "metaversal/MetaversalArchiveLoop.hpp"
#include "metaversal/MetaversalArchiveEngine.hpp"
#include <chrono>
#include <thread>

namespace Metaversal {

std::atomic<bool> MetaversalArchiveLoop::s_running(false);
std::atomic<bool> MetaversalArchiveLoop::s_initialized(false);
std::atomic<int64_t> MetaversalArchiveLoop::s_tickCount(0);
std::atomic<int> MetaversalArchiveLoop::s_tickRate(60);
std::unique_ptr<std::thread> MetaversalArchiveLoop::s_thread;

void MetaversalArchiveLoop::Init() {
    if (s_initialized.exchange(true)) return;
    MetaversalArchiveEngine::Init();
}

void MetaversalArchiveLoop::Shutdown() {
    Stop();
    MetaversalArchiveEngine::Shutdown();
    s_initialized = false;
}

void MetaversalArchiveLoop::Start() {
    if (s_running.exchange(true)) return;
    s_thread = std::make_unique<std::thread>(RunLoop);
}

void MetaversalArchiveLoop::Stop() {
    s_running = false;
    if (s_thread && s_thread->joinable()) {
        s_thread->join();
    }
    s_thread.reset();
}

bool MetaversalArchiveLoop::IsRunning() {
    return s_running;
}

void MetaversalArchiveLoop::Tick() {
    MetaversalArchiveEngine::OnTick();
    s_tickCount++;
}

int64_t MetaversalArchiveLoop::GetTickCount() {
    return s_tickCount;
}

void MetaversalArchiveLoop::SetTickRate(int ticksPerSecond) {
    s_tickRate = ticksPerSecond;
}

void MetaversalArchiveLoop::RunLoop() {
    while (s_running) {
        Tick();
        std::this_thread::sleep_for(
            std::chrono::milliseconds(1000 / s_tickRate.load()));
    }
}

} // namespace Metaversal
