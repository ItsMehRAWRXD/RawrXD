#include "EternalContinuityLoop.hpp"
#include <chrono>
#include <thread>

namespace EternalContinuity {

EternalContinuityLoop::EternalContinuityLoop(EternalContinuityEngine& engine)
    : engine_(engine), running_(false), targetTPS_(60.0), currentTPS_(0.0) {}

EternalContinuityLoop::~EternalContinuityLoop() {
    Stop();
}

void EternalContinuityLoop::Start() {
    if (running_) return;
    running_ = true;
    tickThread_ = std::thread(&EternalContinuityLoop::TickLoop, this);
    frameThread_ = std::thread(&EternalContinuityLoop::FrameLoop, this);
    syncThread_ = std::thread(&EternalContinuityLoop::SyncLoop, this);
}

void EternalContinuityLoop::Stop() {
    running_ = false;
    if (tickThread_.joinable()) tickThread_.join();
    if (frameThread_.joinable()) frameThread_.join();
    if (syncThread_.joinable()) syncThread_.join();
}

bool EternalContinuityLoop::IsRunning() const {
    return running_;
}

void EternalContinuityLoop::SetTargetTPS(double tps) {
    targetTPS_ = tps;
}

double EternalContinuityLoop::GetCurrentTPS() const {
    return currentTPS_.load();
}

void EternalContinuityLoop::RegisterTickCallback(std::function<void()> callback) {
    tickCallback_ = callback;
}

void EternalContinuityLoop::RegisterFrameCallback(std::function<void()> callback) {
    frameCallback_ = callback;
}

void EternalContinuityLoop::RegisterSyncCallback(std::function<void()> callback) {
    syncCallback_ = callback;
}

void EternalContinuityLoop::TickLoop() {
    using namespace std::chrono;
    auto lastTime = steady_clock::now();
    int tickCount = 0;
    auto lastSecond = steady_clock::now();

    while (running_) {
        auto now = steady_clock::now();
        double deltaTime = duration<double>(now - lastTime).count();
        lastTime = now;

        // Process all eternal continuity entities
        auto eternals = engine_.ListEternalContinuities();
        for (const auto& id : eternals) {
            engine_.RunTPCycle(id);
            engine_.RunEMCycle(id);
            engine_.RunRWCycle(id);
            engine_.RunPCCycle(id);
            engine_.RunIECycle(id);
            engine_.RunTFCycle(id);
            engine_.RunISCVycle(id);
        }

        if (tickCallback_) tickCallback_();

        tickCount++;
        auto elapsed = duration<double>(steady_clock::now() - lastSecond).count();
        if (elapsed >= 1.0) {
            currentTPS_ = tickCount / elapsed;
            tickCount = 0;
            lastSecond = steady_clock::now();
        }

        // Maintain target TPS
        double targetInterval = 1.0 / targetTPS_.load();
        auto sleepTime = duration<double>(targetInterval - deltaTime);
        if (sleepTime > duration<double>::zero()) {
            std::this_thread::sleep_for(sleepTime);
        }
    }
}

void EternalContinuityLoop::FrameLoop() {
    using namespace std::chrono;
    auto lastTime = steady_clock::now();

    while (running_) {
        auto now = steady_clock::now();
        double deltaTime = duration<double>(now - lastTime).count();
        lastTime = now;

        // Frame processing for visual updates
        if (frameCallback_) frameCallback_();

        std::this_thread::sleep_for(milliseconds(16)); // ~60 FPS
    }
}

void EternalContinuityLoop::SyncLoop() {
    while (running_) {
        // Synchronization between continuity systems
        if (syncCallback_) syncCallback_();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

} // namespace EternalContinuity
