#include "AbsoluteSupremacyLoop.hpp"
#include <chrono>
#include <thread>

namespace AbsoluteSupremacy {

AbsoluteSupremacyLoop::AbsoluteSupremacyLoop(AbsoluteSupremacyEngine& engine)
    : engine_(engine), running_(false), targetTPS_(60.0), currentTPS_(0.0) {}

AbsoluteSupremacyLoop::~AbsoluteSupremacyLoop() {
    Stop();
}

void AbsoluteSupremacyLoop::Start() {
    if (running_) return;
    running_ = true;
    tickThread_ = std::thread(&AbsoluteSupremacyLoop::TickLoop, this);
    frameThread_ = std::thread(&AbsoluteSupremacyLoop::FrameLoop, this);
    syncThread_ = std::thread(&AbsoluteSupremacyLoop::SyncLoop, this);
}

void AbsoluteSupremacyLoop::Stop() {
    running_ = false;
    if (tickThread_.joinable()) tickThread_.join();
    if (frameThread_.joinable()) frameThread_.join();
    if (syncThread_.joinable()) syncThread_.join();
}

bool AbsoluteSupremacyLoop::IsRunning() const {
    return running_;
}

void AbsoluteSupremacyLoop::SetTargetTPS(double tps) {
    targetTPS_ = tps;
}

double AbsoluteSupremacyLoop::GetCurrentTPS() const {
    return currentTPS_.load();
}

void AbsoluteSupremacyLoop::RegisterTickCallback(std::function<void()> callback) {
    tickCallback_ = callback;
}

void AbsoluteSupremacyLoop::RegisterFrameCallback(std::function<void()> callback) {
    frameCallback_ = callback;
}

void AbsoluteSupremacyLoop::RegisterSyncCallback(std::function<void()> callback) {
    syncCallback_ = callback;
}

void AbsoluteSupremacyLoop::TickLoop() {
    using namespace std::chrono;
    auto lastTime = steady_clock::now();
    int tickCount = 0;
    auto lastSecond = steady_clock::now();

    while (running_) {
        auto now = steady_clock::now();
        double deltaTime = duration<double>(now - lastTime).count();
        lastTime = now;

        // Process all supremacy entities
        auto supremacies = engine_.ListAbsoluteSupremacies();
        for (const auto& id : supremacies) {
            engine_.RunHSCycle(id);
            engine_.RunCACycle(id);
            engine_.RunPDCycle(id);
            engine_.RunCMCycle(id);
            engine_.RunMACycle(id);
            engine_.RunSRCycle(id);
            engine_.RunIWCycle(id);
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

void AbsoluteSupremacyLoop::FrameLoop() {
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

void AbsoluteSupremacyLoop::SyncLoop() {
    while (running_) {
        // Synchronization between supremacy systems
        if (syncCallback_) syncCallback_();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

} // namespace AbsoluteSupremacy
