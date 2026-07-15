#include "InfiniteSynthesisLoop.hpp"
#include <algorithm>
#include <cmath>

namespace InfiniteSynthesis {

InfiniteSynthesisLoop& g_infiniteSynthesisLoop = InfiniteSynthesisLoop::GetInstance();

InfiniteSynthesisLoop& InfiniteSynthesisLoop::GetInstance() {
    static InfiniteSynthesisLoop instance;
    return instance;
}

void InfiniteSynthesisLoop::Init() {
    std::lock_guard<std::mutex> lock(mutex_);
    config_ = InfiniteSynthesisConfig();
    targetFrameDuration_ = std::chrono::duration<double, std::milli>(1000.0 / config_.maxFPS);
    ResetMetrics();
}

void InfiniteSynthesisLoop::Shutdown() {
    Stop();
}

void InfiniteSynthesisLoop::Start() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (metrics_.isRunning.load()) return;
        shouldStop_ = false;
        metrics_.isRunning = true;
        metrics_.isPaused = false;
        startTime_ = std::chrono::steady_clock::now();
        lastTickTime_ = startTime_;
        lastFrameTime_ = startTime_;
    }
    tickThread_ = std::make_unique<std::thread>(&InfiniteSynthesisLoop::TickThreadFunc, this);
    if (config_.enableMultiLayerSynchronization) {
        syncThread_ = std::make_unique<std::thread>(&InfiniteSynthesisLoop::SyncThreadFunc, this);
    }
    if (config_.enableCrossLayerHarmonyHarmonization) {
        harmonyThread_ = std::make_unique<std::thread>(&InfiniteSynthesisLoop::HarmonyThreadFunc, this);
    }
}

void InfiniteSynthesisLoop::Stop() {
    shouldStop_ = true;
    if (tickThread_ && tickThread_->joinable()) { tickThread_->join(); tickThread_.reset(); }
    if (syncThread_ && syncThread_->joinable()) { syncThread_->join(); syncThread_.reset(); }
    if (harmonyThread_ && harmonyThread_->joinable()) { harmonyThread_->join(); harmonyThread_.reset(); }
    metrics_.isRunning = false;
    metrics_.isPaused = false;
}

void InfiniteSynthesisLoop::Pause() { metrics_.isPaused = true; }

void InfiniteSynthesisLoop::Resume() {
    metrics_.isPaused = false;
    lastTickTime_ = std::chrono::steady_clock::now();
    lastFrameTime_ = std::chrono::steady_clock::now();
}

void InfiniteSynthesisLoop::SetConfig(const InfiniteSynthesisConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_ = config;
    targetFrameDuration_ = std::chrono::duration<double, std::milli>(1000.0 / config_.maxFPS);
}

InfiniteSynthesisConfig InfiniteSynthesisLoop::GetConfig() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return config_;
}

InfiniteSynthesisMetrics InfiniteSynthesisLoop::GetMetrics() const { return metrics_; }

void InfiniteSynthesisLoop::ResetMetrics() {
    metrics_.tickCount = 0; metrics_.frameCount = 0; metrics_.currentTPS = 0.0; metrics_.currentFPS = 0.0;
    metrics_.isRunning = false; metrics_.isPaused = false; metrics_.lastSyncTime = 0.0; metrics_.lastHarmonyTime = 0.0;
    metrics_.syncCount = 0; metrics_.harmonyCount = 0;
}

void InfiniteSynthesisLoop::SetTickCallback(InfiniteSynthesisTickCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    tickCallback_ = callback;
}

void InfiniteSynthesisLoop::TickThreadFunc() {
    using namespace std::chrono;
    const auto targetTickDuration = duration<double, std::milli>(1000.0 / config_.targetTPS);
    while (!shouldStop_.load()) {
        if (metrics_.isPaused.load()) { std::this_thread::sleep_for(milliseconds(1)); continue; }
        auto tickStart = steady_clock::now();
        uint64_t currentTick = metrics_.tickCount.fetch_add(1) + 1;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (tickCallback_) tickCallback_(currentTick);
        }
        if (config_.enableOmnipresentTickPropagation) {}
        CalculateTPS();
        auto tickEnd = steady_clock::now();
        auto elapsed = duration_cast<duration<double, std::milli>>(tickEnd - tickStart);
        auto sleepTime = targetTickDuration - elapsed;
        if (sleepTime > duration<double, std::milli>::zero()) std::this_thread::sleep_for(sleepTime);
    }
}

void InfiniteSynthesisLoop::SyncThreadFunc() {
    using namespace std::chrono;
    while (!shouldStop_.load()) {
        if (metrics_.isPaused.load() || !config_.enableMultiLayerSynchronization) { std::this_thread::sleep_for(milliseconds(10)); continue; }
        auto syncStart = steady_clock::now();
        metrics_.syncCount.fetch_add(1);
        metrics_.lastSyncTime = duration_cast<duration<double>>(syncStart.time_since_epoch()).count();
        std::this_thread::sleep_for(duration<double, std::milli>(config_.syncIntervalMs));
    }
}

void InfiniteSynthesisLoop::HarmonyThreadFunc() {
    using namespace std::chrono;
    while (!shouldStop_.load()) {
        if (metrics_.isPaused.load() || !config_.enableCrossLayerHarmonyHarmonization) { std::this_thread::sleep_for(milliseconds(10)); continue; }
        auto harmonyStart = steady_clock::now();
        metrics_.harmonyCount.fetch_add(1);
        metrics_.lastHarmonyTime = duration_cast<duration<double>>(harmonyStart.time_since_epoch()).count();
        std::this_thread::sleep_for(duration<double, std::milli>(config_.harmonyIntervalMs));
    }
}

void InfiniteSynthesisLoop::CalculateTPS() {
    using namespace std::chrono;
    auto now = steady_clock::now();
    auto elapsed = duration_cast<duration<double>>(now - lastTickTime_).count();
    if (elapsed >= 1.0) {
        uint64_t ticks = metrics_.tickCount.load();
        metrics_.currentTPS = static_cast<double>(ticks) / elapsed;
        lastTickTime_ = now; metrics_.tickCount = 0;
    }
}

void InfiniteSynthesisLoop::CalculateFPS() {
    using namespace std::chrono;
    auto now = steady_clock::now();
    auto elapsed = duration_cast<duration<double>>(now - lastFrameTime_).count();
    if (elapsed >= 1.0) {
        uint64_t frames = metrics_.frameCount.load();
        metrics_.currentFPS = static_cast<double>(frames) / elapsed;
        lastFrameTime_ = now; metrics_.frameCount = 0;
    }
}

void InfiniteSynthesisLoop::RenderFrame() {
    if (!metrics_.isRunning.load() || metrics_.isPaused.load()) return;
    auto frameStart = std::chrono::steady_clock::now();
    metrics_.frameCount.fetch_add(1);
    CalculateFPS();
    if (config_.enableFrameLimiting) {
        auto frameEnd = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::duration<double, std::milli>>(frameEnd - frameStart);
        auto sleepTime = targetFrameDuration_ - elapsed;
        if (sleepTime > std::chrono::duration<double, std::milli>::zero()) std::this_thread::sleep_for(sleepTime);
    }
}

} // namespace InfiniteSynthesis
