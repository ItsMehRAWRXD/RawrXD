#pragma once
#include "AbsoluteSupremacyEngine.hpp"
#include <thread>
#include <atomic>
#include <functional>

namespace AbsoluteSupremacy {

class AbsoluteSupremacyLoop {
public:
    AbsoluteSupremacyLoop(AbsoluteSupremacyEngine& engine);
    ~AbsoluteSupremacyLoop();

    void Start();
    void Stop();
    bool IsRunning() const;

    void SetTargetTPS(double tps);
    double GetCurrentTPS() const;

    void RegisterTickCallback(std::function<void()> callback);
    void RegisterFrameCallback(std::function<void()> callback);
    void RegisterSyncCallback(std::function<void()> callback);

private:
    void TickLoop();
    void FrameLoop();
    void SyncLoop();

    AbsoluteSupremacyEngine& engine_;
    std::atomic<bool> running_;
    std::atomic<double> targetTPS_;
    std::atomic<double> currentTPS_;

    std::thread tickThread_;
    std::thread frameThread_;
    std::thread syncThread_;

    std::function<void()> tickCallback_;
    std::function<void()> frameCallback_;
    std::function<void()> syncCallback_;
};

} // namespace AbsoluteSupremacy
