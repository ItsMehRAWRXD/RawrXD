#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <atomic>
#include <cstdint>
#include <functional>
#include <thread>
#include <utility>

namespace rawrxd::watchdog {
enum class Activity : uint8_t { ModelLayer, PrefillToken, DecodeToken, GPUCompleted, ToolCompleted, BuildCompleted, TestCompleted, VerificationCompleted };
enum class State : uint8_t { WaitingForFirstProgress, Active, StartupTimedOut, WallTimedOut, Finished };
struct Config { uint64_t startupMs=30000; uint64_t wallMs=600000; uint32_t pollMs=100; };
struct Status { State state; uint64_t elapsedMs; uint64_t progressEvents; uint64_t lastProgressMs; };
class Watchdog {
    Config config_;
    // Task-relative epoch (reset in Start). Construction-time clocks falsely
    // burn startup budget before the first agentic spawn (tip_016 class).
    std::atomic<uint64_t> start_{0};
    std::atomic<uint64_t> events_{0};
    std::atomic<uint64_t> last_{0};
    std::atomic<bool> finished_{false};
    std::atomic<bool> stop_{false};
    std::atomic<bool> cancellationRequested_{false};
    std::thread monitor_;
public:
    explicit Watchdog(Config c={}):config_(c) {
        if(!config_.pollMs)config_.pollMs=100;
        start_.store(GetTickCount64(),std::memory_order_release);
    }
    ~Watchdog(){Stop();}
    Watchdog(const Watchdog&)=delete;
    Watchdog& operator=(const Watchdog&)=delete;
    // Must be called after measurable work, not merely entry/heartbeat.
    void Progress(Activity) noexcept {
        if(finished_.load(std::memory_order_acquire))return;
        last_.store(GetTickCount64(),std::memory_order_release);
        events_.fetch_add(1,std::memory_order_release);
    }
    void Finish() noexcept {finished_.store(true,std::memory_order_release);}
    Status Inspect() const noexcept {
        const uint64_t now=GetTickCount64();
        const uint64_t count=events_.load(std::memory_order_acquire);
        const uint64_t epoch=start_.load(std::memory_order_acquire);
        const uint64_t elapsed=now-epoch;
        State s=State::WaitingForFirstProgress;
        if(finished_.load(std::memory_order_acquire))s=State::Finished;
        else if(config_.wallMs && elapsed>=config_.wallMs)s=State::WallTimedOut;
        else if(!count && elapsed>=config_.startupMs)s=State::StartupTimedOut;
        else if(count)s=State::Active;
        return {s,elapsed,count,last_.load(std::memory_order_acquire)};
    }
    bool CancellationRequested() const noexcept {return cancellationRequested_.load(std::memory_order_acquire);}
    // Callback runs on monitoring thread, exactly once on first timeout.
    // Callback should request cooperative cancellation; don't kill arbitrary threads.
    bool Start(std::function<void(Status)> onTimeout){
        Stop();
        if(!onTimeout)return false;
        finished_.store(false,std::memory_order_release);
        cancellationRequested_.store(false,std::memory_order_release);
        events_.store(0,std::memory_order_release);
        last_.store(0,std::memory_order_release);
        start_.store(GetTickCount64(),std::memory_order_release);
        stop_.store(false,std::memory_order_release);
        try {
            monitor_=std::thread([this,cb=std::move(onTimeout)]() {
                while(!stop_.load(std::memory_order_acquire)){
                    const auto s=Inspect();
                    if(s.state==State::Finished)break;
                    if(s.state==State::StartupTimedOut || s.state==State::WallTimedOut){
                        cancellationRequested_.store(true,std::memory_order_release);
                        try{cb(s);}catch(...){}
                        break;
                    }
                    Sleep(config_.pollMs);
                }
            });
        } catch (...) {return false;}
        return true;
    }
    void Stop() noexcept {
        stop_.store(true,std::memory_order_release);
        if(monitor_.joinable()){
            if(monitor_.get_id()==std::this_thread::get_id())monitor_.detach();
            else monitor_.join();
        }
    }
};
} // namespace rawrxd::watchdog
