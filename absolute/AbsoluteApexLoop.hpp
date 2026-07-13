#pragma once
#include <atomic>
#include <thread>
#include <memory>

namespace Absolute {

class AbsoluteApexLoop {
public:
    static void Init();
    static void Shutdown();
    static void Start();
    static void Stop();
    static bool IsRunning();
    static void Tick();
    static int64_t GetTickCount();
    static void SetTickRate(int ticksPerSecond);

private:
    static void RunLoop();
    static std::atomic<bool> s_running;
    static std::atomic<bool> s_initialized;
    static std::atomic<int64_t> s_tickCount;
    static std::atomic<int> s_tickRate;
    static std::unique_ptr<std::thread> s_thread;
};

} // namespace Absolute
