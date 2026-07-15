#pragma once

#include <atomic>
#include <thread>
#include <functional>
#include <vector>

namespace Infinity {

class CosmicInfinityLoop {
public:
    static void Init();
    static void Shutdown();
    static void Start();
    static void Stop();
    static bool IsRunning();
    static void RegisterTickCallback(std::function<void()> callback);
    static void SetTickRate(int ticksPerSecond);
    static int GetTickRate();
    static int64_t GetTickCount();
    static float GetCurrentFPS();

private:
    static void LoopThread();
    
    static std::atomic<bool> s_running;
    static std::atomic<bool> s_initialized;
    static std::thread s_loopThread;
    static std::vector<std::function<void()>> s_tickCallbacks;
    static std::atomic<int> s_tickRate;
    static std::atomic<int64_t> s_tickCount;
    static std::atomic<float> s_currentFPS;
    static std::mutex s_callbackMutex;
};

} // namespace Infinity
