#pragma once

#include <atomic>
#include <thread>
#include <mutex>
#include <vector>
#include <functional>
#include <cstdint>

namespace DivineInfinity {

class DivineInfinityLoop {
public:
    using TickCallback = std::function<void()>;

    static void Init();
    static void Shutdown();
    static void Start();
    static void Stop();
    static bool IsRunning();
    static bool IsInitialized();

    static void RegisterTickCallback(TickCallback callback);
    static void UnregisterTickCallback(TickCallback callback);
    static void ClearTickCallbacks();

    static int64_t GetTickCount();
    static float GetCurrentFPS();
    static void SetTargetTPS(int tps);
    static int GetTargetTPS();

private:
    static void LoopThread();
    static void ProcessTick();

    static bool s_initialized;
    static std::atomic<bool> s_running;
    static std::thread s_loopThread;
    static std::mutex s_callbackMutex;
    static std::vector<TickCallback> s_tickCallbacks;
    static std::atomic<int64_t> s_tickCount;
    static std::atomic<float> s_currentFPS;
    static int s_targetTPS;
};

} // namespace DivineInfinity
