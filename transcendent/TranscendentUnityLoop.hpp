#pragma once

#include <functional>
#include <thread>
#include <mutex>
#include <atomic>
#include <vector>
#include <cstdint>

namespace TranscendentUnity {

class TranscendentUnityLoop {
public:
    using TickCallback = std::function<void()>;
    
    // Initialization
    static void Init();
    static void Shutdown();
    static bool IsInitialized();
    
    // Loop control
    static void Start();
    static void Stop();
    static bool IsRunning();
    
    // Callback registration
    static void RegisterTickCallback(TickCallback callback);
    static void UnregisterTickCallback(TickCallback callback);
    static void ClearTickCallbacks();
    
    // Metrics
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

} // namespace TranscendentUnity
