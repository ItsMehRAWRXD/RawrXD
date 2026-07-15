#pragma once

#include <atomic>
#include <thread>
#include <functional>
#include <vector>
#include <cstring>

namespace Synthetic {

class SyntheticConsciousnessLoop {
public:
    SyntheticConsciousnessLoop();
    ~SyntheticConsciousnessLoop();

    void Start();
    void Stop();
    bool IsRunning() const;
    void SetTickRate(int ticksPerSecond);
    int GetTickRate() const;
    int64_t GetTickCount() const;
    void RegisterTickCallback(std::function<void()> callback);
    void RegisterSyntheticCallback(std::function<void(const std::string&)> callback);
    void TriggerSyntheticEvent(const std::string& eventType);
    std::vector<std::string> GetRecentEvents(int count) const;

private:
    void LoopThread();
    void ProcessTick();

    std::atomic<bool> m_running;
    std::atomic<bool> m_shouldStop;
    std::atomic<int> m_tickRate;
    std::atomic<int64_t> m_tickCount;
    std::thread m_loopThread;
    std::vector<std::function<void()>> m_tickCallbacks;
    std::vector<std::function<void(const std::string&)>> m_syntheticCallbacks;
    mutable std::mutex m_callbackMutex;
    std::vector<std::string> m_recentEvents;
    mutable std::mutex m_eventsMutex;
};

} // namespace Synthetic
