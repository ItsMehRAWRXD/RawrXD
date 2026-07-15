#pragma once

#include <atomic>
#include <thread>
#include <functional>
#include <vector>
#include <string>

namespace Quantum {

class QuantumConsciousnessLoop {
public:
    QuantumConsciousnessLoop();
    ~QuantumConsciousnessLoop();

    void Start();
    void Stop();
    bool IsRunning() const;
    void SetTickRate(int ticksPerSecond);
    int GetTickRate() const;
    int64_t GetTickCount() const;
    void RegisterTickCallback(std::function<void()> callback);
    void RegisterQuantumCallback(std::function<void(const std::string&)> callback);
    void TriggerQuantumEvent(const std::string& eventType);
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
    std::vector<std::function<void(const std::string&)>> m_quantumCallbacks;
    mutable std::mutex m_callbackMutex;
    std::vector<std::string> m_recentEvents;
    mutable std::mutex m_eventsMutex;
};

} // namespace Quantum
