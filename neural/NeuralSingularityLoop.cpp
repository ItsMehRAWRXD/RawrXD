#include "neural/NeuralSingularityLoop.hpp"
#include "neural/NeuralSingularityEngine.hpp"
#include <chrono>
#include <algorithm>

namespace Neural {

NeuralSingularityLoop::NeuralSingularityLoop()
    : m_running(false)
    , m_shouldStop(false)
    , m_tickRate(60)
    , m_tickCount(0)
{
}

NeuralSingularityLoop::~NeuralSingularityLoop() {
    Stop();
}

void NeuralSingularityLoop::Start() {
    if (m_running.exchange(true)) return;
    m_shouldStop = false;
    m_loopThread = std::thread(&NeuralSingularityLoop::LoopThread, this);
}

void NeuralSingularityLoop::Stop() {
    m_shouldStop = true;
    if (m_loopThread.joinable()) {
        m_loopThread.join();
    }
    m_running = false;
}

bool NeuralSingularityLoop::IsRunning() const {
    return m_running;
}

void NeuralSingularityLoop::SetTickRate(int ticksPerSecond) {
    m_tickRate = std::max(1, ticksPerSecond);
}

int NeuralSingularityLoop::GetTickRate() const {
    return m_tickRate;
}

int64_t NeuralSingularityLoop::GetTickCount() const {
    return m_tickCount;
}

void NeuralSingularityLoop::RegisterTickCallback(std::function<void()> callback) {
    std::lock_guard<std::mutex> lock(m_callbackMutex);
    m_tickCallbacks.push_back(callback);
}

void NeuralSingularityLoop::RegisterNeuralCallback(std::function<void(const std::string&)> callback) {
    std::lock_guard<std::mutex> lock(m_callbackMutex);
    m_neuralCallbacks.push_back(callback);
}

void NeuralSingularityLoop::TriggerNeuralEvent(const std::string& eventType) {
    {
        std::lock_guard<std::mutex> lock(m_eventsMutex);
        m_recentEvents.push_back(eventType);
        if (m_recentEvents.size() > 100) {
            m_recentEvents.erase(m_recentEvents.begin());
        }
    }
    
    std::lock_guard<std::mutex> lock(m_callbackMutex);
    for (auto& callback : m_neuralCallbacks) {
        callback(eventType);
    }
}

std::vector<std::string> NeuralSingularityLoop::GetRecentEvents(int count) const {
    std::lock_guard<std::mutex> lock(m_eventsMutex);
    int start = std::max(0, static_cast<int>(m_recentEvents.size()) - count);
    return std::vector<std::string>(m_recentEvents.begin() + start, m_recentEvents.end());
}

void NeuralSingularityLoop::LoopThread() {
    auto lastTick = std::chrono::steady_clock::now();
    
    while (!m_shouldStop) {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - lastTick);
        int tickIntervalMs = 1000 / m_tickRate;
        
        if (elapsed.count() >= tickIntervalMs) {
            ProcessTick();
            lastTick = now;
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

void NeuralSingularityLoop::ProcessTick() {
    m_tickCount++;
    NeuralSingularityEngine::OnTick();
    
    std::lock_guard<std::mutex> lock(m_callbackMutex);
    for (auto& callback : m_tickCallbacks) {
        callback();
    }
    
    if (m_tickCount % 100 == 0) {
        TriggerNeuralEvent("neural_pulse_" + std::to_string(m_tickCount));
    }
}

} // namespace Neural
