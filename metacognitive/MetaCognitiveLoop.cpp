#include "metacognitive/MetaCognitiveLoop.hpp"
#include "metacognitive/MetaCognitiveEngine.hpp"
#include <chrono>
#include <algorithm>

namespace MetaCognitive {

MetaCognitiveLoop::MetaCognitiveLoop()
    : m_running(false)
    , m_shouldStop(false)
    , m_tickRate(60)
    , m_tickCount(0)
{
}

MetaCognitiveLoop::~MetaCognitiveLoop() {
    Stop();
}

void MetaCognitiveLoop::Start() {
    if (m_running.exchange(true)) return;
    m_shouldStop = false;
    m_loopThread = std::thread(&MetaCognitiveLoop::LoopThread, this);
}

void MetaCognitiveLoop::Stop() {
    m_shouldStop = true;
    if (m_loopThread.joinable()) {
        m_loopThread.join();
    }
    m_running = false;
}

bool MetaCognitiveLoop::IsRunning() const {
    return m_running;
}

void MetaCognitiveLoop::SetTickRate(int ticksPerSecond) {
    m_tickRate = std::max(1, ticksPerSecond);
}

int MetaCognitiveLoop::GetTickRate() const {
    return m_tickRate;
}

int64_t MetaCognitiveLoop::GetTickCount() const {
    return m_tickCount;
}

void MetaCognitiveLoop::RegisterTickCallback(std::function<void()> callback) {
    std::lock_guard<std::mutex> lock(m_callbackMutex);
    m_tickCallbacks.push_back(callback);
}

void MetaCognitiveLoop::RegisterMetaCognitiveCallback(std::function<void(const std::string&)> callback) {
    std::lock_guard<std::mutex> lock(m_callbackMutex);
    m_metaCognitiveCallbacks.push_back(callback);
}

void MetaCognitiveLoop::TriggerMetaCognitiveEvent(const std::string& eventType) {
    {
        std::lock_guard<std::mutex> lock(m_eventsMutex);
        m_recentEvents.push_back(eventType);
        if (m_recentEvents.size() > 100) {
            m_recentEvents.erase(m_recentEvents.begin());
        }
    }
    
    std::lock_guard<std::mutex> lock(m_callbackMutex);
    for (auto& callback : m_metaCognitiveCallbacks) {
        callback(eventType);
    }
}

std::vector<std::string> MetaCognitiveLoop::GetRecentEvents(int count) const {
    std::lock_guard<std::mutex> lock(m_eventsMutex);
    int start = std::max(0, static_cast<int>(m_recentEvents.size()) - count);
    return std::vector<std::string>(m_recentEvents.begin() + start, m_recentEvents.end());
}

void MetaCognitiveLoop::LoopThread() {
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

void MetaCognitiveLoop::ProcessTick() {
    m_tickCount++;
    MetaCognitiveEngine::OnTick();
    
    std::lock_guard<std::mutex> lock(m_callbackMutex);
    for (auto& callback : m_tickCallbacks) {
        callback();
    }
    
    if (m_tickCount % 100 == 0) {
        TriggerMetaCognitiveEvent("metacognitive_pulse_" + std::to_string(m_tickCount));
    }
}

} // namespace MetaCognitive
