#include "transcendent/TranscendentIntegrationLoop.hpp"
#include "transcendent/TranscendentIntegrationEngine.hpp"
#include <chrono>
#include <algorithm>

namespace Transcendent {

TranscendentIntegrationLoop::TranscendentIntegrationLoop()
    : m_running(false)
    , m_shouldStop(false)
    , m_tickRate(60)
    , m_tickCount(0)
{
}

TranscendentIntegrationLoop::~TranscendentIntegrationLoop() {
    Stop();
}

void TranscendentIntegrationLoop::Start() {
    if (m_running.exchange(true)) return;
    m_shouldStop = false;
    m_loopThread = std::thread(&TranscendentIntegrationLoop::LoopThread, this);
}

void TranscendentIntegrationLoop::Stop() {
    m_shouldStop = true;
    if (m_loopThread.joinable()) {
        m_loopThread.join();
    }
    m_running = false;
}

bool TranscendentIntegrationLoop::IsRunning() const {
    return m_running;
}

void TranscendentIntegrationLoop::SetTickRate(int ticksPerSecond) {
    m_tickRate = std::max(1, ticksPerSecond);
}

int TranscendentIntegrationLoop::GetTickRate() const {
    return m_tickRate;
}

int64_t TranscendentIntegrationLoop::GetTickCount() const {
    return m_tickCount;
}

void TranscendentIntegrationLoop::RegisterTickCallback(std::function<void()> callback) {
    std::lock_guard<std::mutex> lock(m_callbackMutex);
    m_tickCallbacks.push_back(callback);
}

void TranscendentIntegrationLoop::RegisterTranscendentCallback(std::function<void(const std::string&)> callback) {
    std::lock_guard<std::mutex> lock(m_callbackMutex);
    m_transcendentCallbacks.push_back(callback);
}

void TranscendentIntegrationLoop::TriggerTranscendentEvent(const std::string& eventType) {
    {
        std::lock_guard<std::mutex> lock(m_eventsMutex);
        m_recentEvents.push_back(eventType);
        if (m_recentEvents.size() > 100) {
            m_recentEvents.erase(m_recentEvents.begin());
        }
    }
    
    std::lock_guard<std::mutex> lock(m_callbackMutex);
    for (auto& callback : m_transcendentCallbacks) {
        callback(eventType);
    }
}

std::vector<std::string> TranscendentIntegrationLoop::GetRecentEvents(int count) const {
    std::lock_guard<std::mutex> lock(m_eventsMutex);
    int start = std::max(0, static_cast<int>(m_recentEvents.size()) - count);
    return std::vector<std::string>(m_recentEvents.begin() + start, m_recentEvents.end());
}

void TranscendentIntegrationLoop::LoopThread() {
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

void TranscendentIntegrationLoop::ProcessTick() {
    m_tickCount++;
    TranscendentIntegrationEngine::OnTick();
    
    std::lock_guard<std::mutex> lock(m_callbackMutex);
    for (auto& callback : m_tickCallbacks) {
        callback();
    }
    
    if (m_tickCount % 100 == 0) {
        TriggerTranscendentEvent("transcendent_pulse_" + std::to_string(m_tickCount));
    }
}

} // namespace Transcendent
