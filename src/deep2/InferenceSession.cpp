// ============================================================================
// InferenceSession.cpp — Inference Session Manager Implementation
// ============================================================================

#include "InferenceSession.hpp"
#include "../runtime/RawrRuntime.hpp"
#include <chrono>
#include <algorithm>

namespace rawr {

InferenceSession::InferenceSession(uint32_t sessionId) {
    m_state.sessionId = sessionId;
}

InferenceSession::~InferenceSession() {
    End();
}

void InferenceSession::Start(const char* modelName) {
    std::lock_guard<std::mutex> lock(m_mutex);

    m_state.modelName = modelName ? modelName : "unknown";
    m_state.startTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()
    ).count();
    m_state.tokensGenerated = 0;
    m_state.promptTokens = 0;
    m_state.active = true;

    RawrRuntime::Get().Log(LogLevel::Info, "Session started");
}

void InferenceSession::End() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_state.active = false;
    RawrRuntime::Get().Log(LogLevel::Info, "Session ended");
}

void InferenceSession::Reset() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_history.clear();
    m_state.tokensGenerated = 0;
    m_state.promptTokens = 0;
    RawrRuntime::Get().Log(LogLevel::Info, "Session reset");
}

void InferenceSession::AddMessage(const char* role, const char* content) {
    std::lock_guard<std::mutex> lock(m_mutex);

    Message msg;
    msg.role = role ? role : "user";
    msg.content = content ? content : "";
    msg.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();

    m_history.push_back(std::move(msg));

    // Trim history if too long
    if (m_history.size() > 100) {
        m_history.erase(m_history.begin(), m_history.begin() + (m_history.size() - 100));
    }
}

void InferenceSession::ClearHistory() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_history.clear();
}

void InferenceSession::RecordTokens(uint64_t count) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_state.tokensGenerated += count;
}

} // namespace rawr
