// ============================================================================
// InferenceSession.hpp — Inference Session Manager
// Context, KV cache, token stream, cancellation, history
// ============================================================================

#ifndef INFERENCE_SESSION_HPP
#define INFERENCE_SESSION_HPP

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <functional>
#include <mutex>

namespace rawr {

// ============================================================================
// Session State
// ============================================================================
struct SessionState {
    uint32_t sessionId;
    std::string modelName;
    uint64_t startTime;
    uint64_t tokensGenerated;
    uint64_t promptTokens;
    bool active;
};

// ============================================================================
// Message
// ============================================================================
struct Message {
    std::string role;   // "user", "assistant", "system"
    std::string content;
    uint64_t timestamp;
};

// ============================================================================
// InferenceSession — Manages a single inference session
// ============================================================================
class InferenceSession {
public:
    InferenceSession(uint32_t sessionId);
    ~InferenceSession();

    uint32_t GetId() const { return m_state.sessionId; }
    bool IsActive() const { return m_state.active; }

    // Lifecycle
    void Start(const char* modelName);
    void End();
    void Reset();

    // Context
    void SetContextSize(uint64_t size) { m_contextSize = size; }
    uint64_t GetContextSize() const { return m_contextSize; }

    // History
    void AddMessage(const char* role, const char* content);
    const std::vector<Message>& GetHistory() const { return m_history; }
    void ClearHistory();

    // Token tracking
    void RecordTokens(uint64_t count);
    uint64_t GetTokenCount() const { return m_state.tokensGenerated; }

    // State
    SessionState GetState() const { return m_state; }

private:
    SessionState m_state = {};
    std::vector<Message> m_history;
    uint64_t m_contextSize = 2048;
    mutable std::mutex m_mutex;
};

} // namespace rawr

#endif // INFERENCE_SESSION_HPP
