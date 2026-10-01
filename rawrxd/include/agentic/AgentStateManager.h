// ============================================================================
// AgentStateManager.h — RAWRXD_AGENTIC_STATE_MANAGER_001
// Conversation history, budgeted context window, and per-turn metrics.
//
// Token counts are measured with a documented estimator (4 chars per token),
// never assigned as literals.
// ============================================================================
#pragma once

#include <chrono>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <vector>

namespace rawrxd {
namespace agentic {

enum class MessageRole { System, User, Assistant, Tool };

struct Message {
    MessageRole role = MessageRole::User;
    std::string content;
    std::string toolName;
    std::chrono::system_clock::time_point timestamp;
};

struct TurnMetrics {
    std::uint32_t turnNumber = 0;
    std::uint32_t promptTokens = 0;
    std::uint32_t completionTokens = 0;
    std::uint64_t latencyMicros = 0;
    bool toolExecuted = false;
    std::string toolName;
    std::string stopReason;  // "no_tool_call", "max_turns", "stopped", "fatal"
};

// Documented estimate: ~4 characters per token. Deterministic and dependency
// free; it is an estimate and is labelled as such in the receipt fields.
std::uint32_t EstimateTokens(const std::string& text);

class AgentStateManager {
public:
    explicit AgentStateManager(std::uint32_t maxTurns = 16, std::size_t contextCharBudget = 16000)
        : maxTurns_(maxTurns), contextCharBudget_(contextCharBudget) {}

    void Reset(const std::string& systemPrompt);
    void PushUser(const std::string& content);
    void PushAssistant(const std::string& content);
    void PushToolResult(const std::string& toolName, const std::string& result);

    // Builds the model context. The system prompt and the most recent user
    // message are always retained; when the budget is exceeded the OLDEST
    // middle messages are dropped. A naive implementation that `break`s on the
    // first over-budget message silently drops the newest turns, which is the
    // part the model actually needs.
    std::string BuildContextWindow() const;

    // What BuildContextWindow had to drop, for measurement.
    std::uint32_t LastDroppedMessageCount() const;
    std::size_t LastContextChars() const;

    std::vector<Message> History() const;
    void RecordMetrics(const TurnMetrics& metrics);
    std::vector<TurnMetrics> GetMetrics() const;

    std::uint32_t CurrentTurn() const;
    std::uint32_t MaxTurns() const { return maxTurns_; }
    bool ShouldContinue() const;

    void SetFatalError(const std::string& error);
    std::string LastError() const;
    bool HasFatalError() const;

    std::size_t MessageCount() const;

private:
    static const char* RoleName(MessageRole role);

    mutable std::mutex mtx_;
    std::vector<Message> history_;
    std::vector<TurnMetrics> metrics_;
    std::uint32_t currentTurn_ = 0;
    std::uint32_t maxTurns_ = 16;
    std::size_t contextCharBudget_ = 16000;
    bool fatalError_ = false;
    std::string lastError_;
    mutable std::uint32_t lastDropped_ = 0;
    mutable std::size_t lastContextChars_ = 0;
};

} // namespace agentic
} // namespace rawrxd
