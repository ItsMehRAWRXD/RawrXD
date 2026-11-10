// ToolCallExactlyOnceGuard.hpp — Wave2 Issue #49 (roadmap 85→88)
// Fail-closed dedupe of tool_call_id within one agent turn.
// Does NOT mutate Wave1 Ext / ComputerUse / AgentCommands surfaces.
// Wire into ToolCallBridge::ExecuteToolCall only after Wave1 publishes a
// controlling SHA and an absorb review; until then this header + harnesses
// prove the contract in isolation.
#pragma once

#include <mutex>
#include <string>
#include <unordered_set>
#include <utility>

namespace RawrXD {
namespace Agent {

enum class ExactlyOnceAdmit {
    First = 0,
    Duplicate = 1,
    RejectEmptyId = 2
};

// Thread-safe per-turn set. Clear() on BeginUserTurn / EndUserTurn.
class ToolCallExactlyOnceGuard {
public:
    void Clear() {
        std::lock_guard<std::mutex> lock(m_mu);
        m_seen.clear();
        m_firstCount = 0;
        m_dupCount = 0;
        m_emptyRejectCount = 0;
    }

    ExactlyOnceAdmit Admit(const std::string& toolCallId) {
        std::lock_guard<std::mutex> lock(m_mu);
        if (toolCallId.empty()) {
            ++m_emptyRejectCount;
            return ExactlyOnceAdmit::RejectEmptyId;
        }
        const auto inserted = m_seen.insert(toolCallId).second;
        if (!inserted) {
            ++m_dupCount;
            return ExactlyOnceAdmit::Duplicate;
        }
        ++m_firstCount;
        return ExactlyOnceAdmit::First;
    }

    bool Seen(const std::string& toolCallId) const {
        std::lock_guard<std::mutex> lock(m_mu);
        return m_seen.find(toolCallId) != m_seen.end();
    }

    size_t SeenCount() const {
        std::lock_guard<std::mutex> lock(m_mu);
        return m_seen.size();
    }

    int FirstCount() const {
        std::lock_guard<std::mutex> lock(m_mu);
        return m_firstCount;
    }

    int DupCount() const {
        std::lock_guard<std::mutex> lock(m_mu);
        return m_dupCount;
    }

    int EmptyRejectCount() const {
        std::lock_guard<std::mutex> lock(m_mu);
        return m_emptyRejectCount;
    }

private:
    mutable std::mutex m_mu;
    std::unordered_set<std::string> m_seen;
    int m_firstCount = 0;
    int m_dupCount = 0;
    int m_emptyRejectCount = 0;
};

inline const char* ExactlyOnceAdmitName(ExactlyOnceAdmit a) {
    switch (a) {
    case ExactlyOnceAdmit::First: return "FIRST";
    case ExactlyOnceAdmit::Duplicate: return "DUPLICATE";
    case ExactlyOnceAdmit::RejectEmptyId: return "REJECT_EMPTY_ID";
    }
    return "UNKNOWN";
}

} // namespace Agent
} // namespace RawrXD
