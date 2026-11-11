// ============================================================================
// Win32IDE_AgentExecutionFSM.h — SSOT agent lifecycle state machine
// pending / running / waiting / done / error
// Bridge + Executor + AutonomousLoop must drive this; UI timeline observes only.
// ============================================================================
#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>

namespace RawrXD {

enum class AgentExecState : uint8_t {
    Pending = 0,
    Running = 1,
    Waiting = 2,  // approval / human / external
    Done    = 3,
    Error   = 4
};

inline const char* AgentExecStateName(AgentExecState s) {
    switch (s) {
        case AgentExecState::Pending: return "pending";
        case AgentExecState::Running: return "running";
        case AgentExecState::Waiting: return "waiting";
        case AgentExecState::Done:    return "done";
        case AgentExecState::Error:   return "error";
        default:                      return "unknown";
    }
}

// Legal transitions (SSOT table). UI must not invent states.
bool AgentExecTransitionAllowed(AgentExecState from, AgentExecState to);

class AgentExecutionFSM {
public:
    using Observer = std::function<void(AgentExecState from, AgentExecState to,
                                        const std::string& reason)>;

    AgentExecutionFSM() = default;

    AgentExecState state() const {
        return m_state.load(std::memory_order_acquire);
    }

    void setObserver(Observer obs) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_observer = std::move(obs);
    }

    // Returns false if transition illegal; state unchanged.
    bool tryTransition(AgentExecState to, const std::string& reason = {});

    // Force reset to Pending (new task). Always allowed.
    void reset(const std::string& reason = "reset");

    std::string lastReason() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_lastReason;
    }

private:
    std::atomic<AgentExecState> m_state{AgentExecState::Pending};
    mutable std::mutex m_mutex;
    std::string m_lastReason;
    Observer m_observer;
};

// Process-wide product FSM shared by Bridge / Executor / Loop.
AgentExecutionFSM& ProductAgentFSM();

} // namespace RawrXD
