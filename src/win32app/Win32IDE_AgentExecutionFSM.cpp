#include "Win32IDE_AgentExecutionFSM.h"

namespace RawrXD {

bool AgentExecTransitionAllowed(AgentExecState from, AgentExecState to) {
    if (from == to) return true;
    switch (from) {
        case AgentExecState::Pending:
            return to == AgentExecState::Running ||
                   to == AgentExecState::Error;
        case AgentExecState::Running:
            return to == AgentExecState::Waiting ||
                   to == AgentExecState::Done ||
                   to == AgentExecState::Error;
        case AgentExecState::Waiting:
            return to == AgentExecState::Running ||
                   to == AgentExecState::Done ||
                   to == AgentExecState::Error;
        case AgentExecState::Done:
        case AgentExecState::Error:
            // Terminal until explicit reset() → Pending.
            return false;
        default:
            return false;
    }
}

bool AgentExecutionFSM::tryTransition(AgentExecState to,
                                      const std::string& reason) {
    AgentExecState from = m_state.load(std::memory_order_acquire);
    if (!AgentExecTransitionAllowed(from, to)) {
        return false;
    }
    if (!m_state.compare_exchange_strong(from, to,
            std::memory_order_acq_rel, std::memory_order_acquire)) {
        // Lost race; re-check with new from.
        if (!AgentExecTransitionAllowed(from, to)) return false;
        m_state.store(to, std::memory_order_release);
    }
    Observer obs;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_lastReason = reason;
        obs = m_observer;
    }
    if (obs) obs(from, to, reason);
    return true;
}

void AgentExecutionFSM::reset(const std::string& reason) {
    AgentExecState from = m_state.exchange(AgentExecState::Pending,
                                           std::memory_order_acq_rel);
    Observer obs;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_lastReason = reason;
        obs = m_observer;
    }
    if (obs) obs(from, AgentExecState::Pending, reason);
}

AgentExecutionFSM& ProductAgentFSM() {
    static AgentExecutionFSM g_fsm;
    return g_fsm;
}

} // namespace RawrXD
