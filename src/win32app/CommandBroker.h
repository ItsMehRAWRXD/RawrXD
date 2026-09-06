#pragma once
#include "CommandHomeTypes.h"
#include "../agents/SharedAgentWorkRegistry.hpp"

#include <atomic>
#include <mutex>
#include <string>
#include <vector>

namespace RawrXD::CommandHome {

class CommandBroker {
public:
    static CommandBroker& Instance();

    void ResetJournal();
    const std::vector<std::string>& Journal() const { return m_journal; }
    void AppendJournal(const std::string& line);

    const SessionBind& Session() const { return m_session; }
    bool BindSession(const SessionBind& bind);
    bool BindDefaultSession(const std::string& workspaceRoot,
                            const std::string& repoRoot,
                            const std::string& branch);

    AgentActivity& Activity() { return m_activity; }
    const AgentActivity& Activity() const { return m_activity; }

    void SetActivity(AgentActivityState state,
                     const std::string& operation,
                     const std::string& detail,
                     int progressPct = 0);

    void RequestStop();
    bool StopRequested() const { return m_stopRequested.load(); }
    void ClearStop();

    int PendingApprovalCount() const { return m_pendingApprovals; }
    void SetPendingApproval(const std::string& requestText);
    void ClearPendingApproval();
    const std::string& PendingApprovalText() const { return m_pendingApprovalText; }

    bool CanCapability(const char* cap) const;
    bool TryAcquireWriteLease(Agents::AgentWorkLease::Kind kind,
                              const std::string& resource,
                              uint64_t sessionId,
                              uint64_t agentId);

    ExecutionMode executionMode() const { return m_execMode; }
    void SetExecutionMode(ExecutionMode mode) { m_execMode = mode; }

private:
    CommandBroker() = default;

    SessionBind m_session{};
    AgentActivity m_activity{};
    std::vector<std::string> m_journal;
    mutable std::mutex m_mutex;
    std::atomic<bool> m_stopRequested{false};
    int m_pendingApprovals = 0;
    std::string m_pendingApprovalText;
    ExecutionMode m_execMode = ExecutionMode::Plan;
};

} // namespace RawrXD::CommandHome
