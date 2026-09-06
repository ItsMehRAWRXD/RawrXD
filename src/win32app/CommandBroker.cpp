#include "CommandBroker.h"

#include <chrono>

namespace RawrXD::CommandHome {

CommandBroker& CommandBroker::Instance()
{
    static CommandBroker s;
    return s;
}

void CommandBroker::ResetJournal()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_journal.clear();
}

void CommandBroker::AppendJournal(const std::string& line)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_journal.push_back(line);
}

bool CommandBroker::BindSession(const SessionBind& bind)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_session = bind;
    m_session.bound = true;
    AppendJournal("SESSION_BIND machine=" + m_session.machineId +
                  " workspace=" + m_session.workspaceRoot +
                  " branch=" + m_session.branch +
                  " model=" + m_session.modelId);
    return true;
}

bool CommandBroker::BindDefaultSession(const std::string& workspaceRoot,
                                       const std::string& repoRoot,
                                       const std::string& branch)
{
    SessionBind bind;
    bind.machineId = "ThisPC";
    bind.workspaceRoot = workspaceRoot;
    bind.repoRoot = repoRoot.empty() ? workspaceRoot : repoRoot;
    bind.branch = branch.empty() ? "unknown" : branch;
    bind.modelId = "Deep2 Local";
    bind.bound = true;
    bind.capabilities.read = true;
    bind.capabilities.edit = true;
    bind.capabilities.execute = false;
    return BindSession(bind);
}

void CommandBroker::SetActivity(AgentActivityState state,
                              const std::string& operation,
                              const std::string& detail,
                              int progressPct)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_activity.state = state;
    m_activity.operation = operation;
    m_activity.detail = detail;
    m_activity.progressPct = progressPct;
    if (state == AgentActivityState::Working)
        m_stopRequested.store(false);
}

void CommandBroker::RequestStop()
{
    m_stopRequested.store(true);
    SetActivity(AgentActivityState::Stopped, "Stopped", "User requested stop");
    AppendJournal("AGENT_STOP user");
}

void CommandBroker::ClearStop()
{
    m_stopRequested.store(false);
}

void CommandBroker::SetPendingApproval(const std::string& requestText)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_pendingApprovals = 1;
    m_pendingApprovalText = requestText;
    m_activity.state = AgentActivityState::WaitingApproval;
    m_activity.operation = "Approval required";
    m_activity.detail = requestText;
    AppendJournal("APPROVAL_WAITING " + requestText);
}

void CommandBroker::ClearPendingApproval()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_pendingApprovals = 0;
    m_pendingApprovalText.clear();
    if (m_activity.state == AgentActivityState::WaitingApproval)
        m_activity.state = AgentActivityState::Idle;
}

bool CommandBroker::CanCapability(const char* cap) const
{
    if (!m_session.bound)
        return false;
    if (!cap)
        return false;
    const std::string c(cap);
    if (c == "read") return m_session.capabilities.read;
    if (c == "edit") return m_session.capabilities.edit;
    if (c == "execute") return m_session.capabilities.execute;
    if (c == "commit") return m_session.capabilities.commit;
    if (c == "push") return m_session.capabilities.push;
    if (c == "destructive") return m_session.capabilities.destructive;
    return false;
}

bool CommandBroker::TryAcquireWriteLease(Agents::AgentWorkLease::Kind kind,
                                         const std::string& resource,
                                         uint64_t sessionId,
                                         uint64_t agentId)
{
    if (!CanCapability(kind == Agents::AgentWorkLease::Kind::Edit ? "edit" : "execute"))
        return false;
    Agents::AgentWorkLease lease;
    lease.sessionId = sessionId;
    lease.agentId = agentId;
    lease.kind = kind;
    lease.resource = resource;
    const auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
                         std::chrono::steady_clock::now().time_since_epoch())
                         .count();
    lease.startedAtMs = static_cast<uint64_t>(now);
    lease.heartbeatMs = lease.startedAtMs;
    const auto key = Agents::SharedAgentWorkRegistry::makeKey(kind, resource, "");
    const auto out =
        Agents::SharedAgentWorkRegistry::instance().acquireOrJoin(key, sessionId, agentId);
    return out.status == Agents::AcquireResult::Acquired ||
           out.status == Agents::AcquireResult::JoinedExisting;
}

} // namespace RawrXD::CommandHome
