#include "CommandBroker.h"
#include "CommandEventJournal.h"
#include "../agentic/LocalOnlyPolicy.h"
#include "../agents/SharedAgentWorkRegistry.hpp"
#include <sstream>

namespace RawrXD::Command {

CommandBroker& CommandBroker::instance() {
    static CommandBroker b;
    return b;
}

bool CommandBroker::checkCap(Capability c) const {
    const auto& snap = SessionBinder::instance().snapshot();
    return hasCap(snap.capabilities, c);
}

void CommandBroker::setActivityStatus(const std::string& s) {
    std::lock_guard<std::mutex> lock(mu_);
    activity_ = s;
}

std::string CommandBroker::activityStatus() const {
    std::lock_guard<std::mutex> lock(mu_);
    return activity_;
}

const char* CommandBroker::steerModeLabel(SteerMode m) {
    switch (m) {
        case SteerMode::Plan: return "Plan";
        case SteerMode::Build: return "Build";
        case SteerMode::Agent: return "Agent";
    }
    return "Agent";
}

BrokerResult CommandBroker::steer(const std::string& message) {
    BrokerResult r;
    const std::string unbound = SessionBinder::instance().diagnosticIfUnbound();
    if (!unbound.empty()) {
        r.text = unbound;
        return r;
    }
    if (!checkCap(CapExecute)) {
        r.text = "COMMAND: FAIL_CLOSED — execute capability denied.";
        return r;
    }
    if (message.find("11434") != std::string::npos ||
        message.find("ollama") != std::string::npos) {
        r.text = RawrXD::LocalOnly::kHardDiagnostic;
        return r;
    }

    // Drop any prior steer lease before acquiring — chat is not a workspace Edit
    // hold, and a failed first turn used to permanently block Send.
    releaseSteerLease();

    const auto& snap = SessionBinder::instance().snapshot();
    RawrXD::Agents::WorkKey key{
        RawrXD::Agents::AgentWorkLease::Kind::Read,
        snap.workspaceRoot,
        "command_steer"};
    auto lease = RawrXD::Agents::SharedAgentWorkRegistry::instance().acquireOrJoin(
        key, 1, 1);
    if (lease.status == RawrXD::Agents::AcquireResult::ConflictingWrite ||
        lease.status == RawrXD::Agents::AcquireResult::StaleRepo) {
        r.text = (lease.status == RawrXD::Agents::AcquireResult::StaleRepo)
                     ? "COMMAND: FAIL_CLOSED — workspace path rejected (stale repo)."
                     : "COMMAND: FAIL_CLOSED — write lease held by another agent/worktree.";
        return r;
    }
    {
        std::lock_guard<std::mutex> lock(mu_);
        steerLeaseResource_ = key.normalizedResource;
        steerLeaseQuery_ = key.normalizedQuery;
        steerLeaseHeld_ = true;
    }

    CommandEventJournal::instance().append(
        JournalEventType::SteerMessage,
        "\"" + message.substr(0, 200) + "\"");
    setActivityStatus(std::string("RawrXD Agent — ") + steerModeLabel(steerMode_) + " mode");
    agentActive_ = true;
    CommandEventJournal::instance().append(JournalEventType::AgentStarted, "\"steer\"");

    SteerDispatchFn fn;
    SteerMode mode;
    {
        std::lock_guard<std::mutex> lock(mu_);
        fn = steerFn_;
        mode = steerMode_;
    }
    // Raw message + mode — template owns Plan/Build/Agent prompts (no cosmetic prefix).
    if (fn) fn(message, mode);

    r.ok = true;
    r.text = "";
    return r;
}

void CommandBroker::releaseSteerLease() {
    std::string resource;
    std::string query = "command_steer";
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (!steerLeaseResource_.empty())
            resource = steerLeaseResource_;
        if (!steerLeaseQuery_.empty())
            query = steerLeaseQuery_;
        steerLeaseHeld_ = false;
        steerLeaseResource_.clear();
    }
    if (resource.empty()) {
        const auto& snap = SessionBinder::instance().snapshot();
        resource = snap.workspaceRoot;
    }
    if (resource.empty()) return;
    auto& reg = RawrXD::Agents::SharedAgentWorkRegistry::instance();
    // Clear Read (current) and Edit (legacy) leases for command_steer.
    reg.complete(RawrXD::Agents::WorkKey{
        RawrXD::Agents::AgentWorkLease::Kind::Read, resource, query});
    reg.complete(RawrXD::Agents::WorkKey{
        RawrXD::Agents::AgentWorkLease::Kind::Edit, resource, query});
}

void CommandBroker::setAgentActive(bool v) {
    agentActive_ = v;
    if (!v) releaseSteerLease();
}

BrokerResult CommandBroker::stopAgent() {
    BrokerResult r;
    StopDispatchFn fn;
    {
        std::lock_guard<std::mutex> lock(mu_);
        fn = stopFn_;
    }
    if (fn) fn();
    agentActive_ = false;
    releaseSteerLease();
    setActivityStatus("Agent stopped");
    CommandEventJournal::instance().append(JournalEventType::AgentStopped, "\"user_stop\"");
    r.ok = true;
    r.text = "Agent stop requested.";
    return r;
}

BrokerResult CommandBroker::requestApproval(const std::string& action,
                                            const std::string& detail,
                                            Capability cap) {
    BrokerResult r;
    std::lock_guard<std::mutex> lock(mu_);
    PendingApproval p;
    p.id = "apr_" + std::to_string(nextApprovalId_++);
    p.action = action;
    p.detail = detail;
    p.requiredCap = cap;
    pending_.push_back(p);
    CommandEventJournal::instance().append(
        JournalEventType::ApprovalRequested,
        "\"" + p.id + ":" + action + "\"");
    r.needsApproval = true;
    r.approvalId = p.id;
    r.text = "Approval required: " + action + " — " + detail;
    setActivityStatus("Waiting for approval: " + action);
    return r;
}

bool CommandBroker::resolveApproval(const std::string& id, bool allow) {
    std::lock_guard<std::mutex> lock(mu_);
    for (auto it = pending_.begin(); it != pending_.end(); ++it) {
        if (it->id != id) continue;
        CommandEventJournal::instance().append(
            JournalEventType::ApprovalResolved,
            "\"" + id + (allow ? ":allow" : ":deny") + "\"");
        pending_.erase(it);
        setActivityStatus(allow ? "Approval granted" : "Approval denied");
        return true;
    }
    return false;
}

std::vector<PendingApproval> CommandBroker::pendingApprovals() const {
    std::lock_guard<std::mutex> lock(mu_);
    return pending_;
}

size_t CommandBroker::pendingApprovalCount() const {
    std::lock_guard<std::mutex> lock(mu_);
    return pending_.size();
}

}  // namespace RawrXD::Command
