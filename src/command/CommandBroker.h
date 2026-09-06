#pragma once
#include "CapabilityProfile.h"
#include "SessionBinder.h"
#include <functional>
#include <mutex>
#include <string>
#include <vector>

namespace RawrXD::Command {

struct PendingApproval {
    std::string id;
    std::string action;
    std::string detail;
    Capability requiredCap = CapEdit;
};

struct BrokerResult {
    bool ok = false;
    std::string text;
    bool needsApproval = false;
    std::string approvalId;
};

enum class SteerMode { Plan = 0, Build = 1, Agent = 2 };

using SteerDispatchFn = std::function<void(const std::string& message, SteerMode mode)>;
using StopDispatchFn = std::function<void()>;

class CommandBroker {
public:
    static CommandBroker& instance();

    void setSteerHandler(SteerDispatchFn fn) { steerFn_ = std::move(fn); }
    void setStopHandler(StopDispatchFn fn) { stopFn_ = std::move(fn); }

    BrokerResult steer(const std::string& message);
    BrokerResult stopAgent();
    BrokerResult requestApproval(const std::string& action, const std::string& detail,
                                 Capability cap);
    bool resolveApproval(const std::string& id, bool allow);
    std::vector<PendingApproval> pendingApprovals() const;
    size_t pendingApprovalCount() const;

    void setActivityStatus(const std::string& s);
    std::string activityStatus() const;

    bool agentActive() const { return agentActive_; }
    void setAgentActive(bool v);
    void releaseSteerLease();

    void setSteerMode(SteerMode m) { steerMode_ = m; }
    SteerMode steerMode() const { return steerMode_; }
    static const char* steerModeLabel(SteerMode m);

    bool checkCap(Capability c) const;

private:
    mutable std::mutex mu_;
    SteerDispatchFn steerFn_;
    StopDispatchFn stopFn_;
    std::vector<PendingApproval> pending_;
    uint64_t nextApprovalId_ = 1;
    std::string activity_;
    bool agentActive_ = false;
    SteerMode steerMode_ = SteerMode::Agent;
    std::string steerLeaseResource_;
    std::string steerLeaseQuery_ = "command_steer";
    bool steerLeaseHeld_ = false;
};

}  // namespace RawrXD::Command
