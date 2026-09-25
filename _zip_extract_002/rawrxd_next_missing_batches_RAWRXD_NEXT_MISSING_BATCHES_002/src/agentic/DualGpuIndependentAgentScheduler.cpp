#include "DualGpuIndependentAgentScheduler.hpp"

#include <sstream>

namespace RawrXD::Agentic {

bool DualGpuSchedulerReceipt::pass(bool secondaryRequired) const noexcept {
    const bool secondaryOk = secondaryRequired ? secondaryBound : (secondaryBound || secondaryUnavailableHandled);
    const bool distinctOk = secondaryBound ? distinctDevices : !secondaryRequired;
    const bool contextOk = secondaryBound ? independentContexts : !secondaryRequired;
    return primaryBound && secondaryOk && distinctOk && contextOk && sharedToolAuthority && failures == 0;
}

std::string DualGpuSchedulerReceipt::text(bool secondaryRequired) const {
    std::ostringstream o;
    o << "=== RAWRXD_DUAL_GPU_INDEPENDENT_AGENT_001 ===\n";
    o << "PRIMARY_BOUND=" << (primaryBound ? "PASS" : "FAIL") << "\n";
    o << "SECONDARY_BOUND=" << (secondaryBound ? "PASS" : "FAIL") << "\n";
    o << "INDEPENDENT_CONTEXTS=" << (independentContexts ? "PASS" : "FAIL") << "\n";
    o << "DISTINCT_DEVICES=" << (distinctDevices ? "PASS" : "FAIL") << "\n";
    o << "SHARED_TOOL_AUTHORITY=" << (sharedToolAuthority ? "PASS" : "FAIL") << "\n";
    o << "SECONDARY_UNAVAILABLE_HANDLED=" << (secondaryBound ? "NOT_NEEDED" : (secondaryUnavailableHandled ? "PASS" : "FAIL")) << "\n";
    o << "MESSAGES_EXCHANGED=" << messagesExchanged << "\n";
    o << "PRIMARY_RUNS=" << primaryRuns << "\n";
    o << "SECONDARY_RUNS=" << secondaryRuns << "\n";
    o << "FAILURES=" << failures << "\n";
    o << "VERDICT=" << (pass(secondaryRequired) ? "PASS" : "FAIL") << "\n";
    return o.str();
}

DualGpuIndependentAgentScheduler::DualGpuIndependentAgentScheduler(
    DualGpuSchedulerConfig config,
    AgentContextCallbacks callbacks)
    : config_(std::move(config)), callbacks_(callbacks) {
    receipt_.sharedToolAuthority = config_.sharedToolAuthority != nullptr;
}

DualGpuIndependentAgentScheduler::~DualGpuIndependentAgentScheduler() {
    destroyBinding(secondary_);
    destroyBinding(primary_);
}

void DualGpuIndependentAgentScheduler::destroyBinding(std::optional<AgentBinding>& binding) noexcept {
    if (!binding) return;
    if (binding->context && callbacks_.destroy) callbacks_.destroy(callbacks_.user, binding->context);
    binding.reset();
}

std::optional<AgentDevice> DualGpuIndependentAgentScheduler::select(
    const std::vector<AgentDevice>& devices,
    std::uint32_t ordinal) const {
    for (const auto& d : devices) {
        if (d.available && d.ordinal == ordinal) return d;
    }
    return std::nullopt;
}

bool DualGpuIndependentAgentScheduler::bind(
    const std::vector<AgentDevice>& devices,
    std::string primaryModel,
    std::string secondaryModel,
    std::string* why) {

    destroyBinding(secondary_);
    destroyBinding(primary_);
    receipt_ = {};
    receipt_.sharedToolAuthority = config_.sharedToolAuthority != nullptr;

    if (!callbacks_.create || !callbacks_.run) {
        ++receipt_.failures;
        if (why) *why = "agent context callbacks incomplete";
        return false;
    }
    if (!receipt_.sharedToolAuthority) {
        ++receipt_.failures;
        if (why) *why = "canonical shared Tool Authority is required";
        return false;
    }

    const auto primaryDevice = select(devices, config_.preferredPrimaryOrdinal);
    if (!primaryDevice) {
        ++receipt_.failures;
        if (why) *why = "primary GPU unavailable";
        return false;
    }

    void* primaryContext = callbacks_.create(callbacks_.user, *primaryDevice, primaryModel);
    if (!primaryContext) {
        ++receipt_.failures;
        if (why) *why = "primary context creation failed";
        return false;
    }

    primary_ = AgentBinding{1, AgentRole::PrimaryCoder, std::move(primaryModel), *primaryDevice, primaryContext};
    receipt_.primaryBound = true;

    const auto secondaryDevice = select(devices, config_.preferredSecondaryOrdinal);
    if (!secondaryDevice) {
        receipt_.secondaryUnavailableHandled = true;
        if (config_.requireSecondary) {
            ++receipt_.failures;
            if (why) *why = "secondary GPU unavailable";
            return false;
        }
        if (why) why->clear();
        return true;
    }

    if (config_.requireDistinctDevices && secondaryDevice->ordinal == primaryDevice->ordinal) {
        ++receipt_.failures;
        if (why) *why = "primary and secondary resolved to same GPU";
        return false;
    }

    void* secondaryContext = callbacks_.create(callbacks_.user, *secondaryDevice, secondaryModel);
    if (!secondaryContext) {
        ++receipt_.failures;
        if (why) *why = "secondary context creation failed";
        return false;
    }

    secondary_ = AgentBinding{2, AgentRole::SecondaryReviewer, std::move(secondaryModel), *secondaryDevice, secondaryContext};
    receipt_.secondaryBound = true;
    receipt_.distinctDevices = primary_->device.ordinal != secondary_->device.ordinal;
    receipt_.independentContexts = primary_->context != secondary_->context;

    if (!receipt_.independentContexts || (config_.requireDistinctDevices && !receipt_.distinctDevices)) {
        ++receipt_.failures;
        if (why) *why = "agent contexts/devices are not independent";
        return false;
    }

    if (why) why->clear();
    return true;
}

AgentRunResult DualGpuIndependentAgentScheduler::runPrimary(std::string_view prompt) {
    if (!primary_) {
        ++receipt_.failures;
        return {false, {}, "primary agent is not bound"};
    }
    auto r = callbacks_.run(callbacks_.user, primary_->context, prompt);
    ++receipt_.primaryRuns;
    if (!r.ok) ++receipt_.failures;
    return r;
}

AgentRunResult DualGpuIndependentAgentScheduler::runSecondary(std::string_view prompt) {
    if (!secondary_) {
        ++receipt_.failures;
        return {false, {}, "secondary agent is not bound"};
    }
    auto r = callbacks_.run(callbacks_.user, secondary_->context, prompt);
    ++receipt_.secondaryRuns;
    if (!r.ok) ++receipt_.failures;
    return r;
}

bool DualGpuIndependentAgentScheduler::send(AgentMessage message) {
    const bool fromValid = primary_ && message.fromAgent == primary_->agentId || secondary_ && message.fromAgent == secondary_->agentId;
    const bool toValid = primary_ && message.toAgent == primary_->agentId || secondary_ && message.toAgent == secondary_->agentId;
    if (!fromValid || !toValid || message.fromAgent == message.toAgent) {
        ++receipt_.failures;
        return false;
    }
    messages_.push_back(std::move(message));
    ++receipt_.messagesExchanged;
    return true;
}

std::optional<AgentMessage> DualGpuIndependentAgentScheduler::receive(std::uint64_t agentId) {
    for (auto it = messages_.begin(); it != messages_.end(); ++it) {
        if (it->toAgent == agentId) {
            AgentMessage out = std::move(*it);
            messages_.erase(it);
            return out;
        }
    }
    return std::nullopt;
}

} // namespace RawrXD::Agentic
