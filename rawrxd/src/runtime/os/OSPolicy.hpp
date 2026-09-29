// ============================================================================
// OSPolicy.hpp — Admission and Execution Policies
// The registry applies policies to decide whether a capability can execute,
// what resources it can claim, and under what conditions it is admitted.
// ============================================================================
#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <atomic>

namespace RawrXD::OS {

// ---------------------------------------------------------------------------
// Policy verdict
// ---------------------------------------------------------------------------
enum class PolicyVerdict : uint8_t {
    Allow       = 0,
    Deny        = 1,
    Degrade     = 2,   // Allow with reduced resources
    Defer       = 3,   // Allow later, queue for now
    Require     = 4,   // Allow if conditions are met
};

// ---------------------------------------------------------------------------
// Policy — a rule that governs capability admission or resource allocation
// ---------------------------------------------------------------------------
struct Policy {
    std::string id;
    std::string name;
    std::string description;

    // What this policy applies to
    std::vector<std::string> capabilityPatterns;   // Glob patterns for capability IDs
    std::vector<std::string> resourcePatterns;     // Glob patterns for resource IDs

    // Conditions
    uint64_t maxResourceUsage = 0;        // Cap resource usage (0 = unlimited)
    uint64_t maxConcurrentExecutions = 0; // Limit parallel executions (0 = unlimited)
    bool requireHealthy = true;           // Capability must be healthy
    bool requireVerified = false;         // Capability must have PASS evidence
    bool requireDependenciesMet = true;   // All dependencies must be Admitted
    bool allowDegraded = false;           // Allow degraded capabilities
    bool allowSuspended = false;          // Allow resuming suspended capabilities
    bool failClosed = true;               // On uncertain, deny (fail-closed)

    // Priority — higher priority policies override lower
    int32_t priority = 0;

    // Enforcement counters (fail-closed telemetry)
    std::atomic<uint64_t> allowCount{0};
    std::atomic<uint64_t> denyCount{0};
    std::atomic<uint64_t> degradeCount{0};
    std::atomic<uint64_t> deferCount{0};

    // Does this policy match a capability?
    bool matchesCapability(const std::string& capId) const {
        if (capabilityPatterns.empty()) return true;  // Empty = match all
        for (const auto& pat : capabilityPatterns) {
            if (matchGlob(capId, pat)) return true;
        }
        return false;
    }

    // Simple glob matcher (* = any, ? = single char)
    static bool matchGlob(const std::string& str, const std::string& pattern) {
        if (pattern == "*") return true;
        if (pattern.empty()) return str.empty();
        // Simple prefix/suffix match for common cases
        if (pattern.front() == '*' && pattern.back() == '*') {
            std::string mid = pattern.substr(1, pattern.size() - 2);
            return str.find(mid) != std::string::npos;
        }
        if (pattern.front() == '*') {
            std::string suffix = pattern.substr(1);
            return str.size() >= suffix.size() &&
                   str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
        }
        if (pattern.back() == '*') {
            std::string prefix = pattern.substr(0, pattern.size() - 1);
            return str.size() >= prefix.size() &&
                   str.compare(0, prefix.size(), prefix) == 0;
        }
        return str == pattern;
    }
};

// ---------------------------------------------------------------------------
// Policy decision — the result of evaluating policies for a capability
// ---------------------------------------------------------------------------
struct PolicyDecision {
    PolicyVerdict verdict = PolicyVerdict::Deny;
    std::string reason;
    std::string policyId;           // Which policy made the decision
    std::vector<std::string> conditions;  // Conditions that must be met
    uint64_t evaluatedAtNs = 0;
};

} // namespace RawrXD::OS