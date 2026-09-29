// ============================================================================
// OSAdmission.hpp — Capability Admission Gate
// Before a capability can execute, it must pass admission:
//   1. Dependencies satisfied
//   2. Resources available
//   3. Policies allow
//   4. Authority authorizes
//   5. Health is good
// Fail-closed: if any check is uncertain, admission is DENIED.
// ============================================================================
#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include "OSCapability.hpp"
#include "OSPolicy.hpp"
#include "OSAuthority.hpp"
#include "OSEvidence.hpp"

namespace RawrXD::OS {

// ---------------------------------------------------------------------------
// Admission request
// ---------------------------------------------------------------------------
struct AdmissionRequest {
    std::string capabilityId;
    std::string callerSurface;       // CLI, GUI, Agent, Headless, etc.
    std::vector<std::string> requiredResources;
    uint64_t estimatedResourceUsage = 0;
    bool allowDegraded = false;
};

// ---------------------------------------------------------------------------
// Admission result
// ---------------------------------------------------------------------------
struct AdmissionResult {
    bool admitted = false;
    PolicyVerdict verdict = PolicyVerdict::Deny;
    std::string reason;
    std::string policyId;
    std::vector<std::string> unmetDependencies;
    std::vector<std::string> unavailableResources;
    std::vector<std::string> failedPolicies;
    uint64_t evidenceSeq = 0;       // Evidence record sequence
};

// ---------------------------------------------------------------------------
// Admission gate — evaluates all conditions for capability execution
// ---------------------------------------------------------------------------
class OSAdmission {
public:
    static OSAdmission& Instance();

    // Evaluate an admission request
    // Fail-closed: any uncertain check = DENY
    AdmissionResult evaluate(const AdmissionRequest& req,
                             const Capability& capability,
                             const std::vector<Capability>& allCapabilities);

    // Quick check: is this capability admissible right now?
    bool isAdmissible(const std::string& capabilityId);

    // Admission metrics
    uint64_t totalEvaluations() const { return totalEvals_.load(); }
    uint64_t admittedCount() const { return admitted_.load(); }
    uint64_t deniedCount() const { return denied_.load(); }

private:
    OSAdmission() = default;
    ~OSAdmission() = default;
    OSAdmission(const OSAdmission&) = delete;
    OSAdmission& operator=(const OSAdmission&) = delete;

    std::atomic<uint64_t> totalEvals_{0};
    std::atomic<uint64_t> admitted_{0};
    std::atomic<uint64_t> denied_{0};

    // Individual checks (all must pass for admission)
    bool checkDependencies(const Capability& cap,
                           const std::vector<Capability>& all,
                           std::vector<std::string>& unmet);
    bool checkHealth(const Capability& cap);
    bool checkPolicies(const AdmissionRequest& req,
                       const Capability& cap,
                       const std::vector<Policy>& policies,
                       PolicyDecision& decision);
    bool checkAuthority(const AdmissionRequest& req);
};

} // namespace RawrXD::OS