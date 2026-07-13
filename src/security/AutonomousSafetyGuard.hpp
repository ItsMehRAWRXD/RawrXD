/**
 * AutonomousSafetyGuard.hpp
 *
 * Phase D.1 Batch 4/5: Security / Safety Envelope
 *
 * Required controls:
 *   - Mutation limits
 *   - Resource caps
 *   - Rollback requirements
 *   - Human approval gates
 *   - Emergency shutdown
 */

#pragma once

#include "../autonomy/DecisionTypes.hpp"
#include "../core/SovereignState.hpp"
#include "../seg/SEGMutationEngine.hpp"

#include <memory>
#include <vector>
#include <functional>

namespace Security {

/**
 * Safety violation types
 */
enum class SafetyViolation {
    MUTATION_LIMIT_EXCEEDED,
    RESOURCE_CAP_EXCEEDED,
    ROLLBACK_NOT_AVAILABLE,
    APPROVAL_REQUIRED,
    UNSAFE_MODE_TRANSITION,
    CRITICAL_SUBSYSTEM_MODIFICATION,
    EMERGENCY_STOP_TRIGGERED,
    NONE
};

std::string SafetyViolationToString(SafetyViolation violation);

/**
 * Safety policy
 */
struct SafetyPolicy {
    // Mutation limits
    int maxMutationsPerCycle{3};
    int maxConcurrentMutations{5};
    double maxMutationRisk{0.8};
    
    // Resource caps
    double maxCpuUtilization{0.95};
    double maxMemoryUtilization{0.90};
    int maxActiveWorkers{100};
    
    // Approval requirements
    bool requireApprovalForCritical{true};
    bool requireApprovalForSelfOptimizing{true};
    bool requireApprovalForTermination{true};
    
    // Rollback requirements
    bool requireRollbackForMutations{true};
    int maxRollbackDepth{10};
    
    // Emergency thresholds
    double emergencyStabilityThreshold{0.2};
    int emergencyFaultThreshold{5};
    
    std::string ToJson() const;
};

/**
 * Safety check result
 */
struct SafetyCheckResult {
    bool allowed{true};
    SafetyViolation violation{SafetyViolation::NONE};
    std::string reason;
    std::string requiredAction;
    
    std::string ToJson() const;
    static SafetyCheckResult Allow();
    static SafetyCheckResult Deny(SafetyViolation violation, const std::string& reason);
};

/**
 * Approval request
 */
struct ApprovalRequest {
    std::string requestId;
    std::string decisionId;
    std::string description;
    std::string riskAssessment;
    int64_t timestampMs{0};
    int timeoutMs{30000};
    
    std::string ToJson() const;
};

/**
 * Autonomous Safety Guard
 *
 * Enforces safety constraints on autonomous decisions and mutations.
 */
class AutonomousSafetyGuard {
public:
    AutonomousSafetyGuard();
    ~AutonomousSafetyGuard();

    // Disable copy
    AutonomousSafetyGuard(const AutonomousSafetyGuard&) = delete;
    AutonomousSafetyGuard& operator=(const AutonomousSafetyGuard&) = delete;

    /**
     * Initialize safety guard
     */
    bool Initialize(const SafetyPolicy& policy);

    /**
     * Shutdown
     */
    void Shutdown();

    /**
     * Check if decision is safe to execute
     */
    SafetyCheckResult CheckDecision(const Autonomy::Decision& decision,
                                    const Core::SovereignState& state);

    /**
     * Check if mutation is safe to apply
     */
    SafetyCheckResult CheckMutation(const Autonomy::SEGMutation& mutation,
                                    const Core::SovereignState& state);

    /**
     * Check if mode transition is safe
     */
    SafetyCheckResult CheckModeTransition(Core::ExecutionMode from,
                                          Core::ExecutionMode to,
                                          const Core::SovereignState& state);

    /**
     * Request human approval
     */
    std::string RequestApproval(const ApprovalRequest& request);

    /**
     * Grant approval
     */
    bool GrantApproval(const std::string& requestId);

    /**
     * Deny approval
     */
    bool DenyApproval(const std::string& requestId, const std::string& reason);

    /**
     * Check if approval is pending
     */
    bool IsApprovalPending(const std::string& requestId) const;

    /**
     * Trigger emergency stop
     */
    void TriggerEmergencyStop(const std::string& reason);

    /**
     * Clear emergency stop
     */
    void ClearEmergencyStop();

    /**
     * Check if emergency stop is active
     */
    bool IsEmergencyStopActive() const;

    /**
     * Get active constraints
     */
    std::vector<std::string> GetActiveConstraints() const;

    /**
     * Update policy
     */
    void UpdatePolicy(const SafetyPolicy& policy);

    /**
     * Get current policy
     */
    SafetyPolicy GetPolicy() const;

    /**
     * Print status
     */
    void PrintStatus() const;

private:
    SafetyPolicy policy_;
    bool initialized_{false};
    std::atomic<bool> emergencyStopActive_{false};
    
    // Tracking
    int mutationsThisCycle_{0};
    int concurrentMutations_{0};
    std::vector<std::string> pendingApprovals_;
    std::vector<std::string> grantedApprovals_;
    
    // Threading
    mutable std::mutex mutex_;
    
    // Check methods
    SafetyCheckResult CheckMutationLimits(const Autonomy::Decision& decision);
    SafetyCheckResult CheckResourceCaps(const Core::SovereignState& state);
    SafetyCheckResult CheckRollbackAvailability(const Autonomy::SEGMutation& mutation);
    SafetyCheckResult CheckApprovalRequirements(const Autonomy::Decision& decision);
    
    // Helpers
    std::string GenerateRequestId() const;
    void ResetCycleCounters();
};

/**
 * Safety envelope validator
 */
class SafetyEnvelopeValidator {
public:
    /**
     * Validate decision against all safety constraints
     */
    static SafetyCheckResult Validate(const Autonomy::Decision& decision,
                                       const SafetyPolicy& policy,
                                       const Core::SovereignState& state);
    
    /**
     * Validate mutation against all safety constraints
     */
    static SafetyCheckResult Validate(const Autonomy::SEGMutation& mutation,
                                       const SafetyPolicy& policy,
                                       const Core::SovereignState& state);
};

} // namespace Security
