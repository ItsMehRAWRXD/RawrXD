/**
 * SafetyProfile.hpp
 *
 * Phase C.4 Batch 4/5: Safety-Gated Decision Engine
 *
 * Defines safety constraints and profiles for subsystems.
 * Each subsystem has a safety profile that governs allowed actions,
 * risk thresholds, and resource budgets.
 */

#pragma once

#include "DecisionTypes.hpp"
#include "../core/SovereignState.hpp"

#include <cstring>
#include <vector>
#include <map>
#include <set>
#include <memory>

namespace Autonomy {

/**
 * Action classification
 */
enum class ActionSafety {
    ALLOWED,      // Action is permitted
    RESTRICTED,   // Action requires additional validation
    FORBIDDEN,    // Action is prohibited
    CONDITIONAL   // Action allowed only under specific conditions
};

std::string ActionSafetyToString(ActionSafety safety);

/**
 * Resource budget
 */
struct ResourceBudget {
    double maxCpuPercent{80.0};
    double maxMemoryPercent{80.0};
    double maxGpuPercent{90.0};
    int maxConcurrentTasks{100};
    int maxQueueDepth{1000};
    
    bool IsWithinBudget(const Core::SovereignState& state) const;
    std::string ToJson() const;
};

/**
 * Cooldown configuration
 */
struct CooldownConfig {
    int minDecisionIntervalMs{100};       // Minimum time between decisions
    int minMutationIntervalMs{500};       // Minimum time between mutations
    int minRoleChangeIntervalMs{1000};    // Minimum time between role changes
    int minIntentUpdateIntervalMs{200};   // Minimum time between intent updates
    
    std::string ToJson() const;
};

/**
 * Risk thresholds
 */
struct RiskThresholds {
    double safeThreshold{0.2};        // 0.0-0.2: Safe
    double cautionThreshold{0.5};   // 0.2-0.5: Caution
    double unsafeThreshold{0.8};     // 0.5-0.8: Unsafe
    // 0.8-1.0: Critical
    
    ActionSafety ClassifyRisk(double risk) const;
    std::string ToJson() const;
};

/**
 * Safety profile for a subsystem
 */
struct SafetyProfile {
    std::string subsystemName;
    std::string version;
    
    // Allowed/forbidden actions
    std::set<std::string> allowedActions;
    std::set<std::string> forbiddenActions;
    std::set<std::string> restrictedActions;
    
    // Resource budget
    ResourceBudget resourceBudget;
    
    // Cooldowns
    CooldownConfig cooldowns;
    
    // Risk thresholds
    RiskThresholds riskThresholds;
    
    // Mutation constraints
    int maxMutationsPerMinute{10};
    int maxRollbackRetries{3};
    bool requireRollbackPlan{true};
    
    // Decision constraints
    int maxDecisionsPerSecond{10};
    double minDecisionConfidence{0.5};
    bool requireHistoricalValidation{true};
    
    // Intent constraints
    int maxActiveIntents{50};
    int maxConflictingIntents{3};
    
    // Oscillation prevention
    bool enableOscillationPrevention{true};
    double maxOscillationSeverity{0.7};
    
    // Stability requirements
    double minStabilityForMutation{0.6};
    double minConvergenceForMutation{0.7};
    
    std::string ToJson() const;
    void Print() const;
    
    // Check if action is allowed
    ActionSafety CheckAction(const std::string& action) const;
    
    // Validate resource usage
    bool ValidateResources(const Core::SovereignState& state) const;
};

/**
 * Safety profile registry
 */
class SafetyProfileRegistry {
public:
    SafetyProfileRegistry();
    ~SafetyProfileRegistry();

    // Disable copy
    SafetyProfileRegistry(const SafetyProfileRegistry&) = delete;
    SafetyProfileRegistry& operator=(const SafetyProfileRegistry&) = delete;

    /**
     * Initialize registry with default profiles
     */
    bool Initialize();

    /**
     * Register a safety profile
     */
    bool RegisterProfile(const SafetyProfile& profile);

    /**
     * Get profile for subsystem
     */
    std::optional<SafetyProfile> GetProfile(const std::string& subsystem) const;

    /**
     * Update existing profile
     */
    bool UpdateProfile(const SafetyProfile& profile);

    /**
     * Remove profile
     */
    bool RemoveProfile(const std::string& subsystem);

    /**
     * List all registered profiles
     */
    std::vector<std::string> ListProfiles() const;

    /**
     * Create default profile for subsystem
     */
    SafetyProfile CreateDefaultProfile(const std::string& subsystem);

    /**
     * Print status
     */
    void PrintStatus() const;

private:
    std::map<std::string, SafetyProfile> profiles_;
    mutable std::mutex profilesMutex_;
    bool initialized_{false};
};

/**
 * Safety constraint violation
 */
struct SafetyViolation {
    std::string violationId;
    std::string subsystem;
    std::string action;
    std::string constraint;
    std::string description;
    double severity{0.0};  // 0.0-1.0
    int64_t timestampMs{0};
    
    std::string ToJson() const;
    void Print() const;
};

/**
 * Safety constraint checker
 */
class SafetyConstraintChecker {
public:
    SafetyConstraintChecker();
    ~SafetyConstraintChecker();

    /**
     * Initialize checker
     */
    bool Initialize(SafetyProfileRegistry* registry);

    /**
     * Check action against safety profile
     */
    bool CheckAction(const std::string& subsystem,
                    const std::string& action,
                    std::vector<SafetyViolation>& violations);

    /**
     * Check resource constraints
     */
    bool CheckResources(const std::string& subsystem,
                       const Core::SovereignState& state,
                       std::vector<SafetyViolation>& violations);

    /**
     * Check cooldown constraints
     */
    bool CheckCooldown(const std::string& subsystem,
                      const std::string& actionType,
                      int64_t lastActionTimeMs,
                      std::vector<SafetyViolation>& violations);

    /**
     * Get recent violations
     */
    std::vector<SafetyViolation> GetRecentViolations(int limit = 10) const;

    /**
     * Clear violations
     */
    void ClearViolations();

    /**
     * Print status
     */
    void PrintStatus() const;

private:
    SafetyProfileRegistry* registry_{nullptr};
    std::vector<SafetyViolation> violations_;
    mutable std::mutex violationsMutex_;
    int violationCounter_{0};
    
    int64_t GetCurrentTimeMs() const;
    std::string GenerateViolationId();
};

} // namespace Autonomy
