/**
 * SafetyProfile.cpp
 *
 * Phase C.4 Batch 4/5: Safety-Gated Decision Engine
 */

#include "SafetyProfile.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>

namespace Autonomy {

// ============================================================================
// ActionSafety Conversions
// ============================================================================

std::string ActionSafetyToString(ActionSafety safety) {
    switch (safety) {
        case ActionSafety::ALLOWED: return "ALLOWED";
        case ActionSafety::RESTRICTED: return "RESTRICTED";
        case ActionSafety::FORBIDDEN: return "FORBIDDEN";
        case ActionSafety::CONDITIONAL: return "CONDITIONAL";
        default: return "UNKNOWN";
    }
}

// ============================================================================
// ResourceBudget Implementation
// ============================================================================

bool ResourceBudget::IsWithinBudget(const Core::SovereignState& state) const {
    return state.runtime.cpuUtilization <= maxCpuPercent &&
           state.runtime.memoryUsageMB <= (maxMemoryPercent / 100.0) * 1024 * 16 &&  // Assuming 16GB
           state.swarm.activeWorkers <= maxConcurrentTasks;
}

std::string ResourceBudget::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"maxCpuPercent\":" << maxCpuPercent << ",";
    json << "\"maxMemoryPercent\":" << maxMemoryPercent << ",";
    json << "\"maxGpuPercent\":" << maxGpuPercent << ",";
    json << "\"maxConcurrentTasks\":" << maxConcurrentTasks << ",";
    json << "\"maxQueueDepth\":" << maxQueueDepth;
    json << "}";
    return json.str();
}

// ============================================================================
// CooldownConfig Implementation
// ============================================================================

std::string CooldownConfig::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"minDecisionIntervalMs\":" << minDecisionIntervalMs << ",";
    json << "\"minMutationIntervalMs\":" << minMutationIntervalMs << ",";
    json << "\"minRoleChangeIntervalMs\":" << minRoleChangeIntervalMs << ",";
    json << "\"minIntentUpdateIntervalMs\":" << minIntentUpdateIntervalMs;
    json << "}";
    return json.str();
}

// ============================================================================
// RiskThresholds Implementation
// ============================================================================

ActionSafety RiskThresholds::ClassifyRisk(double risk) const {
    if (risk < safeThreshold) {
        return ActionSafety::ALLOWED;
    } else if (risk < cautionThreshold) {
        return ActionSafety::RESTRICTED;
    } else if (risk < unsafeThreshold) {
        return ActionSafety::CONDITIONAL;
    } else {
        return ActionSafety::FORBIDDEN;
    }
}

std::string RiskThresholds::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"safeThreshold\":" << safeThreshold << ",";
    json << "\"cautionThreshold\":" << cautionThreshold << ",";
    json << "\"unsafeThreshold\":" << unsafeThreshold;
    json << "}";
    return json.str();
}

// ============================================================================
// SafetyProfile Implementation
// ============================================================================

std::string SafetyProfile::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"subsystemName\":\"" << subsystemName << "\",";
    json << "\"version\":\"" << version << "\",";
    json << "\"resourceBudget\":" << resourceBudget.ToJson() << ",";
    json << "\"cooldowns\":" << cooldowns.ToJson() << ",";
    json << "\"riskThresholds\":" << riskThresholds.ToJson() << ",";
    json << "\"maxMutationsPerMinute\":" << maxMutationsPerMinute << ",";
    json << "\"maxDecisionsPerSecond\":" << maxDecisionsPerSecond << ",";
    json << "\"minDecisionConfidence\":" << minDecisionConfidence << ",";
    json << "\"minStabilityForMutation\":" << minStabilityForMutation << ",";
    json << "\"minConvergenceForMutation\":" << minConvergenceForMutation;
    json << "}";
    return json.str();
}

void SafetyProfile::Print() const {
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║  SAFETY PROFILE                                                  ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Subsystem: " << std::left << std::setw(47) << subsystemName << " ║\n";
    std::cout << "║  Version:   " << std::setw(47) << version << " ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Resource Budget                                                   ║\n";
    std::cout << "║    CPU:    " << std::setw(48) << resourceBudget.maxCpuPercent << "% ║\n";
    std::cout << "║    Memory: " << std::setw(48) << resourceBudget.maxMemoryPercent << "% ║\n";
    std::cout << "║    Tasks:  " << std::setw(48) << resourceBudget.maxConcurrentTasks << " ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Constraints                                                       ║\n";
    std::cout << "║    Max Mutations/Min: " << std::setw(36) << maxMutationsPerMinute << " ║\n";
    std::cout << "║    Max Decisions/Sec: " << std::setw(36) << maxDecisionsPerSecond << " ║\n";
    std::cout << "║    Min Confidence:    " << std::setw(36) << minDecisionConfidence << " ║\n";
    std::cout << "║    Min Stability:     " << std::setw(36) << minStabilityForMutation << " ║\n";
    std::cout << "║    Min Convergence:   " << std::setw(36) << minConvergenceForMutation << " ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
}

ActionSafety SafetyProfile::CheckAction(const std::string& action) const {
    if (forbiddenActions.count(action) > 0) {
        return ActionSafety::FORBIDDEN;
    }
    if (restrictedActions.count(action) > 0) {
        return ActionSafety::RESTRICTED;
    }
    if (allowedActions.empty() || allowedActions.count(action) > 0) {
        return ActionSafety::ALLOWED;
    }
    return ActionSafety::FORBIDDEN;
}

bool SafetyProfile::ValidateResources(const Core::SovereignState& state) const {
    return resourceBudget.IsWithinBudget(state);
}

// ============================================================================
// SafetyProfileRegistry Implementation
// ============================================================================

SafetyProfileRegistry::SafetyProfileRegistry() = default;
SafetyProfileRegistry::~SafetyProfileRegistry() = default;

bool SafetyProfileRegistry::Initialize() {
    // Register default profiles for major subsystems
    RegisterProfile(CreateDefaultProfile("engine"));
    RegisterProfile(CreateDefaultProfile("swarm"));
    RegisterProfile(CreateDefaultProfile("seg"));
    RegisterProfile(CreateDefaultProfile("mutation"));
    RegisterProfile(CreateDefaultProfile("decision"));
    RegisterProfile(CreateDefaultProfile("intent"));
    
    initialized_ = true;
    std::cout << "[SafetyProfileRegistry] Initialized with " << profiles_.size() << " profiles\n";
    return true;
}

bool SafetyProfileRegistry::RegisterProfile(const SafetyProfile& profile) {
    std::lock_guard<std::mutex> lock(profilesMutex_);
    
    profiles_[profile.subsystemName] = profile;
    std::cout << "[SafetyProfileRegistry] Registered profile for " << profile.subsystemName << "\n";
    return true;
}

std::optional<SafetyProfile> SafetyProfileRegistry::GetProfile(const std::string& subsystem) const {
    std::lock_guard<std::mutex> lock(profilesMutex_);
    
    auto it = profiles_.find(subsystem);
    if (it != profiles_.end()) {
        return it->second;
    }
    
    return std::nullopt;
}

bool SafetyProfileRegistry::UpdateProfile(const SafetyProfile& profile) {
    return RegisterProfile(profile);
}

bool SafetyProfileRegistry::RemoveProfile(const std::string& subsystem) {
    std::lock_guard<std::mutex> lock(profilesMutex_);
    
    auto it = profiles_.find(subsystem);
    if (it == profiles_.end()) {
        return false;
    }
    
    profiles_.erase(it);
    return true;
}

std::vector<std::string> SafetyProfileRegistry::ListProfiles() const {
    std::lock_guard<std::mutex> lock(profilesMutex_);
    
    std::vector<std::string> names;
    for (const auto& [name, _] : profiles_) {
        names.push_back(name);
    }
    return names;
}

SafetyProfile SafetyProfileRegistry::CreateDefaultProfile(const std::string& subsystem) {
    SafetyProfile profile;
    profile.subsystemName = subsystem;
    profile.version = "1.0.0";
    
    // Default resource budget
    profile.resourceBudget.maxCpuPercent = 80.0;
    profile.resourceBudget.maxMemoryPercent = 80.0;
    profile.resourceBudget.maxGpuPercent = 90.0;
    profile.resourceBudget.maxConcurrentTasks = 100;
    profile.resourceBudget.maxQueueDepth = 1000;
    
    // Default cooldowns
    profile.cooldowns.minDecisionIntervalMs = 100;
    profile.cooldowns.minMutationIntervalMs = 500;
    profile.cooldowns.minRoleChangeIntervalMs = 1000;
    profile.cooldowns.minIntentUpdateIntervalMs = 200;
    
    // Default risk thresholds
    profile.riskThresholds.safeThreshold = 0.2;
    profile.riskThresholds.cautionThreshold = 0.5;
    profile.riskThresholds.unsafeThreshold = 0.8;
    
    // Subsystem-specific settings
    if (subsystem == "engine") {
        profile.maxDecisionsPerSecond = 20;
        profile.minDecisionConfidence = 0.6;
        profile.allowedActions = {"optimize", "reconfigure", "scale"};
    } else if (subsystem == "swarm") {
        profile.maxConcurrentTasks = 200;
        profile.cooldowns.minRoleChangeIntervalMs = 500;
        profile.allowedActions = {"assign_task", "rebalance", "scale_workers"};
    } else if (subsystem == "seg") {
        profile.maxMutationsPerMinute = 5;
        profile.minStabilityForMutation = 0.7;
        profile.minConvergenceForMutation = 0.8;
        profile.requireRollbackPlan = true;
        profile.allowedActions = {"mutate_graph", "optimize_path", "merge_nodes"};
    } else if (subsystem == "mutation") {
        profile.maxMutationsPerMinute = 3;
        profile.cooldowns.minMutationIntervalMs = 1000;
        profile.minStabilityForMutation = 0.8;
        profile.requireRollbackPlan = true;
        profile.forbiddenActions = {"destructive_mutation", "irreversible_change"};
    } else if (subsystem == "decision") {
        profile.maxDecisionsPerSecond = 10;
        profile.minDecisionConfidence = 0.7;
        profile.requireHistoricalValidation = true;
        profile.allowedActions = {"approve", "reject", "defer", "escalate"};
    } else if (subsystem == "intent") {
        profile.maxActiveIntents = 50;
        profile.maxConflictingIntents = 2;
        profile.allowedActions = {"create_intent", "modify_intent", "prioritize_intent"};
    }
    
    return profile;
}

void SafetyProfileRegistry::PrintStatus() const {
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║  SAFETY PROFILE REGISTRY                                         ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Registered Profiles: " << std::setw(37) << profiles_.size() << " ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    for (const auto& [name, profile] : profiles_) {
        std::cout << "║  " << std::left << std::setw(20) << name 
                  << " v" << profile.version << std::string(35, ' ') << " ║\n";
    }
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
}

// ============================================================================
// SafetyViolation Implementation
// ============================================================================

std::string SafetyViolation::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"violationId\":\"" << violationId << "\",";
    json << "\"subsystem\":\"" << subsystem << "\",";
    json << "\"action\":\"" << action << "\",";
    json << "\"constraint\":\"" << constraint << "\",";
    json << "\"description\":\"" << description << "\",";
    json << "\"severity\":" << severity << ",";
    json << "\"timestampMs\":" << timestampMs;
    json << "}";
    return json.str();
}

void SafetyViolation::Print() const {
    const char* color = "\033[0m";
    if (severity >= 0.8) color = "\033[31m";      // Critical - red
    else if (severity >= 0.5) color = "\033[33m"; // Warning - yellow
    else if (severity >= 0.2) color = "\033[35m"; // Caution - magenta
    
    std::cout << color;
    std::cout << "[" << subsystem << "] " << action << ": " << description << "\n";
    std::cout << "  Severity: " << std::fixed << std::setprecision(2) << severity << "\n";
    std::cout << "\033[0m";
}

// ============================================================================
// SafetyConstraintChecker Implementation
// ============================================================================

SafetyConstraintChecker::SafetyConstraintChecker() = default;
SafetyConstraintChecker::~SafetyConstraintChecker() = default;

bool SafetyConstraintChecker::Initialize(SafetyProfileRegistry* registry) {
    registry_ = registry;
    return true;
}

bool SafetyConstraintChecker::CheckAction(const std::string& subsystem,
                                          const std::string& action,
                                          std::vector<SafetyViolation>& violations) {
    if (!registry_) return false;
    
    auto profileOpt = registry_->GetProfile(subsystem);
    if (!profileOpt.has_value()) {
        SafetyViolation violation;
        violation.violationId = GenerateViolationId();
        violation.subsystem = subsystem;
        violation.action = action;
        violation.constraint = "profile_exists";
        violation.description = "No safety profile found for subsystem";
        violation.severity = 0.5;
        violation.timestampMs = GetCurrentTimeMs();
        violations.push_back(violation);
        return false;
    }
    
    auto profile = profileOpt.value();
    auto safety = profile.CheckAction(action);
    
    if (safety == ActionSafety::FORBIDDEN) {
        SafetyViolation violation;
        violation.violationId = GenerateViolationId();
        violation.subsystem = subsystem;
        violation.action = action;
        violation.constraint = "action_allowed";
        violation.description = "Action is forbidden by safety profile";
        violation.severity = 1.0;
        violation.timestampMs = GetCurrentTimeMs();
        violations.push_back(violation);
        return false;
    }
    
    if (safety == ActionSafety::RESTRICTED) {
        SafetyViolation violation;
        violation.violationId = GenerateViolationId();
        violation.subsystem = subsystem;
        violation.action = action;
        violation.constraint = "action_restricted";
        violation.description = "Action requires additional validation";
        violation.severity = 0.5;
        violation.timestampMs = GetCurrentTimeMs();
        violations.push_back(violation);
        // Still allowed but flagged
    }
    
    return safety == ActionSafety::ALLOWED || safety == ActionSafety::RESTRICTED;
}

bool SafetyConstraintChecker::CheckResources(const std::string& subsystem,
                                            const Core::SovereignState& state,
                                            std::vector<SafetyViolation>& violations) {
    if (!registry_) return false;
    
    auto profileOpt = registry_->GetProfile(subsystem);
    if (!profileOpt.has_value()) return false;
    
    auto profile = profileOpt.value();
    
    if (!profile.ValidateResources(state)) {
        SafetyViolation violation;
        violation.violationId = GenerateViolationId();
        violation.subsystem = subsystem;
        violation.action = "resource_check";
        violation.constraint = "resource_budget";
        violation.description = "Resource usage exceeds safety budget";
        violation.severity = 0.7;
        violation.timestampMs = GetCurrentTimeMs();
        violations.push_back(violation);
        return false;
    }
    
    return true;
}

bool SafetyConstraintChecker::CheckCooldown(const std::string& subsystem,
                                         const std::string& actionType,
                                         int64_t lastActionTimeMs,
                                         std::vector<SafetyViolation>& violations) {
    if (!registry_) return true;
    
    auto profileOpt = registry_->GetProfile(subsystem);
    if (!profileOpt.has_value()) return true;
    
    auto profile = profileOpt.value();
    
    int64_t now = GetCurrentTimeMs();
    int64_t elapsed = now - lastActionTimeMs;
    int minInterval = 0;
    
    if (actionType == "decision") {
        minInterval = profile.cooldowns.minDecisionIntervalMs;
    } else if (actionType == "mutation") {
        minInterval = profile.cooldowns.minMutationIntervalMs;
    } else if (actionType == "role_change") {
        minInterval = profile.cooldowns.minRoleChangeIntervalMs;
    } else if (actionType == "intent_update") {
        minInterval = profile.cooldowns.minIntentUpdateIntervalMs;
    }
    
    if (elapsed < minInterval) {
        SafetyViolation violation;
        violation.violationId = GenerateViolationId();
        violation.subsystem = subsystem;
        violation.action = actionType;
        violation.constraint = "cooldown";
        violation.description = "Action executed before cooldown period elapsed";
        violation.severity = 0.3;
        violation.timestampMs = now;
        violations.push_back(violation);
        return false;
    }
    
    return true;
}

std::vector<SafetyViolation> SafetyConstraintChecker::GetRecentViolations(int limit) const {
    std::lock_guard<std::mutex> lock(violationsMutex_);
    
    std::vector<SafetyViolation> recent;
    int count = 0;
    for (auto it = violations_.rbegin(); it != violations_.rend() && count < limit; ++it, ++count) {
        recent.push_back(*it);
    }
    return recent;
}

void SafetyConstraintChecker::ClearViolations() {
    std::lock_guard<std::mutex> lock(violationsMutex_);
    violations_.clear();
}

void SafetyConstraintChecker::PrintStatus() const {
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║  SAFETY CONSTRAINT CHECKER                                       ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Total Violations: " << std::setw(38) << violations_.size() << " ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
}

int64_t SafetyConstraintChecker::GetCurrentTimeMs() const {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string SafetyConstraintChecker::GenerateViolationId() {
    return "viol_" + std::to_string(++violationCounter_) + "_" + std::to_string(GetCurrentTimeMs());
}

} // namespace Autonomy
