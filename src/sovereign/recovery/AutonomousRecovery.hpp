// AutonomousRecovery.hpp
// Coordination Primitive #9: Autonomous Recovery Loop
// Detect failures and attempt recovery without human intervention

#pragma once
#include <string>
#include <vector>
#include <functional>
#include <chrono>
#include <map>
#include <thread>

namespace Sovereign {

// Recovery action types
enum class RecoveryActionType {
    RETRY,              // Retry the failed operation
    ROLLBACK,           // Rollback to previous state
    RESTART_COMPONENT,  // Restart a component
    CLEAR_CACHE,        // Clear caches and retry
    FALLBACK_MODE,      // Switch to degraded mode
    ESCALATE            // Escalate to human
};

// Recovery action
struct RecoveryAction {
    RecoveryActionType type;
    std::string target;
    std::string reason;
    uint32_t max_attempts;
    std::chrono::milliseconds delay_between_attempts;
};

// Recovery result
struct RecoveryResult {
    bool success;
    RecoveryAction action;
    uint32_t attempts_made;
    std::string message;
};

// Autonomous recovery system
class AutonomousRecovery {
public:
    static AutonomousRecovery& Instance();
    
    // Register recovery strategies
    void RegisterStrategy(const std::string& failure_pattern, RecoveryAction action);
    
    // Attempt recovery
    RecoveryResult AttemptRecovery(const std::string& failure_context, const std::string& error);
    
    // Check if recovery is in progress
    bool IsRecovering() const;
    
    // Get recovery history
    std::vector<RecoveryResult> GetRecoveryHistory() const;

private:
    AutonomousRecovery() = default;
    std::map<std::string, RecoveryAction> strategies_;
    std::vector<RecoveryResult> history_;
    bool recovering_ = false;
};

} // namespace Sovereign
