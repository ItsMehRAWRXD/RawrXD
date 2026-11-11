// AutonomousRecovery.cpp
// Implementation of the Autonomous Recovery Loop

#include "AutonomousRecovery.hpp"
#include <algorithm>

namespace Sovereign {

AutonomousRecovery& AutonomousRecovery::Instance() {
    static AutonomousRecovery instance;
    return instance;
}

void AutonomousRecovery::RegisterStrategy(const std::string& failure_pattern, RecoveryAction action) {
    strategies_[failure_pattern] = action;
}

RecoveryResult AutonomousRecovery::AttemptRecovery(const std::string& failure_context, const std::string& error) {
    RecoveryResult result;
    result.success = false;
    result.attempts_made = 0;
    
    // Find matching strategy
    for (const auto& [pattern, action] : strategies_) {
        if (error.find(pattern) != std::string::npos || failure_context.find(pattern) != std::string::npos) {
            result.action = action;
            break;
        }
    }
    
    // If no strategy found, use default retry
    if (result.action.type == RecoveryActionType::RETRY && result.action.max_attempts == 0) {
        result.action.type = RecoveryActionType::RETRY;
        result.action.max_attempts = 3;
        result.action.delay_between_attempts = std::chrono::milliseconds(1000);
    }
    
    // Attempt recovery
    for (uint32_t i = 0; i < result.action.max_attempts; ++i) {
        result.attempts_made++;
        
        // Simulate recovery attempt
        std::this_thread::sleep_for(result.action.delay_between_attempts);
        
        // For now, assume success on first attempt
        result.success = true;
        result.message = "Recovery succeeded after " + std::to_string(result.attempts_made) + " attempts";
        break;
    }
    
    if (!result.success) {
        result.message = "Recovery failed after " + std::to_string(result.attempts_made) + " attempts";
    }
    
    history_.push_back(result);
    return result;
}

bool AutonomousRecovery::IsRecovering() const {
    return false;
}

std::vector<RecoveryResult> AutonomousRecovery::GetRecoveryHistory() const {
    return history_;
}

} // namespace Sovereign
