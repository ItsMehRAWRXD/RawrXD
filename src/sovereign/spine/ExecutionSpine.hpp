// ExecutionSpine.hpp
// Coordination Primitive #1: Execution Spine Hardening
// Intent → Plan → Capability Claim → Execution → Validation → Commit
// Never free-form tool loops. Always structured execution.

#pragma once
#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <chrono>
#include <variant>
#include <optional>

namespace Sovereign {

// Phase definitions for the execution spine
enum class ExecutionPhase {
    INTENT_RECEIVED,      // User prompt parsed
    PLAN_GENERATED,       // DAG of steps created
    CAPABILITY_CLAIMED,   // Tools reserved
    EXECUTING,            // Actual work in progress
    VALIDATING,           // Results being checked
    COMMITTED,            // State persisted
    ROLLBACK              // On failure, revert
};

// Intent structure - compressed goal representation
struct Intent {
    std::string goal;
    std::string target_file;
    std::string current_state;
    std::vector<std::string> evidence;
    std::optional<std::string> blocker;
    std::string next_action;
    
    // Serialize to compact format (~200 bytes vs full conversation)
    std::vector<uint8_t> Serialize() const;
    static Intent Deserialize(const std::vector<uint8_t>& data);
};

// Checkpoint for rollback capability
struct Checkpoint {
    ExecutionPhase phase;
    std::chrono::time_point<std::chrono::steady_clock> timestamp;
    std::string state_hash;  // SHA256 of state at this point
    std::function<void()> rollback_action;
};

// Tool capability claim
struct CapabilityClaim {
    std::string tool_name;
    std::string resource_id;
    std::chrono::seconds timeout;
    bool acquired;
};

// Execution result
struct ExecutionResult {
    bool success;
    std::string message;
    std::variant<std::string, std::vector<uint8_t>, int> data;
    std::chrono::milliseconds duration;
};

// The Execution Spine - never free-form, always structured
class ExecutionSpine {
public:
    ExecutionSpine();
    ~ExecutionSpine();

    // Main entry: Intent → Result
    ExecutionResult Execute(const Intent& intent);
    
    // Phase transitions
    void TransitionTo(ExecutionPhase new_phase);
    ExecutionPhase CurrentPhase() const { return current_phase_; }
    
    // Checkpoint management
    void CreateCheckpoint(const std::string& state_hash);
    bool RollbackToLastCheckpoint();
    
    // Capability management
    bool ClaimCapabilities(const std::vector<std::string>& tools);
    void ReleaseCapabilities();
    
    // Validation
    bool ValidateResult(const ExecutionResult& result);
    
    // Persistence
    void PersistResult(const ExecutionResult& result);
    
    // Event callbacks
    using PhaseCallback = std::function<void(ExecutionPhase)>;
    void OnPhaseTransition(PhaseCallback callback);

private:
    ExecutionPhase current_phase_;
    std::vector<Checkpoint> checkpoints_;
    std::vector<CapabilityClaim> active_claims_;
    Intent current_intent_;
    PhaseCallback phase_callback_;
    
    // Phase handlers
    ExecutionResult HandleIntentPhase(const Intent& intent);
    ExecutionResult HandlePlanPhase();
    ExecutionResult HandleCapabilityPhase();
    ExecutionResult HandleExecutionPhase();
    ExecutionResult HandleValidationPhase();
    ExecutionResult HandleCommitPhase();
    
    // Helpers
    std::string ComputeStateHash() const;
    bool VerifyIntegrity() const;
};

// Global spine instance for the IDE
ExecutionSpine& GetGlobalExecutionSpine();

} // namespace Sovereign
