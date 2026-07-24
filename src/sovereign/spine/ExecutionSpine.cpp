// ExecutionSpine.cpp
// Implementation of the hardened execution spine

#include "ExecutionSpine.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstdint>

// Simple FNV-1a hash instead of OpenSSL SHA256 for portability
static std::string ComputeSimpleHash(const std::string& input) {
    const uint64_t FNV_OFFSET_BASIS = 14695981039346656037ULL;
    const uint64_t FNV_PRIME = 1099511628211ULL;
    
    uint64_t hash = FNV_OFFSET_BASIS;
    for (char c : input) {
        hash ^= static_cast<uint64_t>(c);
        hash *= FNV_PRIME;
    }
    
    std::stringstream ss;
    ss << std::hex << std::setw(16) << std::setfill('0') << hash;
    return ss.str();
}

namespace Sovereign {

// Intent serialization (~200 bytes)
std::vector<uint8_t> Intent::Serialize() const {
    std::vector<uint8_t> result;
    
    // Simple binary format: [field_count][field1_len][field1_data]...
    auto write_string = [&result](const std::string& s) {
        uint16_t len = static_cast<uint16_t>(s.length());
        result.push_back(len & 0xFF);
        result.push_back((len >> 8) & 0xFF);
        result.insert(result.end(), s.begin(), s.end());
    };
    
    write_string(goal);
    write_string(target_file);
    write_string(current_state);
    
    // Evidence count
    uint8_t evidence_count = static_cast<uint8_t>(evidence.size());
    result.push_back(evidence_count);
    for (const auto& e : evidence) {
        write_string(e);
    }
    
    // Blocker (optional)
    result.push_back(blocker.has_value() ? 1 : 0);
    if (blocker.has_value()) {
        write_string(*blocker);
    }
    
    write_string(next_action);
    
    return result;
}

Intent Intent::Deserialize(const std::vector<uint8_t>& data) {
    Intent intent;
    size_t pos = 0;
    
    auto read_string = [&data, &pos]() -> std::string {
        if (pos + 2 > data.size()) return "";
        uint16_t len = data[pos] | (data[pos + 1] << 8);
        pos += 2;
        if (pos + len > data.size()) return "";
        std::string result(data.begin() + pos, data.begin() + pos + len);
        pos += len;
        return result;
    };
    
    intent.goal = read_string();
    intent.target_file = read_string();
    intent.current_state = read_string();
    
    uint8_t evidence_count = data[pos++];
    for (uint8_t i = 0; i < evidence_count; i++) {
        intent.evidence.push_back(read_string());
    }
    
    bool has_blocker = data[pos++] != 0;
    if (has_blocker) {
        intent.blocker = read_string();
    }
    
    intent.next_action = read_string();
    
    return intent;
}

ExecutionSpine::ExecutionSpine() 
    : current_phase_(ExecutionPhase::INTENT_RECEIVED) {
}

ExecutionSpine::~ExecutionSpine() {
    // Release any held capabilities
    ReleaseCapabilities();
}

ExecutionResult ExecutionSpine::Execute(const Intent& intent) {
    current_intent_ = intent;
    
    // Phase 1: INTENT_RECEIVED → PLAN_GENERATED
    TransitionTo(ExecutionPhase::PLAN_GENERATED);
    auto plan_result = HandlePlanPhase();
    if (!plan_result.success) {
        return plan_result;
    }
    
    // Phase 2: PLAN_GENERATED → CAPABILITY_CLAIMED
    TransitionTo(ExecutionPhase::CAPABILITY_CLAIMED);
    auto capability_result = HandleCapabilityPhase();
    if (!capability_result.success) {
        return capability_result;
    }
    
    // Phase 3: CAPABILITY_CLAIMED → EXECUTING
    TransitionTo(ExecutionPhase::EXECUTING);
    auto exec_result = HandleExecutionPhase();
    if (!exec_result.success) {
        RollbackToLastCheckpoint();
        return exec_result;
    }
    
    // Phase 4: EXECUTING → VALIDATING
    TransitionTo(ExecutionPhase::VALIDATING);
    if (!ValidateResult(exec_result)) {
        RollbackToLastCheckpoint();
        return ExecutionResult{false, "Validation failed", 0, std::chrono::milliseconds(0)};
    }
    
    // Phase 5: VALIDATING → COMMITTED
    TransitionTo(ExecutionPhase::COMMITTED);
    PersistResult(exec_result);
    
    return exec_result;
}

void ExecutionSpine::TransitionTo(ExecutionPhase new_phase) {
    current_phase_ = new_phase;
    if (phase_callback_) {
        phase_callback_(new_phase);
    }
}

void ExecutionSpine::CreateCheckpoint(const std::string& state_hash) {
    Checkpoint cp;
    cp.phase = current_phase_;
    cp.timestamp = std::chrono::steady_clock::now();
    cp.state_hash = state_hash;
    cp.rollback_action = [this]() {
        // Default rollback: release capabilities
        ReleaseCapabilities();
    };
    checkpoints_.push_back(cp);
}

bool ExecutionSpine::RollbackToLastCheckpoint() {
    if (checkpoints_.empty()) {
        return false;
    }
    
    auto& cp = checkpoints_.back();
    current_phase_ = ExecutionPhase::ROLLBACK;
    
    if (cp.rollback_action) {
        cp.rollback_action();
    }
    
    checkpoints_.pop_back();
    return true;
}

bool ExecutionSpine::ClaimCapabilities(const std::vector<std::string>& tools) {
    // In real implementation, this would check with CapabilityBus
    for (const auto& tool : tools) {
        CapabilityClaim claim;
        claim.tool_name = tool;
        claim.resource_id = tool + "_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        claim.timeout = std::chrono::seconds(300);  // 5 minute default
        claim.acquired = true;  // Assume success for now
        active_claims_.push_back(claim);
    }
    return true;
}

void ExecutionSpine::ReleaseCapabilities() {
    // In real implementation, this would release from CapabilityBus
    active_claims_.clear();
}

bool ExecutionSpine::ValidateResult(const ExecutionResult& result) {
    // Basic validation: must be successful and have data
    if (!result.success) {
        return false;
    }
    
    // Additional validation based on intent
    if (current_intent_.target_file.empty()) {
        return true;  // No file target, skip file validation
    }
    
    // In real implementation, would verify file exists, symbol exists, etc.
    return true;
}

void ExecutionSpine::PersistResult(const ExecutionResult& result) {
    // In real implementation, would write to persistent storage
    // For now, just log the success
    (void)result;
}

void ExecutionSpine::OnPhaseTransition(PhaseCallback callback) {
    phase_callback_ = callback;
}

ExecutionResult ExecutionSpine::HandleIntentPhase(const Intent& intent) {
    (void)intent;
    // Intent is already stored, just validate
    if (current_intent_.goal.empty()) {
        return ExecutionResult{false, "Empty goal", 0, std::chrono::milliseconds(0)};
    }
    return ExecutionResult{true, "Intent validated", 0, std::chrono::milliseconds(0)};
}

ExecutionResult ExecutionSpine::HandlePlanPhase() {
    // Create initial checkpoint
    CreateCheckpoint(ComputeStateHash());
    
    // In real implementation, would generate DAG of steps
    return ExecutionResult{true, "Plan generated", 0, std::chrono::milliseconds(0)};
}

ExecutionResult ExecutionSpine::HandleCapabilityPhase() {
    // Determine required tools from intent
    std::vector<std::string> required_tools;
    
    if (!current_intent_.target_file.empty()) {
        required_tools.push_back("file_operations");
    }
    if (!current_intent_.next_action.empty()) {
        required_tools.push_back("terminal");
    }
    
    if (!ClaimCapabilities(required_tools)) {
        return ExecutionResult{false, "Failed to claim capabilities", 0, std::chrono::milliseconds(0)};
    }
    
    return ExecutionResult{true, "Capabilities claimed", 0, std::chrono::milliseconds(0)};
}

ExecutionResult ExecutionSpine::HandleExecutionPhase() {
    // In real implementation, would execute the plan
    // For now, simulate success
    return ExecutionResult{true, "Execution completed", 0, std::chrono::milliseconds(100)};
}

ExecutionResult ExecutionSpine::HandleValidationPhase() {
    // Validation happens in ValidateResult
    return ExecutionResult{true, "Validation passed", 0, std::chrono::milliseconds(0)};
}

ExecutionResult ExecutionSpine::HandleCommitPhase() {
    // Commit happens in PersistResult
    return ExecutionResult{true, "Committed", 0, std::chrono::milliseconds(0)};
}

std::string ExecutionSpine::ComputeStateHash() const {
    // Simple hash of current state using FNV-1a
    std::string state = std::to_string(static_cast<int>(current_phase_)) + 
                       current_intent_.goal + 
                       current_intent_.target_file;
    return ComputeSimpleHash(state);
}

bool ExecutionSpine::VerifyIntegrity() const {
    // In real implementation, would verify all hashes
    return true;
}

// Global instance
ExecutionSpine& GetGlobalExecutionSpine() {
    static ExecutionSpine instance;
    return instance;
}

} // namespace Sovereign
