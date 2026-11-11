#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <optional>

// =============================================================================
// Intent ABI - Model emits intent, not arbitrary commands
// The contract between reasoning model and runtime
// =============================================================================

namespace RawrXD {
namespace Sovereign {
namespace Intent {

// Intent types - what the model wants to do
enum class IntentType : uint32_t {
    READ_SOURCE = 0,           // Inspect code
    MODIFY_FUNCTION = 1,     // Change function implementation
    ADD_FUNCTION = 2,        // Create new function
    REMOVE_FUNCTION = 3,     // Delete function
    REFACTOR = 4,            // Structural reorganization
    OPTIMIZE = 5,            // Performance improvement
    DEBUG = 6,               // Fix bugs
    GENERATE_TESTS = 7,      // Create test cases
    ANALYZE = 8,             // Static analysis
    DOCUMENT = 9,            // Add documentation
    UNKNOWN = 0xFFFFFFFF
};

// Risk levels for capability gating
enum class RiskLevel : uint8_t {
    LOW = 0,      // Read-only, safe analysis
    MEDIUM = 1,   // Local modifications, tested paths
    HIGH = 2,     // Structural changes, cross-module
    CRITICAL = 3  // Security, build system, deployment
};

// Target identification
struct TargetObject {
    std::string file_path;      // Relative to repo root
    std::string symbol_name;    // Function/class/variable name
    uint32_t line_start = 0;    // Optional: specific line range
    uint32_t line_end = 0;
    std::string ast_node_id;    // Optional: AST node reference
};

// Change description - semantic intent, not text edit
struct ChangeDescription {
    std::string goal;           // What should happen
    std::string rationale;      // Why this change
    std::vector<std::string> constraints;  // Must preserve
    std::vector<std::string> assumptions;  // Expected context
    std::optional<std::string> reference_impl;  // Similar working code
};

// Verification plan - how to validate
struct VerificationPlan {
    bool compile_check = true;
    bool unit_tests = true;
    bool integration_tests = false;
    bool static_analysis = true;
    bool security_scan = true;
    bool performance_regression = false;
    std::vector<std::string> specific_tests;  // Named test cases
};

// The Intent Request - model output format
struct IntentRequest {
    uint64_t session_id = 0;
    IntentType type = IntentType::UNKNOWN;
    TargetObject target;
    ChangeDescription change;
    VerificationPlan verify;
    RiskLevel risk = RiskLevel::HIGH;
    uint64_t timestamp = 0;
    std::string model_version;  // Which model generated this
    
    // Serialization for transport
    std::string ToJson() const;
    static std::optional<IntentRequest> FromJson(const std::string& json);
};

// Intent Response - runtime decision
struct IntentResponse {
    enum class Status {
        ACCEPTED,       // Will execute
        REJECTED,       // Policy violation
        NEEDS_APPROVAL, // Human required
        DEFERRED,       // Queue for later
        INVALID         // Malformed intent
    };
    
    Status status = Status::INVALID;
    std::string transaction_id;  // For tracking
    std::string rejection_reason;  // If rejected
    std::vector<std::string> warnings;
    uint64_t estimated_duration_ms = 0;
};

// Capability Token - scoped permission
struct CapabilityToken {
    uint64_t intent_id = 0;
    std::vector<IntentType> allowed_types;
    std::vector<std::string> allowed_paths;  // Path globs
    RiskLevel max_risk = RiskLevel::CRITICAL;
    uint64_t expiry_timestamp = 0;
    std::string signature;  // HMAC for integrity
    
    bool Validate() const;
    bool Allows(IntentType type, const std::string& path, RiskLevel risk) const;
};

// =============================================================================
// Intent Validation Interface
// =============================================================================

class IIntentValidator {
public:
    virtual ~IIntentValidator() = default;
    virtual IntentResponse Validate(const IntentRequest& intent) = 0;
    virtual bool ValidateToken(const CapabilityToken& token) = 0;
};

// Global validator singleton
IIntentValidator* GetIntentValidator();
void SetIntentValidator(IIntentValidator* validator);

} // namespace Intent
} // namespace Sovereign
} // namespace RawrXD
