#pragma once
#include <stdint.h>
#include <string>
#include <vector>
#include <optional>
#include <variant>
#include <functional>
#include <unordered_map>
#include <mutex>
#include "intent_config.hpp"

// =============================================================================
// Intent ABI - Contract between Model and Runtime
// Models emit Intent, not arbitrary commands
// =============================================================================

namespace RawrXD {
namespace Intent {

// Intent types - what the model wants to do
enum class IntentType : uint32_t {
    UNKNOWN = 0,
    
    // Read operations (always allowed)
    READ_SOURCE = 1,
    READ_AST = 2,
    READ_SYMBOLS = 3,
    READ_TELEMETRY = 4,
    READ_DEPENDENCIES = 5,
    
    // Analysis operations
    ANALYZE_FUNCTION = 10,
    ANALYZE_PERFORMANCE = 11,
    ANALYZE_SECURITY = 12,
    
    // Modification operations (require validation)
    MODIFY_FUNCTION = 20,
    MODIFY_FILE = 21,
    ADD_FUNCTION = 22,
    REMOVE_FUNCTION = 23,
    REFACTOR = 24,
    OPTIMIZE = 25,
    
    // Execution operations (require capability tokens)
    COMPILE = 30,
    RUN_TEST = 31,
    DEBUG = 32,
    RUN_BENCHMARK = 33,
    
    // High-risk operations (require human approval)
    DELETE_PROJECT = 40,
    MODIFY_BUILD_CONFIG = 41,
    ACCESS_CREDENTIALS = 42,
    NETWORK_OPERATION = 43,
    SYSTEM_COMMAND = 44,
    
    // Meta operations
    PROPOSE_PLAN = 50,
    REQUEST_APPROVAL = 51,
    REPORT_STATUS = 52,
};

// Risk levels for intent classification
enum class RiskLevel : uint32_t {
    NONE = 0,       // Read-only, no side effects
    LOW = 1,        // Local modifications, easily reversible
    MEDIUM = 2,     // Cross-file changes, requires validation
    HIGH = 3,       // Build system changes, requires approval
    CRITICAL = 4,   // Destructive operations, requires human
};

// Target specification - what the intent operates on
struct TargetObject {
    std::string file_path;
    std::string symbol_name;  // Function/class/variable name
    uint32_t line_start = 0;
    uint32_t line_end = 0;
    std::string language;     // cpp, python, etc.
    
    // For function-level targeting
    std::string function_signature;
    std::vector<std::string> dependencies;
};

// Change description - what to change
struct ChangeDescription {
    // Instead of raw text edits, use semantic descriptions
    std::string operation;           // "replace_body", "add_parameter", "rename"
    std::string target_fragment;     // What to change
    std::string replacement;         // What to change it to
    std::string reason;              // Why this change
    std::vector<std::string> constraints;  // Must preserve
    
    // Expected behavior
    std::string expected_effect;
    std::vector<std::string> expected_outputs;
};

// Verification plan - how to validate
struct VerificationPlan {
    bool compile = true;
    bool run_tests = true;
    bool static_analysis = true;
    bool security_scan = false;
    bool performance_check = false;
    
    // Specific tests to run
    std::vector<std::string> test_targets;
    std::vector<std::string> benchmark_targets;
    
    // Success criteria
    uint32_t min_tests_passing = 0;
    double max_performance_regression = 0.05;  // 5%
    bool require_security_clean = true;
};

// The Intent Request - what models emit
struct IntentRequest {
    uint64_t session_id = 0;
    uint64_t intent_id = 0;
    
    IntentType type = IntentType::UNKNOWN;
    RiskLevel risk = RiskLevel::NONE;
    
    TargetObject target;
    std::optional<ChangeDescription> change;
    std::optional<VerificationPlan> verification;
    
    // Metadata
    std::string model_source;      // "kimi", "moonshot", "local", etc.
    std::string reasoning;         // Model's explanation
    float confidence = 0.0f;         // Model's confidence (0-1)
    
    // Timing
    uint64_t timestamp_us = 0;
    uint32_t timeout_ms = 30000;     // Default 30s
    
    // Toggles - per-intent overrides
    bool skip_validation = false;
    bool skip_tests = false;
    bool require_human_approval = false;
    bool auto_rollback_on_failure = true;
    
    // Serialize to JSON
    std::string ToJson() const;
    static std::optional<IntentRequest> FromJson(const std::string& json);
};

// Intent Response - what the runtime returns
struct IntentResponse {
    enum class Status : uint32_t {
        PENDING = 0,
        VALIDATING = 1,
        VALIDATED = 2,
        REJECTED = 3,
        EXECUTING = 4,
        EXECUTED = 5,
        FAILED = 6,
        ROLLED_BACK = 7,
    };
    
    uint64_t intent_id = 0;
    Status status = Status::PENDING;
    
    std::string message;
    std::vector<std::string> warnings;
    std::vector<std::string> errors;
    
    // Execution results
    bool compiled = false;
    uint32_t tests_passed = 0;
    uint32_t tests_failed = 0;
    double performance_delta = 0.0;
    bool security_clean = true;
    
    // Rollback info
    std::string rollback_id;
    bool can_rollback = false;
    
    // Serialize to JSON
    std::string ToJson() const;
};

// Capability Token - permission to execute
struct CapabilityToken {
    uint64_t token_id = 0;
    uint64_t intent_id = 0;
    
    std::vector<IntentType> allowed_types;
    std::vector<std::string> allowed_paths;
    std::vector<std::string> denied_paths;
    
    uint64_t expiry_timestamp = 0;
    uint32_t max_executions = 1;
    std::atomic<uint32_t> executions_used{0};
    
    // Check if token allows an intent
    bool Allows(const IntentRequest& intent) const;
    bool IsExpired() const;
    bool IsExhausted() const;
    bool Consume();
    
    // Copy/move constructors (required due to atomic member)
    CapabilityToken() = default;
    CapabilityToken(const CapabilityToken& other);
    CapabilityToken(CapabilityToken&& other) noexcept;
    CapabilityToken& operator=(const CapabilityToken& other);
    CapabilityToken& operator=(CapabilityToken&& other) noexcept;
};

// Intent Validator - checks if intent is valid
class IntentValidator {
public:
    static IntentValidator& Instance();
    
    // Validate an intent request
    struct ValidationResult {
        bool valid = false;
        RiskLevel assessed_risk = RiskLevel::NONE;
        std::vector<std::string> errors;
        std::vector<std::string> warnings;
        std::optional<CapabilityToken> token;
    };
    
    ValidationResult Validate(const IntentRequest& intent);
    
    // Configuration
    void SetPolicyFile(const std::string& path);
    void ReloadPolicy();
    
private:
    IntentValidator() = default;
    
    bool CheckScope(const IntentRequest& intent);
    bool CheckSemantics(const IntentRequest& intent);
    bool CheckSafety(const IntentRequest& intent);
    RiskLevel AssessRisk(const IntentRequest& intent);
};

// Intent Router - routes intents to appropriate handler
class IntentRouter {
public:
    static IntentRouter& Instance();
    
    // Route an intent (returns response)
    IntentResponse Route(const IntentRequest& intent);
    
    // Register handlers
    using IntentHandler = std::function<IntentResponse(const IntentRequest&)>;
    void RegisterHandler(IntentType type, IntentHandler handler);
    
    // Toggle routing
    void EnableRouting(bool enable);
    bool IsRoutingEnabled() const;
    
private:
    std::unordered_map<IntentType, IntentHandler> handlers_;
    std::mutex handlers_mutex_;
    std::atomic<bool> enabled_{true};
};

} // namespace Intent
} // namespace RawrXD
