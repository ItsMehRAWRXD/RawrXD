#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <atomic>

// =============================================================================
// IntentABI - Model Output to Controlled Execution Bridge
// Makes models interchangeable reasoning engines while IDE maintains authority
// =============================================================================

// Toggle macros for compile-time feature selection
#ifndef RAWRXD_INTENT_GUARD_ENABLED
    #define RAWRXD_INTENT_GUARD_ENABLED 1  // Default: ON
#endif

#ifndef RAWRXD_PATCH_FIREWALL_ENABLED
    #define RAWRXD_PATCH_FIREWALL_ENABLED 1  // Default: ON
#endif

#ifndef RAWRXD_HOTPATCH_JOURNAL_ENABLED
    #define RAWRXD_HOTPATCH_JOURNAL_ENABLED 1  // Default: ON
#endif

#ifndef RAWRXD_CAPABILITY_TOKENS_ENABLED
    #define RAWRXD_CAPABILITY_TOKENS_ENABLED 1  // Default: ON
#endif

#ifndef RAWRXD_AST_VALIDATION_ENABLED
    #define RAWRXD_AST_VALIDATION_ENABLED 1  // Default: ON
#endif

namespace RawrXD {
namespace Sovereign {
namespace Guardrails {

// =============================================================================
// Runtime Configuration - All features toggleable at runtime
// =============================================================================

struct GuardrailConfig {
    // Master switches
    std::atomic<bool> intentValidationEnabled{true};
    std::atomic<bool> patchFirewallEnabled{true};
    std::atomic<bool> hotpatchJournalEnabled{true};
    std::atomic<bool> capabilityTokensEnabled{true};
    std::atomic<bool> astValidationEnabled{true};
    std::atomic<bool> atomicActivationEnabled{true};
    std::atomic<bool> rollbackPrimitivesEnabled{true};
    
    // Policy levels (0=permissive, 1=standard, 2=strict, 3=paranoid)
    std::atomic<int> validationStrictness{1};
    std::atomic<int> maxPatchSize{1024 * 1024};  // 1MB default
    std::atomic<int> maxRollbackDepth{100};
    std::atomic<int> sandboxTimeoutMs{30000};    // 30s default
    
    // Feature-specific toggles
    std::atomic<bool> allowFilesystemWrites{true};
    std::atomic<bool> allowNetworkAccess{false};
    std::atomic<bool> allowShellExecution{false};
    std::atomic<bool> allowMemoryPatches{true};
    std::atomic<bool> requireHumanApproval{false};
    std::atomic<bool> autoRollbackOnFailure{true};
    
    // Singleton access
    static GuardrailConfig& Instance();
    
    // Load from JSON config file
    bool LoadFromFile(const std::string& path);
    bool SaveToFile(const std::string& path) const;
    
    // Reset to defaults
    void ResetToDefaults();
    
    // Validate configuration consistency
    bool Validate() const;
};

// =============================================================================
// Intent Types - What the model wants to do
// =============================================================================

enum class IntentType : uint32_t {
    UNKNOWN = 0,
    
    // Read operations (low risk)
    READ_SOURCE = 1,
    ANALYZE_CODE = 2,
    QUERY_SYMBOLS = 3,
    INSPECT_STATE = 4,
    
    // Modification operations (medium risk)
    MODIFY_FUNCTION = 10,
    REFACTOR_CODE = 11,
    OPTIMIZE_KERNEL = 12,
    ADD_TEST = 13,
    UPDATE_COMMENT = 14,
    
    // Structural operations (high risk)
    CREATE_FILE = 20,
    DELETE_FILE = 21,
    RENAME_SYMBOL = 22,
    MODIFY_INTERFACE = 23,
    
    // Build operations (execution risk)
    COMPILE = 30,
    RUN_TEST = 31,
    DEBUG = 32,
    PROFILE = 33,
    
    // Administrative (highest risk)
    HOTPATCH_RUNTIME = 40,
    MODIFY_GUARD_CONFIG = 41,
    BYPASS_VALIDATION = 42,  // Requires explicit override
    
    MAX_INTENT = 0xFFFFFFFF
};

// Risk levels for each intent type
enum class RiskLevel : uint8_t {
    NONE = 0,      // No risk (read-only)
    LOW = 1,       // Safe modifications
    MEDIUM = 2,    // Code changes
    HIGH = 3,      // Structural changes
    CRITICAL = 4,  // Runtime modifications
    ADMIN = 5      // Guardrail bypass
};

// Convert intent to risk level
RiskLevel GetIntentRisk(IntentType type);

// =============================================================================
// Intent Request - Model output structured for validation
// =============================================================================

struct TargetObject {
    std::string filePath;
    std::string symbolName;
    uint64_t lineNumber{0};
    uint64_t columnNumber{0};
    std::vector<std::string> dependencies;
};

struct ChangeDescription {
    std::string operation;           // "replace", "insert", "delete", "modify"
    std::string beforeHash;          // SHA256 of original
    std::string afterHash;           // SHA256 of proposed
    std::string diffContent;         // Unified diff format
    std::string reason;              // Why this change
    std::vector<std::string> constraints;
};

struct VerificationPlan {
    bool compileCheck{true};
    bool unitTests{true};
    bool integrationTests{false};
    bool securityScan{true};
    bool performanceBenchmark{false};
    std::vector<std::string> customChecks;
};

struct IntentRequest {
    uint64_t sessionId{0};
    uint64_t timestamp{0};
    IntentType type{IntentType::UNKNOWN};
    RiskLevel risk{RiskLevel::NONE};
    
    TargetObject target;
    ChangeDescription change;
    VerificationPlan verification;
    
    // Model metadata
    std::string modelProvider;       // "kimi", "moonshot", "local", etc.
    std::string modelVersion;
    float confidenceScore{0.0f};     // Model's confidence 0.0-1.0
    
    // Context
    std::vector<std::string> relevantFiles;
    std::string conversationContext;
    
    // Validation state (filled by guardrails)
    bool preValidated{false};
    std::string validationError;
    
    // Toggle: Skip validation (emergency only)
    bool skipValidation{false};
    std::string skipJustification;
};

// =============================================================================
// Intent Response - Validation result
// =============================================================================

enum class IntentStatus : uint8_t {
    PENDING = 0,
    VALIDATED = 1,
    REJECTED = 2,
    NEEDS_APPROVAL = 3,
    EXECUTED = 4,
    ROLLED_BACK = 5,
    FAILED = 6
};

struct IntentResponse {
    uint64_t sessionId{0};
    IntentStatus status{IntentStatus::PENDING};
    
    // Validation results
    bool syntaxValid{false};
    bool semanticValid{false};
    bool policyCompliant{false};
    bool scopeAllowed{false};
    
    // Execution results
    bool compiled{false};
    bool testsPassed{false};
    bool securityClean{false};
    
    // Metrics
    uint64_t validationTimeUs{0};
    uint64_t executionTimeUs{0};
    
    // Error info
    std::string errorMessage;
    std::vector<std::string> warnings;
    
    // Transaction ID for rollback
    std::string transactionId;
    
    // Toggle: Force execution despite warnings
    bool forceExecute{false};
};

// =============================================================================
// Intent Validator - The guardrail layer
// =============================================================================

class IntentValidator {
public:
    static IntentValidator& Instance();
    
    // Main validation entry point
    IntentResponse Validate(const IntentRequest& request);
    
    // Toggle validation on/off
    void SetEnabled(bool enabled) { enabled_ = enabled; }
    bool IsEnabled() const { return enabled_; }
    
    // Policy configuration
    void SetMaxRiskLevel(RiskLevel max) { maxRiskLevel_ = max; }
    void SetRequireApprovalAbove(RiskLevel level) { approvalThreshold_ = level; }
    
    // Scope validation
    bool IsInAllowedScope(const std::string& path);
    void AddAllowedScope(const std::string& path);
    void RemoveAllowedScope(const std::string& path);
    void ClearAllowedScopes();
    
    // Blocked patterns
    void AddBlockedPattern(const std::string& pattern);
    bool MatchesBlockedPattern(const std::string& content);
    
    // Toggle: AST validation
    void SetAstValidationEnabled(bool enabled) { astValidationEnabled_ = enabled; }
    bool IsAstValidationEnabled() const { return astValidationEnabled_; }

private:
    IntentValidator() = default;
    
    // Validation stages
    bool ValidateSyntax(const IntentRequest& req, std::string& error);
    bool ValidateSemantics(const IntentRequest& req, std::string& error);
    bool ValidatePolicy(const IntentRequest& req, std::string& error);
    bool ValidateScope(const IntentRequest& req, std::string& error);
    
    // State
    std::atomic<bool> enabled_{true};
    std::atomic<RiskLevel> maxRiskLevel_{RiskLevel::ADMIN};
    std::atomic<RiskLevel> approvalThreshold_{RiskLevel::HIGH};
    std::atomic<bool> astValidationEnabled_{true};
    
    std::vector<std::string> allowedScopes_;
    std::vector<std::string> blockedPatterns_;
    mutable std::mutex scopeMutex_;
};

// =============================================================================
// Convenience Macros (respect compile-time toggles)
// =============================================================================

#if RAWRXD_INTENT_GUARD_ENABLED
    #define INTENT_GUARD(expr) if (RawrXD::Sovereign::Guardrails::IntentValidator::Instance().IsEnabled()) { expr; }
    #define INTENT_VALIDATE(req) RawrXD::Sovereign::Guardrails::IntentValidator::Instance().Validate(req)
#else
    #define INTENT_GUARD(expr)
    #define INTENT_VALIDATE(req) IntentResponse{req.sessionId, IntentStatus::VALIDATED, true, true, true, true}
#endif

} // namespace Guardrails
} // namespace Sovereign
} // namespace RawrXD
