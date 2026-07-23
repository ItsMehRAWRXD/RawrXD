#pragma once
#include "IntentABI.hpp"
#include <filesystem>
#include <set>

// =============================================================================
// PatchFirewall - AST-level validation before filesystem writes
// All features toggleable at compile-time and runtime
// =============================================================================

namespace RawrXD {
namespace Sovereign {
namespace Guardrails {

// =============================================================================
// Patch Types - What kind of modification
// =============================================================================

enum class PatchType : uint8_t {
    UNKNOWN = 0,
    TEXT_REPLACE = 1,      // Simple text substitution
    AST_MUTATION = 2,        // Structured AST change
    BINARY_PATCH = 3,        // Machine code modification
    HOTPATCH = 4,          // Runtime code replacement
    METADATA_UPDATE = 5      // Comments, formatting
};

// =============================================================================
// Patch Scope - Where the patch applies
// =============================================================================

struct PatchScope {
    std::filesystem::path basePath;
    std::set<std::string> allowedExtensions;
    std::set<std::string> blockedPaths;
    bool allowSubdirectories{true};
    int maxDepth{10};
    
    // Toggle: Allow creation of new files
    bool allowNewFiles{true};
    // Toggle: Allow deletion of existing files
    bool allowDeletions{false};
    // Toggle: Allow modification of version-controlled files only
    bool vcsOnly{false};
};

// =============================================================================
// Patch Validation Result
// =============================================================================

struct PatchValidation {
    bool allowed{false};
    bool needsApproval{false};
    std::string rejectionReason;
    
    // Metrics
    size_t linesAdded{0};
    size_t linesRemoved{0};
    size_t filesAffected{0};
    size_t symbolsModified{0};
    
    // Risk assessment
    RiskLevel assessedRisk{RiskLevel::NONE};
    std::vector<std::string> riskFactors;
    
    // Toggle: Override (admin only)
    bool overrideApplied{false};
    std::string overrideJustification;
};

// =============================================================================
// PatchFirewall - The gatekeeper
// =============================================================================

class PatchFirewall {
public:
    static PatchFirewall& Instance();
    
    // Master toggle
    void SetEnabled(bool enabled) { enabled_ = enabled; }
    bool IsEnabled() const { return enabled_; }
    
    // Main validation entry
    PatchValidation ValidatePatch(
        const IntentRequest& intent,
        const std::string& proposedPatch
    );
    
    // Scope management
    void SetDefaultScope(const PatchScope& scope) { defaultScope_ = scope; }
    PatchScope GetDefaultScope() const { return defaultScope_; }
    
    // Toggle: AST validation
    void SetAstValidationEnabled(bool enabled) { astValidationEnabled_ = enabled; }
    bool IsAstValidationEnabled() const { return astValidationEnabled_; }
    
    // Toggle: Text-only validation (skip AST)
    void SetTextOnlyMode(bool textOnly) { textOnlyMode_ = textOnly; }
    bool IsTextOnlyMode() const { return textOnlyMode_; }
    
    // Toggle: Dry-run mode (validate but don't apply)
    void SetDryRunMode(bool dryRun) { dryRunMode_ = dryRun; }
    bool IsDryRunMode() const { return dryRunMode_; }
    
    // Blocked patterns
    void AddBlockedPattern(const std::string& pattern);
    void RemoveBlockedPattern(const std::string& pattern);
    bool IsBlocked(const std::string& content) const;
    void ClearBlockedPatterns();
    
    // Required patterns (must be present)
    void AddRequiredPattern(const std::string& pattern);
    bool HasRequiredPatterns(const std::string& content) const;
    void ClearRequiredPatterns();
    
    // Size limits
    void SetMaxPatchSize(size_t bytes) { maxPatchSize_ = bytes; }
    size_t GetMaxPatchSize() const { return maxPatchSize_; }
    
    void SetMaxFilesAffected(size_t count) { maxFilesAffected_ = count; }
    size_t GetMaxFilesAffected() const { return maxFilesAffected_; }
    
    // Rate limiting
    void SetMaxPatchesPerMinute(size_t count) { maxPatchesPerMinute_ = count; }
    size_t GetMaxPatchesPerMinute() const { return maxPatchesPerMinute_; }
    bool CheckRateLimit(const std::string& sessionId);
    
    // Emergency bypass (with audit trail)
    void EmergencyBypass(bool enable, const std::string& justification);
    bool IsEmergencyBypassActive() const { return emergencyBypass_; }

private:
    PatchFirewall() = default;
    
    // Validation stages
    bool ValidateScope(const IntentRequest& intent, PatchValidation& result);
    bool ValidateSize(const std::string& patch, PatchValidation& result);
    bool ValidatePatterns(const std::string& patch, PatchValidation& result);
    bool ValidateAst(const std::string& patch, PatchValidation& result);
    bool ValidateRate(const std::string& sessionId, PatchValidation& result);
    
    // State
    std::atomic<bool> enabled_{true};
    std::atomic<bool> astValidationEnabled_{true};
    std::atomic<bool> textOnlyMode_{false};
    std::atomic<bool> dryRunMode_{false};
    std::atomic<size_t> maxPatchSize_{1024 * 1024};  // 1MB
    std::atomic<size_t> maxFilesAffected_{100};
    std::atomic<size_t> maxPatchesPerMinute_{60};
    std::atomic<bool> emergencyBypass_{false};
    
    PatchScope defaultScope_;
    std::vector<std::string> blockedPatterns_;
    std::vector<std::string> requiredPatterns_;
    mutable std::mutex patternsMutex_;
    
    // Rate tracking
    struct RateEntry {
        std::chrono::steady_clock::time_point timestamp;
        size_t count{0};
    };
    std::unordered_map<std::string, RateEntry> rateTracker_;
    mutable std::mutex rateMutex_;
};

// =============================================================================
// Compile-time toggles
// =============================================================================

#if RAWRXD_PATCH_FIREWALL_ENABLED
    #define PATCH_FIREWALL(expr) if (PatchFirewall::Instance().IsEnabled()) { expr; }
    #define PATCH_VALIDATE(intent, patch) PatchFirewall::Instance().ValidatePatch(intent, patch)
#else
    #define PATCH_FIREWALL(expr)
    #define PATCH_VALIDATE(intent, patch) PatchValidation{true, false, "", 0, 0, 0, 0, RiskLevel::NONE, {}, false, ""}
#endif

} // namespace Guardrails
} // namespace Sovereign
} // namespace RawrXD
