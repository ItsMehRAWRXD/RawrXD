// ============================================================================
// PatchValidator.hpp - Structural Verification Before Write
// Multi-stage validation pipeline for safe code transformation
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <optional>
#include <functional>
#include <nlohmann/json.hpp>
#include "../repo/RepositoryIntelligence.hpp"

// Forward declarations
namespace RawrXD {
namespace Build {
    class BuildIntelligence;
}
}

namespace RawrXD {
namespace Validation {

// ============================================================================
// Validation Severity
// ============================================================================
enum class Severity {
    Info,
    Warning,
    Error,
    Critical
};

// Alias for backward compatibility
using ValidationSeverity = Severity;

// ============================================================================
// Edit Type
// ============================================================================
enum class EditType {
    Insert,
    Delete,
    Replace,
    Move
};

// ============================================================================
// Conflict Detection
// ============================================================================
struct Conflict {
    std::string type;
    std::string filePath;
    std::string location;
    std::string description;
    std::string suggestion;
};

// ============================================================================
// Validation Result
// ============================================================================
struct ValidationIssue {
    Severity severity;
    std::string code;            // Error code (e.g., "PARSE_ERROR", "TYPE_MISMATCH")
    std::string message;
    std::string filePath;
    uint32_t line;
    uint32_t column;
    std::string suggestion;    // Auto-fix suggestion
    bool autoFixable;
    
    nlohmann::json toJson() const;
};

struct ValidationResult {
    bool passed;
    std::vector<ValidationIssue> issues;
    std::string summary;
    
    bool HasErrors() const;
    bool HasCriticalErrors() const;
    std::vector<ValidationIssue> GetErrors() const;
    std::vector<ValidationIssue> GetWarnings() const;
    
    nlohmann::json toJson() const;
};

// ============================================================================
// Source Edit
// ============================================================================
struct SourceEdit {
    std::string filePath;
    uint32_t startLine;
    uint32_t startColumn;
    uint32_t endLine;
    uint32_t endColumn;
    std::string oldText;
    std::string newText;
    std::string description;
    
    nlohmann::json toJson() const;
};

// ============================================================================
// Patch - Collection of Edits
// ============================================================================
struct Patch {
    std::string id;              // UUID
    std::string description;
    std::vector<SourceEdit> edits;
    std::string author;          // "CEOAgent", "User", etc.
    uint64_t timestamp;
    std::vector<std::string> dependencies;
    std::vector<std::string> affectedFiles;
    
    nlohmann::json toJson() const;
    static Patch fromJson(const nlohmann::json& j);
};

// ============================================================================
// Validation Stage Interface
// ============================================================================
class ValidationStage {
public:
    virtual ~ValidationStage() = default;
    virtual std::string GetName() const = 0;
    virtual std::string GetDescription() const = 0;
    virtual ValidationResult Validate(const Patch& patch) = 0;
    virtual bool CanAutoFix() const { return false; }
    virtual Patch AutoFix(const Patch& patch) { return patch; }
};

// ============================================================================
// Concrete Validation Stages
// ============================================================================

// Stage 1: Syntax Validation
class SyntaxValidator : public ValidationStage {
public:
    std::string GetName() const override { return "SyntaxValidator"; }
    std::string GetDescription() const override { return "Parse source files to detect syntax errors"; }
    ValidationResult Validate(const Patch& patch) override;
};

// Stage 2: Semantic Validation
class SemanticValidator : public ValidationStage {
public:
    std::string GetName() const override { return "SemanticValidator"; }
    std::string GetDescription() const override { return "Type checking and symbol resolution"; }
    ValidationResult Validate(const Patch& patch) override;
    
    void SetRepositoryIntelligence(class RawrXD::Repo::RepositoryIntelligence* repo);
    
private:
    RawrXD::Repo::RepositoryIntelligence* repo_ = nullptr;
};

// Stage 3: Style Validation
class StyleValidator : public ValidationStage {
public:
    std::string GetName() const override { return "StyleValidator"; }
    std::string GetDescription() const override { return "Code style and formatting checks"; }
    ValidationResult Validate(const Patch& patch) override;
    bool CanAutoFix() const override { return true; }
    Patch AutoFix(const Patch& patch) override;
};

// Stage 4: Impact Analysis
class ImpactValidator : public ValidationStage {
public:
    std::string GetName() const override { return "ImpactValidator"; }
    std::string GetDescription() const override { return "Analyze affected symbols and files"; }
    ValidationResult Validate(const Patch& patch) override;
    
    void SetRepositoryIntelligence(class RawrXD::Repo::RepositoryIntelligence* repo);
    
private:
    RawrXD::Repo::RepositoryIntelligence* repo_ = nullptr;
};

// Stage 5: Security Validation
class SecurityValidator : public ValidationStage {
public:
    std::string GetName() const override { return "SecurityValidator"; }
    std::string GetDescription() const override { return "Detect security vulnerabilities"; }
    ValidationResult Validate(const Patch& patch) override;
};

// Stage 6: Test Validation
class TestValidator : public ValidationStage {
public:
    std::string GetName() const override { return "TestValidator"; }
    std::string GetDescription() const override { return "Run affected unit tests"; }
    ValidationResult Validate(const Patch& patch) override;
    
    void SetBuildSystem(class BuildManager* build);
    
private:
    class BuildManager* build_ = nullptr;
};

// ============================================================================
// Patch Validator - Main Controller
// ============================================================================
class PatchValidator {
public:
    PatchValidator();
    ~PatchValidator();
    
    // Configuration
    void AddStage(std::unique_ptr<ValidationStage> stage);
    void RemoveStage(const std::string& name);
    void SetStageEnabled(const std::string& name, bool enabled);
    
    // Dependencies
    void SetRepositoryIntelligence(class RawrXD::Repo::RepositoryIntelligence* repo);
    void SetBuildManager(class BuildManager* build);
    
    // Validation
    ValidationResult Validate(const Patch& patch);
    ValidationResult ValidateFast(const Patch& patch);  // Skip expensive stages
    
    // Auto-fix
    Patch AutoFix(const Patch& patch);
    bool CanAutoFix(const Patch& patch) const;
    
    // Dry run
    ValidationResult DryRun(const Patch& patch);
    
    // Statistics
    nlohmann::json GetStatistics() const;
    
    // Preview
    std::optional<std::string> PreviewChanges(const Patch& patch, const std::string& filePath);
    
    // Conflict detection
    bool CanApplySafely(const Patch& patch);
    std::vector<Conflict> DetectConflicts(const Patch& patch);
    
    // Configuration
    void SetStrictMode(bool strict);
    void RequireTests(bool require);
    void SetPerformanceThreshold(float threshold);
    void EnableStyleChecks(bool enable);
    
    // Event callbacks
    using ValidationCallback = std::function<void(const std::string& stage, const ValidationResult& result)>;
    void SetValidationCallback(ValidationCallback cb);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Rollback Manager
// ============================================================================
class RollbackManager {
public:
    RollbackManager();
    ~RollbackManager();
    
    // Snapshot management
    std::string CreateSnapshot(const std::vector<std::string>& files);
    bool RestoreSnapshot(const std::string& snapshotId);
    void DeleteSnapshot(const std::string& snapshotId);
    
    // Patch-based rollback
    Patch CreateRollbackPatch(const Patch& appliedPatch);
    bool ApplyRollback(const Patch& rollbackPatch);
    
    // Transaction support
    void BeginTransaction();
    bool CommitTransaction();
    void RollbackTransaction();
    
    // History
    std::vector<std::string> GetSnapshotIds() const;
    nlohmann::json GetSnapshotInfo(const std::string& snapshotId) const;

private:
    std::map<std::string, std::map<std::string, std::string>> snapshots_;
    std::vector<Patch> transactionStack_;
    bool inTransaction_;
};

// ============================================================================
// Safe File Writer
// ============================================================================
class SafeFileWriter {
public:
    SafeFileWriter();
    ~SafeFileWriter();
    
    void SetRollbackManager(RollbackManager* rollback);
    void SetValidator(PatchValidator* validator);
    
    // Write operations
    bool WriteFile(const std::string& path, const std::string& content);
    bool ApplyPatch(const Patch& patch);
    bool ApplyEdits(const std::vector<SourceEdit>& edits);
    
    // Verification
    bool VerifyWritten(const std::string& path, const std::string& expected);
    
    // Rollback
    bool RollbackLast();
    bool RollbackTo(const std::string& snapshotId);

private:
    RollbackManager* rollback_ = nullptr;
    PatchValidator* validator_ = nullptr;
    std::vector<std::string> lastWrittenFiles_;
};

} // namespace Validation
} // namespace RawrXD
