/*---------------------------------------------------------------------------------------------
 *  VAL-016 Repair Orchestrator
 *  Shared execution schema for autonomous repair (VAL-016.1, VAL-016.2, VAL-016.3)
 *--------------------------------------------------------------------------------------------*/

#pragma once

#include <string>
#include <vector>
#include <chrono>
#include <optional>
#include "nlohmann/json.hpp"

namespace RawrXD {
namespace VAL016 {

// ============================================================================
// FAILURE CLASSIFICATION (Shared with VAL-014)
// ============================================================================

enum class FailureCategory {
    NONE,
    TIMEOUT,
    COMPILE_ERROR,
    LINK_ERROR,
    TEST_FAILURE,
    CONFIGURE_ERROR,
    ENVIRONMENT_MISSING,
    ENVIRONMENT_MISCONFIGURED,
    UNKNOWN
};

std::string failureCategoryToString(FailureCategory cat);
FailureCategory stringToFailureCategory(const std::string& str);

// ============================================================================
// COMPILER DIAGNOSTIC (VAL-016.2+)
// ============================================================================

enum class DiagnosticSeverity {
    NOTE,
    WARNING,
    ERROR,
    FATAL
};

struct CompilerDiagnostic {
    std::string compiler;           // "MSVC", "GCC", "Clang"
    std::string file;               // Source file path
    int line;                       // Line number (1-based)
    int column;                     // Column number (1-based)
    std::string error_code;         // "C2143", "E0020", etc.
    DiagnosticSeverity severity;
    std::string message;            // Human-readable message
    std::string context;            // Surrounding code context
    
    nlohmann::json toJson() const;
    static CompilerDiagnostic fromJson(const nlohmann::json& j);
};

// ============================================================================
// EXECUTION RESULT (Shared Schema)
// ============================================================================

struct ExecutionResult {
    std::string tool;
    std::string command;
    int exitCode;
    int64_t durationMs;
    std::string stdOut;
    std::string stdErr;
    bool timedOut;
    FailureCategory failureCategory;
    bool recoverable;
    std::string failureReason;
    std::vector<CompilerDiagnostic> diagnostics;  // Populated for COMPILE_ERROR
    
    nlohmann::json toJson() const;
    static ExecutionResult fromJson(const nlohmann::json& j);
};

// ============================================================================
// REPAIR ACTION TYPES
// ============================================================================

enum class RepairActionType {
    NONE,
    CREATE_DIRECTORY,
    INSTALL_TOOL,
    APPLY_PATCH,
    RECONFIGURE,
    RETRY_WITH_TIMEOUT,
    INSERT_TOKEN,
    DELETE_TOKEN,
    REPLACE_TOKEN,
    ADD_INCLUDE
};

std::string repairActionToString(RepairActionType action);

// ============================================================================
// REPAIR PATCH (VAL-016.2+)
// ============================================================================

struct RepairPatch {
    std::string file;               // Target file path
    size_t offset;                  // Byte offset in file
    int line;                       // Line number for human reference
    int column;                     // Column number for human reference
    std::string before;             // Text to replace
    std::string after;              // Replacement text
    float confidence;               // Repair confidence (0.0 - 1.0)
    std::string reason;             // Why this repair was chosen
    
    nlohmann::json toJson() const;
    static RepairPatch fromJson(const nlohmann::json& j);
    
    // Generate unified diff format
    std::string toDiffFormat() const;
};

// ============================================================================
// REPAIR STEP
// ============================================================================

struct RepairStep {
    int stepNumber;
    RepairActionType action;
    std::string target;
    std::string description;
    double confidence;
    std::string reason;
    std::optional<RepairPatch> patch;  // For source-level repairs
    
    nlohmann::json toJson() const;
    static RepairStep fromJson(const nlohmann::json& j);
};

// ============================================================================
// REPAIR PLAN
// ============================================================================

struct RepairPlan {
    std::string planId;
    FailureCategory targetFailure;
    std::vector<RepairStep> steps;
    double overallConfidence;
    std::string generatedBy;        // "RuleBased", "LLM", "Hybrid"
    
    nlohmann::json toJson() const;
    static RepairPlan fromJson(const nlohmann::json& j);
};

// ============================================================================
// DIAGNOSIS
// ============================================================================

struct Diagnosis {
    FailureCategory category;
    std::string reason;
    bool recoverable;
    std::vector<CompilerDiagnostic> diagnostics;
    std::string recommendedAction;
    
    nlohmann::json toJson() const;
    static Diagnosis fromJson(const nlohmann::json& j);
};

// ============================================================================
// REPAIR ATTEMPT
// ============================================================================

struct RepairAttempt {
    int attemptNumber;
    std::string timestamp;
    RepairPlan plan;
    bool success;
    std::string result;
    int64_t durationMs;
    
    nlohmann::json toJson() const;
};

// ============================================================================
// REPAIR LIFECYCLE
// ============================================================================

enum class RepairState {
    IDLE,
    FAILURE_INJECTED,
    EXECUTING,
    FAILED,
    DIAGNOSING,
    PLANNING,
    REPAIRING,
    VERIFYING,
    SUCCESS,
    ESCALATED
};

std::string repairStateToString(RepairState state);

struct RepairLifecycle {
    RepairState currentState;
    std::vector<std::pair<RepairState, std::string>> stateHistory;
    int retryCount;
    std::string currentPhase;
    
    void transition(RepairState newState, const std::string& timestamp);
    nlohmann::json toJson() const;
};

// ============================================================================
// PROCESS EXECUTOR (Shared with VAL-014)
// ============================================================================

class ProcessExecutor {
public:
    struct Config {
        uint32_t timeoutMs = 60000;
        bool captureStderr = true;
        bool captureStdout = true;
    };
    
    ExecutionResult execute(const std::string& tool, const std::string& command, 
                           const Config& config = {});
};

// ============================================================================
// DIAGNOSTIC PARSER
// ============================================================================

class DiagnosticParser {
public:
    // Parse MSVC compiler output
    std::vector<CompilerDiagnostic> parseMSVC(const std::string& output, 
                                               const std::string& sourceFile);
    
    // Parse GCC/Clang output
    std::vector<CompilerDiagnostic> parseGCC(const std::string& output,
                                              const std::string& sourceFile);
    
    // Auto-detect format and parse
    std::vector<CompilerDiagnostic> parse(const std::string& output,
                                           const std::string& sourceFile,
                                           const std::string& compilerHint = "");
};

// ============================================================================
// REPAIR ENGINE
// ============================================================================

class RepairEngine {
public:
    // Generate repair plan from execution failure
    RepairPlan generatePlan(const ExecutionResult& failure);
    
    // Execute a repair step
    ExecutionResult executeRepair(const RepairStep& step, ProcessExecutor& executor);
    
    // Apply a patch to source file
    bool applyPatch(const RepairPatch& patch);
    
    // Verify repair by re-execution
    bool verifyRepair(const ExecutionResult& retryResult);
    
private:
    // Known repair patterns
    std::optional<RepairPlan> tryMissingSemicolon(const CompilerDiagnostic& diag);
    std::optional<RepairPlan> tryMissingBrace(const CompilerDiagnostic& diag);
    std::optional<RepairPlan> tryMissingInclude(const CompilerDiagnostic& diag);
    std::optional<RepairPlan> tryUndefinedVariable(const CompilerDiagnostic& diag);
    std::optional<RepairPlan> tryUndefinedReference(const CompilerDiagnostic& diag);
};

// ============================================================================
// EVIDENCE RECORDER (VAL-016 Schema)
// ============================================================================

class EvidenceRecorder {
public:
    explicit EvidenceRecorder(const std::string& basePath);
    
    void beginTrace(const std::string& goal);
    void recordFailureInjection(const std::string& description);
    void recordExecutionAttempt(const ExecutionResult& result, int attemptNumber);
    void recordDiagnosis(const Diagnosis& diagnosis);
    void recordRepairPlan(const RepairPlan& plan);
    void recordRepairExecution(const RepairStep& step, const ExecutionResult& result);
    void recordVerification(const ExecutionResult& result, bool success);
    void endTrace(bool overallSuccess);
    
    void saveTrace();
    void saveExecutionResult(const ExecutionResult& result, const std::string& filename);
    void saveCompilerOutput(const std::string& output, const std::string& filename);
    void saveDiagnostics(const std::vector<CompilerDiagnostic>& diags);
    void saveRepairPlan(const RepairPlan& plan);
    void savePatch(const RepairPatch& patch);
    void saveRepairHistory(const RepairAttempt& attempt);
    void generateCompletionJson(const std::string& path, int exitCode, bool repaired);
    
    std::string getTimestamp() const;
    std::string getBasePath() const { return basePath_; }
    
private:
    std::string basePath_;
    nlohmann::json trace_;
    std::chrono::steady_clock::time_point startTime_;
};

// ============================================================================
// REPAIR ORCHESTRATOR
// ============================================================================

class RepairOrchestrator {
public:
    RepairOrchestrator(const std::string& evidenceBasePath);
    
    // Main repair loop
    bool executeRepairLoop(const std::string& goal);
    
    // Phase handlers
    bool injectFailure();
    ExecutionResult executeBuild();
    Diagnosis diagnoseFailure(const ExecutionResult& failure);
    RepairPlan generateRepairPlan(const Diagnosis& diagnosis);
    bool executeRepair(const RepairPlan& plan);
    bool verifyRepair();
    
    // State access
    RepairState getState() const { return lifecycle_.currentState; }
    const RepairLifecycle& getLifecycle() const { return lifecycle_; }
    
private:
    EvidenceRecorder recorder_;
    ProcessExecutor executor_;
    RepairEngine repairEngine_;
    DiagnosticParser diagnosticParser_;
    RepairLifecycle lifecycle_;
    int attemptCount_;
    
    std::string currentSourceFile_;
    std::string currentBuildCommand_;
};

} // namespace VAL016
} // namespace RawrXD
