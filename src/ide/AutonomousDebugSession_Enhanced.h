/*===========================================================================
 * AutonomousDebugSession_Enhanced.h
 * Enhanced Autonomous Debug Session with Checkpoint/Rollback
 *===========================================================================*/

#ifndef AUTONOMOUS_DEBUG_SESSION_ENHANCED_H
#define AUTONOMOUS_DEBUG_SESSION_ENHANCED_H

#include "DebugAgentBridge.h"
#include "ValidationEngine.h"
#include <vector>
#include <memory>
#include <map>

namespace RawrXD {

/*===========================================================================
 * DEBUG CHECKPOINT
 *===========================================================================*/

struct RegisterSnapshot {
    uint64_t rax, rbx, rcx, rdx;
    uint64_t rsi, rdi, rbp, rsp;
    uint64_t r8, r9, r10, r11;
    uint64_t r12, r13, r14, r15;
    uint64_t rip;
    uint32_t eflags;
    
    RegisterSnapshot() : rax(0), rbx(0), rcx(0), rdx(0),
                         rsi(0), rdi(0), rbp(0), rsp(0),
                         r8(0), r9(0), r10(0), r11(0),
                         r12(0), r13(0), r14(0), r15(0),
                         rip(0), eflags(0) {}
};

struct StackSnapshot {
    uint64_t stackPointer;
    std::vector<uint8_t> stackData;
    std::vector<uint64_t> callStack;
    
    StackSnapshot() : stackPointer(0) {}
};

struct DebugCheckpoint {
    uint64_t id;
    uint64_t timestamp;
    
    // Source state
    std::string sourceHash;       // BLAKE3 of source files
    std::string binaryHash;       // Hash of compiled binary
    
    // Execution state
    RegisterSnapshot registers;
    StackSnapshot stack;
    uint64_t instructionPointer;
    
    // Crash context (if applicable)
    CrashSignature crashSignature;
    bool wasCrashed;
    
    // Patch info (if applied)
    std::string patchApplied;
    std::string patchDescription;
    float patchConfidence;
    
    // Validation results
    ValidationResult validationResult;
    
    // Parent checkpoint (for branching)
    uint64_t parentCheckpointId;
    
    DebugCheckpoint()
        : id(0)
        , timestamp(0)
        , instructionPointer(0)
        , wasCrashed(false)
        , patchConfidence(0.0f)
        , parentCheckpointId(0) {}
};

/*===========================================================================
 * ENHANCED AUTONOMOUS DEBUG SESSION
 *===========================================================================*/

enum class EnhancedDebugState {
    Idle,
    Observing,
    CapturedContext,
    GeneratingFix,
    ValidatingFix,
    ValidationFailed,
    ValidationPassed,
    ApplyingFix,
    FixApplied,
    FixFailed,
    RollingBack,
    Complete,
    MaxAttemptsReached
};

enum class FixOutcome {
    Unknown,
    Success,           // Fix applied, validation passed
    PartialSuccess,    // Fix applied but with warnings
    ValidationFailed,  // Fix failed validation
    Regression,        // Fix caused new issues
    RollbackSuccess,   // Successfully rolled back
    RollbackFailed     // Rollback failed (critical)
};

struct FixAttempt {
    uint32_t attemptNumber;
    DebugCheckpoint checkpointBefore;
    AgentFixProposal proposal;
    ValidationResult validation;
    FixOutcome outcome;
    std::string failureReason;
    uint64_t timestamp;
    uint64_t durationMs;
    
    FixAttempt() : attemptNumber(0), outcome(FixOutcome::Unknown), timestamp(0), durationMs(0) {}
};

class EnhancedAutonomousDebugSession {
public:
    EnhancedAutonomousDebugSession(DebugAgentBridge* bridge, ValidationEngine* validator);
    ~EnhancedAutonomousDebugSession();
    
    // Lifecycle
    void StartSession(const std::string& targetExecutable);
    void StopSession();
    bool IsActive() const;
    
    // Configuration
    void SetMaxAttempts(uint32_t maxAttempts) { m_maxAttempts = maxAttempts; }
    void SetAutoApplyThreshold(float threshold) { m_autoApplyThreshold = threshold; }
    void SetEnableHumanApproval(bool enable) { m_humanApproval = enable; }
    void SetEnableRollback(bool enable) { m_enableRollback = enable; }
    
    // State machine
    EnhancedDebugState GetState() const { return m_state; }
    std::string GetStateDescription() const;
    
    // Checkpoint management
    uint64_t CreateCheckpoint(const std::string& description);
    bool RollbackToCheckpoint(uint64_t checkpointId);
    bool RollbackToLastKnownGood();
    std::vector<DebugCheckpoint> GetCheckpointHistory() const;
    DebugCheckpoint GetCurrentCheckpoint() const;
    
    // Fix attempts
    std::vector<FixAttempt> GetFixHistory() const;
    FixAttempt GetCurrentAttempt() const { return m_currentAttempt; }
    uint32_t GetCurrentAttemptNumber() const { return m_attemptCount; }
    
    // Human interaction
    void ApproveCurrentFix();
    void RejectCurrentFix();
    void RequestAlternativeFix();
    void ForceRollback();
    
    // Statistics
    struct SessionStats {
        uint32_t totalAttempts;
        uint32_t successfulFixes;
        uint32_t failedValidations;
        uint32_t rollbacksPerformed;
        uint64_t totalSessionTimeMs;
        float averageFixConfidence;
        float successRate;
    };
    SessionStats GetStats() const;
    
    // Event callbacks
    using StateChangeCallback = std::function<void(EnhancedDebugState oldState, EnhancedDebugState newState)>;
    using FixProposedCallback = std::function<void(const AgentFixProposal& proposal)>;
    using ValidationCompleteCallback = std::function<void(const ValidationResult& result)>;
    
    void SetStateChangeCallback(StateChangeCallback cb) { m_stateCallback = cb; }
    void SetFixProposedCallback(FixProposedCallback cb) { m_fixProposedCallback = cb; }
    void SetValidationCompleteCallback(ValidationCompleteCallback cb) { m_validationCompleteCallback = cb; }

private:
    DebugAgentBridge* m_bridge;
    ValidationEngine* m_validator;
    
    // State machine
    EnhancedDebugState m_state;
    StateChangeCallback m_stateCallback;
    
    // Configuration
    uint32_t m_maxAttempts;
    float m_autoApplyThreshold;
    bool m_humanApproval;
    bool m_enableRollback;
    
    // Session data
    std::string m_targetExecutable;
    bool m_active;
    uint64_t m_sessionStartTime;
    uint32_t m_attemptCount;
    
    // Checkpoints
    std::map<uint64_t, DebugCheckpoint> m_checkpoints;
    uint64_t m_nextCheckpointId;
    uint64_t m_currentCheckpointId;
    uint64_t m_lastKnownGoodCheckpointId;
    
    // Fix attempts
    std::vector<FixAttempt> m_fixHistory;
    FixAttempt m_currentAttempt;
    
    // Callbacks
    FixProposedCallback m_fixProposedCallback;
    ValidationCompleteCallback m_validationCompleteCallback;
    
    // State machine execution
    void TransitionTo(EnhancedDebugState newState);
    void ExecuteCurrentState();
    
    // State handlers
    void OnEnterObserving();
    void OnEnterCapturedContext();
    void OnEnterGeneratingFix();
    void OnEnterValidatingFix();
    void OnEnterApplyingFix();
    void OnEnterRollingBack();
    void OnEnterComplete();
    
    // Event handlers
    void OnExceptionReceived(const AgentDebugContext& context);
    void OnFixGenerated(const AgentFixProposal& proposal);
    void OnValidationComplete(const ValidationResult& result);
    void OnBuildComplete(bool success);
    void OnFixApplied(bool success);
    
    // Helpers
    DebugCheckpoint CaptureCurrentCheckpoint(const std::string& description);
    bool ApplyFixWithValidation(const AgentCodePatch& patch);
    float CalculateRuntimeConfidence(const AgentFixProposal& proposal, const ValidationResult& validation);
    void LogAttempt(const FixAttempt& attempt);
};

/*===========================================================================
 * SESSION VISUALIZER
 *===========================================================================*/

class DebugSessionVisualizer {
public:
    // Generate visual representation of session
    static std::string GenerateTimeline(const std::vector<FixAttempt>& attempts);
    static std::string GenerateCheckpointGraph(const std::map<uint64_t, DebugCheckpoint>& checkpoints);
    static std::string GenerateConfidenceChart(const std::vector<FixAttempt>& attempts);
    
    // HTML report for CI/CD
    static std::string GenerateHtmlReport(const EnhancedAutonomousDebugSession::SessionStats& stats,
                                          const std::vector<FixAttempt>& attempts);
    
    // Console output
    static void PrintSessionSummary(const EnhancedAutonomousDebugSession* session);
    static void PrintCheckpointTree(const std::map<uint64_t, DebugCheckpoint>& checkpoints);
};

} // namespace RawrXD

#endif // AUTONOMOUS_DEBUG_SESSION_ENHANCED_H
