/*===========================================================================
 * DebugAgentBridge.h
 * RawrXD IDE - Debugger to Agent Bridge
 * 
 * Transforms raw debugger events into structured agent contexts
 * Enables autonomous debug → diagnose → fix workflows
 *===========================================================================*/

#ifndef DEBUG_AGENT_BRIDGE_H
#define DEBUG_AGENT_BRIDGE_H

#include <windows.h>
#include <string>
#include <vector>
#include <cstdint>
#include <functional>
#include <memory>

namespace RawrXD {

/*===========================================================================
 * FORWARD DECLARATIONS
 *===========================================================================*/

struct DebugEvent;
struct RegisterSet;
struct StackFrame;
struct MemoryRange;

/*===========================================================================
 * AGENT DEBUG CONTEXT
 * 
 * Structured payload sent to agent for analysis
 *===========================================================================*/

enum class ExceptionSeverity {
    Info,       // Non-critical (breakpoint, single-step)
    Warning,    // Recoverable (access violation that might be handled)
    Critical    // Fatal (unhandled exception, stack overflow)
};

struct AgentRegisterState {
    std::string name;
    uint64_t value;
    bool modified;      // Changed since last breakpoint
    
    AgentRegisterState() : value(0), modified(false) {}
    AgentRegisterState(const std::string& n, uint64_t v, bool m = false)
        : name(n), value(v), modified(m) {}
};

struct AgentStackFrame {
    uint64_t returnAddress;
    std::string functionName;
    std::string sourceFile;
    uint32_t lineNumber;
    uint64_t framePointer;
    
    AgentStackFrame() : returnAddress(0), lineNumber(0), framePointer(0) {}
};

struct AgentMemorySnapshot {
    uint64_t baseAddress;
    std::vector<uint8_t> data;
    std::string description;  // "Stack top", "Exception address", etc.
    
    AgentMemorySnapshot() : baseAddress(0) {}
};

struct AgentSourceContext {
    std::string filePath;
    uint32_t lineNumber;
    std::vector<std::string> surroundingLines;  // ±5 lines around crash
    std::string currentFunction;
    std::string currentClass;  // If applicable
};

struct AgentDebugContext {
    // Exception info
    uint32_t exceptionCode;
    std::string exceptionName;
    ExceptionSeverity severity;
    uint64_t instructionAddress;
    std::string instructionDisassembly;  // If available
    
    // Module info
    std::string moduleName;
    std::string modulePath;
    uint64_t moduleBase;
    
    // Source location
    AgentSourceContext sourceContext;
    
    // Execution state
    uint32_t threadId;
    uint64_t timestamp;
    std::vector<AgentRegisterState> registers;
    std::vector<AgentStackFrame> callStack;
    
    // Memory snapshots
    std::vector<AgentMemorySnapshot> memorySnapshots;
    
    // Build configuration
    std::string buildConfiguration;  // "Debug", "Release", etc.
    std::string compilerVersion;
    std::vector<std::string> preprocessorDefines;
    
    // Historical context
    std::vector<std::string> recentLogMessages;  // Last N output lines
    uint32_t previousBreakpointCount;
    
    AgentDebugContext() 
        : exceptionCode(0)
        , severity(ExceptionSeverity::Info)
        , instructionAddress(0)
        , moduleBase(0)
        , threadId(0)
        , timestamp(0)
        , previousBreakpointCount(0) {}
};

/*===========================================================================
 * AGENT FIX PROPOSAL
 * 
 * Response from agent with proposed fix
 *===========================================================================*/

struct AgentCodePatch {
    std::string filePath;
    uint32_t lineNumber;
    std::string originalText;
    std::string replacementText;
    std::string description;
    float confidence;
    
    AgentCodePatch() : lineNumber(0), confidence(0.0f) {}
};

struct AgentFixProposal {
    std::string diagnosis;
    std::string rootCause;
    std::vector<AgentCodePatch> patches;
    float confidence;
    std::vector<std::string> explanation;  // Step-by-step reasoning
    std::vector<std::string> testSuggestions;
    
    // Actions the agent wants to take
    bool suggestBreakpoint;
    uint64_t suggestedBreakpointAddress;
    std::string suggestedBreakpointCondition;
    
    bool suggestWatchExpression;
    std::string watchExpression;
    
    AgentFixProposal() : confidence(0.0f), suggestBreakpoint(false), suggestWatchExpression(false) {}
};

/*===========================================================================
 * DEBUG AGENT BRIDGE
 *===========================================================================*/

enum class AgentTaskType {
    DebugRepair,        // Fix a crash/exception
    DebugOptimize,      // Performance issue
    DebugInvestigate,   // User asks "why is this happening?"
    BreakpointSuggest,  // Agent suggests where to break
    WatchSuggest,       // Agent suggests what to watch
    RegressionDetect    // Verify fix didn't break anything
};

struct AgentDebugRequest {
    AgentTaskType taskType;
    AgentDebugContext context;
    std::string userQuery;  // Optional: "Why did this crash?"
    std::vector<std::string> constraints;  // "Don't change public APIs", etc.
    
    AgentDebugRequest() : taskType(AgentTaskType::DebugRepair) {}
};

// Callback types
using AgentFixCallback = std::function<void(const AgentFixProposal& proposal)>;
using AgentProgressCallback = std::function<void(const std::string& status)>;

class DebugAgentBridge {
public:
    DebugAgentBridge();
    ~DebugAgentBridge();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsReady() const;
    
    // Event handlers (called from DebuggerService)
    void OnException(const DebugEvent& event);
    void OnBreakpointHit(const DebugEvent& event);
    void OnSingleStep(const DebugEvent& event);
    void OnProcessExit(const DebugEvent& event);
    
    // Context collection
    AgentDebugContext CaptureContext(uint32_t threadId, uint32_t exceptionCode);
    
    // Agent dispatch
    void DispatchToAgent(const AgentDebugRequest& request);
    void DispatchToAgentAsync(const AgentDebugRequest& request, AgentFixCallback callback);
    
    // Fix application
    bool ApplyFix(const AgentCodePatch& patch);
    bool ApplyFixes(const std::vector<AgentCodePatch>& patches);
    void PreviewFix(const AgentCodePatch& patch);  // Show diff without applying
    
    // Configuration
    void SetAutoFixEnabled(bool enabled) { m_autoFixEnabled = enabled; }
    void SetConfidenceThreshold(float threshold) { m_confidenceThreshold = threshold; }
    void SetMaxContextLines(uint32_t lines) { m_maxContextLines = lines; }
    
    // Callbacks
    void SetFixCallback(AgentFixCallback callback) { m_fixCallback = callback; }
    void SetProgressCallback(AgentProgressCallback callback) { m_progressCallback = callback; }
    
    // History
    std::vector<AgentDebugContext> GetRecentContexts(size_t count = 10) const;
    void ClearHistory();
    
    // Statistics
    struct Stats {
        uint32_t exceptionsHandled;
        uint32_t fixesProposed;
        uint32_t fixesApplied;
        uint32_t fixesRejected;
        float averageConfidence;
        uint64_t totalAnalysisTimeMs;
    };
    Stats GetStats() const;

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
    
    // Configuration
    bool m_autoFixEnabled;
    float m_confidenceThreshold;
    uint32_t m_maxContextLines;
    
    // Callbacks
    AgentFixCallback m_fixCallback;
    AgentProgressCallback m_progressCallback;
    
    // Context collection helpers
    AgentSourceContext CaptureSourceContext(uint64_t address, uint32_t line);
    std::vector<std::string> ReadSurroundingLines(const std::string& filePath, int targetLine, int contextLines);
    std::vector<AgentMemorySnapshot> CaptureMemorySnapshots(uint64_t exceptionAddr, uint64_t stackPtr);
    std::string DisassembleInstruction(uint64_t address);
    std::vector<std::string> CaptureRecentLogs(size_t count);
    
    // Agent communication
    void SendToInferenceEngine(const AgentDebugRequest& request);
    AgentFixProposal ParseAgentResponse(const std::string& response);
};

/*===========================================================================
 * AUTONOMOUS DEBUG SESSION
 * 
 * High-level orchestration of debug → fix → validate loop
 *===========================================================================*/

enum class AutonomousDebugState {
    Idle,
    Observing,      // Waiting for exception
    Analyzing,      // Agent processing
    Proposing,      // Fix ready for review
    Applying,       // Patch being applied
    Rebuilding,     // Build in progress
    Validating,     // Testing the fix
    Complete,       // Success
    Failed          // Could not fix
};

class AutonomousDebugSession {
public:
    AutonomousDebugSession(DebugAgentBridge* bridge);
    ~AutonomousDebugSession();
    
    // Session control
    void StartSession(const std::string& targetExecutable);
    void StopSession();
    
    // Configuration
    void SetAutoApplyThreshold(float confidence) { m_autoApplyThreshold = confidence; }
    void SetMaxAttempts(uint32_t attempts) { m_maxAttempts = attempts; }
    void EnableHumanApproval(bool enable) { m_humanApproval = enable; }
    
    // State
    AutonomousDebugState GetState() const { return m_state; }
    std::string GetStateDescription() const;
    
    // Progress
    uint32_t GetCurrentAttempt() const { return m_currentAttempt; }
    std::vector<AgentFixProposal> GetAttemptHistory() const { return m_attemptHistory; }
    
    // Actions
    void ApproveCurrentFix();
    void RejectCurrentFix();
    void RetryAnalysis();

private:
    DebugAgentBridge* m_bridge;
    AutonomousDebugState m_state;
    
    // Configuration
    float m_autoApplyThreshold;
    uint32_t m_maxAttempts;
    bool m_humanApproval;
    
    // Session state
    uint32_t m_currentAttempt;
    std::vector<AgentFixProposal> m_attemptHistory;
    AgentFixProposal m_currentProposal;
    
    // Event handlers
    void OnExceptionReceived(const AgentDebugContext& context);
    void OnFixReceived(const AgentFixProposal& proposal);
    void OnBuildComplete(bool success);
    void OnValidationComplete(bool passed);
    
    // State machine transitions
    void TransitionTo(AutonomousDebugState newState);
    void ExecuteCurrentState();
};

/*===========================================================================
 * UTILITY FUNCTIONS
 *===========================================================================*/

namespace DebugAgentUtils {
    // Format context for display
    std::string FormatContextSummary(const AgentDebugContext& context);
    std::string FormatFixProposal(const AgentFixProposal& proposal);
    
    // Exception code helpers
    std::string GetExceptionDescription(uint32_t code);
    ExceptionSeverity ClassifyException(uint32_t code);
    
    // Diff generation
    std::string GenerateDiff(const std::string& original, const std::string& modified);
    
    // Validation
    bool ValidatePatch(const AgentCodePatch& patch, std::string* error);
}

} // namespace RawrXD

#endif // DEBUG_AGENT_BRIDGE_H
