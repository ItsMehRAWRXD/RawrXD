/**
 * ============================================================================
 * AI Debugger - Intelligent Debugging Assistant
 * ============================================================================
 * 
 * Features:
 * - Automatic breakpoint suggestions
 * - Variable state analysis
 * - Root cause analysis
 * - Fix suggestions with confidence scores
 * - Exception prediction
 * - Memory leak detection
 * 
 * Reference: VS Code Copilot Chat debugging
 * ============================================================================
 */

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <optional>
#include <functional>
#include <map>
#include <vector>
#include <optional>
#include <map>

namespace RawrXD {
namespace AI {

// Debug session analysis
struct DebugSession {
    std::string executablePath;
    std::vector<std::string> sourceFiles;
    std::map<std::string, std::string> variables;  // name -> value
    std::string currentFunction;
    int currentLine;
    std::string callStack;
    std::string lastException;
};

// Variable analysis
struct VariableAnalysis {
    std::string name;
    std::string type;
    std::string value;
    std::string predictedValue;  // What AI thinks it should be
    std::string anomaly;         // If different from expected
    float confidence;
    std::vector<std::string> relatedVariables;
};

// Breakpoint suggestion
struct BreakpointSuggestion {
    std::string filePath;
    int line;
    std::string condition;       // Optional condition
    std::string reason;          // Why this breakpoint
    float confidence;
    bool isExceptionBreakpoint;
};

// Root cause analysis
struct RootCauseAnalysis {
    std::string description;
    std::string probableCause;
    std::vector<std::string> evidence;
    std::vector<std::string> suggestedFixes;
    float confidence;
    int severity;  // 1-5
};

// Fix suggestion
struct DebugFixSuggestion {
    std::string description;
    std::string originalCode;
    std::string fixedCode;
    std::string explanation;
    float confidence;
    bool isVerified;  // AI verified the fix
    std::vector<std::string> testCases;
};

// Exception prediction
struct ExceptionPrediction {
    std::string exceptionType;
    std::string location;
    int line;
    float probability;
    float confidence;
    int lineNumber;
    std::string triggerCondition;
    std::string prevention;
};

class AIDebugger {
public:
    AIDebugger();
    ~AIDebugger();

    // Breakpoint intelligence
    std::vector<BreakpointSuggestion> suggestBreakpoints(
        const std::string& filePath,
        const std::string& code
    );
    
    std::vector<BreakpointSuggestion> suggestExceptionBreakpoints(
        const std::string& exceptionType
    );

    // Variable analysis
    std::vector<VariableAnalysis> analyzeVariables(
        const DebugSession& session
    );
    
    std::optional<VariableAnalysis> analyzeVariable(
        const DebugSession& session,
        const std::string& varName
    );

    // Root cause analysis
    std::optional<RootCauseAnalysis> analyzeCrash(
        const DebugSession& session,
        const std::string& crashInfo
    );
    
    std::optional<RootCauseAnalysis> analyzeHang(
        const DebugSession& session
    );
    
    std::optional<RootCauseAnalysis> analyzeMemoryIssue(
        const DebugSession& session,
        const std::string& memoryInfo
    );

    // Fix suggestions
    std::vector<DebugFixSuggestion> suggestFixes(
        const DebugSession& session,
        const RootCauseAnalysis& analysis
    );

    // Exception prediction
    std::vector<ExceptionPrediction> predictExceptions(
        const std::string& filePath,
        const std::string& code
    );

    // Natural language debugging
    std::string askDebugger(
        const DebugSession& session,
        const std::string& question
    );
    
    std::string explainVariable(
        const DebugSession& session,
        const std::string& varName
    );
    
    std::string explainCallStack(
        const DebugSession& session
    );

    // Memory analysis
    std::vector<std::string> detectMemoryLeaks(
        const DebugSession& session
    );
    
    std::vector<std::string> detectRaceConditions(
        const DebugSession& session
    );

    // Configuration
    void setModel(const std::string& modelName);
    void setAnalysisDepth(int depth);  // 1-5

private:
    std::string buildDebugPrompt(const DebugSession& session, 
                                  const std::string& task);
    std::vector<BreakpointSuggestion> parseBreakpointSuggestions(
        const std::string& response
    );
    
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

// Global instance
AIDebugger& GetAIDebugger();

} // namespace AI
} // namespace RawrXD
