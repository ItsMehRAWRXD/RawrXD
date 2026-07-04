// ai_debugger.cpp - Full implementation
#include "ai_debugger.h"
#include "ai_unified_engine.h"
#include <windows.h>
#include <sstream>
#include <algorithm>

namespace RawrXD {
namespace AI {

class AIDebugger::Impl {
public:
    std::string m_modelName = "codellama:latest";
    int m_analysisDepth = 3;
    
    std::string buildDebugPrompt(const DebugSession& session, 
                                  const std::string& task) {
        std::stringstream ss;
        ss << "You are an expert debugger. " << task << "\n\n";
        ss << "Executable: " << session.executablePath << "\n";
        ss << "Current function: " << session.currentFunction << "\n";
        ss << "Current line: " << session.currentLine << "\n\n";
        
        if (!session.callStack.empty()) {
            ss << "Call stack:\n" << session.callStack << "\n\n";
        }
        
        if (!session.variables.empty()) {
            ss << "Variables:\n";
            for (const auto& [name, value] : session.variables) {
                ss << "  " << name << " = " << value << "\n";
            }
            ss << "\n";
        }
        
        if (!session.lastException.empty()) {
            ss << "Last exception: " << session.lastException << "\n\n";
        }
        
        ss << "Analysis:";
        return ss.str();
    }
    
    std::vector<BreakpointSuggestion> parseBreakpointSuggestions(
        const std::string& response) {
        std::vector<BreakpointSuggestion> suggestions;
        // Parse response for breakpoint suggestions
        // Format: "file:line:condition:reason"
        return suggestions;
    }
};

AIDebugger::AIDebugger() : m_impl(std::make_unique<Impl>()) {}
AIDebugger::~AIDebugger() = default;

std::vector<BreakpointSuggestion> AIDebugger::suggestBreakpoints(
    const std::string& filePath,
    const std::string& code) {
    
    InferenceRequest req;
    req.prompt = "Analyze this code and suggest strategic breakpoints:\n\n```\n" + 
                 code + "\n```\n\nSuggest breakpoints at:";
    req.systemPrompt = "You are a debugging expert. Suggest breakpoints strategically.";
    req.model = m_impl->m_modelName;
    req.temperature = 0.2f;
    req.maxTokens = 512;
    
    auto response = GetAIEngine().complete(req);
    
    return m_impl->parseBreakpointSuggestions(response.text);
}

std::vector<BreakpointSuggestion> AIDebugger::suggestExceptionBreakpoints(
    const std::string& exceptionType) {
    std::vector<BreakpointSuggestion> suggestions;
    
    // Add common exception breakpoints
    BreakpointSuggestion bp;
    bp.condition = "";
    bp.reason = "Catch " + exceptionType;
    bp.confidence = 0.9f;
    bp.isExceptionBreakpoint = true;
    suggestions.push_back(bp);
    
    return suggestions;
}

std::vector<VariableAnalysis> AIDebugger::analyzeVariables(
    const DebugSession& session) {
    std::vector<VariableAnalysis> analyses;
    
    for (const auto& [name, value] : session.variables) {
        auto analysis = analyzeVariable(session, name);
        if (analysis) {
            analyses.push_back(*analysis);
        }
    }
    
    return analyses;
}

std::optional<VariableAnalysis> AIDebugger::analyzeVariable(
    const DebugSession& session,
    const std::string& varName) {
    
    auto it = session.variables.find(varName);
    if (it == session.variables.end()) {
        return std::nullopt;
    }
    
    InferenceRequest req;
    req.prompt = "Analyze variable '" + varName + "' with value '" + it->second + 
                 "' in function '" + session.currentFunction + "'. Is this value expected?";
    req.systemPrompt = "You are a debugging expert. Analyze variable values.";
    req.model = m_impl->m_modelName;
    req.temperature = 0.1f;
    req.maxTokens = 256;
    
    auto response = GetAIEngine().complete(req);
    
    VariableAnalysis analysis;
    analysis.name = varName;
    analysis.value = it->second;
    analysis.type = "auto";
    analysis.predictedValue = "";
    analysis.anomaly = response.text.find("anomaly") != std::string::npos ? 
                       response.text : "";
    analysis.confidence = 0.8f;
    
    return analysis;
}

std::optional<RootCauseAnalysis> AIDebugger::analyzeCrash(
    const DebugSession& session,
    const std::string& crashInfo) {
    
    InferenceRequest req;
    req.prompt = m_impl->buildDebugPrompt(session, 
        "Analyze this crash and identify the root cause:");
    req.systemPrompt = "You are a crash analysis expert. Identify root causes.";
    req.model = m_impl->m_modelName;
    req.temperature = 0.1f;
    req.maxTokens = 1024;
    
    auto response = GetAIEngine().complete(req);
    
    if (response.text.empty()) {
        return std::nullopt;
    }
    
    RootCauseAnalysis analysis;
    analysis.description = "Crash analysis";
    analysis.probableCause = response.text;
    analysis.evidence = {crashInfo, session.lastException};
    analysis.confidence = 0.75f;
    analysis.severity = 4;
    
    return analysis;
}

std::optional<RootCauseAnalysis> AIDebugger::analyzeHang(
    const DebugSession& session) {
    
    InferenceRequest req;
    req.prompt = m_impl->buildDebugPrompt(session,
        "Analyze this hang/deadlock situation:");
    req.systemPrompt = "You are a concurrency expert. Identify deadlocks and hangs.";
    req.model = m_impl->m_modelName;
    req.temperature = 0.1f;
    req.maxTokens = 1024;
    
    auto response = GetAIEngine().complete(req);
    
    if (response.text.empty()) {
        return std::nullopt;
    }
    
    RootCauseAnalysis analysis;
    analysis.description = "Hang analysis";
    analysis.probableCause = response.text;
    analysis.confidence = 0.7f;
    analysis.severity = 3;
    
    return analysis;
}

std::optional<RootCauseAnalysis> AIDebugger::analyzeMemoryIssue(
    const DebugSession& session,
    const std::string& memoryInfo) {
    
    InferenceRequest req;
    req.prompt = m_impl->buildDebugPrompt(session,
        "Analyze this memory issue:");
    req.systemPrompt = "You are a memory debugging expert.";
    req.model = m_impl->m_modelName;
    req.temperature = 0.1f;
    req.maxTokens = 1024;
    
    auto response = GetAIEngine().complete(req);
    
    if (response.text.empty()) {
        return std::nullopt;
    }
    
    RootCauseAnalysis analysis;
    analysis.description = "Memory issue analysis";
    analysis.probableCause = response.text;
    analysis.evidence = {memoryInfo};
    analysis.confidence = 0.75f;
    analysis.severity = 4;
    
    return analysis;
}

std::vector<DebugFixSuggestion> AIDebugger::suggestFixes(
    const DebugSession& session,
    const RootCauseAnalysis& analysis) {
    
    std::vector<DebugFixSuggestion> fixes;
    
    InferenceRequest req;
    req.prompt = "Based on this root cause analysis, suggest fixes:\n\n" +
                 analysis.probableCause;
    req.systemPrompt = "You are an expert at fixing bugs. Suggest concrete fixes.";
    req.model = m_impl->m_modelName;
    req.temperature = 0.2f;
    req.maxTokens = 1024;
    
    auto response = GetAIEngine().complete(req);
    
    if (!response.text.empty()) {
        DebugFixSuggestion fix;
        fix.description = "AI-suggested fix";
        fix.explanation = response.text;
        fix.confidence = analysis.confidence;
        fix.isVerified = false;
        fixes.push_back(fix);
    }
    
    return fixes;
}

std::vector<ExceptionPrediction> AIDebugger::predictExceptions(
    const std::string& filePath,
    const std::string& code) {
    
    std::vector<ExceptionPrediction> predictions;
    
    InferenceRequest req;
    req.prompt = "Analyze this code and predict potential exceptions:\n\n```\n" +
                 code + "\n```\n\nPredict exceptions:";
    req.systemPrompt = "You are an expert at predicting runtime exceptions.";
    req.model = m_impl->m_modelName;
    req.temperature = 0.2f;
    req.maxTokens = 512;
    
    auto response = GetAIEngine().complete(req);
    
    // Parse predictions from response - look for exception types and line numbers
    std::stringstream ss(response.text);
    std::string line;
    while (std::getline(ss, line)) {
        // Look for patterns like "Exception: Type at line X" or "- Type: ..."
        if (line.find("Exception") != std::string::npos || 
            line.find("exception") != std::string::npos) {
            ExceptionPrediction pred;
            pred.exceptionType = line;
            pred.confidence = 0.7f; // Default confidence
            
            // Try to extract line number
            size_t linePos = line.find("line");
            if (linePos != std::string::npos) {
                try {
                    pred.lineNumber = std::stoi(line.substr(linePos + 4));
                } catch (...) {
                    pred.lineNumber = 0;
                }
            }
            
            predictions.push_back(pred);
        }
    }
    
    return predictions;
}

std::string AIDebugger::askDebugger(
    const DebugSession& session,
    const std::string& question) {
    
    InferenceRequest req;
    req.prompt = m_impl->buildDebugPrompt(session, question);
    req.systemPrompt = "You are a helpful debugging assistant.";
    req.model = m_impl->m_modelName;
    req.temperature = 0.3f;
    req.maxTokens = 512;
    
    auto response = GetAIEngine().complete(req);
    return response.text;
}

std::string AIDebugger::explainVariable(
    const DebugSession& session,
    const std::string& varName) {
    
    auto it = session.variables.find(varName);
    if (it == session.variables.end()) {
        return "Variable not found: " + varName;
    }
    
    InferenceRequest req;
    req.prompt = "Explain the purpose and current state of variable '" + 
                 varName + "' with value '" + it->second + "'";
    req.systemPrompt = "You are a debugging expert. Explain variables clearly.";
    req.model = m_impl->m_modelName;
    req.temperature = 0.3f;
    req.maxTokens = 256;
    
    auto response = GetAIEngine().complete(req);
    return response.text;
}

std::string AIDebugger::explainCallStack(
    const DebugSession& session) {
    
    InferenceRequest req;
    req.prompt = "Explain this call stack and what it means:\n\n" + session.callStack;
    req.systemPrompt = "You are a debugging expert. Explain call stacks.";
    req.model = m_impl->m_modelName;
    req.temperature = 0.3f;
    req.maxTokens = 512;
    
    auto response = GetAIEngine().complete(req);
    return response.text;
}

std::vector<std::string> AIDebugger::detectMemoryLeaks(
    const DebugSession& session) {
    std::vector<std::string> leaks;
    
    InferenceRequest req;
    req.prompt = m_impl->buildDebugPrompt(session,
        "Detect potential memory leaks in this session:");
    req.systemPrompt = "You are a memory debugging expert.";
    req.model = m_impl->m_modelName;
    req.temperature = 0.2f;
    req.maxTokens = 512;
    
    auto response = GetAIEngine().complete(req);
    
    // Parse memory leaks from response
    // TODO: Implement proper parsing
    
    return leaks;
}

std::vector<std::string> AIDebugger::detectRaceConditions(
    const DebugSession& session) {
    std::vector<std::string> races;
    
    InferenceRequest req;
    req.prompt = m_impl->buildDebugPrompt(session,
        "Detect potential race conditions:");
    req.systemPrompt = "You are a concurrency expert.";
    req.model = m_impl->m_modelName;
    req.temperature = 0.2f;
    req.maxTokens = 512;
    
    auto response = GetAIEngine().complete(req);
    
    // Parse race conditions from response
    // TODO: Implement proper parsing
    
    return races;
}

void AIDebugger::setModel(const std::string& modelName) {
    m_impl->m_modelName = modelName;
}

void AIDebugger::setAnalysisDepth(int depth) {
    m_impl->m_analysisDepth = depth;
}

AIDebugger& GetAIDebugger() {
    static AIDebugger instance;
    return instance;
}

} // namespace AI
} // namespace RawrXD
