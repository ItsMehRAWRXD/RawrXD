/*---------------------------------------------------------------------------------------------
 *  VAL-016 Repair Orchestrator Implementation
 *--------------------------------------------------------------------------------------------*/

#include "val016_repair_orchestrator.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <regex>
#include <filesystem>
#include <array>

namespace RawrXD {
namespace VAL016 {

// ============================================================================
// FAILURE CATEGORY
// ============================================================================

std::string failureCategoryToString(FailureCategory cat) {
    switch (cat) {
        case FailureCategory::NONE: return "None";
        case FailureCategory::TIMEOUT: return "Timeout";
        case FailureCategory::COMPILE_ERROR: return "CompileError";
        case FailureCategory::LINK_ERROR: return "LinkError";
        case FailureCategory::TEST_FAILURE: return "TestFailure";
        case FailureCategory::CONFIGURE_ERROR: return "ConfigureError";
        case FailureCategory::ENVIRONMENT_MISSING: return "EnvironmentMissing";
        case FailureCategory::ENVIRONMENT_MISCONFIGURED: return "EnvironmentMisconfigured";
        default: return "Unknown";
    }
}

FailureCategory stringToFailureCategory(const std::string& str) {
    if (str == "None") return FailureCategory::NONE;
    if (str == "Timeout") return FailureCategory::TIMEOUT;
    if (str == "CompileError") return FailureCategory::COMPILE_ERROR;
    if (str == "LinkError") return FailureCategory::LINK_ERROR;
    if (str == "TestFailure") return FailureCategory::TEST_FAILURE;
    if (str == "ConfigureError") return FailureCategory::CONFIGURE_ERROR;
    if (str == "EnvironmentMissing") return FailureCategory::ENVIRONMENT_MISSING;
    if (str == "EnvironmentMisconfigured") return FailureCategory::ENVIRONMENT_MISCONFIGURED;
    return FailureCategory::UNKNOWN;
}

// ============================================================================
// COMPILER DIAGNOSTIC
// ============================================================================

nlohmann::json CompilerDiagnostic::toJson() const {
    nlohmann::json j;
    j["compiler"] = compiler;
    j["file"] = file;
    j["line"] = line;
    j["column"] = column;
    j["error_code"] = error_code;
    j["severity"] = (severity == DiagnosticSeverity::ERROR) ? "error" :
                    (severity == DiagnosticSeverity::WARNING) ? "warning" :
                    (severity == DiagnosticSeverity::FATAL) ? "fatal" : "note";
    j["message"] = message;
    j["context"] = context;
    return j;
}

CompilerDiagnostic CompilerDiagnostic::fromJson(const nlohmann::json& j) {
    CompilerDiagnostic d;
    d.compiler = j.value("compiler", "");
    d.file = j.value("file", "");
    d.line = j.value("line", 0);
    d.column = j.value("column", 0);
    d.error_code = j.value("error_code", "");
    std::string sev = j.value("severity", "error");
    d.severity = (sev == "error") ? DiagnosticSeverity::ERROR :
                 (sev == "warning") ? DiagnosticSeverity::WARNING :
                 (sev == "fatal") ? DiagnosticSeverity::FATAL : DiagnosticSeverity::NOTE;
    d.message = j.value("message", "");
    d.context = j.value("context", "");
    return d;
}

// ============================================================================
// EXECUTION RESULT
// ============================================================================

nlohmann::json ExecutionResult::toJson() const {
    nlohmann::json j;
    j["tool"] = tool;
    j["command"] = command;
    j["exit_code"] = exitCode;
    j["duration_ms"] = durationMs;
    j["stdout"] = stdOut;
    j["stderr"] = stdErr;
    j["timed_out"] = timedOut;
    j["failure_category"] = failureCategoryToString(failureCategory);
    j["recoverable"] = recoverable;
    j["failure_reason"] = failureReason;
    j["diagnostics"] = nlohmann::json::array();
    for (const auto& d : diagnostics) {
        j["diagnostics"].push_back(d.toJson());
    }
    return j;
}

ExecutionResult ExecutionResult::fromJson(const nlohmann::json& j) {
    ExecutionResult r;
    r.tool = j.value("tool", "");
    r.command = j.value("command", "");
    r.exitCode = j.value("exit_code", -1);
    r.durationMs = j.value("duration_ms", 0);
    r.stdOut = j.value("stdout", "");
    r.stdErr = j.value("stderr", "");
    r.timedOut = j.value("timed_out", false);
    r.failureCategory = stringToFailureCategory(j.value("failure_category", "Unknown"));
    r.recoverable = j.value("recoverable", false);
    r.failureReason = j.value("failure_reason", "");
    if (j.contains("diagnostics")) {
        for (const auto& d : j["diagnostics"]) {
            r.diagnostics.push_back(CompilerDiagnostic::fromJson(d));
        }
    }
    return r;
}

// ============================================================================
// REPAIR ACTION
// ============================================================================

std::string repairActionToString(RepairActionType action) {
    switch (action) {
        case RepairActionType::NONE: return "None";
        case RepairActionType::CREATE_DIRECTORY: return "CreateDirectory";
        case RepairActionType::INSTALL_TOOL: return "InstallTool";
        case RepairActionType::APPLY_PATCH: return "ApplyPatch";
        case RepairActionType::RECONFIGURE: return "Reconfigure";
        case RepairActionType::RETRY_WITH_TIMEOUT: return "RetryWithTimeout";
        case RepairActionType::INSERT_TOKEN: return "InsertToken";
        case RepairActionType::DELETE_TOKEN: return "DeleteToken";
        case RepairActionType::REPLACE_TOKEN: return "ReplaceToken";
        case RepairActionType::ADD_INCLUDE: return "AddInclude";
        default: return "Unknown";
    }
}

// ============================================================================
// REPAIR PATCH
// ============================================================================

nlohmann::json RepairPatch::toJson() const {
    nlohmann::json j;
    j["file"] = file;
    j["offset"] = offset;
    j["line"] = line;
    j["column"] = column;
    j["before"] = before;
    j["after"] = after;
    j["confidence"] = confidence;
    j["reason"] = reason;
    return j;
}

RepairPatch RepairPatch::fromJson(const nlohmann::json& j) {
    RepairPatch p;
    p.file = j.value("file", "");
    p.offset = j.value("offset", 0);
    p.line = j.value("line", 0);
    p.column = j.value("column", 0);
    p.before = j.value("before", "");
    p.after = j.value("after", "");
    p.confidence = j.value("confidence", 0.0f);
    p.reason = j.value("reason", "");
    return p;
}

std::string RepairPatch::toDiffFormat() const {
    std::ostringstream oss;
    oss << "--- a/" << file << "\n";
    oss << "+++ b/" << file << "\n";
    oss << "@@ -" << line << "," << 1 << " +" << line << "," << 1 << " @@\n";
    oss << "-" << before << "\n";
    oss << "+" << after << "\n";
    return oss.str();
}

// ============================================================================
// REPAIR STEP
// ============================================================================

nlohmann::json RepairStep::toJson() const {
    nlohmann::json j;
    j["step_number"] = stepNumber;
    j["action"] = repairActionToString(action);
    j["target"] = target;
    j["description"] = description;
    j["confidence"] = confidence;
    j["reason"] = reason;
    if (patch.has_value()) {
        j["patch"] = patch->toJson();
    }
    return j;
}

RepairStep RepairStep::fromJson(const nlohmann::json& j) {
    RepairStep s;
    s.stepNumber = j.value("step_number", 0);
    // Parse action string back to enum
    std::string actionStr = j.value("action", "None");
    s.action = RepairActionType::NONE; // Default
    s.target = j.value("target", "");
    s.description = j.value("description", "");
    s.confidence = j.value("confidence", 0.0);
    s.reason = j.value("reason", "");
    if (j.contains("patch")) {
        s.patch = RepairPatch::fromJson(j["patch"]);
    }
    return s;
}

// ============================================================================
// REPAIR PLAN
// ============================================================================

nlohmann::json RepairPlan::toJson() const {
    nlohmann::json j;
    j["plan_id"] = planId;
    j["target_failure"] = failureCategoryToString(targetFailure);
    j["overall_confidence"] = overallConfidence;
    j["generated_by"] = generatedBy;
    j["steps"] = nlohmann::json::array();
    for (const auto& step : steps) {
        j["steps"].push_back(step.toJson());
    }
    return j;
}

RepairPlan RepairPlan::fromJson(const nlohmann::json& j) {
    RepairPlan p;
    p.planId = j.value("plan_id", "");
    p.targetFailure = stringToFailureCategory(j.value("target_failure", "Unknown"));
    p.overallConfidence = j.value("overall_confidence", 0.0);
    p.generatedBy = j.value("generated_by", "Unknown");
    if (j.contains("steps")) {
        for (const auto& s : j["steps"]) {
            p.steps.push_back(RepairStep::fromJson(s));
        }
    }
    return p;
}

// ============================================================================
// DIAGNOSIS
// ============================================================================

nlohmann::json Diagnosis::toJson() const {
    nlohmann::json j;
    j["category"] = failureCategoryToString(category);
    j["reason"] = reason;
    j["recoverable"] = recoverable;
    j["diagnostics"] = nlohmann::json::array();
    for (const auto& d : diagnostics) {
        j["diagnostics"].push_back(d.toJson());
    }
    j["recommended_action"] = recommendedAction;
    return j;
}

Diagnosis Diagnosis::fromJson(const nlohmann::json& j) {
    Diagnosis d;
    d.category = stringToFailureCategory(j.value("category", "Unknown"));
    d.reason = j.value("reason", "");
    d.recoverable = j.value("recoverable", false);
    if (j.contains("diagnostics")) {
        for (const auto& diag : j["diagnostics"]) {
            d.diagnostics.push_back(CompilerDiagnostic::fromJson(diag));
        }
    }
    d.recommendedAction = j.value("recommended_action", "");
    return d;
}

// ============================================================================
// REPAIR ATTEMPT
// ============================================================================

nlohmann::json RepairAttempt::toJson() const {
    nlohmann::json j;
    j["attempt_number"] = attemptNumber;
    j["timestamp"] = timestamp;
    j["plan"] = plan.toJson();
    j["success"] = success;
    j["result"] = result;
    j["duration_ms"] = durationMs;
    return j;
}

// ============================================================================
// REPAIR LIFECYCLE
// ============================================================================

std::string repairStateToString(RepairState state) {
    switch (state) {
        case RepairState::IDLE: return "Idle";
        case RepairState::FAILURE_INJECTED: return "FailureInjected";
        case RepairState::EXECUTING: return "Executing";
        case RepairState::FAILED: return "Failed";
        case RepairState::DIAGNOSING: return "Diagnosing";
        case RepairState::PLANNING: return "Planning";
        case RepairState::REPAIRING: return "Repairing";
        case RepairState::VERIFYING: return "Verifying";
        case RepairState::SUCCESS: return "Success";
        case RepairState::ESCALATED: return "Escalated";
        default: return "Unknown";
    }
}

void RepairLifecycle::transition(RepairState newState, const std::string& timestamp) {
    currentState = newState;
    stateHistory.emplace_back(newState, timestamp);
}

nlohmann::json RepairLifecycle::toJson() const {
    nlohmann::json j;
    j["current_state"] = repairStateToString(currentState);
    j["retry_count"] = retryCount;
    j["current_phase"] = currentPhase;
    j["history"] = nlohmann::json::array();
    for (const auto& [state, timestamp] : stateHistory) {
        nlohmann::json entry;
        entry["state"] = repairStateToString(state);
        entry["timestamp"] = timestamp;
        j["history"].push_back(entry);
    }
    return j;
}

// ============================================================================
// PROCESS EXECUTOR
// ============================================================================

ExecutionResult ProcessExecutor::execute(const std::string& tool, const std::string& command,
                                        const Config& config) {
    ExecutionResult result;
    result.tool = tool;
    result.command = command;
    
    auto start = std::chrono::steady_clock::now();
    
    std::string fullCommand = command;
    if (config.captureStderr) {
        fullCommand += " 2>&1";
    }
    
    FILE* pipe = _popen(fullCommand.c_str(), "r");
    if (!pipe) {
        result.exitCode = -1;
        result.failureCategory = FailureCategory::ENVIRONMENT_MISSING;
        result.failureReason = "Failed to launch process";
        result.recoverable = false;
        return result;
    }
    
    std::string output;
    std::array<char, 4096> buffer;
    auto deadline = start + std::chrono::milliseconds(config.timeoutMs);
    
    while (std::chrono::steady_clock::now() < deadline) {
        if (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
            output += buffer.data();
        } else {
            break;
        }
    }
    
    result.timedOut = std::chrono::steady_clock::now() >= deadline;
    
    int status = _pclose(pipe);
    result.exitCode = status;
    
    if (config.captureStderr && config.captureStdout) {
        result.stdOut = output;
    }
    
    auto end = std::chrono::steady_clock::now();
    result.durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    
    // Classify failure
    if (result.exitCode == 0) {
        result.failureCategory = FailureCategory::NONE;
        result.recoverable = false;
    } else if (result.timedOut) {
        result.failureCategory = FailureCategory::TIMEOUT;
        result.failureReason = "Execution timed out after " + std::to_string(config.timeoutMs) + "ms";
        result.recoverable = true;
    } else {
        std::string combined = result.stdOut + result.stdErr;
        
        // Debug: print what we're searching
        std::cout << "    [DEBUG] Combined output length: " << combined.length() << "\n";
        std::cout << "    [DEBUG] Looking for 'error C' in: " << combined.substr(0, 100) << "\n";
        
        // MSVC compile errors
        size_t errorPos = combined.find("error C");
        std::cout << "    [DEBUG] Position of 'error C': " << errorPos << " (npos=" << std::string::npos << ")\n";
        
        if (errorPos != std::string::npos) {
            std::cout << "    [DEBUG] Found COMPILE_ERROR!\n";
            result.failureCategory = FailureCategory::COMPILE_ERROR;
            result.failureReason = "Compilation error detected";
            result.recoverable = true;
        }
        // MSVC link errors
        else if (combined.find("LNK") != std::string::npos || 
                 combined.find("unresolved external") != std::string::npos) {
            result.failureCategory = FailureCategory::LINK_ERROR;
            result.failureReason = "Linker error detected";
            result.recoverable = true;
        }
        // Environment issues
        else if (combined.find("No such file or directory") != std::string::npos ||
                 combined.find("cannot find") != std::string::npos ||
                 combined.find("does not exist") != std::string::npos ||
                 combined.find("cannot find the path") != std::string::npos ||
                 combined.find("The system cannot find") != std::string::npos) {
            result.failureCategory = FailureCategory::ENVIRONMENT_MISSING;
            result.failureReason = "Required file or directory missing";
            result.recoverable = true;
        }
        else {
            result.failureCategory = FailureCategory::UNKNOWN;
            result.failureReason = "Unknown failure (exit code: " + std::to_string(result.exitCode) + ")";
            result.recoverable = false;
        }
    }
    
    return result;
}

// ============================================================================
// DIAGNOSTIC PARSER
// ============================================================================

std::vector<CompilerDiagnostic> DiagnosticParser::parseMSVC(const std::string& output,
                                                           const std::string& sourceFile) {
    std::vector<CompilerDiagnostic> diagnostics;
    
    std::cout << "    [parseMSVC] Starting with output length: " << output.length() << "\n";
    
    // MSVC error pattern: file(line,column): error CXXXX: message
    std::regex errorPattern(R"((.+?)\((\d+)(?:,(\d+))?\)\s*:\s*(error|warning)\s+([A-Z]\d+)\s*:\s*(.+?)$))";
    
    std::istringstream stream(output);
    std::string line;
    int lineNum = 0;
    
    while (std::getline(stream, line)) {
        lineNum++;
        std::cout << "    [parseMSVC] Processing line " << lineNum << ": " << line.substr(0, 50) << "\n";
        std::smatch match;
        if (std::regex_search(line, match, errorPattern)) {
            std::cout << "    [parseMSVC] Matched!\n";
            try {
                CompilerDiagnostic diag;
                diag.compiler = "MSVC";
                diag.file = match[1].str();
                std::cout << "    [parseMSVC] File: " << diag.file << "\n";
                diag.line = std::stoi(match[2].str());
                std::cout << "    [parseMSVC] Line: " << diag.line << "\n";
                diag.column = match[3].str().empty() ? 0 : std::stoi(match[3].str());
                diag.severity = (match[4].str() == "error") ? DiagnosticSeverity::ERROR : DiagnosticSeverity::WARNING;
                diag.error_code = match[5].str();
                diag.message = match[6].str();
                diagnostics.push_back(diag);
                std::cout << "    [parseMSVC] Added diagnostic\n";
            } catch (...) {
                std::cout << "    [parseMSVC] Exception caught, skipping\n";
                // Skip malformed diagnostics
            }
        }
    }
    
    std::cout << "    [parseMSVC] Returning " << diagnostics.size() << " diagnostics\n";
    return diagnostics;
}

std::vector<CompilerDiagnostic> DiagnosticParser::parseGCC(const std::string& output,
                                                          const std::string& sourceFile) {
    std::vector<CompilerDiagnostic> diagnostics;
    
    // GCC error pattern: file:line:column: error: message
    std::regex errorPattern(R"((.+?):(\d+):(\d+):\s*(error|warning):\s*(.+?)$))");
    
    std::istringstream stream(output);
    std::string line;
    
    while (std::getline(stream, line)) {
        std::smatch match;
        if (std::regex_search(line, match, errorPattern)) {
            CompilerDiagnostic diag;
            diag.compiler = "GCC";
            diag.file = match[1].str();
            diag.line = std::stoi(match[2].str());
            diag.column = std::stoi(match[3].str());
            diag.severity = (match[4].str() == "error") ? DiagnosticSeverity::ERROR : DiagnosticSeverity::WARNING;
            diag.error_code = "";
            diag.message = match[5].str();
            diagnostics.push_back(diag);
        }
    }
    
    return diagnostics;
}

std::vector<CompilerDiagnostic> DiagnosticParser::parse(const std::string& output,
                                                       const std::string& sourceFile,
                                                       const std::string& compilerHint) {
    if (compilerHint == "MSVC" || output.find("error C") != std::string::npos) {
        return parseMSVC(output, sourceFile);
    }
    return parseGCC(output, sourceFile);
}

// ============================================================================
// REPAIR ENGINE
// ============================================================================

RepairPlan RepairEngine::generatePlan(const ExecutionResult& failure) {
    RepairPlan plan;
    plan.planId = "repair-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    plan.targetFailure = failure.failureCategory;
    plan.generatedBy = "RuleBased";
    
    switch (failure.failureCategory) {
        case FailureCategory::ENVIRONMENT_MISSING:
            {
                RepairStep step;
                step.stepNumber = 1;
                step.action = RepairActionType::CREATE_DIRECTORY;
                step.target = "build";
                step.description = "Create missing build directory";
                step.confidence = 0.95;
                step.reason = "Build directory missing - deterministic fix";
                plan.steps.push_back(step);
                plan.overallConfidence = 0.95;
            }
            break;
            
        case FailureCategory::COMPILE_ERROR:
            // Try known repair patterns
            for (const auto& diag : failure.diagnostics) {
                if (auto p = tryMissingSemicolon(diag)) {
                    plan = *p;
                    break;
                } else if (auto p = tryMissingBrace(diag)) {
                    plan = *p;
                    break;
                } else if (auto p = tryMissingInclude(diag)) {
                    plan = *p;
                    break;
                } else if (auto p = tryUndefinedVariable(diag)) {
                    plan = *p;
                    break;
                }
            }
            break;
            
        case FailureCategory::LINK_ERROR:
            for (const auto& diag : failure.diagnostics) {
                if (auto p = tryUndefinedReference(diag)) {
                    plan = *p;
                    break;
                }
            }
            break;
            
        default:
            plan.overallConfidence = 0.0;
            break;
    }
    
    return plan;
}

std::optional<RepairPlan> RepairEngine::tryMissingSemicolon(const CompilerDiagnostic& diag) {
    if (diag.message.find("missing") != std::string::npos && 
        diag.message.find(";") != std::string::npos) {
        RepairPlan plan;
        plan.planId = "repair-semicolon-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        plan.targetFailure = FailureCategory::COMPILE_ERROR;
        plan.generatedBy = "RuleBased";
        plan.overallConfidence = 0.98;
        
        RepairStep step;
        step.stepNumber = 1;
        step.action = RepairActionType::INSERT_TOKEN;
        step.target = diag.file;
        step.description = "Insert missing semicolon";
        step.confidence = 0.98;
        step.reason = "Compiler diagnostic C2143: missing ';' before '}'";
        
        RepairPatch patch;
        patch.file = diag.file;
        patch.line = diag.line;
        patch.column = diag.column;
        patch.before = "}";
        patch.after = ";}";
        patch.confidence = 0.98f;
        patch.reason = "Insert semicolon before closing brace";
        step.patch = patch;
        
        plan.steps.push_back(step);
        return plan;
    }
    return std::nullopt;
}

std::optional<RepairPlan> RepairEngine::tryMissingBrace(const CompilerDiagnostic& diag) {
    if (diag.message.find("missing") != std::string::npos && 
        diag.message.find("}") != std::string::npos) {
        RepairPlan plan;
        plan.planId = "repair-brace-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        plan.targetFailure = FailureCategory::COMPILE_ERROR;
        plan.generatedBy = "RuleBased";
        plan.overallConfidence = 0.90;
        
        RepairStep step;
        step.stepNumber = 1;
        step.action = RepairActionType::INSERT_TOKEN;
        step.target = diag.file;
        step.description = "Insert missing closing brace";
        step.confidence = 0.90;
        step.reason = "Compiler diagnostic: missing '}'";
        
        RepairPatch patch;
        patch.file = diag.file;
        patch.line = diag.line;
        patch.column = diag.column;
        patch.before = "";
        patch.after = "}";
        patch.confidence = 0.90f;
        patch.reason = "Insert missing closing brace";
        step.patch = patch;
        
        plan.steps.push_back(step);
        return plan;
    }
    return std::nullopt;
}

std::optional<RepairPlan> RepairEngine::tryMissingInclude(const CompilerDiagnostic& diag) {
    if (diag.message.find("undeclared identifier") != std::string::npos ||
        diag.message.find("was not declared") != std::string::npos) {
        // Could be missing include - but this is less certain
        return std::nullopt;
    }
    return std::nullopt;
}

std::optional<RepairPlan> RepairEngine::tryUndefinedVariable(const CompilerDiagnostic& diag) {
    if (diag.message.find("undeclared identifier") != std::string::npos ||
        diag.message.find("was not declared in this scope") != std::string::npos) {
        RepairPlan plan;
        plan.planId = "repair-var-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        plan.targetFailure = FailureCategory::COMPILE_ERROR;
        plan.generatedBy = "RuleBased";
        plan.overallConfidence = 0.70;
        
        RepairStep step;
        step.stepNumber = 1;
        step.action = RepairActionType::REPLACE_TOKEN;
        step.target = diag.file;
        step.description = "Define undefined variable";
        step.confidence = 0.70;
        step.reason = "Compiler diagnostic: undeclared identifier";
        
        // This would need more context to implement properly
        // For now, mark as requiring escalation
        plan.overallConfidence = 0.0;
        return plan;
    }
    return std::nullopt;
}

std::optional<RepairPlan> RepairEngine::tryUndefinedReference(const CompilerDiagnostic& diag) {
    if (diag.message.find("unresolved external") != std::string::npos ||
        diag.message.find("undefined reference") != std::string::npos) {
        RepairPlan plan;
        plan.planId = "repair-link-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        plan.targetFailure = FailureCategory::LINK_ERROR;
        plan.generatedBy = "RuleBased";
        plan.overallConfidence = 0.60;
        
        RepairStep step;
        step.stepNumber = 1;
        step.action = RepairActionType::ADD_INCLUDE;
        step.target = diag.file;
        step.description = "Add missing definition or library";
        step.confidence = 0.60;
        step.reason = "Linker error: undefined reference";
        
        plan.steps.push_back(step);
        return plan;
    }
    return std::nullopt;
}

ExecutionResult RepairEngine::executeRepair(const RepairStep& step, ProcessExecutor& executor) {
    ExecutionResult result;
    result.tool = "repair";
    
    auto start = std::chrono::steady_clock::now();
    
    switch (step.action) {
        case RepairActionType::CREATE_DIRECTORY:
            {
                std::error_code ec;
                std::filesystem::create_directories(step.target, ec);
                result.exitCode = ec ? 1 : 0;
                result.stdOut = ec ? "Failed to create directory: " + ec.message() : "Directory created: " + step.target;
                result.failureCategory = ec ? FailureCategory::ENVIRONMENT_MISCONFIGURED : FailureCategory::NONE;
                result.recoverable = !ec;
            }
            break;
            
        case RepairActionType::APPLY_PATCH:
        case RepairActionType::INSERT_TOKEN:
        case RepairActionType::DELETE_TOKEN:
        case RepairActionType::REPLACE_TOKEN:
            if (step.patch.has_value()) {
                bool success = applyPatch(step.patch.value());
                result.exitCode = success ? 0 : 1;
                result.stdOut = success ? "Patch applied successfully" : "Failed to apply patch";
                result.failureCategory = success ? FailureCategory::NONE : FailureCategory::UNKNOWN;
                result.recoverable = success;
            } else {
                result.exitCode = -1;
                result.stdOut = "No patch provided for patch action";
                result.failureCategory = FailureCategory::UNKNOWN;
                result.recoverable = false;
            }
            break;
            
        case RepairActionType::RETRY_WITH_TIMEOUT:
            result.exitCode = 0;
            result.stdOut = "Retry configured with extended timeout";
            result.failureCategory = FailureCategory::NONE;
            result.recoverable = true;
            break;
            
        default:
            result.exitCode = -1;
            result.stdOut = "Unknown repair action";
            result.failureCategory = FailureCategory::UNKNOWN;
            result.recoverable = false;
            break;
    }
    
    auto end = std::chrono::steady_clock::now();
    result.durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    
    return result;
}

bool RepairEngine::applyPatch(const RepairPatch& patch) {
    // Read original file
    std::ifstream inFile(patch.file);
    if (!inFile) {
        return false;
    }
    
    std::stringstream buffer;
    buffer << inFile.rdbuf();
    std::string content = buffer.str();
    inFile.close();
    
    // Find and replace
    size_t pos = content.find(patch.before);
    if (pos == std::string::npos) {
        return false;
    }
    
    content.replace(pos, patch.before.length(), patch.after);
    
    // Write back
    std::ofstream outFile(patch.file);
    if (!outFile) {
        return false;
    }
    
    outFile << content;
    return outFile.good();
}

bool RepairEngine::verifyRepair(const ExecutionResult& retryResult) {
    return retryResult.exitCode == 0 && retryResult.failureCategory == FailureCategory::NONE;
}

// ============================================================================
// EVIDENCE RECORDER
// ============================================================================

EvidenceRecorder::EvidenceRecorder(const std::string& basePath) 
    : basePath_(basePath), startTime_(std::chrono::steady_clock::now()) {
}

void EvidenceRecorder::beginTrace(const std::string& goal) {
    trace_ = nlohmann::json::object();
    trace_["validation_id"] = "VAL-016";
    trace_["validation_mode"] = "repair";
    trace_["goal"] = goal;
    trace_["timestamp_start"] = getTimestamp();
    trace_["schema_version"] = "VAL-016-v2.0";
    trace_["steps"] = nlohmann::json::array();
}

void EvidenceRecorder::recordFailureInjection(const std::string& description) {
    nlohmann::json step;
    step["phase"] = "failure_injection";
    step["description"] = description;
    step["timestamp"] = getTimestamp();
    trace_["steps"].push_back(step);
}

void EvidenceRecorder::recordExecutionAttempt(const ExecutionResult& result, int attemptNumber) {
    nlohmann::json step;
    step["phase"] = "execution";
    step["attempt"] = attemptNumber;
    step["result"] = result.toJson();
    step["timestamp"] = getTimestamp();
    trace_["steps"].push_back(step);
}

void EvidenceRecorder::recordDiagnosis(const Diagnosis& diagnosis) {
    nlohmann::json step;
    step["phase"] = "diagnosis";
    step["diagnosis"] = diagnosis.toJson();
    step["timestamp"] = getTimestamp();
    trace_["steps"].push_back(step);
}

void EvidenceRecorder::recordRepairPlan(const RepairPlan& plan) {
    nlohmann::json step;
    step["phase"] = "repair_planning";
    step["plan"] = plan.toJson();
    step["timestamp"] = getTimestamp();
    trace_["steps"].push_back(step);
}

void EvidenceRecorder::recordRepairExecution(const RepairStep& step, const ExecutionResult& result) {
    nlohmann::json j;
    j["phase"] = "repair_execution";
    j["step"] = step.toJson();
    j["result"] = result.toJson();
    j["timestamp"] = getTimestamp();
    trace_["steps"].push_back(j);
}

void EvidenceRecorder::recordVerification(const ExecutionResult& result, bool success) {
    nlohmann::json step;
    step["phase"] = "verification";
    step["success"] = success;
    step["result"] = result.toJson();
    step["timestamp"] = getTimestamp();
    trace_["steps"].push_back(step);
}

void EvidenceRecorder::endTrace(bool overallSuccess) {
    trace_["timestamp_end"] = getTimestamp();
    trace_["success"] = overallSuccess;
}

void EvidenceRecorder::saveTrace() {
    std::filesystem::create_directories(basePath_ + "/result");
    std::ofstream file(basePath_ + "/result/trace.json");
    file << trace_.dump(2);
}

void EvidenceRecorder::saveExecutionResult(const ExecutionResult& result, const std::string& filename) {
    std::filesystem::create_directories(basePath_ + "/execution");
    std::ofstream file(basePath_ + "/execution/" + filename);
    file << result.toJson().dump(2);
}

void EvidenceRecorder::saveCompilerOutput(const std::string& output, const std::string& filename) {
    std::filesystem::create_directories(basePath_ + "/execution");
    std::ofstream file(basePath_ + "/execution/" + filename);
    file << output;
}

void EvidenceRecorder::saveDiagnostics(const std::vector<CompilerDiagnostic>& diags) {
    std::filesystem::create_directories(basePath_ + "/repair");
    nlohmann::json j = nlohmann::json::array();
    for (const auto& d : diags) {
        j.push_back(d.toJson());
    }
    std::ofstream file(basePath_ + "/repair/diagnostics.json");
    file << j.dump(2);
}

void EvidenceRecorder::saveRepairPlan(const RepairPlan& plan) {
    std::filesystem::create_directories(basePath_ + "/repair");
    std::ofstream file(basePath_ + "/repair/repair_plan.json");
    file << plan.toJson().dump(2);
}

void EvidenceRecorder::savePatch(const RepairPatch& patch) {
    std::filesystem::create_directories(basePath_ + "/repair");
    std::ofstream jsonFile(basePath_ + "/repair/patch.json");
    jsonFile << patch.toJson().dump(2);
    
    std::ofstream diffFile(basePath_ + "/repair/patch.diff");
    diffFile << patch.toDiffFormat();
}

void EvidenceRecorder::saveRepairHistory(const RepairAttempt& attempt) {
    std::filesystem::create_directories(basePath_ + "/repair");
    std::ofstream file(basePath_ + "/repair/repair_attempts.jsonl", std::ios::app);
    file << attempt.toJson().dump() << "\n";
}

void EvidenceRecorder::generateCompletionJson(const std::string& path, int exitCode, bool repaired) {
    std::filesystem::create_directories(std::filesystem::path(path).parent_path());
    
    auto endTime = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime_).count();
    
    bool success = false;
    if (trace_.contains("success")) {
        const auto& val = trace_["success"];
        if (val.is_boolean()) {
            success = val.get<bool>();
        } else if (val.is_number()) {
            success = val.get<int>() != 0;
        }
    }
    
    nlohmann::json completion;
    completion["validation_id"] = "VAL-016";
    completion["validation_mode"] = "repair";
    completion["title"] = "Autonomous Source-Level Repair";
    completion["status"] = success ? "PASS" : "FAIL";
    completion["exit_code"] = exitCode;
    completion["timestamp_utc"] = getTimestamp();
    completion["duration_ms"] = duration;
    completion["goal"] = trace_.value("goal", "");
    completion["repaired"] = repaired;
    completion["steps_executed"] = trace_["steps"].size();
    completion["evidence_path"] = basePath_;
    completion["verification_level"] = "R";
    completion["schema_version"] = "VAL-016-v2.0";
    completion["notes"] = "Autonomous source-level repair: detect → diagnose → plan → patch → verify";
    
    std::ofstream file(path);
    file << completion.dump(2);
}

std::string EvidenceRecorder::getTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    char buf[100];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&time));
    return buf;
}

// ============================================================================
// REPAIR ORCHESTRATOR
// ============================================================================

RepairOrchestrator::RepairOrchestrator(const std::string& evidenceBasePath)
    : recorder_(evidenceBasePath), attemptCount_(0) {
    lifecycle_.currentState = RepairState::IDLE;
    lifecycle_.retryCount = 0;
}

bool RepairOrchestrator::executeRepairLoop(const std::string& goal) {
    std::cout << "\n========================================\n";
    std::cout << "VAL-016: Autonomous Source-Level Repair\n";
    std::cout << "Goal: " << goal << "\n";
    std::cout << "========================================\n\n";
    
    recorder_.beginTrace(goal);
    
    // STEP 1: Inject failure
    std::cout << "[STEP 1] Failure Injection\n";
    if (!injectFailure()) {
        std::cout << "  Failed to inject failure\n";
        return false;
    }
    recorder_.recordFailureInjection("Created broken.cpp with missing semicolon");
    lifecycle_.transition(RepairState::FAILURE_INJECTED, recorder_.getTimestamp());
    
    // STEP 2: Execute build (will fail)
    std::cout << "\n[STEP 2] Initial Build Attempt\n";
    lifecycle_.transition(RepairState::EXECUTING, recorder_.getTimestamp());
    ExecutionResult firstAttempt = executeBuild();
    attemptCount_++;
    recorder_.recordExecutionAttempt(firstAttempt, attemptCount_);
    recorder_.saveExecutionResult(firstAttempt, "first_attempt.json");
    recorder_.saveCompilerOutput(firstAttempt.stdOut, "compiler_output.txt");
    
    if (firstAttempt.exitCode == 0) {
        std::cout << "  Unexpected: Build succeeded without repair needed\n";
        lifecycle_.transition(RepairState::SUCCESS, recorder_.getTimestamp());
        recorder_.endTrace(true);
        recorder_.saveTrace();
        recorder_.generateCompletionJson(recorder_.getBasePath() + "/result/completion.json", 0, false);
        return true;
    }
    
    std::cout << "  Expected failure detected:\n";
    std::cout << "    Exit code: " << firstAttempt.exitCode << "\n";
    std::cout << "    Category: " << failureCategoryToString(firstAttempt.failureCategory) << "\n";
    std::cout << "    Reason: " << firstAttempt.failureReason << "\n";
    lifecycle_.transition(RepairState::FAILED, recorder_.getTimestamp());
    
    // STEP 3: Diagnose
    std::cout << "\n[STEP 3] Diagnosis\n";
    lifecycle_.transition(RepairState::DIAGNOSING, recorder_.getTimestamp());
    Diagnosis diagnosis = diagnoseFailure(firstAttempt);
    recorder_.recordDiagnosis(diagnosis);
    recorder_.saveDiagnostics(diagnosis.diagnostics);
    
    std::cout << "  Diagnosed as: " << failureCategoryToString(diagnosis.category) << "\n";
    std::cout << "  Recoverable: " << (diagnosis.recoverable ? "Yes" : "No") << "\n";
    
    if (!diagnosis.recoverable) {
        std::cout << "  Failure is not recoverable. Aborting.\n";
        lifecycle_.transition(RepairState::ESCALATED, recorder_.getTimestamp());
        recorder_.endTrace(false);
        recorder_.saveTrace();
        recorder_.generateCompletionJson(recorder_.getBasePath() + "/result/completion.json", 1, false);
        return false;
    }
    
    // STEP 4: Generate repair plan
    std::cout << "\n[STEP 4] Repair Plan Generation\n";
    lifecycle_.transition(RepairState::PLANNING, recorder_.getTimestamp());
    RepairPlan plan = generateRepairPlan(diagnosis);
    recorder_.recordRepairPlan(plan);
    recorder_.saveRepairPlan(plan);
    
    std::cout << "  Plan ID: " << plan.planId << "\n";
    std::cout << "  Target failure: " << failureCategoryToString(plan.targetFailure) << "\n";
    std::cout << "  Confidence: " << plan.overallConfidence << "\n";
    std::cout << "  Generated by: " << plan.generatedBy << "\n";
    std::cout << "  Steps: " << plan.steps.size() << "\n";
    
    for (const auto& step : plan.steps) {
        std::cout << "    Step " << step.stepNumber << ": " << repairActionToString(step.action) << "\n";
        std::cout << "      Target: " << step.target << "\n";
        std::cout << "      Confidence: " << step.confidence << "\n";
        if (step.patch.has_value()) {
            std::cout << "      Patch: " << step.patch->before << " -> " << step.patch->after << "\n";
        }
    }
    
    // STEP 5: Execute repair
    std::cout << "\n[STEP 5] Repair Execution\n";
    lifecycle_.transition(RepairState::REPAIRING, recorder_.getTimestamp());
    bool repairSuccess = executeRepair(plan);
    
    if (!repairSuccess) {
        std::cout << "  Repair execution failed. Aborting.\n";
        lifecycle_.transition(RepairState::ESCALATED, recorder_.getTimestamp());
        recorder_.endTrace(false);
        recorder_.saveTrace();
        recorder_.generateCompletionJson(recorder_.getBasePath() + "/result/completion.json", 1, false);
        return false;
    }
    
    // STEP 6: Verify
    std::cout << "\n[STEP 6] Verification\n";
    lifecycle_.transition(RepairState::VERIFYING, recorder_.getTimestamp());
    bool verificationSuccess = verifyRepair();
    
    if (verificationSuccess) {
        std::cout << "  ✓ Repair verified - build now succeeds\n";
        lifecycle_.transition(RepairState::SUCCESS, recorder_.getTimestamp());
    } else {
        std::cout << "  ✗ Repair failed - build still failing\n";
        lifecycle_.transition(RepairState::ESCALATED, recorder_.getTimestamp());
    }
    
    // Finalize
    recorder_.endTrace(verificationSuccess);
    recorder_.saveTrace();
    
    int exitCode = verificationSuccess ? 0 : 1;
    recorder_.generateCompletionJson(recorder_.getBasePath() + "/result/completion.json", exitCode, verificationSuccess);
    
    std::cout << "\n========================================\n";
    std::cout << "VAL-016: " << (verificationSuccess ? "REPAIR SUCCESS" : "REPAIR FAILED") << "\n";
    std::cout << "Attempts: " << attemptCount_ << "\n";
    std::cout << "========================================\n\n";
    
    return verificationSuccess;
}

bool RepairOrchestrator::injectFailure() {
    // Create test directory
    std::string inputDir = recorder_.getBasePath() + "/input";
    std::filesystem::create_directories(inputDir);
    std::cout << "  Created input directory: " << inputDir << "\n";
    
    // Create broken.cpp with missing semicolon
    std::string sourcePath = inputDir + "/broken.cpp";
    std::ofstream ofs(sourcePath);
    if (!ofs) {
        std::cout << "  Failed to create source file\n";
        return false;
    }
    
    ofs << "// VAL-016.2: Broken source with missing semicolon\n";
    ofs << "// This file is intentionally defective for repair demonstration\n\n";
    ofs << "int main() {\n";
    ofs << "    int x = 42\n";  // Missing semicolon
    ofs << "    return 0;\n";
    ofs << "}\n";
    
    currentSourceFile_ = sourcePath;
    // Use full path to cl.exe
    std::string clPath = "C:\\Program Files\\Microsoft Visual Studio\\18\\Enterprise\\VC\\Tools\\MSVC\\14.51.36231\\bin\\Hostx64\\x64\\cl.exe";
    currentBuildCommand_ = "cmd /c \"\"" + clPath + "\" /nologo /EHsc " + sourcePath + " /Fe:" + inputDir + "/broken.exe 2>&1\"";
    
    std::cout << "  Created broken.cpp with missing semicolon\n";
    std::cout << "  Build command: " << currentBuildCommand_ << "\n";
    
    return ofs.good();
}

ExecutionResult RepairOrchestrator::executeBuild() {
    std::cout << "  Executing build command...\n";
    ExecutionResult result = executor_.execute("cl", currentBuildCommand_);
    
    std::cout << "  Raw stdout length: " << result.stdOut.length() << " bytes\n";
    std::cout << "  Failure category: " << failureCategoryToString(result.failureCategory) << "\n";
    
    // Parse diagnostics if compile error
    if (result.failureCategory == FailureCategory::COMPILE_ERROR) {
        std::cout << "  Parsing diagnostics...\n";
        result.diagnostics = diagnosticParser_.parse(result.stdOut, currentSourceFile_, "MSVC");
        std::cout << "  Parsed " << result.diagnostics.size() << " diagnostics\n";
    }
    
    std::cout << "  executeBuild returning\n";
    return result;
}

Diagnosis RepairOrchestrator::diagnoseFailure(const ExecutionResult& failure) {
    Diagnosis diag;
    diag.category = failure.failureCategory;
    diag.reason = failure.failureReason;
    diag.recoverable = failure.recoverable;
    diag.diagnostics = failure.diagnostics;
    
    // Determine recommended action based on category
    switch (failure.failureCategory) {
        case FailureCategory::COMPILE_ERROR:
            diag.recommendedAction = "Apply source patch based on compiler diagnostics";
            break;
        case FailureCategory::LINK_ERROR:
            diag.recommendedAction = "Add missing definitions or libraries";
            break;
        case FailureCategory::ENVIRONMENT_MISSING:
            diag.recommendedAction = "Create missing directory or install tool";
            break;
        default:
            diag.recommendedAction = "Escalate to human operator";
            break;
    }
    
    return diag;
}

RepairPlan RepairOrchestrator::generateRepairPlan(const Diagnosis& diagnosis) {
    // Create a synthetic execution result for the repair engine
    ExecutionResult failure;
    failure.failureCategory = diagnosis.category;
    failure.failureReason = diagnosis.reason;
    failure.recoverable = diagnosis.recoverable;
    failure.diagnostics = diagnosis.diagnostics;
    
    return repairEngine_.generatePlan(failure);
}

bool RepairOrchestrator::executeRepair(const RepairPlan& plan) {
    bool repairSuccess = true;
    
    for (const auto& step : plan.steps) {
        std::cout << "  Executing: " << repairActionToString(step.action) << "...\n";
        
        ExecutionResult repairResult = repairEngine_.executeRepair(step, executor_);
        recorder_.recordRepairExecution(step, repairResult);
        
        if (step.patch.has_value()) {
            recorder_.savePatch(step.patch.value());
        }
        
        if (repairResult.exitCode != 0) {
            std::cout << "    Repair failed: " << repairResult.stdOut << "\n";
            repairSuccess = false;
            break;
        }
        std::cout << "    Repair succeeded: " << repairResult.stdOut << "\n";
    }
    
    return repairSuccess;
}

bool RepairOrchestrator::verifyRepair() {
    ExecutionResult retryAttempt = executeBuild();
    attemptCount_++;
    recorder_.recordExecutionAttempt(retryAttempt, attemptCount_);
    recorder_.saveExecutionResult(retryAttempt, "retry_attempt.json");
    
    bool success = (retryAttempt.exitCode == 0);
    recorder_.recordVerification(retryAttempt, success);
    
    return success;
}

} // namespace VAL016
} // namespace RawrXD
