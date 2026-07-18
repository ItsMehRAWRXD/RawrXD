// VAL-016.2: Source-Level Autonomous Repair
// Purpose: Demonstrate autonomous repair of compiler errors
// Schema: Structured diagnostics + patch generation + verification

#include <iostream>
#include <fstream>
#include <filesystem>
#include <cstring>
#include <vector>
#include <chrono>
#include <cstdlib>
#include <array>
#include <memory>
#include <thread>
#include <regex>
#include "nlohmann/json.hpp"

namespace RawrXD {

// ============================================================================
// SHARED SCHEMA FROM VAL-016.1
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
    
    nlohmann::json toJson() const {
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
        return j;
    }
};

// ============================================================================
// VAL-016.2: STRUCTURED COMPILER DIAGNOSTICS
// ============================================================================

enum class DiagnosticSeverity { ERROR, WARNING, INFO };

struct CompilerDiagnostic {
    std::string compiler;
    std::string file;
    int line;
    int column;
    std::string errorCode;
    std::string message;
    DiagnosticSeverity severity;
    
    nlohmann::json toJson() const {
        nlohmann::json j;
        j["compiler"] = compiler;
        j["file"] = file;
        j["line"] = line;
        j["column"] = column;
        j["error_code"] = errorCode;
        j["message"] = message;
        j["severity"] = (severity == DiagnosticSeverity::ERROR) ? "error" : 
                       (severity == DiagnosticSeverity::WARNING) ? "warning" : "info";
        return j;
    }
};

// ============================================================================
// VAL-016.2: PATCH REPRESENTATION
// ============================================================================

struct RepairPatch {
    std::string file;
    size_t offset;
    std::string before;
    std::string after;
    float confidence;
    std::string reason;
    
    nlohmann::json toJson() const {
        nlohmann::json j;
        j["file"] = file;
        j["offset"] = offset;
        j["before"] = before;
        j["after"] = after;
        j["confidence"] = static_cast<double>(confidence);
        j["reason"] = reason;
        return j;
    }
    
    std::string generateDiff() const {
        std::ostringstream diff;
        diff << "--- a/" << file << "\n";
        diff << "+++ b/" << file << "\n";
        diff << "@@ -" << offset << ",1 +" << offset << ",1 @@\n";
        diff << "-" << before << "\n";
        diff << "+" << after << "\n";
        return diff.str();
    }
};

// ============================================================================
// VAL-016.2: DIAGNOSTIC PARSER
// ============================================================================

class DiagnosticParser {
public:
    std::vector<CompilerDiagnostic> parseMSVC(const std::string& output) {
        std::vector<CompilerDiagnostic> diagnostics;
        
        // MSVC error pattern: file(line,col) or file(line): error code: message
        std::regex msvcPattern(R"--((.+?)\((\d+)(?:,(\d+))?\):\s*(error|warning)\s+(\w+):\s*(.+?)$)--");
        std::smatch match;
        
        std::istringstream stream(output);
        std::string line;
        while (std::getline(stream, line)) {
            if (std::regex_search(line, match, msvcPattern)) {
                CompilerDiagnostic diag;
                diag.compiler = "MSVC";
                diag.file = match[1].str();
                diag.line = std::stoi(match[2].str());
                diag.column = match[3].matched ? std::stoi(match[3].str()) : 0;
                diag.severity = (match[4].str() == "error") ? DiagnosticSeverity::ERROR : DiagnosticSeverity::WARNING;
                diag.errorCode = match[5].str();
                diag.message = match[6].str();
                diagnostics.push_back(diag);
            }
        }
        
        return diagnostics;
    }
};

// ============================================================================
// VAL-016.2: REPAIR CLASSIFIER
// ============================================================================

enum class RepairType {
    UNKNOWN,
    INSERT_SEMICOLON,
    INSERT_BRACE,
    ADD_INCLUDE,
    ADD_DECLARATION
};

struct RepairClassification {
    RepairType type;
    std::string description;
    float confidence;
    std::string reason;
};

class RepairClassifier {
public:
    RepairClassification classify(const CompilerDiagnostic& diag) {
        RepairClassification classification;
        classification.type = RepairType::UNKNOWN;
        classification.confidence = 0.0f;
        
        // Missing semicolon pattern
        if (diag.errorCode == "C2143" || diag.errorCode == "C2144") {
            if (diag.message.find("missing") != std::string::npos && 
                diag.message.find(";") != std::string::npos) {
                classification.type = RepairType::INSERT_SEMICOLON;
                classification.description = "Insert missing semicolon";
                classification.confidence = 0.98f;
                classification.reason = "MSVC C2143: syntax error - missing ';' detected";
            }
        }
        // Missing brace pattern
        else if (diag.errorCode == "C1075" || diag.errorCode == "C2143") {
            if (diag.message.find("{") != std::string::npos || 
                diag.message.find("}") != std::string::npos) {
                classification.type = RepairType::INSERT_BRACE;
                classification.description = "Insert missing brace";
                classification.confidence = 0.95f;
                classification.reason = "Brace mismatch detected";
            }
        }
        // Missing include pattern
        else if (diag.errorCode == "C1083") {
            if (diag.message.find("cannot open") != std::string::npos) {
                classification.type = RepairType::ADD_INCLUDE;
                classification.description = "Add missing include";
                classification.confidence = 0.90f;
                classification.reason = "Header file not found";
            }
        }
        
        return classification;
    }
};

// ============================================================================
// VAL-016.2: PATCH GENERATOR
// ============================================================================

class PatchGenerator {
public:
    RepairPatch generatePatch(const CompilerDiagnostic& diag, const RepairClassification& classification, 
                              const std::string& filePath) {
        RepairPatch patch;
        patch.file = filePath;
        patch.confidence = classification.confidence;
        patch.reason = classification.reason;
        
        // Read the file content
        std::ifstream file(filePath);
        std::string content((std::istreambuf_iterator<char>(file)),
                            std::istreambuf_iterator<char>());
        file.close();
        
        // Find the line(s)
        std::istringstream stream(content);
        std::string line;
        std::string prevLine;
        int currentLine = 1;
        size_t offset = 0;
        size_t prevOffset = 0;
        
        while (std::getline(stream, line)) {
            if (currentLine == diag.line) {
                break;
            }
            prevOffset = offset;
            prevLine = line;
            offset += line.length() + 1; // +1 for newline
            currentLine++;
        }
        
        switch (classification.type) {
            case RepairType::INSERT_SEMICOLON:
                // For missing semicolon, the error is reported on the line AFTER the missing semicolon
                // We need to add semicolon to the PREVIOUS line
                if (diag.line > 1 && !prevLine.empty()) {
                    patch.before = prevLine;
                    patch.after = prevLine + ";";
                    patch.offset = prevOffset + prevLine.length();
                } else {
                    // Fallback to current line
                    patch.before = line;
                    patch.after = line + ";";
                    patch.offset = offset + line.length();
                }
                break;
                
            case RepairType::INSERT_BRACE:
                patch.before = line;
                patch.after = line + " }";
                patch.offset = offset + line.length();
                break;
                
            default:
                patch.before = line;
                patch.after = line;
                patch.offset = offset;
                break;
        }
        
        return patch;
    }
    
    bool applyPatch(const RepairPatch& patch, const std::string& filePath) {
        // Read file
        std::ifstream inFile(filePath);
        std::string content((std::istreambuf_iterator<char>(inFile)),
                            std::istreambuf_iterator<char>());
        inFile.close();

        // Apply patch
        size_t pos = content.find(patch.before);
        if (pos == std::string::npos) {
            return false;
        }

        content.replace(pos, patch.before.length(), patch.after);

        // Write back
        std::ofstream outFile(filePath);
        outFile << content;
        outFile.close();

        return true;
    }

    bool validatePatch(const RepairPatch& patch, const std::string& filePath) {
        // Read file
        std::ifstream inFile(filePath);
        std::string content((std::istreambuf_iterator<char>(inFile)),
                            std::istreambuf_iterator<char>());
        inFile.close();

        // Check if 'before' text exists in file
        return content.find(patch.before) != std::string::npos;
    }
};

// ============================================================================
// PLATFORM EXECUTOR (from VAL-016.1)
// ============================================================================

class ProcessExecutor {
public:
    struct Config {
        uint32_t timeoutMs = 60000;
        bool captureStderr = true;
        bool captureStdout = true;
    };
    
    ExecutionResult execute(const std::string& tool, const std::string& command, 
                           const Config& config = {}) {
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
            result.failureReason = "Execution timed out";
            result.recoverable = true;
        } else {
            std::string combined = result.stdOut + result.stdErr;
            
            if (combined.find("error C") != std::string::npos) {
                result.failureCategory = FailureCategory::COMPILE_ERROR;
                result.failureReason = "Compilation error detected";
                result.recoverable = true;
            } else if (combined.find("LNK") != std::string::npos) {
                result.failureCategory = FailureCategory::LINK_ERROR;
                result.failureReason = "Linker error detected";
                result.recoverable = true;
            } else {
                result.failureCategory = FailureCategory::UNKNOWN;
                result.failureReason = "Unknown failure";
                result.recoverable = false;
            }
        }
        
        return result;
    }
};

// ============================================================================
// EVIDENCE RECORDER
// ============================================================================

class EvidenceRecorder {
public:
    EvidenceRecorder(const std::string& basePath) : basePath_(basePath) {
        startTime_ = std::chrono::steady_clock::now();
    }
    
    void beginTrace(const std::string& goal) {
        trace_ = nlohmann::json::object();
        trace_["validation_id"] = "VAL-016.2";
        trace_["validation_mode"] = "source_repair";
        trace_["goal"] = goal;
        trace_["timestamp_start"] = getTimestamp();
        trace_["schema_version"] = "VAL-016-v2.0";
        trace_["steps"] = nlohmann::json::array();
    }
    
    void recordFailureInjection(const std::string& description) {
        nlohmann::json step;
        step["phase"] = "failure_injection";
        step["description"] = description;
        step["timestamp"] = getTimestamp();
        trace_["steps"].push_back(step);
    }
    
    void recordBuildAttempt(const ExecutionResult& result, int attemptNumber) {
        nlohmann::json step;
        step["phase"] = "build";
        step["attempt"] = attemptNumber;
        step["result"] = result.toJson();
        step["timestamp"] = getTimestamp();
        trace_["steps"].push_back(step);
    }
    
    void recordDiagnostics(const std::vector<CompilerDiagnostic>& diagnostics) {
        nlohmann::json step;
        step["phase"] = "diagnostics";
        step["diagnostics"] = nlohmann::json::array();
        for (const auto& diag : diagnostics) {
            step["diagnostics"].push_back(diag.toJson());
        }
        step["timestamp"] = getTimestamp();
        trace_["steps"].push_back(step);
    }
    
    void recordRepairPlan(const RepairClassification& classification, const RepairPatch& patch) {
        nlohmann::json step;
        step["phase"] = "repair_plan";
        step["classification"] = classification.description;
        step["confidence"] = static_cast<double>(classification.confidence);
        step["patch"] = patch.toJson();
        step["timestamp"] = getTimestamp();
        trace_["steps"].push_back(step);
    }

    void recordConfidenceGate(float confidence, const std::string& action) {
        nlohmann::json step;
        step["phase"] = "confidence_gate";
        step["confidence"] = confidence;
        step["action"] = action;
        step["timestamp"] = getTimestamp();
        trace_["steps"].push_back(step);
    }

    void recordPatchApplied(const RepairPatch& patch, bool success) {
        nlohmann::json step;
        step["phase"] = "patch_applied";
        step["patch"] = patch.toJson();
        step["success"] = success;
        step["timestamp"] = getTimestamp();
        trace_["steps"].push_back(step);
    }
    
    void recordVerification(const ExecutionResult& result, bool success) {
        nlohmann::json step;
        step["phase"] = "verification";
        step["success"] = success;
        step["result"] = result.toJson();
        step["timestamp"] = getTimestamp();
        trace_["steps"].push_back(step);
    }
    
    void endTrace(bool overallSuccess) {
        trace_["timestamp_end"] = getTimestamp();
        trace_["success"] = overallSuccess;
    }
    
    void saveTrace() {
        std::filesystem::create_directories(basePath_ + "/result");
        std::ofstream file(basePath_ + "/result/trace.json");
        file << trace_.dump(2);
    }
    
    void saveBuildAttempt(const ExecutionResult& result, const std::string& filename) {
        std::filesystem::create_directories(basePath_ + "/execution");
        std::ofstream file(basePath_ + "/execution/" + filename);
        file << result.toJson().dump(2);
    }
    
    void saveCompilerOutput(const std::string& output) {
        std::filesystem::create_directories(basePath_ + "/execution");
        std::ofstream file(basePath_ + "/execution/compiler_output.txt");
        file << output;
    }
    
    void saveDiagnostics(const std::vector<CompilerDiagnostic>& diagnostics) {
        std::filesystem::create_directories(basePath_ + "/repair");
        nlohmann::json j = nlohmann::json::array();
        for (const auto& diag : diagnostics) {
            j.push_back(diag.toJson());
        }
        std::ofstream file(basePath_ + "/repair/diagnostics.json");
        file << j.dump(2);
    }
    
    void saveRepairPlan(const RepairClassification& classification, const RepairPatch& patch) {
        std::filesystem::create_directories(basePath_ + "/repair");
        nlohmann::json j;
        j["classification"] = classification.description;
        j["confidence"] = classification.confidence;
        j["reason"] = classification.reason;
        j["patch"] = patch.toJson();
        std::ofstream file(basePath_ + "/repair/repair_plan.json");
        file << j.dump(2);
    }
    
    void savePatchDiff(const RepairPatch& patch) {
        std::filesystem::create_directories(basePath_ + "/repair");
        std::ofstream file(basePath_ + "/repair/patch.diff");
        file << patch.generateDiff();
    }
    
    void saveRepairHistory(const nlohmann::json& history) {
        std::filesystem::create_directories(basePath_ + "/repair");
        std::ofstream file(basePath_ + "/repair/repair_attempts.jsonl", std::ios::app);
        file << history.dump() << "\n";
    }
    
    void generateCompletionJson(const std::string& path, int exitCode, bool repaired) {
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
        completion["validation_id"] = "VAL-016.2";
        completion["validation_mode"] = "source_repair";
        completion["title"] = "Source-Level Autonomous Repair";
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
        completion["notes"] = "Autonomous source repair: compile error -> diagnostic -> patch -> verify";
        
        std::ofstream file(path);
        file << completion.dump(2);
    }
    
    std::string getTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        char buf[100];
        std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&time));
        return buf;
    }
    
private:
    std::string basePath_;
    nlohmann::json trace_;
    std::chrono::steady_clock::time_point startTime_;
};

// ============================================================================
// VAL-016.2 DEMONSTRATION
// ============================================================================

class Val016SourceRepairDemo {
public:
    Val016SourceRepairDemo() : recorder_("validation/val-016-2"), attemptCount_(0) {}
    
    bool execute(const std::string& goal) {
        std::cout << "\n========================================\n";
        std::cout << "VAL-016.2: Source-Level Autonomous Repair\n";
        std::cout << "Goal: " << goal << "\n";
        std::cout << "========================================\n\n";
        
        recorder_.beginTrace(goal);
        
        // STEP 1: Create input directory and inject failure
        std::cout << "[STEP 1] Failure Injection\n";
        std::string inputDir = "validation/val-016-2/input";
        std::filesystem::create_directories(inputDir);
        std::string brokenFile = inputDir + "/broken.cpp";
        injectFailure(brokenFile);
        recorder_.recordFailureInjection("Created broken.cpp with missing semicolon");
        std::cout << "  Created: " << brokenFile << "\n";
        
        // STEP 2: Initial build attempt (will fail)
        std::cout << "\n[STEP 2] Initial Build Attempt\n";
        // Use full path to cl.exe
        std::string clPath = "C:\\Program Files\\Microsoft Visual Studio\\18\\Enterprise\\VC\\Tools\\MSVC\\14.51.36231\\bin\\Hostx64\\x64\\cl.exe";
        std::string buildCmd = "\"" + clPath + "\" /nologo /c " + brokenFile + " /Fo" + inputDir + "/broken.obj";
        ExecutionResult firstAttempt = executor_.execute("cl", buildCmd);
        attemptCount_++;
        recorder_.recordBuildAttempt(firstAttempt, attemptCount_);
        recorder_.saveBuildAttempt(firstAttempt, "first_attempt.json");
        recorder_.saveCompilerOutput(firstAttempt.stdOut);
        
        if (firstAttempt.exitCode == 0) {
            std::cout << "  Unexpected: Build succeeded without repair needed\n";
            recorder_.endTrace(true);
            recorder_.saveTrace();
            recorder_.generateCompletionJson("validation/val-016-2/result/completion.json", 0, false);
            return true;
        }
        
        std::cout << "  Expected failure detected:\n";
        std::cout << "    Exit code: " << firstAttempt.exitCode << "\n";
        std::cout << "    Category: " << failureCategoryToString(firstAttempt.failureCategory) << "\n";
        
        // STEP 3: Parse diagnostics
        std::cout << "\n[STEP 3] Parse Compiler Diagnostics\n";
        auto diagnostics = diagParser_.parseMSVC(firstAttempt.stdOut);
        recorder_.recordDiagnostics(diagnostics);
        recorder_.saveDiagnostics(diagnostics);
        
        std::cout << "  Parsed " << diagnostics.size() << " diagnostic(s):\n";
        for (const auto& diag : diagnostics) {
            std::cout << "    " << diag.errorCode << ": " << diag.message << "\n";
            std::cout << "      at " << diag.file << "(" << diag.line << "," << diag.column << ")\n";
        }
        
        if (diagnostics.empty()) {
            std::cout << "  No diagnostics parsed. Cannot repair.\n";
            recorder_.endTrace(false);
            recorder_.saveTrace();
            recorder_.generateCompletionJson("validation/val-016-2/result/completion.json", 1, false);
            return false;
        }
        
        // STEP 4: Classify repair
        std::cout << "\n[STEP 4] Classify Repair\n";
        auto classification = classifier_.classify(diagnostics[0]);
        std::cout << "  Classification: " << classification.description << "\n";
        std::cout << "  Confidence: " << classification.confidence << "\n";
        std::cout << "  Reason: " << classification.reason << "\n";
        
        if (classification.type == RepairType::UNKNOWN) {
            std::cout << "  Unknown repair type. Cannot proceed.\n";
            recorder_.endTrace(false);
            recorder_.saveTrace();
            recorder_.generateCompletionJson("validation/val-016-2/result/completion.json", 1, false);
            return false;
        }
        
        // STEP 5: Generate patch
        std::cout << "\n[STEP 5] Generate Patch\n";
        RepairPatch patch = patchGen_.generatePatch(diagnostics[0], classification, brokenFile);
        recorder_.recordRepairPlan(classification, patch);
        recorder_.saveRepairPlan(classification, patch);
        recorder_.savePatchDiff(patch);
        
        std::cout << "  Patch generated:\n";
        std::cout << "    File: " << patch.file << "\n";
        std::cout << "    Before: '" << patch.before << "'\n";
        std::cout << "    After: '" << patch.after << "'\n";
        std::cout << "    Confidence: " << patch.confidence << "\n";
        
        // STEP 5b: Confidence Gate
        std::cout << "\n[STEP 5b] Confidence Gate\n";
        enum class ConfidenceAction { AUTO_APPLY, REQUIRE_APPROVAL, REJECT };
        ConfidenceAction action;
        std::string actionReason;
        
        if (patch.confidence >= 0.95f) {
            action = ConfidenceAction::AUTO_APPLY;
            actionReason = "High confidence (>= 0.95) - auto-apply";
        } else if (patch.confidence >= 0.75f) {
            action = ConfidenceAction::REQUIRE_APPROVAL;
            actionReason = "Medium confidence (0.75-0.95) - requires approval";
        } else {
            action = ConfidenceAction::REJECT;
            actionReason = "Low confidence (< 0.75) - reject";
        }
        
        std::cout << "  Action: " << actionReason << "\n";
        recorder_.recordConfidenceGate(patch.confidence, actionReason);
        
        if (action == ConfidenceAction::REJECT) {
            std::cout << "  Patch rejected due to low confidence.\n";
            recorder_.endTrace(false);
            recorder_.saveTrace();
            recorder_.generateCompletionJson("validation/val-016-2/result/completion.json", 1, false);
            return false;
        }
        
        // For demo purposes, auto-approve medium confidence
        if (action == ConfidenceAction::REQUIRE_APPROVAL) {
            std::cout << "  (Demo: Auto-approving medium confidence patch)\n";
        }
        
        // STEP 6: Pre-apply Validation
        std::cout << "\n[STEP 6] Pre-apply Validation\n";
        bool patchValid = patchGen_.validatePatch(patch, brokenFile);
        if (!patchValid) {
            std::cout << "  Patch validation failed - 'before' text not found in file.\n";
            recorder_.endTrace(false);
            recorder_.saveTrace();
            recorder_.generateCompletionJson("validation/val-016-2/result/completion.json", 1, false);
            return false;
        }
        std::cout << "  Patch validated - 'before' text found in file.\n";

        // STEP 7: Apply patch
        std::cout << "\n[STEP 7] Apply Patch\n";
        bool patchApplied = patchGen_.applyPatch(patch, brokenFile);
        recorder_.recordPatchApplied(patch, patchApplied);
        
        if (!patchApplied) {
            std::cout << "  Failed to apply patch.\n";
            recorder_.endTrace(false);
            recorder_.saveTrace();
            recorder_.generateCompletionJson("validation/val-016-2/result/completion.json", 1, false);
            return false;
        }
        std::cout << "  Patch applied successfully.\n";
        
        // STEP 8: Rebuild
        std::cout << "\n[STEP 8] Rebuild\n";
        ExecutionResult retryAttempt = executor_.execute("cl", buildCmd);
        attemptCount_++;
        recorder_.recordBuildAttempt(retryAttempt, attemptCount_);
        recorder_.saveBuildAttempt(retryAttempt, "retry_attempt.json");

        std::cout << "  Retry exit code: " << retryAttempt.exitCode << "\n";

        // STEP 9: Verification
        std::cout << "\n[STEP 9] Verification\n";
        bool verificationSuccess = (retryAttempt.exitCode == 0);
        recorder_.recordVerification(retryAttempt, verificationSuccess);
        
        if (verificationSuccess) {
            std::cout << "  ✓ Repair verified - build now succeeds\n";
        } else {
            std::cout << "  ✗ Repair failed - build still failing\n";
            std::cout << "    Output: " << retryAttempt.stdOut.substr(0, 200) << "\n";
        }
        
        // Finalize
        recorder_.endTrace(verificationSuccess);
        recorder_.saveTrace();
        
        nlohmann::json historyEntry;
        historyEntry["attempt"] = 1;
        historyEntry["failure"] = diagnostics[0].errorCode;
        historyEntry["action"] = classification.description;
        historyEntry["result"] = verificationSuccess ? "Success" : "Failure";
        historyEntry["timestamp"] = recorder_.getTimestamp();
        recorder_.saveRepairHistory(historyEntry);
        
        int exitCode = verificationSuccess ? 0 : 1;
        recorder_.generateCompletionJson("validation/val-016-2/result/completion.json", exitCode, verificationSuccess);
        
        std::cout << "\n========================================\n";
        std::cout << "VAL-016.2: " << (verificationSuccess ? "REPAIR SUCCESS" : "REPAIR FAILED") << "\n";
        std::cout << "Attempts: " << attemptCount_ << "\n";
        std::cout << "========================================\n\n";
        
        return verificationSuccess;
    }
    
private:
    EvidenceRecorder recorder_;
    ProcessExecutor executor_;
    DiagnosticParser diagParser_;
    RepairClassifier classifier_;
    PatchGenerator patchGen_;
    int attemptCount_;
    
    void injectFailure(const std::string& filePath) {
        std::ofstream file(filePath);
        file << "// VAL-016.2: Broken file with missing semicolon\n";
        file << "int main() {\n";
        file << "    return 0\n";  // Missing semicolon
        file << "}\n";
        file.close();
    }
};

} // namespace RawrXD

int main(int argc, char* argv[]) {
    std::string goal = "Demonstrate autonomous source-level repair";
    
    if (argc > 1) {
        goal = argv[1];
    }
    
    RawrXD::Val016SourceRepairDemo demo;
    bool success = demo.execute(goal);
    
    return success ? 0 : 1;
}
