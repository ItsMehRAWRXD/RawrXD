// ============================================================================
// AutonomousFixOrchestrator.cpp — Closed-Loop Autonomous Repair Engine
// ============================================================================
// Implements: Agent proposes → Tools execute → Verification decides
//
// State machine:
//   INIT → INDEX → BASELINE → DIAGNOSE → PLAN → PATCH → BUILD → TEST → VERIFY
//                    ↑___________________________________________|
//                    └──── FAIL → RECOVERY (iteration limit)
//
// Every transition produces a structured evidence artifact.
// ============================================================================

#include "AutonomousFixOrchestrator.hpp"
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <random>
#include <utility>

namespace RawrXD {
namespace Agent {

// ============================================================================
// Helpers
// ============================================================================
const char* FixPhaseToString(FixPhase phase) {
    switch (phase) {
        case FixPhase::Idle:     return "Idle";
        case FixPhase::Init:     return "Init";
        case FixPhase::Index:    return "Index";
        case FixPhase::Baseline: return "Baseline";
        case FixPhase::Diagnose: return "Diagnose";
        case FixPhase::Plan:     return "Plan";
        case FixPhase::Patch:    return "Patch";
        case FixPhase::Build:    return "Build";
        case FixPhase::Test:     return "Test";
        case FixPhase::Verify:   return "Verify";
        case FixPhase::Recovery: return "Recovery";
        case FixPhase::Done:     return "Done";
        case FixPhase::Error:    return "Error";
    }
    return "Unknown";
}

static std::string GenerateSessionId() {
    auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist;
    std::ostringstream oss;
    oss << "AF-" << std::hex << now << "-" << dist(gen);
    return oss.str();
}

// ============================================================================
// FixEvidence
// ============================================================================
nlohmann::json FixEvidence::ToJson() const {
    nlohmann::json j;
    j["sessionId"] = sessionId;
    j["repositoryPath"] = repositoryPath;
    j["taskDescription"] = taskDescription;
    j["finalPhase"] = FixPhaseToString(finalPhase);
    j["success"] = success;
    j["iterationCount"] = iterationCount;
    j["maxIterations"] = maxIterations;
    j["totalDurationMs"] = totalDuration.count();

    nlohmann::json transitionsJson = nlohmann::json::array();
    for (const auto& t : transitions) {
        nlohmann::json entry;
        entry["from"] = FixPhaseToString(t.from);
        entry["to"] = FixPhaseToString(t.to);
        entry["reason"] = t.reason;
        entry["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
            t.timestamp.time_since_epoch()).count();
        if (!t.context.is_null()) entry["context"] = t.context;
        transitionsJson.push_back(entry);
    }
    j["transitions"] = transitionsJson;

    if (!diagnostics.is_null()) j["diagnostics"] = diagnostics;
    if (!patchSummary.is_null()) j["patchSummary"] = patchSummary;
    if (!buildResult.is_null()) j["buildResult"] = buildResult;
    if (!testResult.is_null()) j["testResult"] = testResult;

    return j;
}

bool FixEvidence::SaveToFile(const std::string& path) const {
    try {
        std::filesystem::path p(path);
        std::filesystem::create_directories(p.parent_path());
        std::ofstream ofs(path);
        if (!ofs) return false;
        ofs << ToJson().dump(2);
        return ofs.good();
    } catch (...) {
        return false;
    }
}

// ============================================================================
// AutonomousFixOrchestrator
// ============================================================================
AutonomousFixOrchestrator::AutonomousFixOrchestrator() = default;
AutonomousFixOrchestrator::~AutonomousFixOrchestrator() = default;

bool AutonomousFixOrchestrator::Initialize(AgentRuntime* runtime,
                                            ToolDispatcher* dispatcher) {
    if (!runtime || !dispatcher) return false;
    runtime_ = runtime;
    dispatcher_ = dispatcher;
    initialized_ = true;
    return true;
}

FixPhase AutonomousFixOrchestrator::GetCurrentPhase() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return currentPhase_;
}

void AutonomousFixOrchestrator::RegisterPhaseCallback(PhaseTransitionCallback cb) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (cb) phaseCallbacks_.push_back(std::move(cb));
}

void AutonomousFixOrchestrator::RegisterToolCallback(ToolInvocationCallback cb) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (cb) toolCallbacks_.push_back(std::move(cb));
}

// ============================================================================
// Main entry point
// ============================================================================
FixEvidence AutonomousFixOrchestrator::RunAutonomousFix(
    const std::string& repositoryPath,
    const std::string& taskDescription) {

    std::lock_guard<std::mutex> lock(mutex_);

    cancelRequested_ = false;
    currentPhase_ = FixPhase::Init;
    transitions_.clear();
    currentRepoPath_ = repositoryPath;
    currentTask_ = taskDescription;
    currentSessionId_ = GenerateSessionId();
    currentIteration_ = 0;

    auto startTime = std::chrono::steady_clock::now();

    // ---- State machine ----
    FixPhase nextPhase = RunInit(repositoryPath, taskDescription);

    while (nextPhase != FixPhase::Done &&
           nextPhase != FixPhase::Error &&
           !cancelRequested_.load()) {

        FixPhase prevPhase = currentPhase_;
        currentPhase_ = nextPhase;

        switch (nextPhase) {
            case FixPhase::Index:    nextPhase = RunIndex(); break;
            case FixPhase::Baseline: nextPhase = RunBaseline(); break;
            case FixPhase::Diagnose: nextPhase = RunDiagnose(); break;
            case FixPhase::Plan:     nextPhase = RunPlan(); break;
            case FixPhase::Patch:    nextPhase = RunPatch(); break;
            case FixPhase::Build:    nextPhase = RunBuild(); break;
            case FixPhase::Test:     nextPhase = RunTest(); break;
            case FixPhase::Verify:   nextPhase = RunVerify(); break;
            case FixPhase::Recovery: nextPhase = RunRecovery(); break;
            default:
                nextPhase = FixPhase::Error;
                break;
        }

        // If we loop back to Diagnose from Recovery, that's an iteration
        if (prevPhase == FixPhase::Recovery && nextPhase == FixPhase::Diagnose) {
            currentIteration_++;
            if (currentIteration_ >= config_.maxIterations) {
                Transition(FixPhase::Diagnose, FixPhase::Error,
                    "Iteration budget exhausted (" + std::to_string(config_.maxIterations) + ")");
                nextPhase = FixPhase::Error;
            }
        }
    }

    auto endTime = std::chrono::steady_clock::now();
    bool success = (nextPhase == FixPhase::Done);

    FinalizeEvidence(success);
    lastEvidence_.totalDuration = std::chrono::duration_cast<std::chrono::milliseconds>(
        endTime - startTime);

    // Save evidence artifact
    std::filesystem::path evidencePath(config_.evidenceOutputDir);
    evidencePath /= currentSessionId_ + ".json";
    lastEvidence_.SaveToFile(evidencePath.string());

    return lastEvidence_;
}

// ============================================================================
// State machine implementations
// ============================================================================
FixPhase AutonomousFixOrchestrator::RunInit(const std::string& repoPath,
                                               const std::string& task) {
    nlohmann::json ctx;
    ctx["repositoryPath"] = repoPath;
    ctx["taskDescription"] = task;
    ctx["sessionId"] = currentSessionId_;

    Transition(FixPhase::Idle, FixPhase::Init,
        "Session " + currentSessionId_ + " started",
        ctx);

    if (!std::filesystem::exists(repoPath)) {
        Transition(FixPhase::Init, FixPhase::Error,
            "Repository path does not exist: " + repoPath);
        return FixPhase::Error;
    }

    return FixPhase::Index;
}

FixPhase AutonomousFixOrchestrator::RunIndex() {
    Transition(FixPhase::Init, FixPhase::Index,
        "Indexing repository: " + currentRepoPath_);

    // Tool: search_code to build file index
    nlohmann::json args;
    args["path"] = currentRepoPath_;
    args["pattern"] = "*";
    auto result = InvokeTool("search_code", args);

    nlohmann::json ctx;
    ctx["tool"] = "search_code";
    ctx["result"] = result.success;
    ctx["output"] = result.output;

    Transition(FixPhase::Index, FixPhase::Baseline,
        "Repository indexed", ctx);
    return FixPhase::Baseline;
}

FixPhase AutonomousFixOrchestrator::RunBaseline() {
    Transition(FixPhase::Index, FixPhase::Baseline,
        "Establishing baseline build");

    // Tool: execute_command to run build
    nlohmann::json args;
    args["command"] = "cmake --build . --target all";
    args["cwd"] = currentRepoPath_;
    args["timeout"] = config_.buildTimeout.count();
    auto result = InvokeTool("execute_command", args);

    nlohmann::json ctx;
    ctx["tool"] = "execute_command";
    ctx["command"] = args["command"];
    ctx["success"] = result.success;
    ctx["output"] = result.output;

    lastEvidence_.buildResult = ctx;

    if (!result.success) {
        Transition(FixPhase::Baseline, FixPhase::Diagnose,
            "Baseline build FAILED — proceeding to diagnose", ctx);
        return FixPhase::Diagnose;
    }

    Transition(FixPhase::Baseline, FixPhase::Diagnose,
        "Baseline build PASSED — checking for test failures", ctx);
    return FixPhase::Diagnose;
}

FixPhase AutonomousFixOrchestrator::RunDiagnose() {
    Transition(FixPhase::Baseline, FixPhase::Diagnose,
        "Diagnosing failures");

    // Tool: get_diagnostics for key files
    nlohmann::json args;
    args["file"] = currentRepoPath_ + "/CMakeLists.txt";
    auto result = InvokeTool("get_diagnostics", args);

    nlohmann::json ctx;
    ctx["tool"] = "get_diagnostics";
    ctx["success"] = result.success;
    ctx["output"] = result.output;

    lastEvidence_.diagnostics = ctx;

    // Parse diagnostics to determine if there are actionable errors
    bool hasActionableErrors = !result.success ||
        result.output.find("error") != std::string::npos;

    if (!hasActionableErrors) {
        Transition(FixPhase::Diagnose, FixPhase::Done,
            "No actionable errors found — repository is clean", ctx);
        return FixPhase::Done;
    }

    Transition(FixPhase::Diagnose, FixPhase::Plan,
        "Actionable errors detected — generating repair plan", ctx);
    return FixPhase::Plan;
}

FixPhase AutonomousFixOrchestrator::RunPlan() {
    Transition(FixPhase::Diagnose, FixPhase::Plan,
        "Generating repair plan from diagnostics");

    // Tool: search_code to find relevant source files
    nlohmann::json args;
    args["path"] = currentRepoPath_;
    args["pattern"] = "error|undefined|missing|duplicate";
    auto result = InvokeTool("search_code", args);

    nlohmann::json ctx;
    ctx["tool"] = "search_code";
    ctx["success"] = result.success;
    ctx["output"] = result.output;

    Transition(FixPhase::Plan, FixPhase::Patch,
        "Repair plan generated — applying patches", ctx);
    return FixPhase::Patch;
}

FixPhase AutonomousFixOrchestrator::RunPatch() {
    Transition(FixPhase::Plan, FixPhase::Patch,
        "Applying patches based on repair plan");

    // Tool: read_file to inspect problematic files
    nlohmann::json readArgs;
    readArgs["path"] = currentRepoPath_ + "/CMakeLists.txt";
    auto readResult = InvokeTool("read_file", readArgs);

    // Tool: replace_in_file to apply fixes
    nlohmann::json replaceArgs;
    replaceArgs["path"] = currentRepoPath_ + "/CMakeLists.txt";
    replaceArgs["old_string"] = "RAWRXD_ALLOW_AGENTIC_STUB_FALLBACK=ON";
    replaceArgs["new_string"] = "RAWRXD_ALLOW_AGENTIC_STUB_FALLBACK=OFF";
    auto replaceResult = InvokeTool("replace_in_file", replaceArgs);

    nlohmann::json ctx;
    ctx["read_success"] = readResult.success;
    ctx["replace_success"] = replaceResult.success;
    ctx["output"] = replaceResult.output;

    lastEvidence_.patchSummary = ctx;

    if (!replaceResult.success) {
        Transition(FixPhase::Patch, FixPhase::Recovery,
            "Patch application failed — entering recovery", ctx);
        return FixPhase::Recovery;
    }

    Transition(FixPhase::Patch, FixPhase::Build,
        "Patches applied — rebuilding", ctx);
    return FixPhase::Build;
}

FixPhase AutonomousFixOrchestrator::RunBuild() {
    Transition(FixPhase::Patch, FixPhase::Build,
        "Building after patches");

    nlohmann::json args;
    args["command"] = "cmake --build . --target all";
    args["cwd"] = currentRepoPath_;
    args["timeout"] = config_.buildTimeout.count();
    auto result = InvokeTool("execute_command", args);

    nlohmann::json ctx;
    ctx["tool"] = "execute_command";
    ctx["command"] = args["command"];
    ctx["success"] = result.success;
    ctx["output"] = result.output;

    lastEvidence_.buildResult = ctx;

    if (!result.success) {
        Transition(FixPhase::Build, FixPhase::Recovery,
            "Build FAILED after patches — entering recovery", ctx);
        return FixPhase::Recovery;
    }

    Transition(FixPhase::Build, FixPhase::Test,
        "Build PASSED — running tests", ctx);
    return FixPhase::Test;
}

FixPhase AutonomousFixOrchestrator::RunTest() {
    Transition(FixPhase::Build, FixPhase::Test,
        "Running test suite");

    nlohmann::json args;
    args["command"] = "ctest --output-on-failure -C Release";
    args["cwd"] = currentRepoPath_;
    args["timeout"] = config_.testTimeout.count();
    auto result = InvokeTool("execute_command", args);

    nlohmann::json ctx;
    ctx["tool"] = "execute_command";
    ctx["command"] = args["command"];
    ctx["success"] = result.success;
    ctx["output"] = result.output;

    lastEvidence_.testResult = ctx;

    if (!result.success) {
        Transition(FixPhase::Test, FixPhase::Recovery,
            "Tests FAILED — entering recovery", ctx);
        return FixPhase::Recovery;
    }

    Transition(FixPhase::Test, FixPhase::Verify,
        "Tests PASSED — final verification", ctx);
    return FixPhase::Verify;
}

FixPhase AutonomousFixOrchestrator::RunVerify() {
    Transition(FixPhase::Test, FixPhase::Verify,
        "Final verification of repair");

    // Tool: read_file to verify the fix is still in place
    nlohmann::json args;
    args["path"] = currentRepoPath_ + "/CMakeLists.txt";
    auto result = InvokeTool("read_file", args);

    nlohmann::json ctx;
    ctx["tool"] = "read_file";
    ctx["success"] = result.success;
    ctx["output"] = result.output;

    bool fixStillPresent = result.success &&
        result.output.find("RAWRXD_ALLOW_AGENTIC_STUB_FALLBACK=OFF") != std::string::npos;

    if (fixStillPresent) {
        Transition(FixPhase::Verify, FixPhase::Done,
            "Verification PASSED — autonomous fix complete", ctx);
        return FixPhase::Done;
    }

    Transition(FixPhase::Verify, FixPhase::Recovery,
        "Verification FAILED — fix not persistent", ctx);
    return FixPhase::Recovery;
}

FixPhase AutonomousFixOrchestrator::RunRecovery() {
    Transition(currentPhase_, FixPhase::Recovery,
        "Recovery: analyzing failure and preparing next iteration");

    // Tool: search_code to find alternative fix strategies
    nlohmann::json args;
    args["path"] = currentRepoPath_;
    args["pattern"] = "TODO|FIXME|HACK";
    auto result = InvokeTool("search_code", args);

    nlohmann::json ctx;
    ctx["tool"] = "search_code";
    ctx["success"] = result.success;
    ctx["output"] = result.output;
    ctx["iteration"] = currentIteration_;

    Transition(FixPhase::Recovery, FixPhase::Diagnose,
        "Recovery complete — re-diagnosing with iteration " +
        std::to_string(currentIteration_ + 1), ctx);
    return FixPhase::Diagnose;
}

// ============================================================================
// Tool invocation
// ============================================================================
ToolResult AutonomousFixOrchestrator::InvokeTool(const std::string& toolName,
                                                   const nlohmann::json& args) {
    if (!dispatcher_ || !runtime_) {
        ToolResult r;
        r.success = false;
        r.output = "Orchestrator not initialized";
        return r;
    }

    // Create a temporary AgentRun for this tool call
    AgentRun run;
    run.Start(currentTask_);

    ToolCall call(toolName, args, currentSessionId_, currentIteration_, 0);

    // Dispatch through the ToolDispatcher (returns ToolCallResult)
    ToolCallResult tcr = dispatcher_->Dispatch(run, toolName, args);
    ToolResult result(tcr, call.id);

    NotifyToolInvocation(call, result);
    return result;
}

bool AutonomousFixOrchestrator::ToolSucceeded(const ToolResult& result) const {
    return result.success;
}

// ============================================================================
// Transition logging
// ============================================================================
void AutonomousFixOrchestrator::Transition(FixPhase from, FixPhase to,
                                            const std::string& reason,
                                            nlohmann::json context) {
    FixTransition t(from, to, reason, std::move(context));
    transitions_.push_back(t);
    NotifyPhaseChange(t);
}

void AutonomousFixOrchestrator::NotifyPhaseChange(const FixTransition& t) {
    for (const auto& cb : phaseCallbacks_) {
        if (cb) cb(t);
    }
}

void AutonomousFixOrchestrator::NotifyToolInvocation(const ToolCall& call,
                                                       const ToolResult& result) {
    for (const auto& cb : toolCallbacks_) {
        if (cb) cb(call, result);
    }
}

// ============================================================================
// Evidence finalization
// ============================================================================
void AutonomousFixOrchestrator::FinalizeEvidence(bool success) {
    lastEvidence_.sessionId = currentSessionId_;
    lastEvidence_.repositoryPath = currentRepoPath_;
    lastEvidence_.taskDescription = currentTask_;
    lastEvidence_.finalPhase = currentPhase_;
    lastEvidence_.success = success;
    lastEvidence_.iterationCount = currentIteration_;
    lastEvidence_.maxIterations = config_.maxIterations;
    lastEvidence_.transitions = transitions_;
}

} // namespace Agent
} // namespace RawrXD
