// =============================================================================
// SelfRepairLoop.h — Autonomous Engineering Cycle
// =============================================================================
// Implements the core autonomous development loop:
//   1. Load task from persistent backlog
//   2. Generate implementation via active inference backend (Deep2 primary)
//   3. Apply source changes (via tool registry)
//   4. Compile and link
//   5. Run regression tests
//   6. On PASS: commit and continue
//   7. On FAIL: diagnose, retry (with backoff), or revert
//   8. Checkpoint progress
//   9. Select next task
//
// Safety:
//   - Never splices output from two different models during failover
//   - Never replays tool side-effects (edits, builds, commands) on failover
//   - Git isolation: all changes on a feature branch, rebased before commit
//   - Approval gates for high-impact changes
//   - Disk space, time, and resource limits enforced per task
//   - Rollback to last verified baseline on persistent failure
//
// This is the engine for RawrXD's self-development capability.
// =============================================================================
#pragma once

#include "InferenceBackend.h"
#include "BackendRouter.h"
#include "ToolCallBridge.h"
#include "PersistentTaskBacklog.h"
#include "tool_core.hpp"
#include <string>
#include <vector>
#include <functional>
#include <chrono>
#include <optional>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace RawrXD {
namespace Agent {

// ---------------------------------------------------------------------------
// Build result
// ---------------------------------------------------------------------------
struct BuildResult {
    bool        success = false;
    std::string output;          // Build output (truncated to limits)
    std::string error_output;
    int         exit_code = 0;
    double      elapsed_seconds = 0;
    std::vector<std::string> warnings;
    std::vector<std::string> errors;
};

// ---------------------------------------------------------------------------
// Test result
// ---------------------------------------------------------------------------
struct TestResult {
    bool        success = false;
    std::string output;
    int         tests_passed = 0;
    int         tests_failed = 0;
    int         tests_total  = 0;
    double      elapsed_seconds = 0;
    std::vector<std::string> failures;
};

// ---------------------------------------------------------------------------
// Self-repair cycle outcome
// ---------------------------------------------------------------------------
enum class CycleOutcome : int {
    Success          = 0,   // Build + tests passed, changes committed
    BuildFailed      = 1,   // Compile/link failed; repair attempted
    TestFailed       = 2,   // Tests failed; repair attempted
    RepairSucceeded  = 3,   // Repair attempt succeeded after prior failure
    Reverted         = 4,   // Changes reverted to last known-good baseline
    Blocked          = 5,   // Task blocked (resources, dependencies)
};

inline const char* CycleOutcomeName(CycleOutcome o) {
    switch (o) {
        case CycleOutcome::Success:         return "success";
        case CycleOutcome::BuildFailed:     return "build_failed";
        case CycleOutcome::TestFailed:      return "test_failed";
        case CycleOutcome::RepairSucceeded: return "repair_succeeded";
        case CycleOutcome::Reverted:        return "reverted";
        case CycleOutcome::Blocked:         return "blocked";
        default:                            return "unknown";
    }
}

// ---------------------------------------------------------------------------
// Self-repair configuration
// ---------------------------------------------------------------------------
struct SelfRepairConfig {
    std::string   workspace_dir;
    std::string   build_dir          = "build";
    std::string   build_config       = "Release";
    std::string   git_branch_prefix  = "rawrxd-auto";
    std::string   test_command       = "";       // Empty = all tests
    int           max_retries        = 3;
    int           max_repair_attempts = 3;
    int           build_timeout_min  = 10;
    int           test_timeout_min   = 5;
    bool          auto_commit        = true;
    bool          require_test_pass  = true;
    bool          revert_on_failure  = true;
    int           min_exit_code_for_parity_fail = 1;  // For DeepSeek parity test
};

// ---------------------------------------------------------------------------
// Tool execution result (for repair diagnostics)
// ---------------------------------------------------------------------------
struct ToolExecDetail {
    std::string tool_name;
    std::string args_json;
    std::string output;
    std::string error;
    bool        success = false;
    double      elapsed_ms = 0;
};

// ---------------------------------------------------------------------------
// SelfRepairLoop — autonomous engineering cycle
// ---------------------------------------------------------------------------
class SelfRepairLoop {
public:
    using ProgressCallback = std::function<void(const std::string& stage,
                                                 const std::string& detail)>;

    explicit SelfRepairLoop(const SelfRepairConfig& config);
    ~SelfRepairLoop() = default;

    // ---- Main entry point: run one full autonomous cycle ----
    // Returns the outcome and fills in details
    CycleOutcome RunCycle(
        const std::string& task_description,
        const json&        conversation_context = json::array(),
        ProgressCallback   on_progress = nullptr);

    // ---- Individual stages (also exposed for fine-grained control) ----
    BuildResult BuildProject();
    TestResult  RunTests();
    std::string DiagnoseFailure(const BuildResult& build, const TestResult& test);
    bool        ApplyRepair(const std::string& diagnosis, const json& context);
    bool        CommitChanges(const std::string& message);
    bool        RevertToBaseline();
    std::string GetCurrentGitCommit() const;
    std::string GetGitDiff() const;

    // ---- State introspection ----
    PersistentTask& GetCurrentTask() { return m_currentTask; }
    std::string GetWorkspaceDir() const { return m_config.workspace_dir; }
    BackendMode GetBackendMode() const;
    void SetBackendMode(BackendMode mode);

    // ---- Resource monitoring ----
    size_t GetDiskUsageMb() const;
    bool   CheckDiskSpace(size_t required_mb) const;
    void   CleanupOldBuilds(int keep_last_n = 3) const;

private:
    SelfRepairConfig m_config;
    PersistentTaskBacklog m_backlog;
    PersistentTask m_currentTask;
    std::unique_ptr<BackendRouter> m_router;
    std::unique_ptr<ToolCallBridge> m_toolBridge;
    rawrxd::tools::Registry m_toolRegistry;

    // ---- Internal stages ----
    bool     GenerateAndApplyChanges(const std::string& prompt,
                                      const json& context,
                                      ProgressCallback progress);
    BuildResult CompileAndLink(ProgressCallback progress);
    TestResult ExecuteTests(ProgressCallback progress);
    std::string AnalyzeBuildErrors(const BuildResult& result);
    std::string AnalyzeTestFailures(const TestResult& result);
    bool     SaveCheckpoint();
    bool     RestoreCheckpoint();
    std::string GenerateCommitMessage(const std::vector<TaskStep>& steps) const;
    json     BuildToolSchemasForLLM() const;

    // ---- Git operations ----
    std::string RunGitCommand(const std::vector<std::string>& args,
                               const std::string& cwd = "") const;
    bool CreateFeatureBranch();
    bool CheckoutBaseline();
    void InitGitIfNecessary();

    // ---- LLM interaction ----
    json        BuildSystemPrompt() const;
    std::string GetWorkspaceContext() const;
};

} // namespace Agent
} // namespace RawrXD
