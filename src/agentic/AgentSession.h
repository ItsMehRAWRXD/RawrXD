// =============================================================================
// AgentSession.h — Session State + Driver-Owned Audit Ledger
// =============================================================================
// Fixes the RAWRXD_SELF_AUDIT_001 defects:
//
//   1. "The agent loop ended without a final structured ledger."
//      -> The DRIVER owns the ledger, not the model. It is written
//         incrementally after every event and finalized on ANY exit path
//         (success, failure, crash, cancellation). A model that runs out of
//         turns, emits malformed JSON, or loses its connection cannot erase
//         execution evidence.
//
//   2. "run_build ok=1 needs a stronger certificate."
//      -> BuildResult records process_exit_code, build_target,
//         build_configuration, artifacts_verified, compiler_errors and
//         log_path. Those fields come from real process evidence, never
//         assumed from a tool's self-reported success.
//
//   3. Path resolution: the model treated "What RawrXD Is" as a filesystem
//      path. -> The session supplies the canonical workspace root at
//         initialisation, tools default to it, and a rejected path returns
//         permitted alternatives instead of silently failing.
//
//   4. Tool calls must be persisted with args and results, not just counts.
//
// Authoritative fields required by the audit checklist:
//   task_id, git_revision, git_branch, model_identity, session_start,
//   agent_turns, tool_calls, tool_results, build_results, files_modified,
//   tests_executed, failure_reasons, last_checkpoint, termination_reason,
//   driver_exit_code, final_verdict
// =============================================================================
#pragma once

#include "InferenceBackend.h"
#include "AgentMode.h"
#include "PersistentTaskBacklog.h"

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <chrono>
#include <fstream>
#include <filesystem>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace RawrXD {
namespace Agent {

// ---------------------------------------------------------------------------
// Tool call record (durable, per-call)
// ---------------------------------------------------------------------------
struct ToolCallRecord {
    std::string tool_name;
    json        args;
    bool        ok = false;
    std::string output;
    std::string error;
    int64_t     timestamp = 0;
    double      elapsed_ms = 0.0;
    bool        approved_by = false;   // was an approval callback consulted?
    std::string denial_reason;         // set when the mode policy denied it
};

// ---------------------------------------------------------------------------
// Build evidence (strong certificate — not just ok=1)
// ---------------------------------------------------------------------------
struct BuildEvidence {
    bool        tool_ok = false;            // tool wrapper itself ran
    int         process_exit_code = -1;     // REAL compiler exit code
    std::string build_target;
    std::string build_configuration;
    bool        artifacts_verified = false;
    int         compiler_errors = 0;
    int         compiler_warnings = 0;
    std::string log_path;
    std::string command;
    double      elapsed_seconds = 0.0;
    std::vector<std::string> artifact_paths;

    bool Succeeded() const { return tool_ok && process_exit_code == 0 && artifacts_verified; }

    json ToJson() const {
        return {
            {"tool_ok", tool_ok},
            {"process_exit_code", process_exit_code},
            {"build_target", build_target},
            {"build_configuration", build_configuration},
            {"artifacts_verified", artifacts_verified},
            {"compiler_errors", compiler_errors},
            {"compiler_warnings", compiler_warnings},
            {"log_path", log_path},
            {"command", command},
            {"elapsed_seconds", elapsed_seconds},
            {"artifact_paths", artifact_paths},
            {"success", Succeeded()},
        };
    }
};

// ---------------------------------------------------------------------------
// Test evidence
// ---------------------------------------------------------------------------
struct TestEvidence {
    bool        tool_ok = false;
    int         process_exit_code = -1;
    int         tests_passed = 0;
    int         tests_failed = 0;
    int         tests_total  = 0;
    std::string log_path;
    std::string command;
    double      elapsed_seconds = 0.0;
    std::vector<std::string> failures;

    bool Succeeded() const { return tool_ok && process_exit_code == 0 && tests_failed == 0; }

    json ToJson() const {
        return {
            {"tool_ok", tool_ok},
            {"process_exit_code", process_exit_code},
            {"tests_passed", tests_passed},
            {"tests_failed", tests_failed},
            {"tests_total", tests_total},
            {"log_path", log_path},
            {"command", command},
            {"elapsed_seconds", elapsed_seconds},
            {"success", Succeeded()},
        };
    }
};

// ---------------------------------------------------------------------------
// Termination reasons
// ---------------------------------------------------------------------------
enum class TerminationReason : int {
    Running = 0,
    ModelCompleted = 1,      // model emitted a validated final answer
    ModelRanOutOfTurns = 2,  // hit max turns without final answer
    MalformedModelOutput = 3,
    BackendUnavailable = 4,
    Cancelled = 5,
    ToolDenied = 6,
    BuildFailed = 7,
    TestFailed = 8,
    Reverted = 9,
    DriverException = 10,
    DriverCrashed = 11,
};

inline const char* TerminationReasonName(TerminationReason r) {
    switch (r) {
        case TerminationReason::Running:              return "running";
        case TerminationReason::ModelCompleted:       return "model_completed";
        case TerminationReason::ModelRanOutOfTurns:   return "model_ran_out_of_turns";
        case TerminationReason::MalformedModelOutput: return "malformed_model_output";
        case TerminationReason::BackendUnavailable:   return "backend_unavailable";
        case TerminationReason::Cancelled:            return "cancelled";
        case TerminationReason::ToolDenied:           return "tool_denied";
        case TerminationReason::BuildFailed:          return "build_failed";
        case TerminationReason::TestFailed:           return "test_failed";
        case TerminationReason::Reverted:             return "reverted";
        case TerminationReason::DriverException:      return "driver_exception";
        case TerminationReason::DriverCrashed:        return "driver_crashed";
        default:                                      return "unknown";
    }
}

// ---------------------------------------------------------------------------
// AgentSession — durable, incrementally persisted execution record
// ---------------------------------------------------------------------------
class AgentSession {
public:
    struct Identity {
        std::string task_id;
        std::string git_revision;
        std::string git_branch;
        std::string model_identity;   // e.g. "ollama/qwen3:8b" or "deep2/qwen3:8b"
        int64_t     session_start = 0;
        std::string workspace_root;
        std::string cli_version = "rawr-cli/2.0";
    };

    AgentSession();
    explicit AgentSession(const std::string& ledger_path);

    // ---- Identity / configuration ----
    void SetTaskId(std::string id) { m_task_id = std::move(id); Flush(); }
    void SetGitState(const std::string& revision, const std::string& branch);
    void SetModelIdentity(const std::string& id) { m_model_identity = std::move(id); Flush(); }
    void SetWorkspaceRoot(const std::string& root) { m_workspace_root = std::move(root); Flush(); }
    void SetMode(AgentMode mode) { m_mode = mode; Flush(); }
    AgentMode GetMode() const { return m_mode; }
    void SetLedgerPath(const std::string& path);

    const std::string& TaskId() const { return m_task_id; }
    const Identity& GetIdentity() const { return m_identity; }

    // ---- Conversation (model session, shared across mode switches) ----
    void AppendUserMessage(const std::string& content);
    void AppendAssistantMessage(const std::string& content);
    void AppendToolResultMessage(const ToolCallRecord& record);
    const json& Conversation() const { return m_conversation; }
    void SetConversation(const json& conv) { m_conversation = conv; Flush(); }

    // ---- Event recording (each triggers an incremental flush) ----
    void RecordAgentTurn();
    void RecordToolCall(const ToolCallRecord& record);
    void RecordBuild(const BuildEvidence& build);
    void RecordTest(const TestEvidence& test);
    void RecordFileModified(const std::string& path);
    void RecordFailure(const std::string& reason);
    void RecordCheckpoint(const std::string& path);
    void RecordCommit(const std::string& sha, const std::string& message);

    // ---- Model final answer (validated structure) ----
    struct FinalAnswer {
        bool        valid = false;
        std::string summary;
        std::string remaining_work;
        std::vector<std::string> changes_made;
        std::vector<std::string> evidence;
        std::string validation_error;
    };
    void RecordFinalAnswer(const FinalAnswer& answer);

    // ---- Termination ----
    void SetTermination(TerminationReason reason, int driver_exit_code);
    void SetVerdict(const std::string& verdict) { m_final_verdict = std::move(verdict); Flush(); }

    // ---- Persistence (driver-owned; independent of the model) ----
    void Flush() const;                       // write the whole ledger atomically
    bool LoadFromDisk();                      // recovery on next launch
    json ToJson() const;
    std::string LedgerPath() const { return m_ledger_path; }

    // ---- Time helper (public: callers record event timestamps) ----
    static int64_t NowUnix();

    // ---- Self-Audit 002 acceptance counters ----
    int  AgentTurnCount() const { return m_agent_turns; }
    int  ToolCallCount() const { return static_cast<int>(m_tool_calls.size()); }
    int  SuccessfulToolCallCount() const;
    bool HasFinalAnswer() const { return m_final_answer.valid; }
    int  FileModifiedCount() const { return static_cast<int>(m_files_modified.size()); }

    // ---- Evidence accessors (for self-audit) ----
    const std::vector<BuildEvidence>& Builds() const { return m_builds; }
    const std::vector<TestEvidence>&  Tests()  const { return m_tests; }
    const std::vector<json>&          Commits() const { return m_commits; }
    TerminationReason Termination() const { return m_termination; }
    std::string TerminationName() const { return TerminationReasonName(m_termination); }
    int             DriverExitCode() const { return m_driver_exit_code; }

private:
    // Identity
    Identity     m_identity;
    std::string  m_task_id;
    std::string  m_git_revision;
    std::string  m_git_branch;
    std::string  m_model_identity;
    std::string  m_workspace_root;
    int64_t      m_session_start = 0;
    AgentMode    m_mode = AgentMode::Code;

    // Execution records
    json m_conversation = json::array();
    int  m_agent_turns = 0;
    std::vector<ToolCallRecord> m_tool_calls;
    std::vector<BuildEvidence>  m_builds;
    std::vector<TestEvidence>   m_tests;
    std::vector<std::string>    m_files_modified;
    std::vector<std::string>    m_failure_reasons;
    std::vector<std::string>    m_checkpoints;
    std::vector<json>           m_commits;
    FinalAnswer m_final_answer;

    // Termination
    TerminationReason m_termination = TerminationReason::Running;
    int               m_driver_exit_code = -1;
    std::string       m_final_verdict;

    // Persistence
    std::string        m_ledger_path;
    mutable std::mutex m_mtx;

    static int64_t NowUnixPublic() { return NowUnix(); }
    void EnsureLedgerPath() const;
    bool WriteAtomically(const std::string& path, const std::string& content) const;
};

} // namespace Agent
} // namespace RawrXD
