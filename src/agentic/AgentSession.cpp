// =============================================================================
// AgentSession.cpp — Driver-owned incremental audit ledger
// =============================================================================
#include "AgentSession.h"
#include <sstream>
#include <cstdlib>

namespace RawrXD {
namespace Agent {

int64_t AgentSession::NowUnix() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

AgentSession::AgentSession() {
    m_session_start = NowUnix();
    m_identity.session_start = m_session_start;
    m_ledger_path = ".rawrxd/ledger/agent_session.json";
}

AgentSession::AgentSession(const std::string& ledger_path) : m_ledger_path(ledger_path) {
    m_session_start = NowUnix();
    m_identity.session_start = m_session_start;
}

void AgentSession::SetLedgerPath(const std::string& path) {
    m_ledger_path = path;
    EnsureLedgerPath();
}

void AgentSession::EnsureLedgerPath() const {
    if (m_ledger_path.empty()) return;
    std::error_code ec;
    std::filesystem::path p(m_ledger_path);
    if (p.has_parent_path()) {
        std::filesystem::create_directories(p.parent_path(), ec);
    }
}

bool AgentSession::WriteAtomically(const std::string& path, const std::string& content) const {
    if (path.empty()) return false;
    std::string tmp = path + ".tmp";
    {
        std::ofstream f(tmp, std::ios::trunc);
        if (!f) return false;
        f << content;
        f.flush();
        if (!f) return false;
    }
    std::error_code ec;
    std::filesystem::rename(tmp, path, ec);
    if (ec) {
        // Fall back to a direct write on rename failure (e.g. cross-device).
        std::ofstream f(path, std::ios::trunc);
        if (!f) return false;
        f << content;
        return static_cast<bool>(f);
    }
    return true;
}

void AgentSession::SetGitState(const std::string& revision, const std::string& branch) {
    m_git_revision = revision;
    m_git_branch = branch;
    m_identity.git_revision = revision;
    m_identity.git_branch = branch;
    Flush();
}

void AgentSession::AppendUserMessage(const std::string& content) {
    m_conversation.push_back({
        {"role", "user"},
        {"content", content},
        {"timestamp", NowUnix()},
    });
    Flush();
}

void AgentSession::AppendAssistantMessage(const std::string& content) {
    m_conversation.push_back({
        {"role", "assistant"},
        {"content", content},
        {"timestamp", NowUnix()},
    });
    Flush();
}

void AgentSession::AppendToolResultMessage(const ToolCallRecord& record) {
    json msg = {
        {"role", "tool"},
        {"name", record.tool_name},
        {"content", record.ok ? record.output : record.error},
        {"timestamp", record.timestamp},
    };
    if (!record.args.is_null()) msg["args"] = record.args;
    m_conversation.push_back(msg);
    Flush();
}

void AgentSession::RecordAgentTurn() {
    m_agent_turns++;
    Flush();
}

void AgentSession::RecordToolCall(const ToolCallRecord& record) {
    m_tool_calls.push_back(record);
    Flush();
}

void AgentSession::RecordBuild(const BuildEvidence& build) {
    m_builds.push_back(build);
    if (!build.Succeeded()) {
        m_failure_reasons.push_back("build failed: exit code " +
            std::to_string(build.process_exit_code) +
            ", errors=" + std::to_string(build.compiler_errors));
    }
    Flush();
}

void AgentSession::RecordTest(const TestEvidence& test) {
    m_tests.push_back(test);
    if (!test.Succeeded()) {
        m_failure_reasons.push_back("tests failed: " +
            std::to_string(test.tests_failed) + "/" +
            std::to_string(test.tests_total));
    }
    Flush();
}

void AgentSession::RecordFileModified(const std::string& path) {
    if (std::find(m_files_modified.begin(), m_files_modified.end(), path) ==
        m_files_modified.end()) {
        m_files_modified.push_back(path);
    }
    Flush();
}

void AgentSession::RecordFailure(const std::string& reason) {
    m_failure_reasons.push_back(reason);
    Flush();
}

void AgentSession::RecordCheckpoint(const std::string& path) {
    m_checkpoints.push_back(path);
    Flush();
}

void AgentSession::RecordCommit(const std::string& sha, const std::string& message) {
    m_commits.push_back({
        {"sha", sha},
        {"message", message},
        {"timestamp", NowUnix()},
    });
    Flush();
}

void AgentSession::RecordFinalAnswer(const FinalAnswer& answer) {
    m_final_answer = answer;
    Flush();
}

void AgentSession::SetTermination(TerminationReason reason, int driver_exit_code) {
    m_termination = reason;
    m_driver_exit_code = driver_exit_code;
    Flush();
}

int AgentSession::SuccessfulToolCallCount() const {
    int n = 0;
    for (const auto& t : m_tool_calls) if (t.ok) n++;
    return n;
}

json AgentSession::ToJson() const {
    json j;
    j["schema"] = "RAWRXD_AGENT_LEDGER/1.0";

    // --- Authoritative identity block ---
    // (local copy: m_identity itself is read-only inside this const method)
    Identity id;
    id.task_id        = m_task_id;
    id.git_revision   = m_git_revision;
    id.git_branch     = m_git_branch;
    id.model_identity = m_model_identity;
    id.session_start  = m_session_start;
    id.workspace_root = m_workspace_root;

    j["task_id"]          = id.task_id;
    j["git_revision"]     = id.git_revision;
    j["git_branch"]       = id.git_branch;
    j["model_identity"]   = id.model_identity;
    j["session_start"]    = id.session_start;
    j["workspace_root"]   = id.workspace_root;

    // --- Model session ---
    j["agent_mode"]       = AgentModeName(m_mode);
    j["conversation"]     = m_conversation;

    // --- Execution counters ---
    j["agent_turns"]      = m_agent_turns;
    j["tool_calls"]       = json::array();
    for (const auto& t : m_tool_calls) {
        j["tool_calls"].push_back({
            {"tool", t.tool_name},
            {"args", t.args},
            {"ok", t.ok},
            {"output", t.output.size() > 8192 ? t.output.substr(0, 8192) + "...[truncated]" : t.output},
            {"error", t.error},
            {"timestamp", t.timestamp},
            {"elapsed_ms", t.elapsed_ms},
            {"approved", t.approved_by},
            {"denial_reason", t.denial_reason},
        });
    }

    // --- Build / test evidence ---
    j["build_results"] = json::array();
    for (const auto& b : m_builds) j["build_results"].push_back(b.ToJson());

    j["tests_executed"] = json::array();
    for (const auto& t : m_tests) j["tests_executed"].push_back(t.ToJson());

    // --- Source changes ---
    j["files_modified"] = m_files_modified;
    j["commits"] = m_commits;
    j["checkpoints"] = m_checkpoints;
    j["failure_reasons"] = m_failure_reasons;

    // --- Termination ---
    j["termination_reason"] = TerminationReasonName(m_termination);
    j["driver_exit_code"]   = m_driver_exit_code;
    j["final_verdict"]      = m_final_verdict;

    // --- Model final answer (may be absent; the driver still records) ---
    j["final_answer"] = {
        {"valid", m_final_answer.valid},
        {"summary", m_final_answer.summary},
        {"remaining_work", m_final_answer.remaining_work},
        {"changes_made", m_final_answer.changes_made},
        {"evidence", m_final_answer.evidence},
        {"validation_error", m_final_answer.validation_error},
    };

    // --- Derived acceptance flags (Self-Audit 002) ---
    j["acceptance"] = {
        {"agent_turns", m_agent_turns},
        {"tool_calls", static_cast<int>(m_tool_calls.size())},
        {"tool_calls_succeeded", SuccessfulToolCallCount()},
        {"source_edit_performed", !m_files_modified.empty()},
        {"build_passed", !m_builds.empty() && m_builds.back().Succeeded()},
        {"tests_passed", !m_tests.empty() && m_tests.back().Succeeded()},
        {"final_ledger_present", true},
        {"crash_free_exit", m_driver_exit_code == 0},
    };

    return j;
}

void AgentSession::Flush() const {
    EnsureLedgerPath();
    WriteAtomically(m_ledger_path, ToJson().dump(2));
}

bool AgentSession::LoadFromDisk() {
    if (m_ledger_path.empty()) return false;
    std::ifstream f(m_ledger_path);
    if (!f) return false;

    json j;
    try {
        f >> j;
    } catch (const json::exception&) {
        return false;   // corrupt ledger is not silently accepted
    }

    m_task_id          = j.value("task_id", std::string());
    m_git_revision     = j.value("git_revision", std::string());
    m_git_branch       = j.value("git_branch", std::string());
    m_model_identity   = j.value("model_identity", std::string());
    m_session_start    = j.value("session_start", int64_t(0));
    m_workspace_root   = j.value("workspace_root", std::string());
    m_agent_turns      = j.value("agent_turns", 0);
    m_conversation     = j.value("conversation", json::array());
    m_files_modified   = j.value("files_modified", std::vector<std::string>());
    m_failure_reasons  = j.value("failure_reasons", std::vector<std::string>());
    m_checkpoints      = j.value("checkpoints", std::vector<std::string>());
    m_commits          = j.value("commits", json::array());
    m_final_verdict    = j.value("final_verdict", std::string());

    auto mode = j.value("agent_mode", std::string("code"));
    AgentMode m{};
    if (AgentModeParse(mode, m)) m_mode = m;

    for (const auto& b : j.value("build_results", json::array())) {
        BuildEvidence e;
        e.tool_ok           = b.value("tool_ok", false);
        e.process_exit_code = b.value("process_exit_code", -1);
        e.build_target      = b.value("build_target", std::string());
        e.build_configuration = b.value("build_configuration", std::string());
        e.artifacts_verified= b.value("artifacts_verified", false);
        e.compiler_errors   = b.value("compiler_errors", 0);
        e.compiler_warnings = b.value("compiler_warnings", 0);
        e.log_path          = b.value("log_path", std::string());
        m_builds.push_back(e);
    }

    for (const auto& t : j.value("tests_executed", json::array())) {
        TestEvidence e;
        e.tool_ok           = t.value("tool_ok", false);
        e.process_exit_code = t.value("process_exit_code", -1);
        e.tests_passed      = t.value("tests_passed", 0);
        e.tests_failed      = t.value("tests_failed", 0);
        e.tests_total       = t.value("tests_total", 0);
        e.log_path          = t.value("log_path", std::string());
        m_tests.push_back(e);
    }

    for (const auto& t : j.value("tool_calls", json::array())) {
        ToolCallRecord r;
        r.tool_name   = t.value("tool", std::string());
        r.args        = t.value("args", json::object());
        r.ok          = t.value("ok", false);
        r.output      = t.value("output", std::string());
        r.error       = t.value("error", std::string());
        r.timestamp   = t.value("timestamp", int64_t(0));
        r.elapsed_ms  = t.value("elapsed_ms", 0.0);
        r.approved_by = t.value("approved", false);
        r.denial_reason = t.value("denial_reason", std::string());
        m_tool_calls.push_back(r);
    }

    if (j.contains("final_answer")) {
        const auto& fa = j["final_answer"];
        m_final_answer.valid            = fa.value("valid", false);
        m_final_answer.summary          = fa.value("summary", std::string());
        m_final_answer.remaining_work   = fa.value("remaining_work", std::string());
        m_final_answer.changes_made     = fa.value("changes_made", std::vector<std::string>());
        m_final_answer.evidence         = fa.value("evidence", std::vector<std::string>());
        m_final_answer.validation_error = fa.value("validation_error", std::string());
    }

    return true;
}

} // namespace Agent
} // namespace RawrXD
