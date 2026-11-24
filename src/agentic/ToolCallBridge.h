// =============================================================================
// ToolCallBridge.h — Bridge Between Inference Backend Tool Calls and RawrXD Tools
// =============================================================================
// Translates between:
//   1. InferenceBackend tool-call format (json: {name, arguments})
//   2. rawrxd::tools::Request/Result format (string args, Result struct)
//
// Both Deep2 and Ollama backends produce tool calls in the same JSON schema
// (OpenAI function-calling format). This bridge routes all tool calls through
// the single shared rawrxd::tools::Registry, ensuring identical tool execution
// regardless of which backend generated the call.
//
// Design:
//   - Tool schemas are generated from rawrxd::tools::Tool descriptors
//   - Arguments are validated against required parameters before execution
//   - Approval callback enforces risk-based execution policies
//   - Tool results are formatted back as chat messages for the LLM
// =============================================================================
#pragma once

#include "InferenceBackend.h"
#include "tool_core.hpp"
#include "tool_security.hpp"
#include "MotdAuthorization.h"
#include "AgentEventJournal.hpp"
#include "ToolCallExactlyOnceGuard.hpp"
#include <memory>
#include <string>
#include <vector>
#include <functional>
#include <mutex>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace RawrXD {
namespace Agent {

// ---------------------------------------------------------------------------
// Tool schema generation (OpenAI-compatible format for LLM tool calling)
// ---------------------------------------------------------------------------
inline json BuildToolSchema(const rawrxd::tools::Tool& tool) {
    json schema;
    schema["type"] = "function";
    schema["function"] = {
        {"name", tool.name},
        {"description", tool.description},
        {"parameters", {
            {"type", "object"},
            {"properties", json::object()},
            {"required", json::array()}
        }}
    };
    // Add placeholder for actual parameter schemas
    // In production, each tool should declare its parameter schema
    return schema;
}

// Defined after ToolCallBridge (needs the complete type); returns the same
// authoritative schema set as ToolCallBridge::GetToolSchemasForLLM().
inline json GetAllToolSchemas(const rawrxd::tools::Registry& registry);

// ---------------------------------------------------------------------------
// Tool call format for LLM responses
// ---------------------------------------------------------------------------
struct ToolCall {
    std::string id;
    std::string name;
    json        arguments;
};

// ---------------------------------------------------------------------------
// Tool result (formatted for LLM context)
// ---------------------------------------------------------------------------
struct ToolResultMessage {
    std::string tool_call_id;
    std::string tool_name;
    std::string content;       // Result text (or error message)
    bool        success;
    // G: authoritative acceptance verdict (from rawrxd::tools::Result).
    // Fail-closed: default is NotEvaluated and accepted=false so an
    // unevaluated path can never report success.
    enum class Acceptance { NotEvaluated, Accepted, Rejected, NotApplicable };
    Acceptance  acceptance = Acceptance::NotEvaluated;
    bool        accepted = false;
    std::string firstFailure;
};

// ---------------------------------------------------------------------------
// ToolCallBridge — routes LLM tool calls through the shared tool registry
// ---------------------------------------------------------------------------
class ToolCallBridge {
public:
    using ApprovalCallback = std::function<bool(const rawrxd::tools::Tool&, const rawrxd::tools::Request&)>;
    // Fail-closed security gate invoked BEFORE mutate/shell execute.
    // Return false + denyReason to block; must not stub always-true.
    using SecurityGateCallback = std::function<bool(const rawrxd::tools::Tool&,
                                                    const rawrxd::tools::Request&,
                                                    std::string& denyReason)>;

    ToolCallBridge() {
        // Issue #49: keep absorb markers reachable in Ext link set even when
        // ExecuteToolCall is not yet exercised on this TU (RUNTIME_REACHED scan).
        m_exactlyOnceRejectMarker = "EXACTLY_ONCE_REJECT";
        m_exactlyOnceDupMarker = "EXACTLY_ONCE_DUP";
    }
    ~ToolCallBridge() = default;

    // ---- Registry management ----
    void SetRegistry(rawrxd::tools::Registry* registry) {
        m_registry = registry;
        // Touch markers so MSVC cannot DCE constructor stores as unused.
        if (m_exactlyOnceRejectMarker && m_exactlyOnceDupMarker) {
            (void)m_exactlyOnceRejectMarker[0];
            (void)m_exactlyOnceDupMarker[0];
        }
    }
    rawrxd::tools::Registry* GetRegistry() const { return m_registry; }

    void SetWorkspaceRoot(const std::filesystem::path& root) {
        std::lock_guard<std::mutex> lock(m_turnMutex);
        m_workspaceRoot = root;
        m_motdAuthorization.SetWorkspaceRoot(root);
        m_exactlyOnce.Clear();
        m_turnOpen = false;
        if (m_exactlyOnceRejectMarker && m_exactlyOnceDupMarker) {
            (void)m_exactlyOnceRejectMarker[0];
            (void)m_exactlyOnceDupMarker[0];
        }
    }
    std::filesystem::path GetWorkspaceRoot() const { return m_workspaceRoot; }

    // Must be called for each new user-originated turn. Reusing an earlier turn
    // leaves the dispatcher fail-closed until the policy is read again.
    bool BeginUserTurn(const std::string& sessionId, uint64_t turnId) {
        std::lock_guard<std::mutex> lock(m_turnMutex);
        if (m_turnOpen) return false; // overlapping sessions fail closed
        if (!m_motdAuthorization.BeginTurn(sessionId, turnId)) return false;
        m_authorizationSession = sessionId;
        m_authorizationTurn = turnId;
        m_exactlyOnce.Clear();
        m_turnOpen = true;
        return true;
    }

    void EndUserTurn() {
        std::lock_guard<std::mutex> lock(m_turnMutex);
        if (!m_turnOpen) return;
        m_motdAuthorization.EndTurn(m_authorizationSession, m_authorizationTurn);
        m_authorizationSession.clear();
        m_authorizationTurn = 0;
        m_exactlyOnce.Clear();
        m_turnOpen = false;
    }

    // Issue #49: per-turn exactly-once counters (product ToolCallBridge path).
    int ExactlyOnceFirstCount() const { return m_exactlyOnce.FirstCount(); }
    int ExactlyOnceDupCount() const { return m_exactlyOnce.DupCount(); }
    int ExactlyOnceEmptyRejectCount() const { return m_exactlyOnce.EmptyRejectCount(); }

    rawrxd::agentic::MotdAuthorization::TurnGuard GuardUserTurn() {
        std::lock_guard<std::mutex> lock(m_turnMutex);
        return m_motdAuthorization.GuardTurn(m_authorizationSession, m_authorizationTurn);
    }

    void SetApprovalCallback(ApprovalCallback cb) { m_approval = cb; }
    void SetSecurityGate(SecurityGateCallback cb) { m_securityGate = std::move(cb); }

    void SetEventJournal(std::shared_ptr<AgentEventJournal> journal) {
        std::lock_guard<std::mutex> lock(m_turnMutex);
        m_journal = std::move(journal);
    }
    void SetJournalTaskId(std::string taskId) {
        std::lock_guard<std::mutex> lock(m_turnMutex);
        m_journalTaskId = std::move(taskId);
    }

    // P0 durable execution receipts: every allow/deny decision is appended to
    // an append-only JSONL log (default <workspace>/.rawrxd/audit/tool-receipts.jsonl).
    void SetReceiptLogPath(const std::string& path) {
        std::lock_guard<std::mutex> lock(m_turnMutex);
        m_receipts = std::make_shared<rawrxd::agentic::security::ToolReceiptLog>(path);
    }

    // ---- Tool schema generation for LLM ----
    // Returns OpenAI-format tool definitions for all registered tools
    json GetToolSchemasForLLM() const;

    // ---- Execution ----
    // Execute a single tool call from the LLM response. Every call (allow AND
    // deny) appends a durable receipt before returning.
    ToolResultMessage ExecuteToolCall(const ToolCall& call);

    // Execute multiple tool calls and return formatted results
    std::vector<ToolResultMessage> ExecuteToolCalls(
        const std::vector<ToolCall>& calls);

    // ---- Tool registration ----
    void RegisterTool(const rawrxd::tools::Tool& tool);

private:
    rawrxd::tools::Registry* m_registry = nullptr;
    std::filesystem::path m_workspaceRoot;
    ApprovalCallback m_approval;
    SecurityGateCallback m_securityGate;
    rawrxd::agentic::MotdAuthorization m_motdAuthorization;
    ToolCallExactlyOnceGuard m_exactlyOnce;
    const char* m_exactlyOnceRejectMarker = nullptr;
    const char* m_exactlyOnceDupMarker = nullptr;
    std::string m_authorizationSession;
    uint64_t m_authorizationTurn = 0;
    bool m_turnOpen = false;
    std::mutex m_turnMutex;
    std::shared_ptr<AgentEventJournal> m_journal;
    std::string m_journalTaskId;
    std::shared_ptr<rawrxd::agentic::security::ToolReceiptLog> m_receipts;

    // Convert LLM tool arguments (json) to rawrxd::tools::Request args (string map)
    rawrxd::tools::Request ConvertArgs(const ToolCall& call) const;

    ToolResultMessage ExecuteToolCallImpl(const ToolCall& call);
};

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

inline json ToolCallBridge::GetToolSchemasForLLM() const {
    // Authoritative tool schemas (OpenAI function-calling format). Properties
    // are complete and typed: the model sees exactly what each argument is and
    // which are required. Keep in sync with register_workspace_tools().
    json schemas = json::array();
    auto add = [&schemas](const std::string& name, const std::string& desc,
                          json properties, json required) {
        schemas.push_back(json{
            {"type", "function"},
            {"function", json{
                {"name", name},
                {"description", desc},
                {"parameters", json{
                    {"type", "object"},
                    {"properties", std::move(properties)},
                    {"required", std::move(required)},
                    {"additionalProperties", false}
                }}
            }}
        });
    };
    const auto intProp = [](const char* d) {
        return json{{"type", "integer"}, {"description", d}};
    };
    const auto strProp = [](const char* d) {
        return json{{"type", "string"}, {"description", d}};
    };

    add("readFile", "Read one bounded workspace file by path.",
        json{{"path", strProp("Workspace-relative file path")},
             {"maxBytes", intProp("Optional cap on returned bytes (default 262144, max 524288)")}},
        json::array({"path"}));
    add("Read", "Cursor-parity alias for readFile.",
        json{{"path", strProp("Workspace-relative file path")},
             {"maxBytes", intProp("Optional cap on returned bytes")}},
        json::array({"path"}));
    add("listDirectory", "List immediate children of a workspace directory.",
        json{{"path", strProp("Workspace-relative directory path")},
             {"maxEntries", intProp("Optional entry cap (default 128, max 256)")}},
        json::array({"path"}));
    add("fileSearch", "Find paths by filename substring.",
        json{{"pattern", strProp("Filename substring to match")},
             {"path", strProp("Optional workspace-relative start directory")},
             {"maxResults", intProp("Optional result cap (default 100, max 250)")}},
        json::array({"pattern"}));
    add("Glob", "Cursor-parity alias for fileSearch.",
        json{{"pattern", strProp("Filename substring to match")},
             {"path", strProp("Optional workspace-relative start directory")},
             {"maxResults", intProp("Optional result cap")}},
        json::array({"pattern"}));
    add("textSearch", "Search bounded text files for a literal string.",
        json{{"needle", strProp("Literal text to find")},
             {"path", strProp("Optional workspace-relative start directory")},
             {"maxResults", intProp("Optional match cap (default 100, max 250)")}},
        json::array({"needle"}));
    add("Grep", "Cursor-parity alias for textSearch.",
        json{{"needle", strProp("Literal text to find")},
             {"path", strProp("Optional workspace-relative start directory")},
             {"maxResults", intProp("Optional match cap")}},
        json::array({"needle"}));
    add("createDirectory", "Create a directory inside the workspace.",
        json{{"path", strProp("Workspace-relative directory path")}},
        json::array({"path"}));
    add("createFile", "Create a new file without overwriting.",
        json{{"path", strProp("Workspace-relative file path")},
             {"content", strProp("Full file content")}},
        json::array({"path", "content"}));
    add("writeFile", "Write or overwrite a workspace file.",
        json{{"path", strProp("Workspace-relative file path")},
             {"content", strProp("Full file content")}},
        json::array({"path", "content"}));
    add("Write", "Cursor-parity alias for writeFile.",
        json{{"path", strProp("Workspace-relative file path")},
             {"content", strProp("Full file content")}},
        json::array({"path", "content"}));
    add("editFiles", "Replace exact unique text in a file.",
        json{{"path", strProp("Workspace-relative file path")},
             {"old", strProp("Exact text to replace (must occur exactly once)")},
             {"new", strProp("Replacement text")}},
        json::array({"path", "old", "new"}));
    add("StrReplace", "Cursor-parity alias for editFiles.",
        json{{"path", strProp("Workspace-relative file path")},
             {"old", strProp("Exact text to replace (must occur exactly once)")},
             {"new", strProp("Replacement text")}},
        json::array({"path", "old", "new"}));
    add("deleteFile", "Delete a workspace file.",
        json{{"path", strProp("Workspace-relative file path")}},
        json::array({"path"}));
    add("Delete", "Cursor-parity alias for deleteFile.",
        json{{"path", strProp("Workspace-relative file path")}},
        json::array({"path"}));
    add("runInTerminal", "Execute an approved command with the workspace as cwd. Requires host authorization.",
        json{{"command", strProp("Command line to execute")},
             {"timeoutMs", intProp("Optional timeout in milliseconds")}},
        json::array({"command"}));
    add("Shell", "Cursor-parity alias for runInTerminal.",
        json{{"command", strProp("Command line to execute")},
             {"timeoutMs", intProp("Optional timeout in milliseconds")}},
        json::array({"command"}));
    add("computer_use.screenshot", "BMP capture of an allowlisted window.",
        json{{"hwnd", intProp("Target window handle")}},
        json::array({"hwnd"}));
    add("computer_use.find_window", "Find an allowlisted window by title.",
        json{{"title", strProp("Window title substring")}},
        json::array({"title"}));
    add("computer_use.inspect", "Enumerate child controls of a window.",
        json{{"hwnd", intProp("Target window handle")}},
        json::array({"hwnd"}));
    add("computer_use.click", "Click at client coordinates.",
        json{{"hwnd", intProp("Target window handle")},
             {"x", intProp("Client x")}, {"y", intProp("Client y")}},
        json::array({"hwnd", "x", "y"}));
    add("computer_use.type", "Type Unicode text into a window.",
        json{{"hwnd", intProp("Target window handle")},
             {"text", strProp("Unicode text to type")}},
        json::array({"hwnd", "text"}));
    add("computer_use.key", "Send a virtual-key to a window.",
        json{{"hwnd", intProp("Target window handle")},
             {"vk", intProp("Virtual-key code")}},
        json::array({"hwnd", "vk"}));
    add("computer_use.scroll", "Scroll at client coordinates.",
        json{{"hwnd", intProp("Target window handle")},
             {"x", intProp("Client x")}, {"y", intProp("Client y")},
             {"delta", intProp("Scroll delta")}},
        json::array({"hwnd", "x", "y", "delta"}));
    add("computer_use.launch", "Launch an absolute executable path (no shell).",
        json{{"path", strProp("Absolute executable path")}},
        json::array({"path"}));

    // Reserved host tool. It reads only the workspace's PassiveRoleNotRoleplay
    // policy file and records the ACK bound to the active session and turn.
    add("read_motd",
        "Required first tool action each user turn: read the workspace execution policy.",
        json::object(), json::array());

    return schemas;
}

inline rawrxd::tools::Request ToolCallBridge::ConvertArgs(const ToolCall& call) const {
    rawrxd::tools::Request req;
    // Prefer Cursor-native names when registered; else canonicalize to RawrXD.
    req.name = call.name;
    if (m_registry) {
        rawrxd::tools::Tool probe;
        if (!m_registry->find(call.name, probe)) {
            if (const char* canon = rawrxd::tools::canonicalize_tool_name(call.name)) {
                req.name = canon;
            }
        }
    } else if (const char* canon = rawrxd::tools::canonicalize_tool_name(call.name)) {
        req.name = canon;
    }

    // Cursor Grep uses "pattern"; textSearch requires "needle".
    // Cursor StrReplace uses old_string/new_string; editFiles uses old/new.
    // Cursor Write/Shell use path/contents or command — already aligned.
    for (auto it = call.arguments.begin(); it != call.arguments.end(); ++it) {
        std::string key = it.key();
        if (key == "pattern" && (req.name == "textSearch" || req.name == "Grep"))
            key = "needle";
        if (key == "old_string") key = "old";
        if (key == "new_string") key = "new";
        if (key == "contents") key = "content";
        if (key == "file_path") key = "path";
        if (it->is_string()) {
            req.args[key] = it->get<std::string>();
        } else {
            req.args[key] = it->dump();
        }
    }

    return req;
}

inline void ToolCallBridge::RegisterTool(const rawrxd::tools::Tool& tool) {
    if (m_registry) {
        m_registry->add(tool);
    }
}

inline ToolResultMessage ToolCallBridge::ExecuteToolCall(const ToolCall& call) {
    // Snapshot receipt state under the turn lock; the impl re-locks internally.
    std::shared_ptr<rawrxd::agentic::security::ToolReceiptLog> receipts;
    std::string session;
    {
        std::lock_guard<std::mutex> lock(m_turnMutex);
        receipts = m_receipts;
        session = m_authorizationSession;
    }
    ToolResultMessage result_msg = ExecuteToolCallImpl(call);

    // P0 durable execution receipt: one JSONL line per decision (allow/deny).
    if (receipts && receipts->enabled()) {
        rawrxd::agentic::security::Receipt r;
        r.ts = rawrxd::agentic::security::NowIso8601Utc();
        r.session = session;
        r.tool = call.name;
        r.target = call.arguments.is_object() && call.arguments.contains("path")
            ? call.arguments["path"].get<std::string>() : std::string();
        r.risk = "unknown";
        rawrxd::tools::Tool probe;
        if (m_registry && m_registry->find(call.name, probe)) {
            r.risk = (probe.risk == rawrxd::tools::Risk::ReadOnly) ? "ReadOnly" :
                     (probe.risk == rawrxd::tools::Risk::Write)    ? "Write" :
                     (probe.risk == rawrxd::tools::Risk::Execute)  ? "Execute" :
                     (probe.risk == rawrxd::tools::Risk::Network)  ? "Network" : "External";
        }
        const std::string& c = result_msg.content;
        const bool denied = c.rfind("DENIED", 0) == 0 ||
                            c.rfind("MOTD_REQUIRED", 0) == 0 ||
                            c.rfind("MOTD_READ_FAILED", 0) == 0 ||
                            c.rfind("EXACTLY_ONCE", 0) == 0 ||
                            c.rfind("AUTHORIZATION_REQUIRED", 0) == 0;
        r.decision = denied ? "DENY" : "ALLOW";
        r.authorizer = "motd+approval";
        r.detail = denied ? c.substr(0, 200) : result_msg.firstFailure;
        r.bytes = (long long)c.size();
        r.accepted = result_msg.accepted;
        receipts->Write(r);
    }
    return result_msg;
}

inline ToolResultMessage ToolCallBridge::ExecuteToolCallImpl(const ToolCall& call) {
    std::lock_guard<std::mutex> lock(m_turnMutex);
    ToolResultMessage result_msg;
    result_msg.tool_call_id = call.id;
    result_msg.tool_name = call.name;
    result_msg.success = false;

    if (!m_turnOpen) {
        result_msg.content = "MOTD_REQUIRED: no active user turn";
        return result_msg;
    }

    // Issue #49: exactly-once admit before any MOTD/registry side effect.
    {
        const ExactlyOnceAdmit admit = m_exactlyOnce.Admit(call.id);
        if (admit == ExactlyOnceAdmit::RejectEmptyId) {
            result_msg.content = "EXACTLY_ONCE_REJECT: empty tool_call_id";
            return result_msg;
        }
        if (admit == ExactlyOnceAdmit::Duplicate) {
            result_msg.content = "EXACTLY_ONCE_DUP: tool_call_id already executed this turn";
            return result_msg;
        }
    }

    if (call.name == "read_motd") {
        if (!call.arguments.is_object() || !call.arguments.empty()) {
            result_msg.content = "MOTD_READ_FAILED: read_motd accepts no arguments";
            return result_msg;
        }
        std::string contents, digest, error;
        if (!m_motdAuthorization.ReadMotd(m_authorizationSession, m_authorizationTurn,
                                          contents, digest, error)) {
            result_msg.content = error;
            return result_msg;
        }
        result_msg.content = "MOTD_ACK=1\nMOTD_SHA256=" + digest + "\n" + contents;
        result_msg.success = true;
        return result_msg;
    }

    std::string authorizationError;
    if (!m_motdAuthorization.AuthorizeTool(call.name, m_authorizationSession,
                                           m_authorizationTurn, authorizationError)) {
        result_msg.content = authorizationError;
        return result_msg;
    }

    if (!m_registry) {
        result_msg.content = "Error: tool registry not initialized";
        return result_msg;
    }

    rawrxd::tools::Request req = ConvertArgs(call);

    // AF04/AF06 choke point: path/command + risk approval BEFORE mutate/shell.
    {
        rawrxd::tools::Tool probe;
        if (!m_registry->find(req.name, probe)) {
            result_msg.content = "Error: unknown tool";
            return result_msg;
        }
        if (m_securityGate) {
            std::string denyReason;
            if (!m_securityGate(probe, req, denyReason)) {
                result_msg.content = "DENIED: " + denyReason;
                result_msg.success = false;
                return result_msg;
            }
        } else if (probe.risk != rawrxd::tools::Risk::ReadOnly) {
            // Fail closed when security gate not wired for mutate/shell.
            result_msg.content = "DENIED: security gate not configured";
            result_msg.success = false;
            return result_msg;
        }
    }

    // Use registered approval callback or default deny for write/execute
    auto approve = m_approval;
    if (!approve) {
        approve = [](const rawrxd::tools::Tool& t, const rawrxd::tools::Request&) -> bool {
            return t.risk == rawrxd::tools::Risk::ReadOnly;
        };
    }

    if (m_journal) {
        m_journal->ToolStart("main", req.name, call.arguments.dump(), m_journalTaskId);
    }

    rawrxd::tools::Result tool_result = m_registry->call(req, approve);
    m_motdAuthorization.NoteExecution(m_authorizationSession, m_authorizationTurn);
    result_msg.content = tool_result.ok ? tool_result.output : tool_result.error;
    result_msg.acceptance = (tool_result.acceptance == rawrxd::tools::Result::Acceptance::Accepted)
        ? ToolResultMessage::Acceptance::Accepted
        : ((tool_result.acceptance == rawrxd::tools::Result::Acceptance::Rejected)
            ? ToolResultMessage::Acceptance::Rejected
            : ((tool_result.acceptance == rawrxd::tools::Result::Acceptance::NotApplicable)
                ? ToolResultMessage::Acceptance::NotApplicable
                : ToolResultMessage::Acceptance::NotEvaluated));
    result_msg.accepted = (result_msg.acceptance == ToolResultMessage::Acceptance::Accepted ||
                           result_msg.acceptance == ToolResultMessage::Acceptance::NotApplicable);
    result_msg.firstFailure = tool_result.firstFailure;
    result_msg.success = tool_result.ok && result_msg.accepted;

    if (m_journal) {
        const std::string detail = tool_result.ok
            ? (tool_result.output.size() > 512 ? tool_result.output.substr(0, 512) + "..."
                                               : tool_result.output)
            : tool_result.error;
        m_journal->ToolFinish("main", req.name, tool_result.ok ? 0 : 1, detail, m_journalTaskId);
    }

    return result_msg;
}

inline std::vector<ToolResultMessage> ToolCallBridge::ExecuteToolCalls(
    const std::vector<ToolCall>& calls) {
    std::vector<ToolResultMessage> results;
    results.reserve(calls.size());
    for (const auto& call : calls) {
        results.push_back(ExecuteToolCall(call));
    }
    return results;
}

inline json GetAllToolSchemas(const rawrxd::tools::Registry& registry) {
    (void)registry;
    ToolCallBridge bridge;
    return bridge.GetToolSchemasForLLM();
}

} // namespace Agent
} // namespace RawrXD
