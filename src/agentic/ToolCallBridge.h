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
#include <string>
#include <vector>
#include <functional>
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

inline json GetAllToolSchemas(const rawrxd::tools::Registry& registry) {
    json schemas = json::array();
    // We can't iterate tools directly, so we provide a known set
    // In practice, the orchestrator maintains a registry and generates schemas
    return schemas;
}

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
};

// ---------------------------------------------------------------------------
// ToolCallBridge — routes LLM tool calls through the shared tool registry
// ---------------------------------------------------------------------------
class ToolCallBridge {
public:
    using ApprovalCallback = std::function<bool(const rawrxd::tools::Tool&, const rawrxd::tools::Request&)>;

    ToolCallBridge() = default;
    ~ToolCallBridge() = default;

    // ---- Registry management ----
    void SetRegistry(rawrxd::tools::Registry* registry) { m_registry = registry; }
    rawrxd::tools::Registry* GetRegistry() const { return m_registry; }

    void SetWorkspaceRoot(const std::filesystem::path& root) { m_workspaceRoot = root; }
    std::filesystem::path GetWorkspaceRoot() const { return m_workspaceRoot; }

    void SetApprovalCallback(ApprovalCallback cb) { m_approval = cb; }

    // ---- Tool schema generation for LLM ----
    // Returns OpenAI-format tool definitions for all registered tools
    json GetToolSchemasForLLM() const;

    // ---- Execution ----
    // Execute a single tool call from the LLM response
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

    // Convert LLM tool arguments (json) to rawrxd::tools::Request args (string map)
    rawrxd::tools::Request ConvertArgs(const ToolCall& call) const;
};

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

inline json ToolCallBridge::GetToolSchemasForLLM() const {
    json schemas = json::array();

    // Generate schemas for all workspace tools registered via register_workspace_tools
    // Each tool is registered with its name, description, risk, and required args.
    // We generate OpenAI-compatible JSON schema for each.

    // Static tool list — matches register_workspace_tools registrations
    struct ToolInfo {
        std::string name;
        std::string description;
        std::vector<std::string> required;
    };

    std::vector<ToolInfo> tools = {
        {"readFile",       "Read bounded workspace file", {"path"}},
        {"listDirectory",  "List workspace directory", {"path"}},
        {"fileSearch",     "Find paths by filename substring", {"pattern"}},
        {"textSearch",     "Search bounded text files", {"needle"}},
        {"createDirectory", "Create directory inside workspace", {"path"}},
        {"createFile",      "Create a new file without overwriting", {"path", "content"}},
        {"editFiles",       "Replace exact unique text in a file", {"path", "old", "new"}},
#ifdef _WIN32
        {"runInTerminal",   "Execute explicitly approved command in workspace", {"command"}},
#endif
    };

    for (const auto& t : tools) {
        json schema;
        schema["type"] = "function";
        schema["function"] = json{
            {"name", t.name},
            {"description", t.description},
            {"parameters", json{
                {"type", "object"},
                {"properties", json::object()},
                {"required", t.required}
            }}
        };
        schemas.push_back(schema);
    }

    return schemas;
}

inline rawrxd::tools::Request ToolCallBridge::ConvertArgs(const ToolCall& call) const {
    rawrxd::tools::Request req;
    req.name = call.name;

    for (auto it = call.arguments.begin(); it != call.arguments.end(); ++it) {
        if (it->is_string()) {
            req.args[it.key()] = it->get<std::string>();
        } else {
            // Non-string arguments: serialize to JSON string
            req.args[it.key()] = it->dump();
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
    ToolResultMessage result_msg;
    result_msg.tool_call_id = call.id;
    result_msg.tool_name = call.name;
    result_msg.success = false;

    if (!m_registry) {
        result_msg.content = "Error: tool registry not initialized";
        return result_msg;
    }

    rawrxd::tools::Request req = ConvertArgs(call);

    // Use registered approval callback or default deny for write/execute
    auto approve = m_approval;
    if (!approve) {
        approve = [](const rawrxd::tools::Tool& t, const rawrxd::tools::Request&) -> bool {
            return t.risk == rawrxd::tools::Risk::ReadOnly;
        };
    }

    rawrxd::tools::Result tool_result = m_registry->call(req, approve);
    result_msg.content = tool_result.ok ? tool_result.output : tool_result.error;
    result_msg.success = tool_result.ok;

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

} // namespace Agent
} // namespace RawrXD
