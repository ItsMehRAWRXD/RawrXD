// ============================================================================
// agent_tool_exec_smoke.cpp -- REAL Ollama tool-execution acceptance
// ============================================================================
// Drives the PRODUCTION agentic backend (RawrXD::Agent::OllamaBackend, the same
// class the autonomous/agentic engines use) against a live Ollama server and
// executes the tool the MODEL itself requests through the production workspace
// tool registry (rawrxd::tools::register_workspace_tools).
//
// This is not a mock and not a hardcoded result: it performs a real HTTP
// /api/chat round trip, parses the model-emitted tool call, runs the real tool
// handler, and (best effort) resumes inference with the real observation.
//
// Usage:
//   agent_tool_exec_smoke [model] [workspaceDir] [endpoint]
// Defaults: model=qwen3:8b workspace=. endpoint=http://127.0.0.1:11434
//
// Exit codes (fail-closed):
//   0  backend initialized, model list fetched, model emitted a tool call,
//      and the real tool executed successfully
//   2  usage / initialization / transport failure
//   3  model produced no tool call (real outcome, reported honestly)
//   4  tool call produced by the model failed to execute
// ============================================================================
#include "agentic/OllamaBackend.h"
#include "agentic/tool_core.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

using json = nlohmann::json;
using RawrXD::Agent::BackendConfig;
using RawrXD::Agent::BackendKind;
using RawrXD::Agent::ChatMessage;
using RawrXD::Agent::InferenceResult;
using RawrXD::Agent::OllamaBackend;

namespace {

std::string env_or(const char* name, const std::string& fallback) {
    const char* v = std::getenv(name);
    return (v && *v) ? std::string(v) : fallback;
}

std::string clip(const std::string& s, size_t n) {
    if (s.size() <= n) return s;
    return s.substr(0, n) + "...[truncated]";
}

json build_tool_schema() {
    json tools = json::array();
    tools.push_back({
        {"type", "function"},
        {"function", {
            {"name", "listDirectory"},
            {"description", "List the immediate children of a workspace directory."},
            {"parameters", {
                {"type", "object"},
                {"properties", {
                    {"path", {{"type", "string"}, {"description", "Workspace-relative directory, e.g. '.'"}}}
                }},
                {"required", json::array({"path"})}
            }}
        }}
    });
    return tools;
}

} // namespace

int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);
    const std::string model     = argc > 1 ? argv[1] : env_or("RAWRXD_OLLAMA_MODEL", "qwen3:8b");
    const std::string workspace = argc > 2 ? argv[2] : env_or("RAWRXD_AGENT_WORKSPACE", ".");
    const std::string endpoint  = argc > 3 ? argv[3] : env_or("RAWRXD_OLLAMA_ENDPOINT", "http://127.0.0.1:11434");

    std::printf("=== REAL OLLAMA TOOL-EXECUTION ACCEPTANCE ===\n");
    std::printf("ENDPOINT=%s\nMODEL=%s\nWORKSPACE=%s\n", endpoint.c_str(), model.c_str(), workspace.c_str());

    OllamaBackend backend;
    BackendConfig cfg;
    cfg.kind        = BackendKind::Ollama;
    cfg.endpoint    = endpoint;
    cfg.model       = model;
    cfg.max_tokens  = 512;
    cfg.num_ctx     = 4096;
    cfg.timeout_ms  = 120000;
    cfg.temperature = 0.1f;

    if (!backend.Initialize(cfg)) {
        std::printf("RESULT=INIT_FAILED\nERROR=%s\n", backend.GetHealth().last_error.c_str());
        return 2;
    }
    std::printf("BACKEND_HEALTHY=true\n");

    // Real model discovery over the wire.
    const std::vector<std::string> models = backend.ListModels();
    std::printf("MODELS_LISTED=%zu\n", models.size());
    for (size_t i = 0; i < models.size() && i < 5; ++i)
        std::printf("  MODEL[%zu]=%s\n", i, models[i].c_str());

    // Force a real tool call from the model.
    std::vector<ChatMessage> messages;
    messages.push_back({"system",
        "You are an agent that inspects a workspace using tools. "
        "To list files you MUST call the listDirectory tool with path set to \".\". "
        "Do not answer with prose; emit the tool call now.",
        "", json::array()});
    messages.push_back({"user", "List the workspace root directory.", "", json::array()});

    const json tools = build_tool_schema();
    InferenceResult res = backend.ChatSync(messages, tools);

    std::printf("CHAT_OK=%s\n", res.success ? "true" : "false");
    if (!res.success) {
        std::printf("RESULT=CHAT_FAILED\nERROR=%s\n", res.error_message.c_str());
        return 2;
    }
    std::printf("PROMPT_TOKENS=%llu COMPLETION_TOKENS=%llu TPS=%.2f\n",
                (unsigned long long)res.prompt_tokens,
                (unsigned long long)res.completion_tokens,
                res.tokens_per_sec);
    std::printf("RESPONSE_TEXT=%s\n", clip(res.response, 400).c_str());
    std::printf("HAS_TOOL_CALLS=%s\n", res.has_tool_calls ? "true" : "false");

    if (!res.has_tool_calls || res.tool_calls.empty()) {
        std::printf("RESULT=NO_TOOL_CALL\n");
        return 3;
    }

    // Execute the model-requested tool through the production registry.
    rawrxd::tools::Registry registry;
    rawrxd::tools::register_workspace_tools(registry, workspace);

    bool any_ok = false;
    std::vector<std::string> tool_names;
    std::vector<std::string> tool_outputs;
    for (size_t i = 0; i < res.tool_calls.size(); ++i) {
        const std::string& name = res.tool_calls[i].first;
        const json& args        = res.tool_calls[i].second;
        std::printf("TOOL_CALL[%zu]=%s ARGS=%s\n", i, name.c_str(), args.dump().c_str());

        rawrxd::tools::Request req;
        req.name = name;
        if (args.is_object()) {
            for (auto it = args.begin(); it != args.end(); ++it) {
                if (it.value().is_string()) req.args[it.key()] = it.value().get<std::string>();
                else req.args[it.key()] = it.value().dump();
            }
        }

        rawrxd::tools::Result tr = registry.call(req, nullptr);
        std::printf("TOOL_RESULT[%zu].ok=%s acceptance=%d\n", i, tr.ok ? "true" : "false",
                    static_cast<int>(tr.acceptance));
        std::printf("TOOL_OUTPUT[%zu]=%s\n", i, clip(tr.output, 800).c_str());
        if (!tr.error.empty()) std::printf("TOOL_ERROR[%zu]=%s\n", i, tr.error.c_str());
        if (tr.ok) any_ok = true;

        tool_names.push_back(name);
        tool_outputs.push_back(tr.output);
    }

    // Best-effort resume: feed the real observation back for a final answer.
    std::vector<ChatMessage> follow;
    follow.push_back(messages[0]);
    follow.push_back(messages[1]);
    for (size_t i = 0; i < tool_names.size(); ++i) {
        const std::string id = "call_" + std::to_string(i);
        ChatMessage a;
        a.role = "assistant";
        a.content = res.response;
        a.tool_calls = json::array({{{"id", id}, {"type", "function"},
            {"function", {{"name", tool_names[i]},
                          {"arguments", res.tool_calls[i].second.dump()}}}}});
        follow.push_back(a);
        ChatMessage t;
        t.role = "tool";
        t.tool_call_id = id;
        t.content = tool_outputs[i];
        follow.push_back(t);
    }

    InferenceResult fin = backend.ChatSync(follow, tools);
    std::printf("RESUME_OK=%s\n", fin.success ? "true" : "false");
    if (fin.success)
        std::printf("FINAL_ANSWER=%s\n", clip(fin.response, 600).c_str());
    else
        std::printf("RESUME_ERROR=%s\n", fin.error_message.c_str());

    if (!any_ok) {
        std::printf("RESULT=TOOL_FAILED\n");
        return 4;
    }
    std::printf("RESULT=TOOL_EXECUTION_PASS\n");
    return 0;
}