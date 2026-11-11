// ============================================================================
// BoundedAgentLoop.cpp — bounded model/tool orchestration
// ============================================================================
// This implementation deliberately reuses BackendRouter and WorkspaceToolHost.
// It adds the missing control loop, not another model loader or tool runtime.
// ============================================================================

#include "BoundedAgentLoop.h"
#include "tool_call_parser.h"
#include "backend/ollama_client.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <sstream>

namespace RawrXD {
namespace Agent {

namespace {

uint64_t NowMs() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

std::string JsonString(const nlohmann::json& value) {
    if (value.is_string()) return value.get<std::string>();
    return value.dump();
}

void AddSchema(nlohmann::json& schemas,
               const char* name,
               const char* description,
               std::initializer_list<const char*> required) {
    nlohmann::json properties = nlohmann::json::object();
    for (const char* key : required) {
        properties[key] = { {"type", "string"} };
    }
    schemas.push_back({
        {"type", "function"},
        {"function", {
            {"name", name},
            {"description", description},
            {"parameters", {
                {"type", "object"},
                {"properties", properties},
                {"required", required},
                {"additionalProperties", true}
            }}
        }}
    });
}

} // namespace

BoundedAgentLoop::BoundedAgentLoop() = default;

BoundedAgentLoop::~BoundedAgentLoop() {
    Cancel();
    if (m_worker.joinable()) m_worker.join();
}

void BoundedAgentLoop::Configure(const AgentLoopConfig& config) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (IsRunning()) return;
    m_config = config;
    m_config.maxSteps = std::max(1, std::min(config.maxSteps, 128));
    m_config.maxTokensPerRequest = std::max(1,
        std::min(config.maxTokensPerRequest, 1048576));
    // Runtime objects are tied to the workspace and endpoint. Recreate them
    // only while idle so a running turn cannot observe half-applied config.
    m_router.reset();
    m_registry.reset();
    m_workspaceTools.reset();
}

void BoundedAgentLoop::SetLLMBackend(LLMChatFunction backend) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!IsRunning()) m_llmBackend = std::move(backend);
}

void BoundedAgentLoop::SetProgressCallback(AgentProgressCallback callback) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_progressCallback = std::move(callback);
}

void BoundedAgentLoop::SetCompleteCallback(AgentCompleteCallback callback) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_completeCallback = std::move(callback);
}

void BoundedAgentLoop::NotifyProgress(const std::string& status,
                                      const std::string& detail) {
    AgentProgressCallback callback;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        callback = m_progressCallback;
    }
    if (callback) callback(m_currentStep.load(), m_config.maxSteps, status, detail);
}

bool BoundedAgentLoop::EnsureRuntime() {
    RegisterRuntimeTools();
    if (m_llmBackend) return true;

    const std::string endpoint = m_config.ollamaBaseUrl.empty()
        ? "http://127.0.0.1:11434" : m_config.ollamaBaseUrl;

    m_router = std::make_unique<BackendRouter>();
    RouterConfig routerConfig;
    routerConfig.mode = BackendMode::Ollama;
    routerConfig.fallback_endpoint = endpoint;
    routerConfig.fallback_model = m_config.model;
    routerConfig.fallback_max_tokens = m_config.maxTokensPerRequest;
    routerConfig.fallback_num_ctx = std::max(8192,
        std::min(1048576, m_config.maxTokensPerRequest * 2));

    if (!m_router->Initialize(routerConfig)) return false;

    // The backend may have selected an installed model when the caller left
    // model empty. Make that selection visible in the framework configuration.
    m_config.model = m_router->GetFallbackHealth().model_name;
    if (m_config.model.empty()) m_config.model = m_router->GetActiveModel();

    m_llmBackend = [this](const LLMChatRequest& request) {
        LLMChatResponse out;
        if (!m_router) {
            out.error = "backend router is not initialized";
            return out;
        }

        std::vector<ChatMessage> messages;
        messages.reserve(request.messages.size());
        for (const auto& message : request.messages) {
            ChatMessage converted;
            converted.role = message.value("role", std::string());
            converted.content = message.value("content", std::string());
            converted.tool_call_id = message.value("tool_call_id", std::string());
            if (message.contains("tool_calls")) converted.tool_calls = message["tool_calls"];
            messages.push_back(std::move(converted));
        }

        BackendRouter::FailoverInfo failover;
        InferenceResult result = m_router->ChatSync(messages, request.tools, &failover);
        out.success = result.success;
        out.content = result.response;
        out.error = result.error_message;
        out.promptTokens = static_cast<int>(result.prompt_tokens);
        out.completionTokens = static_cast<int>(result.completion_tokens);
        if (result.has_tool_calls && !result.tool_calls.empty()) {
            out.hasToolCall = true;
            out.toolName = result.tool_calls.front().first;
            out.toolArgs = result.tool_calls.front().second;
            out.toolCallId = result.tool_call_ids.empty()
                ? "call_" + out.toolName : result.tool_call_ids.front();
        }
        return out;
    };
    return true;
}

void BoundedAgentLoop::RegisterRuntimeTools() {
    if (m_registry) return;

    const std::string root = m_config.workingDirectory.empty()
        ? std::filesystem::current_path().string() : m_config.workingDirectory;
    m_registry = std::make_unique<rawrxd::tools::Registry>();
    m_workspaceTools = std::make_unique<WorkspaceToolHost>(root);
    m_workspaceTools->RegisterWorkspaceTools(*m_registry);

    // Expose the existing certified build/test host through the same registry
    // used by filesystem tools. The model never receives a second dispatch API.
    WorkspaceToolHost* host = m_workspaceTools.get();
    m_registry->add({
        "runBuild", "Build the workspace and return build evidence", rawrxd::tools::Risk::Execute,
        {}, [host](const rawrxd::tools::Request& request) {
            const std::string config = request.args.count("config")
                ? request.args.at("config") : "Release";
            const std::string target = request.args.count("target")
                ? request.args.at("target") : "";
            const std::string evidence = host->WorkspaceRoot() + "/.rawrxd_autonomous/agent_build";
            BuildEvidence result = host->RunBuild(target, config, evidence);
            return rawrxd::tools::Result{result.Succeeded(), result.ToJson().dump(),
                result.Succeeded() ? std::string() : "build evidence did not pass"};
        }});

    m_registry->add({
        "runTests", "Run workspace tests and return test evidence", rawrxd::tools::Risk::Execute,
        {}, [host](const rawrxd::tools::Request& request) {
            const std::string filter = request.args.count("filter")
                ? request.args.at("filter") : "";
            const std::string evidence = host->WorkspaceRoot() + "/.rawrxd_autonomous/agent_tests";
            TestEvidence result = host->RunTests(filter, evidence);
            return rawrxd::tools::Result{result.Succeeded(), result.ToJson().dump(),
                result.Succeeded() ? std::string() : "test evidence did not pass"};
        }});

    m_registry->add({
        "runInTerminal", "Run an explicitly authorized command in the workspace",
        rawrxd::tools::Risk::Execute, {"command"}, [host](const rawrxd::tools::Request& request) {
            const std::string command = rawrxd::tools::arg(request, "command");
            std::string full = "cd /D \"" + host->WorkspaceRoot() + "\" && " + command + " 2>&1";
#ifdef _WIN32
            FILE* pipe = _popen(full.c_str(), "r");
#else
            FILE* pipe = popen(full.c_str(), "r");
#endif
            if (!pipe) return rawrxd::tools::Result{false, "", "failed to start command"};
            std::string output;
            char buffer[4096];
            while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
                output += buffer;
                if (output.size() > 4 * 1024 * 1024) {
                    output.append("\n...[output truncated]\n");
                    break;
                }
            }
#ifdef _WIN32
            const int exitCode = _pclose(pipe);
#else
            const int exitCode = pclose(pipe);
#endif
            output += "\nexit_code=" + std::to_string(exitCode);
            return rawrxd::tools::Result{exitCode == 0, output,
                exitCode == 0 ? std::string() : "command failed"};
        }});
}

nlohmann::json BoundedAgentLoop::BuildToolSchemas() const {
    nlohmann::json schemas = nlohmann::json::array();
    AddSchema(schemas, "readFile", "Read a bounded file inside the workspace", {"path"});
    AddSchema(schemas, "listDirectory", "List a directory inside the workspace", {"path"});
    AddSchema(schemas, "fileSearch", "Find files by name inside the workspace", {"pattern"});
    AddSchema(schemas, "textSearch", "Search text in bounded workspace files", {"needle"});
    AddSchema(schemas, "createFile", "Create a new file inside the workspace", {"path", "content"});
    AddSchema(schemas, "editFiles", "Replace one exact unique text block", {"path", "old", "new"});
    AddSchema(schemas, "runBuild", "Build the workspace and return evidence", {});
    AddSchema(schemas, "runTests", "Run the workspace tests and return evidence", {});
    AddSchema(schemas, "runInTerminal", "Run an authorized workspace command", {"command"});
    return schemas;
}

ToolCallResult BoundedAgentLoop::DispatchTool(const std::string& name,
                                              const nlohmann::json& args) {
    if (!m_registry) return ToolCallResult::Error("tool registry is not initialized");

    rawrxd::tools::Tool descriptor;
    if (!m_registry->find(name, descriptor)) return ToolCallResult::NotFound(name);
    if (m_config.dryRun && descriptor.risk != rawrxd::tools::Risk::ReadOnly) {
        return ToolCallResult::Sandbox("dry-run blocked tool: " + name);
    }

    rawrxd::tools::Request request;
    request.name = name;
    if (args.is_object()) {
        for (auto it = args.begin(); it != args.end(); ++it) {
            request.args[it.key()] = JsonString(it.value());
        }
    }

    const auto start = std::chrono::steady_clock::now();
    rawrxd::tools::Result result = m_registry->call(request,
        [](const rawrxd::tools::Tool&, const rawrxd::tools::Request&) { return true; });
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();

    ToolCallResult output = result.ok
        ? ToolCallResult::Ok(result.output)
        : ToolCallResult::Error(result.error);
    output.toolName = name;
    output.argsUsed = args;
    output.durationMs = elapsed;
    return output;
}

nlohmann::json BoundedAgentLoop::BuildSystemMessage() {
    std::ostringstream prompt;
    prompt << "You are RawrXD's bounded local coding agent.\n"
           << "Work only inside the authorized workspace. Use paths relative to the workspace root (use '.' for its root); never emit container paths such as /home/user/workspace.\n"
           << "Use one tool at a time, inspect before editing, and verify edits with build/tests.\n"
           << "When the task is complete, answer with a concise final result.\n"
           << "Tool schemas:\n" << BuildToolSchemas().dump();
    return {{"role", "system"}, {"content", prompt.str()}};
}

nlohmann::json BoundedAgentLoop::BuildUserMessage(const std::string& prompt) {
    return {{"role", "user"}, {"content", prompt}};
}

nlohmann::json BoundedAgentLoop::BuildToolResultMessage(
    const std::string& callId, const ToolCallResult& result) {
    nlohmann::json message = result.toLLMMessage(callId);
    message["content"] = result.isSuccess() ? result.output : "Error: " + result.error;
    return message;
}

nlohmann::json BoundedAgentLoop::BuildAssistantToolCallMessage(
    const LLMChatResponse& response) {
    return {
        {"role", "assistant"},
        {"content", response.content},
        {"tool_calls", nlohmann::json::array({{
            {"id", response.toolCallId.empty() ? "call_" + response.toolName : response.toolCallId},
            {"type", "function"},
            {"function", {
                {"name", response.toolName},
                {"arguments", response.toolArgs}
            }}
        }})}
    };
}

std::string BoundedAgentLoop::RunLoop(const std::string& userPrompt) {
    if (!EnsureRuntime()) {
        m_state.store(AgentLoopState::Error);
        m_transcript.SetOutcome("backend_unavailable");
        return "Error: no usable local inference backend";
    }
    m_transcript.SetModel(m_config.model);

    if (!m_config.transcriptPath.empty()) {
        std::error_code ec;
        std::filesystem::create_directories(
            std::filesystem::path(m_config.transcriptPath).parent_path(), ec);
    }

    std::vector<nlohmann::json> messages;
    messages.push_back(BuildSystemMessage());
    messages.push_back(BuildUserMessage(userPrompt));
    std::string lastInvalidSignature;
    int repeatedInvalidCall = 0;

    for (int stepNumber = 1; stepNumber <= m_config.maxSteps; ++stepNumber) {
        if (m_cancelled.load()) {
            m_state.store(AgentLoopState::Error);
            m_transcript.SetOutcome("cancelled");
            return "Cancelled";
        }

        m_currentStep.store(stepNumber);
        m_state.store(AgentLoopState::WaitingForModel);
        NotifyProgress("model", "requesting bounded model step");

        LLMChatRequest request;
        request.messages = messages;
        request.tools = BuildToolSchemas();
        request.model = m_config.model;
        request.maxTokens = m_config.maxTokensPerRequest;

        const auto modelStart = std::chrono::steady_clock::now();
        LLMChatResponse response = m_llmBackend(request);
        const auto modelMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - modelStart).count();

        if (!response.success) {
            TranscriptStep record;
            record.stepNumber = stepNumber;
            record.timestampMs = NowMs();
            record.modelResponse = response.error;
            record.modelLatencyMs = modelMs;
            record.tokensSent = request.messages.empty() ? 0 :
                static_cast<int>(request.messages.size());
            m_transcript.AddStep(record);
            m_state.store(AgentLoopState::Error);
            m_transcript.SetOutcome("model_error");
            if (!m_config.transcriptPath.empty()) m_transcript.SaveToFile(m_config.transcriptPath);
            return "Error: " + (response.error.empty() ? "model request failed" : response.error);
        }

        // Native tool calls are authoritative. For models without native tool
        // support, parse the same JSON contract from visible response text.
        if (!response.hasToolCall && !response.content.empty()) {
            const auto parsed = RawrXD::Agentic::ToolCallParser::parse(response.content);
            if (!parsed.toolCalls.empty()) {
                response.hasToolCall = true;
                response.toolName = parsed.toolCalls.front().name;
                response.toolArgs = parsed.toolCalls.front().arguments;
                response.toolCallId = parsed.toolCalls.front().id.empty()
                    ? "call_" + response.toolName : parsed.toolCalls.front().id;
            }
        }

        if (!response.hasToolCall) {
            if (response.content.empty()) {
                m_state.store(AgentLoopState::Error);
                m_transcript.SetOutcome("empty_model_answer");
                return "Error: model returned no visible answer";
            }
            TranscriptStep record;
            record.stepNumber = stepNumber;
            record.timestampMs = NowMs();
            record.modelResponse = response.content;
            record.reasoning = response.reasoning;
            record.modelLatencyMs = modelMs;
            record.tokensReceived = response.completionTokens;
            m_transcript.AddStep(record);
            m_state.store(AgentLoopState::Complete);
            m_transcript.SetOutcome("complete");
            if (!m_config.transcriptPath.empty()) m_transcript.SaveToFile(m_config.transcriptPath);

            AgentCompleteCallback callback;
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                callback = m_completeCallback;
            }
            if (callback) callback(response.content, m_transcript);
            return response.content;
        }

        m_state.store(AgentLoopState::ExecutingTool);
        NotifyProgress("tool", response.toolName);
        const auto toolStart = std::chrono::steady_clock::now();
        ToolCallResult toolResult = DispatchTool(response.toolName, response.toolArgs);
        toolResult.durationMs = std::max<int64_t>(toolResult.durationMs,
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - toolStart).count());

        TranscriptStep record;
        record.stepNumber = stepNumber;
        record.timestampMs = NowMs();
        record.modelResponse = response.content;
        record.reasoning = response.reasoning;
        record.toolCallName = response.toolName;
        record.toolCallArgs = response.toolArgs;
        record.toolResult = toolResult;
        record.modelLatencyMs = modelMs;
        record.toolLatencyMs = toolResult.durationMs;
        record.tokensReceived = response.completionTokens;
        m_transcript.AddStep(record);
        if (response.toolName == "readFile" && response.toolArgs.contains("path")) {
            m_transcript.RecordFileRead(JsonString(response.toolArgs["path"]));
        } else if ((response.toolName == "createFile" ||
                    response.toolName == "editFiles") &&
                   response.toolArgs.contains("path")) {
            m_transcript.RecordFileWrite(JsonString(response.toolArgs["path"]));
        }

        messages.push_back(BuildAssistantToolCallMessage(response));
        messages.push_back(BuildToolResultMessage(
            response.toolCallId.empty() ? "call_" + response.toolName : response.toolCallId,
            toolResult));
        if (!toolResult.isSuccess()) {
            NotifyProgress("tool_error", toolResult.error);
            const std::string signature = response.toolName + "\n" + response.toolArgs.dump();
            if (signature == lastInvalidSignature) {
                ++repeatedInvalidCall;
            } else {
                lastInvalidSignature = signature;
                repeatedInvalidCall = 1;
            }
            messages.push_back({
                {"role", "user"},
                {"content", "The previous tool call was rejected: " + toolResult.error +
                            ". Do not repeat that invalid call. Re-read the file or provide the "
                            "final answer; only edit when path, old, and new are all present."}
            });
            if (repeatedInvalidCall >= 2) {
                m_state.store(AgentLoopState::Error);
                m_transcript.SetOutcome("model_nonprogress");
                if (!m_config.transcriptPath.empty()) m_transcript.SaveToFile(m_config.transcriptPath);
                return "Error: model repeated an invalid tool call: " + response.toolName;
            }
        } else {
            lastInvalidSignature.clear();
            repeatedInvalidCall = 0;
        }
    }

    m_state.store(AgentLoopState::StepLimitReached);
    m_transcript.SetOutcome("step_limit_reached");
    if (!m_config.transcriptPath.empty()) m_transcript.SaveToFile(m_config.transcriptPath);
    return "Agent stopped after reaching the configured step limit.";
}

std::string BoundedAgentLoop::Execute(const std::string& userPrompt) {
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (IsRunning()) return "Error: agent loop is already running";
    }
    if (m_worker.joinable()) m_worker.join();

    m_cancelled.store(false);
    m_currentStep.store(0);
    m_state.store(AgentLoopState::WaitingForModel);
    m_transcript.Reset();
    m_transcript.SetInitialPrompt(userPrompt);
    m_transcript.SetModel(m_config.model);
    m_transcript.SetWorkingDirectory(m_config.workingDirectory);

    const std::string answer = RunLoop(userPrompt);
    if (m_state.load() != AgentLoopState::Complete &&
        m_state.load() != AgentLoopState::StepLimitReached &&
        m_state.load() != AgentLoopState::Error) {
        m_state.store(AgentLoopState::Complete);
    }
    return answer;
}

void BoundedAgentLoop::ExecuteAsync(const std::string& userPrompt) {
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (IsRunning()) return;
    }
    if (m_worker.joinable()) m_worker.join();
    m_worker = std::thread([this, userPrompt]() { Execute(userPrompt); });
}

void BoundedAgentLoop::Cancel() {
    m_cancelled.store(true);
    if (m_router) m_router->Cancel();
}

LLMChatResponse BoundedAgentLoop::NativeChat(const LLMChatRequest& request,
                                             const std::string& baseUrl) {
    LLMChatResponse result;
    Backend::OllamaClient client(baseUrl.empty()
        ? "http://127.0.0.1:11434" : baseUrl);
    if (!client.testConnection()) {
        result.error = "Ollama is not reachable";
        return result;
    }

    Backend::OllamaChatRequest ollamaRequest;
    ollamaRequest.model = request.model;
    ollamaRequest.stream = false;
    ollamaRequest.tools = request.tools;
    for (const auto& message : request.messages) {
        Backend::OllamaChatMessage converted;
        converted.role = message.value("role", std::string());
        converted.content = message.value("content", std::string());
        converted.tool_call_id = message.value("tool_call_id", std::string());
        if (message.contains("tool_calls")) converted.tool_calls = message["tool_calls"];
        ollamaRequest.messages.push_back(std::move(converted));
    }
    ollamaRequest.options["temperature"] = request.temperature;
    ollamaRequest.options["num_predict"] = request.maxTokens;

    const Backend::OllamaResponse response = client.chatSync(ollamaRequest);
    if (!response.error.empty() || !response.done) {
        result.error = response.error.empty() ? "incomplete Ollama response" : response.error;
        return result;
    }
    result.success = true;
    result.content = response.message.empty() ? response.response : response.message;
    result.promptTokens = static_cast<int>(response.prompt_eval_count);
    result.completionTokens = static_cast<int>(response.eval_count);
    if (response.tool_calls.is_array() && !response.tool_calls.empty()) {
        const auto& call = response.tool_calls.front();
        result.hasToolCall = true;
        result.toolName = call.value("name",
            call.value("function", nlohmann::json::object()).value("name", ""));
        result.toolArgs = call.value("arguments",
            call.value("function", nlohmann::json::object()).value("arguments",
                nlohmann::json::object()));
    }
    return result;
}

} // namespace Agent
} // namespace RawrXD
