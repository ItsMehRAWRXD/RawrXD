// Agentic Framework Bridge Implementation
// Connects Win32IDE to Native C++ Agent (Parity with rawrxd_cli)

#include "Win32IDE_AgenticBridge.h"
#include "IDELogger.h"
#include "Win32IDE.h"
#include "Win32IDE_AgentExecutionFSM.h"
#include "../native_agent.hpp"
#include <sstream>
#include <algorithm>
#include <regex>
#include <thread>
#include <chrono>

AgenticBridge::AgenticBridge(Win32IDE* ide)
    : m_ide(ide)
    , m_initialized(false)
    , m_agentLoopRunning(false)
    , m_modelName("rawrxd-native-v1")
    , m_ollamaServer("http://localhost:11434")
    , m_hProcess(nullptr)
    , m_hStdoutRead(nullptr)
    , m_hStdoutWrite(nullptr)
    , m_hStdinRead(nullptr)
    , m_hStdinWrite(nullptr)
{
    LOG_INFO("AgenticBridge constructed (Native Mode)");
}

AgenticBridge::~AgenticBridge() {
    StopAgentLoop();
    CancelAutonomousTask();
    m_loopTransport.reset();
    KillPowerShellProcess();
    LOG_INFO("AgenticBridge destroyed");
}

void AgenticBridge::EnsureLoopTransport() {
    if (!m_loopTransport) {
        m_loopTransport = std::make_unique<AgenticLoopBridge>(m_ide);
        LOG_INFO("AgenticBridge adopted AgenticLoopBridge as process transport");
    }
}

AgenticLoopBridge* AgenticBridge::LoopTransport() {
    EnsureLoopTransport();
    return m_loopTransport.get();
}

const AgenticLoopBridge* AgenticBridge::LoopTransport() const {
    return m_loopTransport.get();
}

bool AgenticBridge::StartAutonomousTask(
    const AgenticLoopBridge::TaskConfig& config,
    AgenticLoopBridge::ProgressCallback progress,
    AgenticLoopBridge::ToolCallback toolCb,
    AgenticLoopBridge::CompleteCallback completeCb) {
    EnsureLoopTransport();
    if (!m_loopTransport) return false;
    RawrXD::ProductAgentFSM().reset("bridge_autonomous_start");
    if (!RawrXD::ProductAgentFSM().tryTransition(
            RawrXD::AgentExecState::Running, "bridge_StartAutonomousTask")) {
        LOG_ERROR("AgenticBridge::StartAutonomousTask FSM refused Running");
        return false;
    }
    const bool started = m_loopTransport->StartTask(
        config, std::move(progress), std::move(toolCb),
        [completeCb](bool success, const std::string& summary) {
            RawrXD::ProductAgentFSM().tryTransition(
                success ? RawrXD::AgentExecState::Done
                        : RawrXD::AgentExecState::Error,
                "bridge_autonomous_complete");
            if (completeCb) completeCb(success, summary);
        });
    if (!started) {
        RawrXD::ProductAgentFSM().tryTransition(
            RawrXD::AgentExecState::Error, "bridge_StartTask_failed");
    }
    return started;
}

void AgenticBridge::CancelAutonomousTask() {
    if (m_loopTransport) m_loopTransport->Cancel();
    // From Running/Waiting → Error; if already terminal/pending, reset for next task.
    if (!RawrXD::ProductAgentFSM().tryTransition(
            RawrXD::AgentExecState::Error, "bridge_cancel")) {
        RawrXD::ProductAgentFSM().reset("bridge_cancel_reset");
    }
}

bool AgenticBridge::IsAutonomousRunning() const {
    return m_loopTransport && m_loopTransport->IsRunning();
}

bool AgenticBridge::IsAgentLoopRunning() const {
    return m_agentLoopRunning.load() || IsAutonomousRunning();
}

bool AgenticBridge::Initialize(const std::string& frameworkPath, const std::string& modelName) {
    LOG_INFO("AgenticBridge::Initialize called [NATIVE STACK]");
    
    if (m_initialized) {
        LOG_WARNING("AgenticBridge already initialized");
        return true;
    }
    
    // Set model if provided
    if (!modelName.empty()) {
        m_modelName = modelName;
    }

    // Gap 5: bind ToolCallBridge SSOT (+ SecurityGate via ComputerUse wiring).
    if (m_ide) m_ide->ensureAgentToolSsotReady();

    // Gap 9: BackendRouter is the model path (Deep2/Ollama). CPU engine is /load only.
    LOG_INFO("Creating BackendRouter for IDE agent model turns...");
    m_router = std::make_unique<RawrXD::Agent::BackendRouter>();
    RawrXD::Agent::RouterConfig cfg;
    cfg.mode = RawrXD::Agent::BackendMode::Auto;
    cfg.fallback_endpoint = m_ollamaServer.empty() ? "http://127.0.0.1:11434" : m_ollamaServer;
    cfg.fallback_model = m_modelName;
    cfg.primary_model = "deep2-native";
    cfg.allow_cloud_fallback = false;
    if (!m_router->Initialize(cfg)) {
        LOG_ERROR("BackendRouter Initialize failed");
        return false;
    }

    // Legacy local GGUF helper for explicit /load — not used for Ask/tool turns.
    m_nativeEngine = std::make_unique<RawrXD::CPUInferenceEngine>();
    m_nativeAgent = std::make_unique<RawrXD::NativeAgent>(m_nativeEngine.get());
    m_nativeAgent->SetOutputCallback([this](const std::string& chunk) {
        if (m_outputCallback) m_outputCallback("stream", chunk);
    });

    m_initialized = true;
    LOG_INFO("AgenticBridge initialized (BackendRouter + ToolCallBridge SSOT).");
    return true;
}

AgentResponse AgenticBridge::ExecuteAgentCommand(const std::string& prompt) {
    LOG_INFO("ExecuteAgentCommand: " + prompt);

    AgentResponse response;
    response.type = AgentResponseType::ANSWER;

    if (!m_initialized || !m_router) {
        response.type = AgentResponseType::AGENT_ERROR;
        response.content = "Agent not initialized (BackendRouter required).";
        return response;
    }

    if (m_ide) m_ide->ensureAgentToolSsotReady();

    // Direct tool lines MUST hit ToolCallBridge::ExecuteToolCall (SecurityGate).
    if (IsToolCall(prompt) || prompt.rfind("TOOL ", 0) == 0) {
        return DispatchToolLine(prompt);
    }

    auto fullOutput = std::make_shared<std::string>();
    if (m_nativeAgent) {
        m_nativeAgent->SetOutputCallback([this, fullOutput](const std::string& chunk) {
            *fullOutput += chunk;
            if (m_outputCallback) m_outputCallback("stream", chunk);
        });
    }

    if (prompt == "/max" && m_nativeAgent) {
        m_nativeAgent->SetMaxMode(true);
        response.content = "Max Mode Enabled (Native Threads)";
    } else if (prompt == "/think" && m_nativeAgent) {
        static bool t = false; t = !t;
        m_nativeAgent->SetDeepThink(t);
        response.content = std::string("Deep Thinking ") + (t ? "Enabled" : "Disabled");
    } else if (prompt == "/research" && m_nativeAgent) {
        static bool r = false; r = !r;
        m_nativeAgent->SetDeepResearch(r);
        response.content = std::string("Deep Research ") + (r ? "Enabled" : "Disabled");
    } else if (prompt == "/norefusal" && m_nativeAgent) {
        static bool n = false; n = !n;
        m_nativeAgent->SetNoRefusal(n);
        response.content = std::string("No Refusal Mode ") + (n ? "Enabled" : "Disabled");
    } else if (prompt.find("/load ") == 0 && m_nativeEngine) {
        std::string path = prompt.substr(6);
        if (m_nativeEngine->LoadModel(path)) {
            response.content = "Model loaded successfully: " + path;
        } else {
            response.content = "Failed to load model from: " + path;
            response.type = AgentResponseType::AGENT_ERROR;
        }
    } else {
        // Gap 9: model-backed turns go through BackendRouter (not CPUInferenceEngine Ask).
        response = ChatViaBackendRouter(prompt);
        return response;
    }

    response.rawOutput = *fullOutput;
    return response;
}

// Deprecated Stubs — replaced with real implementations
bool AgenticBridge::SpawnPowerShellProcess(const std::string& scriptPath, const std::string& arguments) {
    // Gap 5 criterion 3: block alternate CreateProcess tool path on agent commands.
    // Tools must use dispatchAgentTool → ToolCallBridge::ExecuteToolCall (SecurityGate).
    (void)scriptPath;
    (void)arguments;
    LOG_ERROR("SpawnPowerShellProcess BYPASS_BLOCKED — use dispatchAgentTool/SSOT");
    return false;
}
bool AgenticBridge::ReadProcessOutput(std::string& output, DWORD timeoutMs) {
    if (!m_hStdoutRead) return false;
    
    output.clear();
    CHAR buffer[4096];
    DWORD bytesRead = 0;
    
    // Read available output with timeout
    BOOL result = ReadFile(m_hStdoutRead, buffer, sizeof(buffer) - 1, &bytesRead, NULL);
    if (result && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        output = buffer;
        return true;
    }
    
    return false;
}

void AgenticBridge::KillPowerShellProcess() {
    if (m_hProcess) {
        TerminateProcess(m_hProcess, 1);
        CloseHandle(m_hProcess);
        m_hProcess = nullptr;
    }
    if (m_hStdoutRead) { CloseHandle(m_hStdoutRead); m_hStdoutRead = nullptr; }
    if (m_hStdoutWrite) { CloseHandle(m_hStdoutWrite); m_hStdoutWrite = nullptr; }
    if (m_hStdinRead) { CloseHandle(m_hStdinRead); m_hStdinRead = nullptr; }
    if (m_hStdinWrite) { CloseHandle(m_hStdinWrite); m_hStdinWrite = nullptr; }
}

std::string AgenticBridge::ResolveFrameworkPath() {
    // Return the directory containing the executable
    char path[MAX_PATH];
    if (GetModuleFileNameA(NULL, path, MAX_PATH) > 0) {
        std::string fullPath(path);
        size_t pos = fullPath.find_last_of("\\/");
        if (pos != std::string::npos) {
            return fullPath.substr(0, pos);
        }
    }
    return ".";
}

std::string AgenticBridge::ResolveToolsModulePath() {
    std::string frameworkPath = ResolveFrameworkPath();
    return frameworkPath + "\\tools";
}

std::vector<std::string> AgenticBridge::GetAvailableTools() {
    if (m_ide) {
        m_ide->ensureAgentToolSsotReady();
        if (auto* reg = m_ide->agentToolsRegistry()) return reg->names();
    }
    return {};
}

std::string AgenticBridge::GetAgentStatus() {
    if (!m_initialized) return "Not Initialized";
    if (m_agentLoopRunning.load() || IsAutonomousRunning()) return "Running";
    if (m_router && m_router->IsInitialized()) {
        return std::string("Ready (BackendRouter mode=") +
               RawrXD::Agent::BackendModeName(m_router->GetMode()) + ")";
    }
    return "Ready";
}

AgentResponse AgenticBridge::DispatchToolLine(const std::string& line) {
    AgentResponse response;
    response.type = AgentResponseType::TOOL_CALL;
    if (!m_ide) {
        response.type = AgentResponseType::AGENT_ERROR;
        response.content = "No IDE for ToolCallBridge SSOT";
        return response;
    }

    std::string rest = line;
    if (rest.rfind("TOOL:", 0) == 0 || rest.rfind("tool:", 0) == 0) rest = rest.substr(5);
    else if (rest.rfind("TOOL ", 0) == 0) rest = rest.substr(5);
    while (!rest.empty() && rest[0] == ' ') rest.erase(rest.begin());

    std::string name;
    std::string argsJson = "{}";
    const size_t colon = rest.find(':');
    const size_t space = rest.find(' ');
    size_t sep = std::string::npos;
    if (colon != std::string::npos && (space == std::string::npos || colon < space)) sep = colon;
    else if (space != std::string::npos) sep = space;
    if (sep == std::string::npos) {
        name = rest;
    } else {
        name = rest.substr(0, sep);
        argsJson = rest.substr(sep + 1);
        while (!argsJson.empty() && argsJson[0] == ' ') argsJson.erase(argsJson.begin());
        if (argsJson.empty()) argsJson = "{}";
    }

    RawrXD::Agent::ToolCall call;
    call.id = "ide-agent-" + std::to_string(
        std::chrono::steady_clock::now().time_since_epoch().count());
    call.name = name;
    try {
        call.arguments = nlohmann::json::parse(argsJson);
    } catch (...) {
        call.arguments = nlohmann::json::object();
        call.arguments["command"] = argsJson;
        call.arguments["path"] = argsJson;
    }

    // Single choke point → ToolCallBridge::ExecuteToolCall (+ SecurityGate).
    auto result = m_ide->dispatchAgentTool(call);
    response.toolName = name;
    response.toolArgs = argsJson;
    response.content = result.content;
    response.rawOutput = result.content;
    response.type = result.success ? AgentResponseType::TOOL_CALL
                                   : AgentResponseType::AGENT_ERROR;
    if (m_outputCallback) m_outputCallback("tool:" + name, result.content);
    return response;
}

AgentResponse AgenticBridge::ChatViaBackendRouter(const std::string& prompt) {
    AgentResponse response;
    response.type = AgentResponseType::ANSWER;
    if (!m_router || !m_router->IsInitialized()) {
        response.type = AgentResponseType::AGENT_ERROR;
        response.content = "BackendRouter not initialized";
        return response;
    }

    if (m_ide) m_ide->ensureAgentToolSsotReady();

    std::vector<RawrXD::Agent::ChatMessage> messages;
    messages.push_back({"user", prompt, "", nlohmann::json()});

    nlohmann::json tools = nlohmann::json::array();
    if (m_ide && m_ide->agentToolCallBridge()) {
        tools = m_ide->agentToolCallBridge()->GetToolSchemasForLLM();
    }

    RawrXD::Agent::BackendRouter::FailoverInfo failover;
    auto result = m_router->ChatSync(messages, tools, &failover);

    std::string proof = std::string("BACKEND_ROUTER_SELECTED kind=") +
        RawrXD::Agent::BackendName(m_router->GetActiveBackendKind()) +
        " mode=" + RawrXD::Agent::BackendModeName(m_router->GetMode()) +
        " failover=" + (failover.did_failover ? "1" : "0");
    if (m_outputCallback) m_outputCallback("router", proof);

    if (!result.success) {
        response.type = AgentResponseType::AGENT_ERROR;
        response.content = result.error_message.empty() ? "ChatSync failed" : result.error_message;
        response.rawOutput = response.content;
        return response;
    }

    std::string out = result.response;
    if (result.has_tool_calls && m_ide) {
        for (const auto& tc : result.tool_calls) {
            RawrXD::Agent::ToolCall call;
            call.id = "ide-br-" + tc.first;
            call.name = tc.first;
            call.arguments = tc.second;
            auto tr = m_ide->dispatchAgentTool(call);
            out += "\n[tool:" + tc.first + "] " + tr.content;
            response.toolName = tc.first;
            response.toolArgs = tc.second.dump();
            response.type = AgentResponseType::TOOL_CALL;
        }
    }

    response.content = out;
    response.rawOutput = out;
    if (out.find("<thinking>") != std::string::npos) response.type = AgentResponseType::THINKING;
    if (m_outputCallback) m_outputCallback("stream", out);
    return response;
}

void AgenticBridge::SetModel(const std::string& modelName) {
    m_modelName = modelName;
}

void AgenticBridge::SetOllamaServer(const std::string& serverUrl) {
    m_ollamaServer = serverUrl;
}

void AgenticBridge::SetOutputCallback(OutputCallback callback) {
    m_outputCallback = callback;
}

bool AgenticBridge::StartAgentLoop(const std::string& initialPrompt, int maxIterations) {
    if (!m_initialized || !m_router) return false;
    if (m_agentLoopRunning.load()) return true;
    if (m_agentThread.joinable()) m_agentThread.join();

    m_agentLoopRunning.store(true);
    m_agentThread = std::thread([this, initialPrompt, maxIterations]() {
        int iteration = 0;
        while (m_agentLoopRunning.load() && iteration < maxIterations) {
            // Gap 9: loop iterations use BackendRouter, not CPUInferenceEngine Ask.
            (void)ChatViaBackendRouter(initialPrompt);
            ++iteration;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        m_agentLoopRunning.store(false);
    });
    return true;
}

void AgenticBridge::StopAgentLoop() {
    m_agentLoopRunning.store(false);
    if (m_agentThread.joinable() &&
        m_agentThread.get_id() != std::this_thread::get_id()) {
        m_agentThread.join();
    }
}

AgentResponse AgenticBridge::ParseAgentResponse(const std::string& rawOutput) {
    AgentResponse response;
    response.type = AgentResponseType::ANSWER;
    response.content = rawOutput;
    
    // Simple heuristic: if output starts with "TOOL:", treat as tool call
    if (rawOutput.rfind("TOOL:", 0) == 0) {
        response.type = AgentResponseType::TOOL_CALL;
        response.content = rawOutput.substr(5);
    }
    return response;
}

bool AgenticBridge::IsToolCall(const std::string& line) {
    return line.rfind("TOOL:", 0) == 0 || line.rfind("tool:", 0) == 0;
}

bool AgenticBridge::IsAnswer(const std::string& line) {
    return !IsToolCall(line) && !line.empty();
}
