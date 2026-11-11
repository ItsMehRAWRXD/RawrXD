// Agentic Framework Bridge Implementation
// Connects Win32IDE to Native C++ Agent (Parity with rawrxd_cli)

#include "Win32IDE_AgenticBridge.h"
#include "IDELogger.h"
#include "Win32IDE.h"
#include "../native_agent.hpp"
#include <sstream>
#include <algorithm>
#include <regex>

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
    LOG_INFO("AgenticBridge destroyed");
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

    // Initialize Native Engine
    LOG_INFO("Creating Native CPU Inference Engine...");
    m_nativeEngine = std::make_unique<CPUInference::CPUInferenceEngine>();
    
    // Try to load model immediately if we have a guess, or just init the engine structure
    // We assume the engine manages its own "empty" state if no model is loaded yet.
    
    // Initialize Native Agent Layer
    LOG_INFO("Creating Native Agent...");
    m_nativeAgent = std::make_unique<RawrXD::NativeAgent>(m_nativeEngine.get());
    
    // Wire output callback for streaming
    // referencing this inside lambda requires care, but AgenticBridge outlives the agent usually
    m_nativeAgent->SetOutputCallback([this](const std::string& chunk) {
         if (m_outputCallback) {
             m_outputCallback("stream", chunk);
         }
    });

    m_initialized = true;
    LOG_INFO("AgenticBridge initialized successfully.");
    
    return true;
}

AgentResponse AgenticBridge::ExecuteAgentCommand(const std::string& prompt) {
    LOG_INFO("ExecuteAgentCommand: " + prompt);
    
    AgentResponse response;
    response.type = AgentResponseType::ANSWER;
    
    if (!m_initialized || !m_nativeAgent) {
        response.type = AgentResponseType::AGENT_ERROR;
        response.content = "Agent not initialized.";
        return response;
    }

    std::string fullOutput;
    
    // Temporary override of callback to capture full output for the return struct
    // while ALSO streaming to the GUI
    m_nativeAgent->SetOutputCallback([&](const std::string& chunk) {
        fullOutput += chunk;
        if (m_outputCallback) {
            m_outputCallback("stream", chunk);
        }
    });

    // PARITY LOGIC calling rawrxd_cli features
    if (prompt == "/max") {
         m_nativeAgent->SetMaxMode(true);
         response.content = "Max Mode Enabled (Native Threads)";
    }
    else if (prompt == "/think") {
         static bool t = false; t = !t;
         m_nativeAgent->SetDeepThink(t);
         response.content = std::string("Deep Thinking ") + (t ? "Enabled" : "Disabled");
    }
    else if (prompt == "/research") {
         static bool r = false; r = !r;
         m_nativeAgent->SetDeepResearch(r);
         response.content = std::string("Deep Research ") + (r ? "Enabled" : "Disabled");
    }
    else if (prompt == "/norefusal") {
         static bool n = false; n = !n;
         m_nativeAgent->SetNoRefusal(n);
         response.content = std::string("No Refusal Mode ") + (n ? "Enabled" : "Disabled");
    }
    else if (prompt.find("/load ") == 0) {
        std::string path = prompt.substr(6);
        if (m_nativeEngine->LoadModel(path)) {
            response.content = "Model loaded successfully: " + path;
        } else {
            response.content = "Failed to load model from: " + path;
            response.type = AgentResponseType::AGENT_ERROR;
        }
    }
    else if (prompt.find("/bugreport ") == 0) {
         std::string path = prompt.substr(11);
         m_nativeAgent->BugReport(path); 
         response.content = fullOutput;
    }
    // Explicit /edit logic
    else if (prompt.find("/edit ") == 0) {
         // syntax: /edit <file> <instructions>
         std::string rest = prompt.substr(6);
         size_t spacePos = rest.find(" ");
         if (spacePos != std::string::npos) {
             std::string path = rest.substr(0, spacePos);
             std::string inst = rest.substr(spacePos + 1);
             m_nativeAgent->Edit(path, inst);
             response.content = fullOutput;
         } else {
             response.content = "Usage: /edit <file> <instructions>";
         }
    }
    // Explicit /plan logic
    else if (prompt.find("/plan ") == 0) {
         std::string task = prompt.substr(6);
         m_nativeAgent->Plan(task);
         response.content = fullOutput;
    }
    // Explicit /suggest logic
    else if (prompt.find("/suggest ") == 0) {
         std::string path = prompt.substr(9);
         m_nativeAgent->Suggest(path);
         response.content = fullOutput;
    }
    // Explicit /patch logic (HotPatching)
    else if (prompt.find("/patch ") == 0) {
         std::string path = prompt.substr(7);
         m_nativeAgent->HotPatch(path);
         response.content = fullOutput;
    }
    // General Query
    else {
         m_nativeAgent->Ask(prompt);
         response.content = fullOutput;
         if (fullOutput.find("<thinking>") != std::string::npos) {
             response.type = AgentResponseType::THINKING;
         }
    }

    response.rawOutput = fullOutput;
    return response;
}

// Deprecated Stubs
bool AgenticBridge::SpawnPowerShellProcess(const std::string& scriptPath, const std::string& arguments) { return true; }
bool AgenticBridge::ReadProcessOutput(std::string& output, DWORD timeoutMs) { return true; }
void AgenticBridge::KillPowerShellProcess() {}
std::string AgenticBridge::ResolveFrameworkPath() { return ""; }
std::string AgenticBridge::ResolveToolsModulePath() { return ""; }
std::vector<std::string> AgenticBridge::GetAvailableTools() { return {}; }
std::string AgenticBridge::GetAgentStatus() { return m_initialized ? "Ready (Native)" : "Not Initialized"; }
void AgenticBridge::SetModel(const std::string& modelName) { m_modelName = modelName; }
void AgenticBridge::SetOllamaServer(const std::string& serverUrl) { m_ollamaServer = serverUrl; }
void AgenticBridge::SetOutputCallback(OutputCallback callback) { m_outputCallback = callback; }
bool AgenticBridge::StartAgentLoop(const std::string& initialPrompt, int maxIterations) { return false; }
void AgenticBridge::StopAgentLoop() {}
AgentResponse AgenticBridge::ParseAgentResponse(const std::string& rawOutput) { return {}; }
bool AgenticBridge::IsToolCall(const std::string& line) { return false; }
bool AgenticBridge::IsAnswer(const std::string& line) { return true; }
