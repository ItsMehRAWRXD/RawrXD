// Agentic Framework Bridge Implementation
// Connects Win32IDE to Native C++ Agent (Parity with rawrxd_cli)

#include "Win32IDE_AgenticBridge.h"
#include "IDELogger.h"
#include "Win32IDE.h"
#include "Win32IDE_Deep2Bridge.h"
#include "../native_agent.hpp"
#include "../agentic_workflow_bridge.h"
#include <nlohmann/json.hpp>
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
    m_nativeEngine = std::make_unique<RawrXD::CPUInferenceEngine>();
    
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

    std::string workflowTool;
    std::string workflowArgs = "{}";
    if (prompt.rfind("/browser ", 0) == 0) {
        workflowTool = "browser_navigate";
        nlohmann::json browserParams;
        browserParams["url"] = prompt.substr(9);
        browserParams["visible"] = true;
        workflowArgs = browserParams.dump();
    } else if (prompt.rfind("/tool ", 0) == 0) {
        const std::string request = prompt.substr(6);
        const size_t separator = request.find_first_of(" \t");
        workflowTool = separator == std::string::npos ? request : request.substr(0, separator);
        if (separator != std::string::npos) workflowArgs = request.substr(separator + 1);
    } else if (prompt.rfind("tool:", 0) == 0) {
        const std::string request = prompt.substr(5);
        const size_t separator = request.find_first_of(" \t");
        workflowTool = separator == std::string::npos ? request : request.substr(0, separator);
        if (separator != std::string::npos) workflowArgs = request.substr(separator + 1);
    }

    if (!workflowTool.empty()) {
        response.type = AgentResponseType::TOOL_CALL;
        response.toolName = workflowTool;
        response.toolArgs = workflowArgs;
        try {
            const auto params = nlohmann::json::parse(workflowArgs);
            nlohmann::json result;
            if (!RawrXD::Workflow::dispatchWorkflowTool(workflowTool, params, result)) {
                response.type = AgentResponseType::AGENT_ERROR;
                response.content = "Unknown native workflow tool: " + workflowTool;
            } else {
                response.content = result.dump(2);
            }
        } catch (const std::exception& e) {
            response.type = AgentResponseType::AGENT_ERROR;
            response.content = "Native workflow tool input error: ";
            response.content += e.what();
        }
        response.rawOutput = response.content;
        return response;
    }

    if (m_ide && m_ide->m_deep2Bridge && m_ide->m_deep2Bridge->IsModelLoaded()) {
        response.content = m_ide->m_deep2Bridge->GenerateSync(prompt, 512);
        response.rawOutput = response.content;
        if (response.content.empty() || response.content.rfind("Error:", 0) == 0) {
            response.type = AgentResponseType::AGENT_ERROR;
        }
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

// Deprecated Stubs — replaced with real implementations
bool AgenticBridge::SpawnPowerShellProcess(const std::string& scriptPath, const std::string& arguments) {
    LOG_INFO("SpawnPowerShellProcess: " + scriptPath + " " + arguments);
    
    // Kill any existing process first
    KillPowerShellProcess();
    
    // Build command line
    std::string cmdLine = "powershell.exe -ExecutionPolicy Bypass -File \"" + scriptPath + "\"";
    if (!arguments.empty()) {
        cmdLine += " " + arguments;
    }
    
    // Set up pipes for stdout
    SECURITY_ATTRIBUTES saAttr = {sizeof(SECURITY_ATTRIBUTES), NULL, TRUE};
    if (!CreatePipe(&m_hStdoutRead, &m_hStdoutWrite, &saAttr, 0)) {
        LOG_ERROR("SpawnPowerShellProcess: CreatePipe failed");
        return false;
    }
    if (!SetHandleInformation(m_hStdoutRead, HANDLE_FLAG_INHERIT, 0)) {
        LOG_ERROR("SpawnPowerShellProcess: SetHandleInformation failed");
        CloseHandle(m_hStdoutRead);
        CloseHandle(m_hStdoutWrite);
        m_hStdoutRead = m_hStdoutWrite = nullptr;
        return false;
    }
    
    // Set up pipe for stdin
    if (!CreatePipe(&m_hStdinRead, &m_hStdinWrite, &saAttr, 0)) {
        LOG_ERROR("SpawnPowerShellProcess: CreatePipe(stdin) failed");
        CloseHandle(m_hStdoutRead);
        CloseHandle(m_hStdoutWrite);
        m_hStdoutRead = m_hStdoutWrite = nullptr;
        return false;
    }
    if (!SetHandleInformation(m_hStdinWrite, HANDLE_FLAG_INHERIT, 0)) {
        LOG_ERROR("SpawnPowerShellProcess: SetHandleInformation(stdin) failed");
        CloseHandle(m_hStdoutRead);
        CloseHandle(m_hStdoutWrite);
        CloseHandle(m_hStdinRead);
        CloseHandle(m_hStdinWrite);
        m_hStdoutRead = m_hStdoutWrite = m_hStdinRead = m_hStdinWrite = nullptr;
        return false;
    }
    
    PROCESS_INFORMATION piProcInfo = {0};
    STARTUPINFOW siStartInfo = {0};
    siStartInfo.cb = sizeof(STARTUPINFO);
    siStartInfo.hStdError = m_hStdoutWrite;
    siStartInfo.hStdOutput = m_hStdoutWrite;
    siStartInfo.hStdInput = m_hStdinRead;
    siStartInfo.dwFlags |= STARTF_USESTDHANDLES;
    
    std::wstring wcmdLine(cmdLine.begin(), cmdLine.end());
    
    BOOL success = CreateProcessW(
        NULL,               // No module name (use command line)
        &wcmdLine[0],       // Command line
        NULL,               // Process handle not inheritable
        NULL,               // Thread handle not inheritable
        TRUE,               // Set handle inheritance to TRUE
        CREATE_NO_WINDOW,   // No window
        NULL,               // Use parent's environment block
        NULL,               // Use parent's starting directory
        &siStartInfo,       // Pointer to STARTUPINFO
        &piProcInfo         // Pointer to PROCESS_INFORMATION
    );
    
    if (!success) {
        LOG_ERROR("SpawnPowerShellProcess: CreateProcessW failed: " + std::to_string(GetLastError()));
        CloseHandle(m_hStdoutRead);
        CloseHandle(m_hStdoutWrite);
        CloseHandle(m_hStdinRead);
        CloseHandle(m_hStdinWrite);
        m_hStdoutRead = m_hStdoutWrite = m_hStdinRead = m_hStdinWrite = nullptr;
        return false;
    }
    
    m_hProcess = piProcInfo.hProcess;
    CloseHandle(piProcInfo.hThread);
    
    LOG_INFO("SpawnPowerShellProcess: Process started (PID=" + std::to_string(GetProcessId(m_hProcess)) + ")");
    return true;
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
    std::vector<std::string> tools = {
        "list_dir", "read_file", "write_file", "run_command", "search_text"
    };
    for (const auto& schema : RawrXD::Workflow::workflowToolSchemas()) {
        if (schema.contains("name") && schema.at("name").is_string()) {
            tools.push_back(schema.at("name").get<std::string>());
        }
    }
    return tools;
}

std::string AgenticBridge::GetAgentStatus() {
    if (!m_initialized) return "Not Initialized";
    if (m_agentLoopRunning) return "Running (Native)";
    if (m_hProcess) return "Process Active";
    return "Ready (Native)";
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
    if (!m_initialized || !m_nativeAgent) return false;
    if (m_agentLoopRunning) return true;
    
    m_agentLoopRunning = true;
    m_agentThread = std::thread([this, initialPrompt, maxIterations]() {
        int iteration = 0;
        while (m_agentLoopRunning && iteration < maxIterations) {
            // Process one agent iteration
            m_nativeAgent->Ask(initialPrompt);
            ++iteration;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        m_agentLoopRunning = false;
    });
    m_agentThread.detach();
    
    return true;
}

void AgenticBridge::StopAgentLoop() {
    m_agentLoopRunning = false;
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
