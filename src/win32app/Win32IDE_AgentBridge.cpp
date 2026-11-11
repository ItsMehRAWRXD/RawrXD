// ============================================================================
// Win32IDE_AgentBridge.cpp — AI Telemetry & Control Bridge Implementation
// ============================================================================

#include "Win32IDE_AgentBridge.hpp"
#include "Win32IDE.h"
#include <windows.h>
#include <psapi.h>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <chrono>

#pragma comment(lib, "psapi.lib")

namespace RawrXD::AgentBridge {

// Static member definition
std::atomic<bool> AgentBridge::s_headless{false};

// ============================================================================
// TELEMETRY DATA SERIALIZATION
// ============================================================================

std::string TelemetryData::toJson() const {
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"timestamp\": " << timestamp << ",\n";
    oss << "  \"processId\": " << processId << ",\n";
    oss << "  \"threadId\": " << threadId << ",\n";
    oss << "  \"memory\": {\n";
    oss << "    \"workingSetBytes\": " << workingSetBytes << ",\n";
    oss << "    \"virtualMemoryBytes\": " << virtualMemoryBytes << ",\n";
    oss << "    \"peakWorkingSetBytes\": " << peakWorkingSetBytes << "\n";
    oss << "  },\n";
    oss << "  \"gdi\": {\n";
    oss << "    \"objects\": " << gdiObjects << ",\n";
    oss << "    \"userObjects\": " << userObjects << ",\n";
    oss << "    \"peakObjects\": " << gdiObjectsPeak << "\n";
    oss << "  },\n";
    oss << "  \"window\": {\n";
    oss << "    \"width\": " << windowWidth << ",\n";
    oss << "    \"height\": " << windowHeight << ",\n";
    oss << "    \"isMinimized\": " << (isMinimized ? "true" : "false") << ",\n";
    oss << "    \"isForeground\": " << (isForeground ? "true" : "false") << "\n";
    oss << "  },\n";
    oss << "  \"editor\": {\n";
    oss << "    \"width\": " << editorWidth << ",\n";
    oss << "    \"height\": " << editorHeight << ",\n";
    oss << "    \"cursorLine\": " << cursorLine << ",\n";
    oss << "    \"cursorColumn\": " << cursorColumn << ",\n";
    oss << "    \"totalLines\": " << totalLines << ",\n";
    oss << "    \"currentFile\": \"" << currentFile << "\"\n";
    oss << "  },\n";
    oss << "  \"lsp\": {\n";
    oss << "    \"connected\": " << (lspConnected ? "true" : "false") << ",\n";
    oss << "    \"serverName\": \"" << lspServerName << "\",\n";
    oss << "    \"pendingRequests\": " << lspPendingRequests << ",\n";
    oss << "    \"diagnosticsCount\": " << lspDiagnosticsCount << "\n";
    oss << "  },\n";
    oss << "  \"performance\": {\n";
    oss << "    \"lastFrameTimeMs\": " << std::fixed << std::setprecision(2) << lastFrameTimeMs << ",\n";
    oss << "    \"avgFrameTimeMs\": " << avgFrameTimeMs << ",\n";
    oss << "    \"messagesPerSecond\": " << messagesPerSecond << "\n";
    oss << "  },\n";
    oss << "  \"agent\": {\n";
    oss << "    \"running\": " << (agentRunning ? "true" : "false") << ",\n";
    oss << "    \"queueSize\": " << agentQueueSize << ",\n";
    oss << "    \"lastAction\": \"" << lastAgentAction << "\"\n";
    oss << "  },\n";
    oss << "  \"errors\": {\n";
    oss << "    \"count\": " << errorCount << ",\n";
    oss << "    \"lastError\": \"" << lastError << "\"\n";
    oss << "  }\n";
    oss << "}";
    return oss.str();
}

// ============================================================================
// AGENT COMMAND SERIALIZATION
// ============================================================================

AgentCommand AgentCommand::fromJson(const std::string& json) {
    AgentCommand cmd;
    cmd.rawJson = json;
    
    // Simple JSON parsing (production would use proper parser)
    auto extractString = [](const std::string& json, const std::string& key) -> std::string {
        size_t pos = json.find("\"" + key + "\"");
        if (pos == std::string::npos) return "";
        pos = json.find(":", pos);
        if (pos == std::string::npos) return "";
        pos = json.find("\"", pos);
        if (pos == std::string::npos) return "";
        size_t end = json.find("\"", pos + 1);
        if (end == std::string::npos) return "";
        return json.substr(pos + 1, end - pos - 1);
    };
    
    auto extractInt = [](const std::string& json, const std::string& key) -> int {
        size_t pos = json.find("\"" + key + "\"");
        if (pos == std::string::npos) return 0;
        pos = json.find(":", pos);
        if (pos == std::string::npos) return 0;
        return std::stoi(json.substr(pos + 1));
    };
    
    std::string typeStr = extractString(json, "type");
    if (typeStr == "ping") cmd.type = AgentCommandType::Ping;
    else if (typeStr == "screenshot") cmd.type = AgentCommandType::Screenshot;
    else if (typeStr == "getState") cmd.type = AgentCommandType::GetState;
    else if (typeStr == "setFocus") cmd.type = AgentCommandType::SetFocus;
    else if (typeStr == "resize") cmd.type = AgentCommandType::Resize;
    else if (typeStr == "move") cmd.type = AgentCommandType::Move;
    else if (typeStr == "openFile") cmd.type = AgentCommandType::OpenFile;
    else if (typeStr == "closeFile") cmd.type = AgentCommandType::CloseFile;
    else if (typeStr == "saveFile") cmd.type = AgentCommandType::SaveFile;
    else if (typeStr == "gotoLine") cmd.type = AgentCommandType::GotoLine;
    else if (typeStr == "findText") cmd.type = AgentCommandType::FindText;
    else if (typeStr == "replaceText") cmd.type = AgentCommandType::ReplaceText;
    else if (typeStr == "executeCommand") cmd.type = AgentCommandType::ExecuteCommand;
    else if (typeStr == "runBuild") cmd.type = AgentCommandType::RunBuild;
    else if (typeStr == "runDebug") cmd.type = AgentCommandType::RunDebug;
    else if (typeStr == "stopDebug") cmd.type = AgentCommandType::StopDebug;
    else if (typeStr == "setBreakpoint") cmd.type = AgentCommandType::SetBreakpoint;
    else if (typeStr == "clearBreakpoint") cmd.type = AgentCommandType::ClearBreakpoint;
    else if (typeStr == "requestHover") cmd.type = AgentCommandType::RequestHover;
    else if (typeStr == "requestCompletion") cmd.type = AgentCommandType::RequestCompletion;
    else if (typeStr == "agentPrompt") cmd.type = AgentCommandType::AgentPrompt;
    else if (typeStr == "setConfig") cmd.type = AgentCommandType::SetConfig;
    else if (typeStr == "getConfig") cmd.type = AgentCommandType::GetConfig;
    else if (typeStr == "dumpLayout") cmd.type = AgentCommandType::DumpLayout;
    else if (typeStr == "resetLsp") cmd.type = AgentCommandType::ResetLsp;
    else if (typeStr == "shutdown") cmd.type = AgentCommandType::Shutdown;
    
    cmd.commandId = extractInt(json, "commandId");
    
    // Extract parameters
    size_t paramsPos = json.find("\"parameters\"");
    if (paramsPos != std::string::npos) {
        size_t braceOpen = json.find("{", paramsPos);
        size_t braceClose = json.find("}", braceOpen);
        if (braceOpen != std::string::npos && braceClose != std::string::npos) {
            std::string paramsSection = json.substr(braceOpen + 1, braceClose - braceOpen - 1);
            // Parse key-value pairs
            size_t pos = 0;
            while (pos < paramsSection.size()) {
                size_t keyStart = paramsSection.find("\"", pos);
                if (keyStart == std::string::npos) break;
                size_t keyEnd = paramsSection.find("\"", keyStart + 1);
                if (keyEnd == std::string::npos) break;
                std::string key = paramsSection.substr(keyStart + 1, keyEnd - keyStart - 1);
                
                size_t colonPos = paramsSection.find(":", keyEnd);
                if (colonPos == std::string::npos) break;
                
                size_t valStart = paramsSection.find_first_not_of(" \\t", colonPos + 1);
                if (valStart == std::string::npos) break;
                
                std::string value;
                if (paramsSection[valStart] == '\"') {
                    size_t valEnd = paramsSection.find("\"", valStart + 1);
                    if (valEnd != std::string::npos) {
                        value = paramsSection.substr(valStart + 1, valEnd - valStart - 1);
                        pos = valEnd + 1;
                    }
                } else {
                    size_t valEnd = paramsSection.find_first_of(",}", valStart);
                    if (valEnd == std::string::npos) valEnd = paramsSection.size();
                    value = paramsSection.substr(valStart, valEnd - valStart);
                    pos = valEnd;
                }
                
                cmd.parameters[key] = value;
            }
        }
    }
    
    return cmd;
}

std::string AgentCommand::toJson() const {
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"timestamp\": " << timestamp << ",\n";
    oss << "  \"commandId\": " << commandId << ",\n";
    oss << "  \"type\": \"";
    switch (type) {
        case AgentCommandType::Ping: oss << "ping"; break;
        case AgentCommandType::Screenshot: oss << "screenshot"; break;
        case AgentCommandType::GetState: oss << "getState"; break;
        case AgentCommandType::SetFocus: oss << "setFocus"; break;
        case AgentCommandType::Resize: oss << "resize"; break;
        case AgentCommandType::Move: oss << "move"; break;
        case AgentCommandType::OpenFile: oss << "openFile"; break;
        case AgentCommandType::CloseFile: oss << "closeFile"; break;
        case AgentCommandType::SaveFile: oss << "saveFile"; break;
        case AgentCommandType::GotoLine: oss << "gotoLine"; break;
        case AgentCommandType::FindText: oss << "findText"; break;
        case AgentCommandType::ReplaceText: oss << "replaceText"; break;
        case AgentCommandType::ExecuteCommand: oss << "executeCommand"; break;
        case AgentCommandType::RunBuild: oss << "runBuild"; break;
        case AgentCommandType::RunDebug: oss << "runDebug"; break;
        case AgentCommandType::StopDebug: oss << "stopDebug"; break;
        case AgentCommandType::SetBreakpoint: oss << "setBreakpoint"; break;
        case AgentCommandType::ClearBreakpoint: oss << "clearBreakpoint"; break;
        case AgentCommandType::RequestHover: oss << "requestHover"; break;
        case AgentCommandType::RequestCompletion: oss << "requestCompletion"; break;
        case AgentCommandType::AgentPrompt: oss << "agentPrompt"; break;
        case AgentCommandType::SetConfig: oss << "setConfig"; break;
        case AgentCommandType::GetConfig: oss << "getConfig"; break;
        case AgentCommandType::DumpLayout: oss << "dumpLayout"; break;
        case AgentCommandType::ResetLsp: oss << "resetLsp"; break;
        case AgentCommandType::Shutdown: oss << "shutdown"; break;
        default: oss << "unknown"; break;
    }
    oss << "\",\n";
    oss << "  \"parameters\": {\n";
    bool first = true;
    for (const auto& [key, value] : parameters) {
        if (!first) oss << ",\n";
        first = false;
        oss << "    \"" << key << "\": \"" << value << "\"";
    }
    oss << "\n  }\n";
    oss << "}";
    return oss.str();
}

std::string AgentResponse::toJson() const {
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"commandId\": " << commandId << ",\n";
    oss << "  \"success\": " << (success ? "true" : "false") << ",\n";
    oss << "  \"message\": \"" << message << "\"";
    if (!data.empty()) {
        oss << ",\n  \"data\": {\n";
        bool first = true;
        for (const auto& [key, value] : data) {
            if (!first) oss << ",\n";
            first = false;
            oss << "    \"" << key << "\": \"" << value << "\"";
        }
        oss << "\n  }";
    }
    oss << "\n}";
    return oss.str();
}

// ============================================================================
// AGENT BRIDGE IMPLEMENTATION
// ============================================================================

static AgentBridge* g_agentBridge = nullptr;

AgentBridge::AgentBridge() = default;

AgentBridge::~AgentBridge() {
    shutdown();
}

bool AgentBridge::initialize(const Config& config) {
    if (m_running) return true;
    
    m_config = config;
    if (!m_config.enabled) return false;
    
    // Check for headless mode
    s_headless = isHeadlessMode();
    
    // Start telemetry thread
    m_running = true;
    if (m_config.telemetryIntervalMs > 0) {
        m_telemetryThread = std::thread(&AgentBridge::telemetryLoop, this);
    }
    
    // Start command thread
    if (m_config.commandPollIntervalMs > 0) {
        m_commandThread = std::thread(&AgentBridge::commandLoop, this);
    }
    
    log("AgentBridge initialized", false);
    return true;
}

void AgentBridge::shutdown() {
    if (!m_running) return;
    
    m_running = false;
    
    if (m_telemetryThread.joinable()) {
        m_telemetryThread.join();
    }
    if (m_commandThread.joinable()) {
        m_commandThread.join();
    }
    
    log("AgentBridge shutdown", false);
}

void AgentBridge::setConfig(const Config& config) {
    m_config = config;
}

AgentBridge::Config AgentBridge::getConfig() const {
    return m_config;
}

void AgentBridge::updateTelemetry(const TelemetryData& data) {
    std::lock_guard<std::mutex> lock(m_telemetryMutex);
    m_currentTelemetry = data;
    m_telemetryHistory.push_back(data);
    if (m_telemetryHistory.size() > 100) {
        m_telemetryHistory.erase(m_telemetryHistory.begin());
    }
}

void AgentBridge::updateTelemetryField(const std::string& field, const std::string& value) {
    std::lock_guard<std::mutex> lock(m_telemetryMutex);
    if (field == "currentFile") m_currentTelemetry.currentFile = value;
    else if (field == "cursorLine") m_currentTelemetry.cursorLine = std::stoi(value);
    else if (field == "cursorColumn") m_currentTelemetry.cursorColumn = std::stoi(value);
    else if (field == "totalLines") m_currentTelemetry.totalLines = std::stoi(value);
    else if (field == "lspConnected") m_currentTelemetry.lspConnected = (value == "true");
    else if (field == "lspServerName") m_currentTelemetry.lspServerName = value;
    else if (field == "lastError") m_currentTelemetry.lastError = value;
}

TelemetryData AgentBridge::getCurrentTelemetry() const {
    std::lock_guard<std::mutex> lock(m_telemetryMutex);
    return m_currentTelemetry;
}

void AgentBridge::registerCommandHandler(AgentCommandType type, CommandHandler handler) {
    std::lock_guard<std::mutex> lock(m_handlersMutex);
    m_commandHandlers[type] = handler;
}

void AgentBridge::forceTelemetryDump() {
    writeTelemetryToFile();
}

void AgentBridge::sendResponse(const AgentResponse& response) {
    writeResponse(response);
}

void AgentBridge::log(const std::string& message, bool isError) {
    writeLog(message, isError);
}

bool AgentBridge::isHeadlessMode() {
    static bool checked = false;
    static bool headless = false;
    if (!checked) {
        // Check command line or environment variable
        const char* env = getenv("RAWRXD_HEADLESS");
        if (env && strcmp(env, "1") == 0) {
            headless = true;
        }
        checked = true;
    }
    return headless;
}

void AgentBridge::setHeadlessMode(bool headless) {
    s_headless = headless;
}

// ============================================================================
// BACKGROUND THREADS
// ============================================================================

void AgentBridge::telemetryLoop() {
    while (m_running) {
        // Collect system metrics
        {
            std::lock_guard<std::mutex> lock(m_telemetryMutex);
            collectSystemMetrics(m_currentTelemetry);
            collectMemoryMetrics(m_currentTelemetry);
            collectGdiMetrics(m_currentTelemetry);
            m_currentTelemetry.timestamp = GetTickCount64();
            m_currentTelemetry.processId = GetCurrentProcessId();
            m_currentTelemetry.threadId = GetCurrentThreadId();
        }
        
        // Write to file
        writeTelemetryToFile();
        
        // Sleep
        Sleep(m_config.telemetryIntervalMs);
    }
}

void AgentBridge::commandLoop() {
    while (m_running) {
        pollCommandFile();
        Sleep(m_config.commandPollIntervalMs);
    }
}

// ============================================================================
// FILE I/O
// ============================================================================

void AgentBridge::writeTelemetryToFile() {
    if (m_config.telemetryPath.empty()) return;
    
    TelemetryData data = getCurrentTelemetry();
    std::string json = data.toJson();
    
    std::ofstream file(m_config.telemetryPath);
    if (file.is_open()) {
        file << json;
        file.close();
    }
}

void AgentBridge::pollCommandFile() {
    if (m_config.commandInputPath.empty()) return;
    
    // Check if file exists and has been modified
    WIN32_FILE_ATTRIBUTE_DATA attrData;
    if (!GetFileAttributesExA(m_config.commandInputPath.c_str(), GetFileExInfoStandard, &attrData)) {
        return; // File doesn't exist
    }
    
    FILETIME lastWrite = attrData.ftLastWriteTime;
    if (CompareFileTime(&lastWrite, &m_lastCommandFileTime) <= 0) {
        return; // No changes
    }
    m_lastCommandFileTime = lastWrite;
    
    // Read command file
    std::ifstream file(m_config.commandInputPath);
    if (!file.is_open()) return;
    
    std::string json((std::istreambuf_iterator<char>(file)),
                     std::istreambuf_iterator<char>());
    file.close();
    
    // Parse and process
    AgentCommand cmd = AgentCommand::fromJson(json);
    if (cmd.type != AgentCommandType::Unknown) {
        cmd.timestamp = GetTickCount64();
        cmd.commandId = m_nextCommandId++;
        processCommand(cmd);
    }
}

void AgentBridge::processCommand(const AgentCommand& cmd) {
    CommandHandler handler;
    {
        std::lock_guard<std::mutex> lock(m_handlersMutex);
        auto it = m_commandHandlers.find(cmd.type);
        if (it != m_commandHandlers.end()) {
            handler = it->second;
        }
    }
    
    AgentResponse response;
    response.commandId = cmd.commandId;
    
    if (handler) {
        response = handler(cmd);
    } else {
        response.success = false;
        response.message = "No handler registered for command type";
    }
    
    writeResponse(response);
    
    // Log
    log("Command processed: " + std::to_string(static_cast<int>(cmd.type)) + 
        " success=" + (response.success ? "true" : "false"), !response.success);
}

void AgentBridge::writeResponse(const AgentResponse& response) {
    if (m_config.responseOutputPath.empty()) return;
    
    std::string json = response.toJson();
    std::ofstream file(m_config.responseOutputPath);
    if (file.is_open()) {
        file << json;
        file.close();
    }
}

void AgentBridge::writeLog(const std::string& message, bool isError) {
    if (m_config.logPath.empty()) return;
    
    std::ofstream file(m_config.logPath, std::ios::app);
    if (file.is_open()) {
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        file << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
        file << " [" << (isError ? "ERROR" : "INFO") << "] ";
        file << message << std::endl;
        file.close();
    }
}

// ============================================================================
// SYSTEM METRICS
// ============================================================================

void AgentBridge::collectSystemMetrics(TelemetryData& data) {
    // Window metrics
    HWND hwnd = GetForegroundWindow();
    if (hwnd) {
        RECT rc;
        GetWindowRect(hwnd, &rc);
        data.windowWidth = rc.right - rc.left;
        data.windowHeight = rc.bottom - rc.top;
        data.isForeground = true;
        data.isMinimized = IsIconic(hwnd);
    }
}

void AgentBridge::collectMemoryMetrics(TelemetryData& data) {
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        data.workingSetBytes = pmc.WorkingSetSize;
        data.virtualMemoryBytes = pmc.PagefileUsage;
        data.peakWorkingSetBytes = pmc.PeakWorkingSetSize;
    }
}

void AgentBridge::collectGdiMetrics(TelemetryData& data) {
    data.gdiObjects = GetGuiResources(GetCurrentProcess(), GR_GDIOBJECTS);
    data.userObjects = GetGuiResources(GetCurrentProcess(), GR_USEROBJECTS);
}

// ============================================================================
// GLOBAL ACCESS
// ============================================================================

AgentBridge* getAgentBridge() {
    return g_agentBridge;
}

bool initializeAgentBridge(const AgentBridge::Config& config) {
    if (g_agentBridge) return true;
    
    g_agentBridge = new AgentBridge();
    return g_agentBridge->initialize(config);
}

void shutdownAgentBridge() {
    if (g_agentBridge) {
        delete g_agentBridge;
        g_agentBridge = nullptr;
    }
}

} // namespace RawrXD::AgentBridge
