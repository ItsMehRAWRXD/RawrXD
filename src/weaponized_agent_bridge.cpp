// ============================================================================
// weaponized_agent_bridge.cpp — C++ bridge to Node.js weaponized agent system
// ============================================================================

#include "weaponized_agent_bridge.hpp"
#include <process.h>
#include <shellapi.h>
#include <windows.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <chrono>
#include <algorithm>

namespace RawrXD {

WeaponizedAgentBridge::WeaponizedAgentBridge() {
    m_ttlMs.store(120000);
}

WeaponizedAgentBridge::~WeaponizedAgentBridge() {
    shutdown();
}

bool WeaponizedAgentBridge::initialize(const std::string& agentScriptPath) {
    if (m_initialized.load()) return true;
    m_agentScriptPath = agentScriptPath.empty() ? detectAgentScriptPath() : agentScriptPath;
    DWORD attrs = GetFileAttributesA(m_agentScriptPath.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) return false;
    m_startTime.store(static_cast<int64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count()));
    m_initialized.store(true);
    return true;
}

void WeaponizedAgentBridge::shutdown() {
    if (!m_initialized.load()) return;
    m_initialized.store(false);
    m_streamCallback = nullptr;
}

WeaponizedAgentBridge::MissionResult 
WeaponizedAgentBridge::executeMission(const std::string& missionType, const std::string& missionParams) {
    if (!m_initialized.load()) { MissionResult r; r.error = "Agent not initialized"; return r; }
    int64_t elapsed = static_cast<int64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count()) - m_startTime.load();
    if (elapsed > m_ttlMs.load()) { MissionResult r; r.error = "TTL expired"; return r; }
    std::string cmd = "node \"" + m_agentScriptPath + "\" \"" + escapeCommand(missionType);
    if (!missionParams.empty()) cmd += " " + escapeCommand(missionParams);
    cmd += "\"";
    return executeNodeScript(m_agentScriptPath, cmd);
}

WeaponizedAgentBridge::MissionResult 
WeaponizedAgentBridge::executeCommand(const std::string& command) {
    if (!m_initialized.load()) { MissionResult r; r.error = "Agent not initialized"; return r; }
    int64_t elapsed = static_cast<int64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count()) - m_startTime.load();
    if (elapsed > m_ttlMs.load()) { MissionResult r; r.error = "TTL expired"; return r; }
    return executeNodeScript(m_agentScriptPath, command);
}

WeaponizedAgentBridge::MissionResult 
WeaponizedAgentBridge::executeNodeScript(const std::string& scriptPath, const std::string& args) {
    MissionResult result;
    std::string cmd = "node \"" + scriptPath + "\" " + args;
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi = {0};
    si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    si.wShowWindow = SW_HIDE;
    HANDLE hReadPipe, hWritePipe;
    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) { result.error = "Failed to create pipe"; return result; }
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;
    std::string output;
    if (CreateProcessA(NULL, (LPSTR)cmd.c_str(), NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(hWritePipe);
        char buffer[4096];
        DWORD bytesRead;
        while (ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
            buffer[bytesRead] = '\0';
            output += buffer;
            if (m_streamCallback) m_streamCallback(buffer);
        }
        WaitForSingleObject(pi.hProcess, 30000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseHandle(hReadPipe);
        result.success = true;
        result.output = output;
    } else {
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        result.error = "Failed to execute agent script";
    }
    return result;
}

void WeaponizedAgentBridge::setStreamCallback(StreamCallback cb) {
    m_streamCallback = std::move(cb);
}

int64_t WeaponizedAgentBridge::getRemainingTime() const {
    int64_t elapsed = static_cast<int64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count()) - m_startTime.load();
    int64_t remaining = m_ttlMs.load() - elapsed;
    return remaining > 0 ? remaining : 0;
}

std::string WeaponizedAgentBridge::detectAgentScriptPath() {
    std::vector<std::string> paths = {
        "F:\\temp\\agentic\\Everything_MyCopilot_IDE\\consolidated\\weaponized_agent.js",
        "d:\\weaponized_agent.js",
        "d:\\rawrxd\\src\\weaponized_agent.js",
        "d:\\rawrxd\\security-engines\\weaponized_agent.js"
    };
    for (const auto& path : paths) {
        DWORD attrs = GetFileAttributesA(path.c_str());
        if (attrs != INVALID_FILE_ATTRIBUTES) return path;
    }
    return "F:\\temp\\agentic\\Everything_MyCopilot_IDE\\consolidated\\weaponized_agent.js";
}

std::string WeaponizedAgentBridge::escapeCommand(const std::string& cmd) {
    std::string result;
    for (char c : cmd) {
        if (c == '"' || c == '\\') result += '\\';
        result += c;
    }
    return result;
}

} // namespace RawrXD
