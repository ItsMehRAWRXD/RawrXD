// ============================================================================
// weaponized_agent_bridge.cpp
// Fixed issues:
//  - Command injection: args are now passed as a properly quoted argv string
//    built with a strict allowlist check, not raw concatenation
//  - Hardcoded personal dev paths removed; script resolved relative to exe
//    or from RAWRXD_AGENT_SCRIPT env var
// ============================================================================

#include "weaponized_agent_bridge.hpp"
#include <windows.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <chrono>
#include <algorithm>
#include <cctype>

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
    if (m_agentScriptPath.empty()) return false;
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

// Validate that a string contains only safe identifier/path characters.
// Rejects anything that could be a shell metacharacter.
static bool isSafeArg(const std::string& s) {
    if (s.empty()) return true;
    for (char c : s) {
        // Allow alphanumerics, spaces, hyphens, underscores, dots, forward/back slashes, colons
        if (std::isalnum(static_cast<unsigned char>(c))) continue;
        if (c == ' ' || c == '-' || c == '_' || c == '.' ||
            c == '/' || c == '\\' || c == ':') continue;
        return false;
    }
    return true;
}

// Build a properly quoted command-line argument (Windows quoting rules).
// Follows the algorithm described in MSDN "Parsing C++ Command-Line Arguments".
static std::string quoteArg(const std::string& arg) {
    // If no special chars, no quoting needed
    if (arg.find_first_of(" \t\n\v\"") == std::string::npos)
        return arg;

    std::string result = "\"";
    for (size_t i = 0; i < arg.size(); ++i) {
        size_t numBackslashes = 0;
        while (i < arg.size() && arg[i] == '\\') { ++i; ++numBackslashes; }
        if (i == arg.size()) {
            // Backslashes before closing quote must be doubled
            result.append(numBackslashes * 2, '\\');
            break;
        }
        if (arg[i] == '"') {
            result.append(numBackslashes * 2 + 1, '\\');
            result += '"';
        } else {
            result.append(numBackslashes, '\\');
            result += arg[i];
        }
    }
    result += '"';
    return result;
}

WeaponizedAgentBridge::MissionResult
WeaponizedAgentBridge::executeMission(const std::string& missionType, const std::string& missionParams) {
    MissionResult r;
    if (!m_initialized.load()) { r.error = "Agent not initialized"; return r; }

    int64_t elapsed = static_cast<int64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count()) - m_startTime.load();
    if (elapsed > m_ttlMs.load()) { r.error = "TTL expired"; return r; }

    // Validate inputs against allowlist before building command line
    if (!isSafeArg(missionType)) {
        r.error = "Invalid characters in missionType";
        return r;
    }
    if (!isSafeArg(missionParams)) {
        r.error = "Invalid characters in missionParams";
        return r;
    }

    // Build command line: node "<script>" "<missionType>" ["<missionParams>"]
    std::string cmdLine = "node " + quoteArg(m_agentScriptPath)
                        + " " + quoteArg(missionType);
    if (!missionParams.empty())
        cmdLine += " " + quoteArg(missionParams);

    return executeNodeScript(m_agentScriptPath, cmdLine);
}

WeaponizedAgentBridge::MissionResult
WeaponizedAgentBridge::executeCommand(const std::string& command) {
    MissionResult r;
    if (!m_initialized.load()) { r.error = "Agent not initialized"; return r; }

    int64_t elapsed = static_cast<int64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count()) - m_startTime.load();
    if (elapsed > m_ttlMs.load()) { r.error = "TTL expired"; return r; }

    // command must be a safe identifier (no shell metacharacters)
    if (!isSafeArg(command)) {
        r.error = "Invalid characters in command";
        return r;
    }

    std::string cmdLine = "node " + quoteArg(m_agentScriptPath) + " " + quoteArg(command);
    return executeNodeScript(m_agentScriptPath, cmdLine);
}

WeaponizedAgentBridge::MissionResult
WeaponizedAgentBridge::executeNodeScript(const std::string& /*scriptPath*/, const std::string& cmdLine) {
    MissionResult result;

    STARTUPINFOA si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    si.wShowWindow = SW_HIDE;

    SECURITY_ATTRIBUTES sa{ sizeof(sa), nullptr, TRUE };
    HANDLE hRead = nullptr, hWrite = nullptr;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
        result.error = "Failed to create pipe";
        return result;
    }
    // Ensure the read end is not inherited by the child
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    si.hStdOutput = hWrite;
    si.hStdError  = hWrite;

    PROCESS_INFORMATION pi{};
    // CreateProcessA requires a mutable buffer for lpCommandLine
    std::string mutableCmd = cmdLine;
    if (CreateProcessA(nullptr, mutableCmd.data(), nullptr, nullptr,
                       TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        CloseHandle(hWrite);
        hWrite = nullptr;

        std::string output;
        char buffer[4096];
        DWORD bytesRead = 0;
        while (ReadFile(hRead, buffer, sizeof(buffer) - 1, &bytesRead, nullptr) && bytesRead > 0) {
            buffer[bytesRead] = '\0';
            output += buffer;
            if (m_streamCallback) m_streamCallback(std::string(buffer, bytesRead));
        }
        WaitForSingleObject(pi.hProcess, 30000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        result.success = true;
        result.output  = std::move(output);
    } else {
        result.error = "Failed to execute agent script";
    }

    if (hRead)  CloseHandle(hRead);
    if (hWrite) CloseHandle(hWrite);
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
    // 1. Honour explicit environment variable override
    char envBuf[MAX_PATH] = {};
    if (GetEnvironmentVariableA("RAWRXD_AGENT_SCRIPT", envBuf, MAX_PATH) > 0) {
        if (GetFileAttributesA(envBuf) != INVALID_FILE_ATTRIBUTES)
            return std::string(envBuf);
    }

    // 2. Look for weaponized_agent.js next to the running executable
    char exePath[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);
    std::string base(exePath);
    auto slash = base.find_last_of("\\/");
    if (slash != std::string::npos) base = base.substr(0, slash + 1);

    std::string candidate = base + "weaponized_agent.js";
    if (GetFileAttributesA(candidate.c_str()) != INVALID_FILE_ATTRIBUTES)
        return candidate;

    // 3. Sub-directory fallback relative to exe
    candidate = base + "agents\\weaponized_agent.js";
    if (GetFileAttributesA(candidate.c_str()) != INVALID_FILE_ATTRIBUTES)
        return candidate;

    return {}; // Not found — caller must provide path explicitly
}

// escapeCommand kept for any legacy callers but no longer used internally
std::string WeaponizedAgentBridge::escapeCommand(const std::string& cmd) {
    return quoteArg(cmd);
}

} // namespace RawrXD
