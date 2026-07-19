// SovereignBridge.cpp
// RawrXD IDE → Sovereign Runtime Integration Bridge
// Process orchestration layer - no runtime logic duplication

#include "SovereignBridge.hpp"
#include <sstream>
#include <iomanip>
#include <fstream>
#include <algorithm>
#include <chrono>
#include <direct.h>

namespace RawrXD {
namespace IDE {

SovereignBridge::SovereignBridge()
{
}

SovereignBridge::~SovereignBridge()
{
}

bool SovereignBridge::IsRuntimeAvailable() const
{
    // Check if rawrxd.exe exists in PATH or current directory
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA("rawrxd.exe", &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        FindClose(hFind);
        return true;
    }
    
    // Check in common locations
    const char* paths[] = {
        "..\\..\\rawrxd.exe",
        "..\\..\\..\\rawrxd.exe",
        "d:\\rawrxd-ci-bootstrap\\build\\rawrxd.exe",
        "d:\\rawrxd-ci-bootstrap\\rawrxd.exe"
    };
    
    for (const auto& path : paths) {
        hFind = FindFirstFileA(path, &findData);
        if (hFind != INVALID_HANDLE_VALUE) {
            FindClose(hFind);
            return true;
        }
    }
    
    return false;
}

SovereignResult SovereignBridge::Validate(
    const std::string& prompt,
    const SovereignConfig& config)
{
    SovereignResult result;
    
    // Build command line
    std::string cmdLine = BuildCommandLine(prompt, config);
    
    // Execute and capture
    int exitCode = -1;
    result.output = ExecuteCommand(cmdLine, exitCode, config.timeoutMs);
    result.started = !result.output.empty() || exitCode != -1;
    result.completed = exitCode != -1;
    result.exitCode = exitCode;
    
    if (!result.completed) {
        m_lastError = "Sovereign runtime execution timed out or failed";
        return result;
    }
    
    // Find the evidence bundle that was just created
    result.runPath = FindLatestEvidenceBundle(config.evidenceRoot);
    if (!result.runPath.empty()) {
        result.certificatePath = result.runPath + "\\certificate.json";
        
        // Parse certificate
        if (ParseCertificate(result.certificatePath, result)) {
            result.passed = (result.gatesFailed == 0 && result.gatesPassed > 0);
        }
    }
    
    return result;
}

SovereignResult SovereignBridge::QuickValidate(const std::string& prompt)
{
    SovereignConfig config;
    config.autonomous = true;
    config.validate = true;
    config.maxTokens = 64;  // Quick validation
    return Validate(prompt, config);
}

std::string SovereignBridge::BuildCommandLine(
    const std::string& prompt,
    const SovereignConfig& config) const
{
    std::stringstream cmd;
    
    // Runtime executable
    cmd << "\"" << config.runtimePath << "\"";
    
    // Model path
    cmd << " --model \"" << config.modelPath << "\"";
    
    // Prompt
    cmd << " --prompt \"" << EscapeCommandLine(prompt) << "\"";
    
    // Max tokens
    cmd << " --max-tokens " << config.maxTokens;
    
    // Backend
    cmd << " --backend " << config.backend;
    
    // Seed (if non-zero)
    if (config.seed != 0) {
        cmd << " --seed " << config.seed;
    }
    
    // Autonomous mode
    if (config.autonomous) {
        cmd << " --autonomous";
    }
    
    // Validation mode
    if (config.validate) {
        cmd << " --validate";
    }
    
    // Evidence output directory
    cmd << " --evidence \"" << config.evidenceRoot << "\"";
    
    return cmd.str();
}

std::string SovereignBridge::ExecuteCommand(
    const std::string& command,
    int& outExitCode,
    int timeoutMs)
{
    std::string output;
    outExitCode = -1;
    
    // Security: Create anonymous pipe for output capture
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;
    
    HANDLE hReadPipe = NULL;
    HANDLE hWritePipe = NULL;
    
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        m_lastError = "Failed to create pipe";
        return output;
    }
    
    // Ensure read handle is not inherited
    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);
    
    // Setup process
    STARTUPINFOA si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.hStdError = hWritePipe;
    si.hStdOutput = hWritePipe;
    si.dwFlags |= STARTF_USESTDHANDLES;
    
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));
    
    // Create process
    char* cmdBuffer = _strdup(command.c_str());
    
    BOOL success = CreateProcessA(
        NULL,           // Application name
        cmdBuffer,      // Command line
        NULL,           // Process security attributes
        NULL,           // Thread security attributes
        TRUE,           // Inherit handles
        CREATE_NO_WINDOW, // Creation flags
        NULL,           // Environment
        NULL,           // Current directory
        &si,
        &pi
    );
    
    free(cmdBuffer);
    CloseHandle(hWritePipe);
    
    if (!success) {
        m_lastError = "Failed to launch sovereign runtime";
        CloseHandle(hReadPipe);
        return output;
    }
    
    // Read output with timeout
    char buffer[4096];
    DWORD bytesRead;
    DWORD totalBytes = 0;
    auto startTime = std::chrono::steady_clock::now();
    
    while (true) {
        // Check for timeout
        auto elapsed = std::chrono::steady_clock::now() - startTime;
        if (std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count() > timeoutMs) {
            TerminateProcess(pi.hProcess, 1);
            m_lastError = "Sovereign runtime execution timed out";
            break;
        }
        
        // Check if process has exited
        DWORD waitResult = WaitForSingleObject(pi.hProcess, 100);
        
        // Read available output
        DWORD available = 0;
        if (PeekNamedPipe(hReadPipe, NULL, 0, NULL, &available, NULL) && available > 0) {
            if (ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
                buffer[bytesRead] = '\0';
                output += buffer;
                totalBytes += bytesRead;
                
                // Prevent excessive output
                if (totalBytes > 10 * 1024 * 1024) { // 10MB limit
                    output += "\n[Output truncated - exceeded 10MB limit]";
                    break;
                }
            }
        }
        
        if (waitResult == WAIT_OBJECT_0) {
            // Process exited, drain remaining output
            while (ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
                buffer[bytesRead] = '\0';
                output += buffer;
            }
            break;
        }
    }
    
    // Get exit code
    DWORD exitCode;
    if (GetExitCodeProcess(pi.hProcess, &exitCode)) {
        outExitCode = static_cast<int>(exitCode);
    }
    
    // Cleanup
    CloseHandle(hReadPipe);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    return output;
}

std::string SovereignBridge::EscapeCommandLine(const std::string& arg)
{
    std::string escaped;
    bool needsQuotes = false;
    
    // Check if quotes are needed
    if (arg.find_first_of(" \"\t") != std::string::npos) {
        needsQuotes = true;
    }
    
    if (needsQuotes) {
        escaped += '"';
    }
    
    for (size_t i = 0; i < arg.length(); ++i) {
        char c = arg[i];
        
        if (c == '"') {
            // Escape quotes
            escaped += "\\\"";
        } else if (c == '\\' && i + 1 < arg.length() && arg[i + 1] == '"') {
            // Escape backslash before quote
            escaped += "\\\\";
        } else {
            escaped += c;
        }
    }
    
    if (needsQuotes) {
        escaped += '"';
    }
    
    return escaped;
}

std::string SovereignBridge::FindLatestEvidenceBundle(const std::string& evidenceRoot)
{
    std::string latestPath;
    FILETIME latestTime = {0, 0};
    
    std::string searchPath = evidenceRoot + "\\*";
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA(searchPath.c_str(), &findData);
    
    if (hFind == INVALID_HANDLE_VALUE) {
        return latestPath;
    }
    
    do {
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (strcmp(findData.cFileName, ".") != 0 && 
                strcmp(findData.cFileName, "..") != 0) {
                // Check if this directory contains a certificate.json
                std::string bundlePath = evidenceRoot + "\\" + findData.cFileName;
                std::string certPath = bundlePath + "\\certificate.json";
                
                WIN32_FILE_ATTRIBUTE_DATA certAttr;
                if (GetFileAttributesExA(certPath.c_str(), GetFileExInfoStandard, &certAttr)) {
                    // Compare file times
                    if (CompareFileTime(&certAttr.ftLastWriteTime, &latestTime) > 0) {
                        latestTime = certAttr.ftLastWriteTime;
                        latestPath = bundlePath;
                    }
                }
            }
        }
    } while (FindNextFileA(hFind, &findData));
    
    FindClose(hFind);
    return latestPath;
}

bool SovereignBridge::ParseCertificate(
    const std::string& certificatePath,
    SovereignResult& outResult)
{
    std::ifstream file(certificatePath);
    if (!file.is_open()) {
        return false;
    }
    
    std::string line;
    std::string content;
    while (std::getline(file, line)) {
        content += line + "\n";
    }
    file.close();
    
    // Simple JSON parsing for certificate fields
    // Look for: "passed": true, "gates_passed": N, "gates_failed": M, "hash": "..."
    
    auto findBool = [&content](const std::string& key) -> bool {
        size_t pos = content.find("\"" + key + "\"");
        if (pos == std::string::npos) return false;
        
        pos = content.find(":", pos);
        if (pos == std::string::npos) return false;
        
        // Skip whitespace
        pos++;
        while (pos < content.length() && isspace(content[pos])) pos++;
        
        // Check for true/false
        if (content.substr(pos, 4) == "true") return true;
        return false;
    };
    
    auto findInt = [&content](const std::string& key) -> int {
        size_t pos = content.find("\"" + key + "\"");
        if (pos == std::string::npos) return 0;
        
        pos = content.find(":", pos);
        if (pos == std::string::npos) return 0;
        
        pos++;
        while (pos < content.length() && isspace(content[pos])) pos++;
        
        int value = 0;
        while (pos < content.length() && isdigit(content[pos])) {
            value = value * 10 + (content[pos] - '0');
            pos++;
        }
        return value;
    };
    
    auto findString = [&content](const std::string& key) -> std::string {
        size_t pos = content.find("\"" + key + "\"");
        if (pos == std::string::npos) return "";
        
        pos = content.find(":", pos);
        if (pos == std::string::npos) return "";
        
        pos = content.find("\"", pos);
        if (pos == std::string::npos) return "";
        
        pos++; // Skip opening quote
        size_t end = content.find("\"", pos);
        if (end == std::string::npos) return "";
        
        return content.substr(pos, end - pos);
    };
    
    outResult.passed = findBool("passed");
    outResult.gatesPassed = findInt("gates_passed");
    outResult.gatesFailed = findInt("gates_failed");
    outResult.gatesTotal = findInt("gates_total");
    outResult.validationHash = findString("hash");
    
    // Parse execution time if present
    std::string execTime = findString("execution_time_ms");
    if (!execTime.empty()) {
        outResult.executionTimeMs = std::stod(execTime);
    }
    
    return true;
}

} // namespace IDE
} // namespace RawrXD
