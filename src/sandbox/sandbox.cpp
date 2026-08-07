// ============================================================================
// sandbox.cpp — Agent Sandbox for Safe Tool Execution
// Win32 native implementation using CreateProcess (no Qt dependency)
// ============================================================================
#include "sandbox.h"
#include <algorithm>
#include <sstream>
#include <cstring>
#include <filesystem>
#include <fstream>

#ifdef _WIN32
#include <windows.h>
#include <shellapi.h>
#else
#include <sys/wait.h>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <fcntl.h>
#endif

namespace fs = std::filesystem;

namespace RawrXD {
namespace Sandbox {

// ============================================================================
// Constructor / Destructor
// ============================================================================
Sandbox::Sandbox() = default;
Sandbox::~Sandbox() { Shutdown(); }

// ============================================================================
// Initialization
// ============================================================================
bool Sandbox::Initialize(const SandboxConfig& config) {
    m_config = config;

    // Set up default allow list if empty
    if (m_config.allowList.empty()) {
        m_config.allowList = {
            "cmake", "ninja", "make", "gcc", "g++", "clang", "clang++",
            "git", "python", "python3", "node", "npm", "cargo",
            "ctest", "dotnet", "msbuild", "ml64", "ml",
            "cat", "grep", "find", "ls", "dir", "echo",
            "diff", "patch", "head", "tail", "wc", "sort",
            "powershell", "pwsh", "cmd", "bash", "sh",
        };
    }

    // Set up default deny list
    if (m_config.denyList.empty()) {
        m_config.denyList = {
            "rm -rf /", "rm -rf /*", "format", "del /f /s",
            "shutdown", "reboot", "halt", "poweroff",
            "dd", "mkfs", "fdisk", "parted",
            "wget", "curl", "nc", "netcat", "nmap",
        };
    }

    m_initialized = true;
    return true;
}

void Sandbox::Shutdown() {
    m_initialized = false;
}

// ============================================================================
// Command Execution
// ============================================================================
ExecutionResult Sandbox::Execute(const std::string& command,
                                  const std::vector<std::string>& arguments,
                                  const std::string& workingDir) {
    ExecutionResult result;

    if (!m_initialized) {
        result.error = "Sandbox not initialized";
        return result;
    }

    // Check if command is allowed
    if (!IsCommandAllowed(command)) {
        m_deniedCount++;
        result.error = "Command not allowed: " + command;
        return result;
    }

    m_execCount++;

#ifdef _WIN32
    return ExecuteWindows(command, arguments, workingDir);
#else
    return ExecutePosix(command, arguments, workingDir);
#endif
}

// ============================================================================
// File Operations
// ============================================================================
bool Sandbox::ReadFile(const std::string& path, std::string& content) {
    if (!IsPathAllowed(path)) return false;
    try {
        std::ifstream file(path, std::ios::binary);
        if (!file.is_open()) return false;
        std::stringstream ss;
        ss << file.rdbuf();
        content = ss.str();
        return true;
    } catch (...) { return false; }
}

bool Sandbox::WriteFile(const std::string& path, const std::string& content) {
    if (!IsPathAllowed(path)) return false;
    try {
        fs::create_directories(fs::path(path).parent_path());
        std::ofstream file(path, std::ios::binary);
        if (!file.is_open()) return false;
        file.write(content.data(), content.size());
        return true;
    } catch (...) { return false; }
}

bool Sandbox::DeleteFile(const std::string& path) {
    if (!IsPathAllowed(path)) return false;
    try { return fs::remove(path); } catch (...) { return false; }
}

bool Sandbox::CreateDirectory(const std::string& path) {
    if (!IsPathAllowed(path)) return false;
    try { return fs::create_directories(path); } catch (...) { return false; }
}

// ============================================================================
// Validation
// ============================================================================
bool Sandbox::IsCommandAllowed(const std::string& command) const {
    std::string cmd = command;
    size_t spacePos = cmd.find(' ');
    if (spacePos != std::string::npos) cmd = cmd.substr(0, spacePos);
    size_t sepPos = cmd.find_last_of("/\\");
    if (sepPos != std::string::npos) cmd = cmd.substr(sepPos + 1);

    for (const auto& denied : m_config.denyList) {
        if (cmd == denied || command.find(denied) != std::string::npos) return false;
    }
    for (const auto& allowed : m_config.allowList) {
        if (cmd == allowed) return true;
    }
    return false;
}

bool Sandbox::IsPathAllowed(const std::string& path) const {
    if (m_config.allowedPaths.empty()) return true;
    std::string resolved = SanitizePath(path);
    for (const auto& denied : m_config.deniedPaths) {
        if (resolved.find(denied) != std::string::npos) return false;
    }
    for (const auto& allowed : m_config.allowedPaths) {
        if (resolved.find(allowed) == 0) return true;
    }
    return m_config.allowedPaths.empty();
}

std::string Sandbox::SanitizePath(const std::string& path) const {
    try {
        fs::path p(path);
        if (p.is_relative()) p = fs::absolute(p);
        return p.lexically_normal().string();
    } catch (...) { return path; }
}

// ============================================================================
// Windows Execution (CreateProcess, no Qt)
// ============================================================================
ExecutionResult Sandbox::ExecuteWindows(const std::string& command,
                                         const std::vector<std::string>& arguments,
                                         const std::string& workingDir) {
    ExecutionResult result;

    // Build command line
    std::string cmdLine = command;
    for (const auto& arg : arguments) {
        cmdLine += " \"" + arg + "\"";
    }

    // Set up pipes for stdout/stderr
    SECURITY_ATTRIBUTES saAttr;
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    HANDLE hStdoutRead, hStdoutWrite;
    HANDLE hStderrRead, hStderrWrite;

    if (!CreatePipe(&hStdoutRead, &hStdoutWrite, &saAttr, 0)) {
        result.error = "Failed to create stdout pipe";
        return result;
    }
    if (!CreatePipe(&hStderrRead, &hStderrWrite, &saAttr, 0)) {
        CloseHandle(hStdoutRead); CloseHandle(hStdoutWrite);
        result.error = "Failed to create stderr pipe";
        return result;
    }

    SetHandleInformation(hStdoutRead, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(hStderrRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si = {0};
    si.cb = sizeof(STARTUPINFOA);
    si.hStdError = hStderrWrite;
    si.hStdOutput = hStdoutWrite;
    si.dwFlags |= STARTF_USESTDHANDLES;

    PROCESS_INFORMATION pi = {0};
    std::string workDir = workingDir.empty() ? "." : workingDir;
    std::string cmdLineCopy = cmdLine;

    auto t0 = std::chrono::high_resolution_clock::now();

    BOOL success = CreateProcessA(NULL, &cmdLineCopy[0], NULL, NULL, TRUE,
                                  CREATE_NO_WINDOW, NULL, workDir.c_str(), &si, &pi);

    CloseHandle(hStdoutWrite);
    CloseHandle(hStderrWrite);

    if (!success) {
        CloseHandle(hStdoutRead); CloseHandle(hStderrRead);
        result.error = "CreateProcess failed: " + std::to_string(GetLastError());
        return result;
    }

    DWORD waitResult = WaitForSingleObject(pi.hProcess, m_config.timeoutMs);
    auto t1 = std::chrono::high_resolution_clock::now();
    result.durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

    if (waitResult == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, 1);
        result.error = "Command timed out after " + std::to_string(m_config.timeoutMs) + "ms";
    } else {
        DWORD exitCode = 0;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        result.exitCode = exitCode;
        result.success = (exitCode == 0);
    }

    char buf[4096];
    DWORD bytesRead;
    while (ReadFile(hStdoutRead, buf, sizeof(buf) - 1, &bytesRead, NULL) && bytesRead > 0) {
        buf[bytesRead] = '\0';
        result.stdout_output += buf;
    }
    while (ReadFile(hStderrRead, buf, sizeof(buf) - 1, &bytesRead, NULL) && bytesRead > 0) {
        buf[bytesRead] = '\0';
        result.stderr_output += buf;
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hStdoutRead);
    CloseHandle(hStderrRead);

    return result;
}

// ============================================================================
// POSIX Execution
// ============================================================================
ExecutionResult Sandbox::ExecutePosix(const std::string& command,
                                       const std::vector<std::string>& arguments,
                                       const std::string& workingDir) {
    ExecutionResult result;
    std::vector<char*> argv;
    std::string cmdCopy = command;
    argv.push_back(&cmdCopy[0]);
    for (const auto& arg : arguments) argv.push_back(const_cast<char*>(arg.c_str()));
    argv.push_back(nullptr);

    int stdoutPipe[2], stderrPipe[2];
    if (pipe(stdoutPipe) < 0 || pipe(stderrPipe) < 0) {
        result.error = "Failed to create pipes"; return result;
    }

    pid_t pid = fork();
    if (pid < 0) { result.error = "Fork failed"; return result; }

    if (pid == 0) {
        close(stdoutPipe[0]); close(stderrPipe[0]);
        dup2(stdoutPipe[1], STDOUT_FILENO); dup2(stderrPipe[1], STDERR_FILENO);
        close(stdoutPipe[1]); close(stderrPipe[1]);
        if (!workingDir.empty()) chdir(workingDir.c_str());
        execvp(command.c_str(), argv.data());
        _exit(1);
    }

    close(stdoutPipe[1]); close(stderrPipe[1]);
    auto t0 = std::chrono::high_resolution_clock::now();

    char buf[4096]; ssize_t bytesRead;
    while ((bytesRead = read(stdoutPipe[0], buf, sizeof(buf) - 1)) > 0) {
        buf[bytesRead] = '\0'; result.stdout_output += buf;
    }
    while ((bytesRead = read(stderrPipe[0], buf, sizeof(buf) - 1)) > 0) {
        buf[bytesRead] = '\0'; result.stderr_output += buf;
    }

    int status;
    waitpid(pid, &status, 0);
    auto t1 = std::chrono::high_resolution_clock::now();
    result.durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
    result.exitCode = WEXITSTATUS(status);
    result.success = (result.exitCode == 0);
    close(stdoutPipe[0]); close(stderrPipe[0]);
    return result;
}

} // namespace Sandbox
} // namespace RawrXD

