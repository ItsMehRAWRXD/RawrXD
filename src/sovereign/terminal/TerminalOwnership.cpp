// ============================================================================
// TerminalOwnership.cpp - Persistent Terminal Sessions Implementation
// ============================================================================

#include "TerminalOwnership.hpp"
#include <cstring>
#include <iostream>
#include <thread>
#include <chrono>
#include <windows.h>

namespace Sovereign {

TerminalOwnership::TerminalOwnership() = default;
TerminalOwnership::~TerminalOwnership() {
    Shutdown();
}

bool TerminalOwnership::Initialize() { return true; }

void TerminalOwnership::Shutdown() {
    for (auto& [id, session] : sessions_) {
        if (session.processHandle) {
            TerminateProcess(session.processHandle, 0);
            CloseHandle(session.processHandle);
        }
    }
    sessions_.clear();
}

uint64_t TerminalOwnership::CreateSession(const std::string& agentId, const std::string& command, const std::string& cwd) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    uint64_t id = nextSessionId_++;
    TerminalSession session;
    session.id = id;
    session.agentId = agentId;
    session.command = command;
    session.cwd = cwd.empty() ? "." : cwd;
    session.state = TerminalState::CREATED;
    session.created = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    session.hasExited = false;
    
    // Create process
    SECURITY_ATTRIBUTES sa = {sizeof(sa), nullptr, TRUE};
    HANDLE stdinRead, stdinWrite, stdoutRead, stdoutWrite, stderrRead, stderrWrite;
    CreatePipe(&stdinRead, &stdinWrite, &sa, 0);
    CreatePipe(&stdoutRead, &stdoutWrite, &sa, 0);
    CreatePipe(&stderrRead, &stderrWrite, &sa, 0);
    
    session.stdinPipe = stdinWrite;
    session.stdoutPipe = stdoutRead;
    session.stderrPipe = stderrRead;
    
    STARTUPINFO si = {sizeof(si)};
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = stdinRead;
    si.hStdOutput = stdoutWrite;
    si.hStdError = stderrWrite;
    
    PROCESS_INFORMATION pi;
    std::string cmdLine = "cmd.exe /c " + command;
    
    if (CreateProcess(nullptr, &cmdLine[0], nullptr, nullptr, TRUE, 
                      CREATE_NO_WINDOW, nullptr, session.cwd.c_str(), &si, &pi)) {
        session.pid = pi.dwProcessId;
        session.processHandle = pi.hProcess;
        session.state = TerminalState::RUNNING;
        CloseHandle(pi.hThread);
        
        // Start output reader threads
        std::thread(&TerminalOwnership::ReadPipeThread, this, id, true).detach();
        std::thread(&TerminalOwnership::ReadPipeThread, this, id, false).detach();
    }
    
    sessions_[id] = session;
    stats_.totalSessions++;
    stats_.activeSessions++;
    
    return id;
}

bool TerminalOwnership::DestroySession(uint64_t sessionId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = sessions_.find(sessionId);
    if (it == sessions_.end()) return false;
    
    if (it->second.processHandle) {
        TerminateProcess(it->second.processHandle, 0);
        CloseHandle(it->second.processHandle);
    }
    
    sessions_.erase(it);
    stats_.activeSessions--;
    return true;
}

bool TerminalOwnership::WriteInput(uint64_t sessionId, const std::string& input) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = sessions_.find(sessionId);
    if (it == sessions_.end()) return false;
    
    DWORD written;
    std::string cmd = input + "\n";
    WriteFile(it->second.stdinPipe, cmd.c_str(), cmd.size(), &written, nullptr);
    stats_.totalBytesWritten += written;
    return true;
}

TerminalOutput TerminalOwnership::ReadOutput(uint64_t sessionId) {
    std::lock_guard<std::mutex> lock(mutex_);
    TerminalOutput output;
    auto it = sessions_.find(sessionId);
    if (it == sessions_.end()) return output;
    
    output.stdout_data = it->second.stdoutBuffer;
    output.stderr_data = it->second.stderrBuffer;
    output.state = it->second.state;
    output.exitCode = it->second.exitCode;
    
    return output;
}

void TerminalOwnership::ReadPipeThread(uint64_t sessionId, bool isStdout) {
    char buffer[4096];
    DWORD bytesRead;
    HANDLE pipe;
    
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = sessions_.find(sessionId);
        if (it == sessions_.end()) return;
        pipe = isStdout ? it->second.stdoutPipe : it->second.stderrPipe;
    }
    
    while (ReadFile(pipe, buffer, sizeof(buffer), &bytesRead, nullptr) && bytesRead > 0) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = sessions_.find(sessionId);
        if (it == sessions_.end()) break;
        
        std::string output(buffer, bytesRead);
        if (isStdout) {
            it->second.stdoutBuffer += output;
        } else {
            it->second.stderrBuffer += output;
        }
        stats_.totalBytesRead += bytesRead;
        
        if (outputCallback_) outputCallback_(sessionId, output);
    }
}

TerminalOwnership::TerminalStats TerminalOwnership::GetStats() const {
    return stats_;
}

bool TerminalOwnership::Terminate(uint64_t sessionId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = sessions_.find(sessionId);
    if (it == sessions_.end()) return false;
    
    if (it->second.processHandle) {
        TerminateProcess(it->second.processHandle, 1);
        it->second.state = TerminalState::TERMINATED;
        it->second.hasExited = true;
        it->second.exitCode = 1;
    }
    return true;
}

bool TerminalOwnership::WaitForExit(uint64_t sessionId, uint64_t timeoutMs) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = sessions_.find(sessionId);
    if (it == sessions_.end()) return false;
    
    if (it->second.hasExited) return true;
    
    // Non-blocking check - full implementation would wait
    DWORD exitCode;
    if (GetExitCodeProcess(it->second.processHandle, &exitCode)) {
        if (exitCode != STILL_ACTIVE) {
            it->second.exitCode = exitCode;
            it->second.hasExited = true;
            it->second.state = TerminalState::COMPLETED;
            return true;
        }
    }
    return false;
}

bool TerminalOwnership::SendSignal(uint64_t sessionId, uint32_t signal) {
    (void)signal;
    // Windows doesn't support POSIX signals, map to Terminate
    return Terminate(sessionId);
}

std::string TerminalOwnership::ReadStdout(uint64_t sessionId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = sessions_.find(sessionId);
    if (it == sessions_.end()) return "";
    return it->second.stdoutBuffer;
}

std::string TerminalOwnership::ReadStderr(uint64_t sessionId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = sessions_.find(sessionId);
    if (it == sessions_.end()) return "";
    return it->second.stderrBuffer;
}

std::vector<TerminalSession> TerminalOwnership::GetSessionsByAgent(const std::string& agentId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<TerminalSession> result;
    for (const auto& [id, session] : sessions_) {
        if (session.agentId == agentId) {
            result.push_back(session);
        }
    }
    return result;
}

TerminalSession TerminalOwnership::GetSession(uint64_t sessionId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = sessions_.find(sessionId);
    if (it != sessions_.end()) {
        return it->second;
    }
    return TerminalSession{};
}

size_t TerminalOwnership::GetActiveSessionCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t count = 0;
    for (const auto& [id, session] : sessions_) {
        if (!session.hasExited) {
            count++;
        }
    }
    return count;
}

void TerminalOwnership::SetOutputCallback(std::function<void(uint64_t, const std::string&)> callback) {
    outputCallback_ = callback;
}

void TerminalOwnership::SetExitCallback(std::function<void(uint64_t, uint64_t)> callback) {
    exitCallback_ = callback;
}

bool TerminalOwnership::IsSessionAlive(uint64_t sessionId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = sessions_.find(sessionId);
    if (it == sessions_.end()) return false;
    return !it->second.hasExited;
}

} // namespace Sovereign
