// ============================================================================
// TerminalOwnership.hpp - Persistent Terminal Sessions for Agents
// Process handles, stdout/stderr streams, exit codes, recovery
// ============================================================================

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>
#include <atomic>
#include <mutex>

namespace Sovereign {

// Terminal state
enum class TerminalState {
    CREATED,
    RUNNING,
    BLOCKED,
    COMPLETED,
    FAILED,
    TIMEOUT,
    TERMINATED
};

// Terminal output
struct TerminalOutput {
    std::string stdout_data;
    std::string stderr_data;
    uint64_t exitCode;
    TerminalState state;
    uint64_t durationMs;
    uint64_t peakMemory;
};

// Terminal session
struct TerminalSession {
    uint64_t id;
    std::string agentId;
    std::string command;
    std::string cwd;
    TerminalState state;
    uint64_t pid;
    void* processHandle;
    void* stdinPipe;
    void* stdoutPipe;
    void* stderrPipe;
    uint64_t created;
    uint64_t lastActivity;
    std::string stdoutBuffer;
    std::string stderrBuffer;
    bool hasExited;
    uint64_t exitCode;
};

// Terminal ownership manager
class TerminalOwnership {
public:
    static TerminalOwnership& Instance() {
        static TerminalOwnership instance;
        return instance;
    }
    
    TerminalOwnership();
    ~TerminalOwnership();

    bool Initialize();
    void Shutdown();

    uint64_t CreateSession(const std::string& agentId, const std::string& command, const std::string& cwd = "");
    bool DestroySession(uint64_t sessionId);
    bool IsSessionAlive(uint64_t sessionId) const;

    bool WriteInput(uint64_t sessionId, const std::string& input);
    TerminalOutput ReadOutput(uint64_t sessionId);
    std::string ReadStdout(uint64_t sessionId);
    std::string ReadStderr(uint64_t sessionId);

    bool WaitForExit(uint64_t sessionId, uint64_t timeoutMs = 30000);
    bool Terminate(uint64_t sessionId);
    bool SendSignal(uint64_t sessionId, uint32_t signal);

    std::vector<TerminalSession> GetSessionsByAgent(const std::string& agentId) const;
    TerminalSession GetSession(uint64_t sessionId) const;
    size_t GetActiveSessionCount() const;

    void SetOutputCallback(std::function<void(uint64_t, const std::string&)> callback);
    void SetExitCallback(std::function<void(uint64_t, uint64_t)> callback);

    struct TerminalStats {
        uint64_t totalSessions;
        uint64_t activeSessions;
        uint64_t completedSessions;
        uint64_t failedSessions;
        uint64_t totalBytesRead;
        uint64_t totalBytesWritten;
    };
    TerminalStats GetStats() const;

private:
    std::unordered_map<uint64_t, TerminalSession> sessions_;
    uint64_t nextSessionId_ = 1;
    TerminalStats stats_;
    mutable std::mutex mutex_;
    
    std::function<void(uint64_t, const std::string&)> outputCallback_;
    std::function<void(uint64_t, uint64_t)> exitCallback_;
    
    bool CreateProcessPipes(TerminalSession& session);
    void ReadPipeThread(uint64_t sessionId, bool isStdout);
};

} // namespace Sovereign
