#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <atomic>
#include <thread>
#include <mutex>
#include <functional>
#include <queue>
#include <unordered_set>
#include <condition_variable>
#include "IDELogger.h"
#include "agent_esp.hpp"
#include "rawrxd_snap_detectors.hpp"
#include "deep2_progress_watchdog.hpp"

// Forward declaration
class Win32IDE;

// Agentic Loop Bridge - connects IDE to deep2_agentic_loop.exe
class AgenticLoopBridge {
public:
    struct ToolResult {
        bool success;
        std::string output;
        int exitCode;
        std::string toolName;
        std::string target;
    };

    struct TaskConfig {
        // "local" invokes the native GGUF path; "ollama" passes the model
        // identifier to the local Ollama HTTP-backed agent runtime. Keep this
        // explicit so the bridge cannot reinterpret a model ID as a file path.
        std::string provider = "local";
        std::string modelPath;
        std::string workDir;
        std::string targetFile;
        std::string task;
        int maxSteps = 8;
        int maxNewTokens = 512;
        int maxRetries = 2;
        int maxWallTimeSec = 300;
        int maxTotalTokens = 8192;
        bool quiet = true;
        // When true, use the canonical RawrXD CLI one-shot agent.  This is
        // the same backend exercised by `rawr run`, so GUI chat does not
        // silently use a second, divergent agent implementation.
        bool useCliAgent = false;
        bool approveMutations = false;
        bool readOnly = true;
    };

    using ProgressCallback = std::function<void(const std::string& message)>;
    using ToolCallback = std::function<void(const ToolResult&)>;
    using CompleteCallback = std::function<void(bool success, const std::string& summary)>;

    AgenticLoopBridge(Win32IDE* ide);
    ~AgenticLoopBridge();

    // Start an autonomous repair task with startup recovery
    bool StartTask(const TaskConfig& config, ProgressCallback progress, ToolCallback toolCb, CompleteCallback completeCb);
    
    // Cancel running task
    void Cancel();
    
    // Check if task is running
    bool IsRunning() const { return m_running.load(); }
    
    // Get current status
    std::string GetStatus() const;

    // ESP telemetry
    void SetESPBus(rawrxd::esp::Bus* bus, uint64_t requestId = 0);

private:
    // Startup recovery
    void StartupRecovery();
    bool IsAbandonedProcess(const rawrxd::snap::Process& proc);
    
    // Event handlers
    void HandleSnapEvent(const rawrxd::snap::Event& event);
    void HandleWatchdogTimeout(const rawrxd::watchdog::Status& status);
    
    // Worker thread
    void WorkerThread();
    void CompleteTask(bool success, const std::string& summary, DWORD exitCode = 1);
    
    // Process management
    bool LaunchAgenticLoop();
    void TerminateProcessTree(DWORD pid);
    void ReadProcessOutput();
    
    // ESP event publishing
    void PublishESPEvent(rawrxd::esp::Kind kind, const std::string& message, int value = 0);
    
    // Parse agentic loop output for tool calls
    void ParseOutput(const std::string& line);

    Win32IDE* m_ide = nullptr;
    
    std::atomic<bool> m_running{false};
    std::atomic<bool> m_cancelRequested{false};
    std::atomic<bool> m_processStarted{false};
    std::atomic<bool> m_completionSent{false};
    
    HANDLE m_process = nullptr;
    HANDLE m_stdoutRead = nullptr;
    HANDLE m_stdoutWrite = nullptr;
    HANDLE m_stdinRead = nullptr;
    HANDLE m_stdinWrite = nullptr;
    DWORD m_processId = 0;
    
    std::thread m_workerThread;
    std::thread m_outputThread;
    std::mutex m_callbackMutex;
    
    ProgressCallback m_progressCallback;
    ToolCallback m_toolCallback;
    CompleteCallback m_completeCallback;
    
    TaskConfig m_currentConfig;
    std::string m_accumulatedOutput;
    std::queue<std::string> m_outputQueue;
    std::mutex m_queueMutex;
    std::condition_variable m_queueCv;
    
    // ESP Telemetry
    rawrxd::esp::Bus* m_espBus = nullptr;
    uint64_t m_espRequestId = 0;
    // Child CLI events are forwarded once per child request/sequence pair.
    // The child JSONL remains the authoritative raw record.
    std::unordered_set<std::string> m_forwardedChildEvents;
    
    // SNAP Detector for process monitoring
    rawrxd::snap::Detector m_snapDetector;
    std::atomic<bool> m_snapStarted{false};
    
    // Progress Watchdog
    rawrxd::watchdog::Watchdog m_watchdog;
};
