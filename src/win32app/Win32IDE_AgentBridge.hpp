// ============================================================================
// Win32IDE_AgentBridge.hpp — AI Telemetry & Control Bridge
// ============================================================================
// Provides bi-directional communication between RawrXD IDE and external AI
// agents via file-based telemetry and command interfaces.
//
// Architecture: Non-blocking I/O, thread-safe, JSON-based protocol
//
// Phase 22: AI Control Bridge
// Copyright (c) 2024-2026 RawrXD IDE Project
// ============================================================================

#pragma once

#ifndef RAWRXD_WIN32IDE_AGENT_BRIDGE_HPP
#define RAWRXD_WIN32IDE_AGENT_BRIDGE_HPP

#include <windows.h>
#include <string>
#include <atomic>
#include <thread>
#include <functional>
#include <map>
#include <vector>
#include <mutex>

namespace RawrXD::AgentBridge {

// ============================================================================
// TELEMETRY DATA — Current IDE state snapshot
// ============================================================================

struct TelemetryData {
    // System metrics
    uint64_t timestamp = 0;
    uint32_t processId = 0;
    uint32_t threadId = 0;
    
    // Memory metrics
    size_t workingSetBytes = 0;
    size_t virtualMemoryBytes = 0;
    size_t peakWorkingSetBytes = 0;
    
    // GDI metrics
    uint32_t gdiObjects = 0;
    uint32_t userObjects = 0;
    uint32_t gdiObjectsPeak = 0;
    
    // Window metrics
    int windowWidth = 0;
    int windowHeight = 0;
    bool isMinimized = false;
    bool isForeground = false;
    
    // Editor metrics
    int editorWidth = 0;
    int editorHeight = 0;
    int cursorLine = 0;
    int cursorColumn = 0;
    int totalLines = 0;
    int selectionStart = 0;
    int selectionEnd = 0;
    std::string currentFile;
    std::string currentLanguage;
    
    // LSP metrics
    bool lspConnected = false;
    std::string lspServerName;
    int lspPendingRequests = 0;
    int lspDiagnosticsCount = 0;
    
    // Performance metrics
    double lastFrameTimeMs = 0.0;
    double avgFrameTimeMs = 0.0;
    uint32_t messagesProcessed = 0;
    uint32_t messagesPerSecond = 0;
    
    // Agent metrics
    bool agentRunning = false;
    int agentQueueSize = 0;
    std::string lastAgentAction;
    
    // Error state
    std::string lastError;
    uint32_t errorCount = 0;
    
    std::string toJson() const;
};

// ============================================================================
// AGENT COMMAND — Instructions from external AI
// ============================================================================

enum class AgentCommandType {
    Unknown,
    Ping,           // Health check
    Screenshot,     // Request visual state (if available)
    GetState,       // Request full telemetry dump
    SetFocus,       // Focus window
    Resize,         // Resize window
    Move,           // Move window
    OpenFile,       // Open a file
    CloseFile,      // Close current file
    SaveFile,       // Save current file
    GotoLine,       // Navigate to line
    FindText,       // Find in file
    ReplaceText,    // Replace in file
    ExecuteCommand, // Execute IDE command by ID
    RunBuild,       // Trigger build
    RunDebug,       // Start debugging
    StopDebug,      // Stop debugging
    SetBreakpoint,  // Set breakpoint at line
    ClearBreakpoint,// Clear breakpoint
    RequestHover,   // Request hover at position
    RequestCompletion, // Request completion at position
    AgentPrompt,    // Send prompt to agent
    SetConfig,      // Set configuration value
    GetConfig,      // Get configuration value
    DumpLayout,     // Dump layout tree
    ResetLsp,       // Reset LSP connection
    Shutdown        // Graceful shutdown
};

struct AgentCommand {
    uint64_t timestamp = 0;
    uint32_t commandId = 0;
    AgentCommandType type = AgentCommandType::Unknown;
    std::map<std::string, std::string> parameters;
    std::string rawJson;
    
    static AgentCommand fromJson(const std::string& json);
    std::string toJson() const;
};

struct AgentResponse {
    uint32_t commandId = 0;
    bool success = false;
    std::string message;
    std::map<std::string, std::string> data;
    
    std::string toJson() const;
};

// ============================================================================
// AGENT BRIDGE — Main interface
// ============================================================================

class AgentBridge {
public:
    struct Config {
        std::string telemetryPath = "rawrxd_telemetry.json";
        std::string commandInputPath = "ai_control.json";
        std::string responseOutputPath = "ai_response.json";
        std::string logPath = "rawrxd_agent.log";
        uint32_t telemetryIntervalMs = 500;
        uint32_t commandPollIntervalMs = 100;
        bool enabled = true;
        bool verboseLogging = false;
    };
    
    using CommandHandler = std::function<AgentResponse(const AgentCommand&)>;
    
    AgentBridge();
    ~AgentBridge();
    
    // Lifecycle
    bool initialize(const Config& config);
    void shutdown();
    bool isRunning() const { return m_running; }
    
    // Configuration
    void setConfig(const Config& config);
    Config getConfig() const;
    
    // Telemetry
    void updateTelemetry(const TelemetryData& data);
    void updateTelemetryField(const std::string& field, const std::string& value);
    TelemetryData getCurrentTelemetry() const;
    
    // Command handling
    void registerCommandHandler(AgentCommandType type, CommandHandler handler);
    void registerDefaultHandlers(class Win32IDE* ide);
    
    // Manual operations
    void forceTelemetryDump();
    void sendResponse(const AgentResponse& response);
    void log(const std::string& message, bool isError = false);
    
    // Headless mode
    static bool isHeadlessMode();
    static void setHeadlessMode(bool headless);
    
private:
    Config m_config;
    std::atomic<bool> m_running{false};
    static std::atomic<bool> s_headless;
    
    // Threads
    std::thread m_telemetryThread;
    std::thread m_commandThread;
    
    // State
    mutable std::mutex m_telemetryMutex;
    TelemetryData m_currentTelemetry;
    std::vector<TelemetryData> m_telemetryHistory;
    
    mutable std::mutex m_handlersMutex;
    std::map<AgentCommandType, CommandHandler> m_commandHandlers;
    
    // File monitoring
    HANDLE m_commandFileHandle = INVALID_HANDLE_VALUE;
    FILETIME m_lastCommandFileTime{};
    uint32_t m_nextCommandId = 1;
    
    // Internal methods
    void telemetryLoop();
    void commandLoop();
    void writeTelemetryToFile();
    void pollCommandFile();
    void processCommand(const AgentCommand& cmd);
    void writeResponse(const AgentResponse& response);
    void writeLog(const std::string& message, bool isError);
    
    // System metrics
    void collectSystemMetrics(TelemetryData& data);
    void collectMemoryMetrics(TelemetryData& data);
    void collectGdiMetrics(TelemetryData& data);
};

// ============================================================================
// GLOBAL ACCESS
// ============================================================================

AgentBridge* getAgentBridge();
bool initializeAgentBridge(const AgentBridge::Config& config);
void shutdownAgentBridge();

} // namespace RawrXD::AgentBridge

#endif // RAWRXD_WIN32IDE_AGENT_BRIDGE_HPP
