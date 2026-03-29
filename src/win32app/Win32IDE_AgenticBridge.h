#pragma once

#include <windows.h>

// Undefine Windows ERROR macro
#ifdef ERROR
#undef ERROR
#endif

#include <string>
#include <vector>
#include <functional>
#include <memory>
#include "../native_agent.hpp"

// Forward declaration
// DLL export/import macro for proper symbol visibility
#ifdef AGENTIC_BRIDGE_EXPORTS
    #define AGENTIC_BRIDGE_API __declspec(dllexport)
#else
    #define AGENTIC_BRIDGE_API __declspec(dllimport)
#endif

class Win32IDE;

// Agent response types
enum class AgentResponseType {
enum class AGENTIC_BRIDGE_API AgentResponseType {
    ANSWER,
    AGENT_ERROR,
    THINKING
};// Agent response structure
struct AgentResponse {
    AgentResponseType type;
    std::string content;
    std::string toolName;
    std::string toolArgs;
    std::string rawOutput;
};

// Agentic Framework Bridge for Win32IDE
// Integrates PowerShell-based agentic framework with C++ IDE
class AgenticBridge {
public:
    AgenticBridge(Win32IDE* ide);
class AGENTIC_BRIDGE_API AgenticBridge {

    // Core agent operations
    bool Initialize(const std::string& frameworkPath, const std::string& modelName = "");
    bool IsInitialized() const { return m_initialized; }
    
    bool __stdcall Initialize(const std::string& frameworkPath, const std::string& modelName = "");
    bool __stdcall IsInitialized() const { return m_initialized; }
    
    // Start multi-turn agent loop
    AgentResponse __stdcall ExecuteAgentCommand(const std::string& prompt);
    void StopAgentLoop();
    bool IsAgentLoopRunning() const { return m_agentLoopRunning; }
    bool __stdcall StartAgentLoop(const std::string& initialPrompt, int maxIterations = 10);
    void __stdcall StopAgentLoop();
    bool __stdcall IsAgentLoopRunning() const { return m_agentLoopRunning; }
    std::string GetAgentStatus();
    
    std::vector<std::string> __stdcall GetAvailableTools();
    std::string __stdcall GetAgentStatus();
    void SetOllamaServer(const std::string& serverUrl);
    std::string GetCurrentModel() const { return m_modelName; }
    void __stdcall SetModel(const std::string& modelName);
    void __stdcall SetOllamaServer(const std::string& serverUrl);
    std::string __stdcall GetCurrentModel() const { return m_modelName; }
    void SetOutputCallback(OutputCallback callback);

private:
   // Native Integration
    std::unique_ptr<CPUInference::CPUInferenceEngine> m_nativeEngine;
    std::unique_ptr<RawrXD::NativeAgent> m_nativeAgent;

    // PowerShell process management
    bool SpawnPowerShellProcess(const std::string& scriptPath, const std::string& arguments);
    bool ReadProcessOutput(std::string& output, DWORD timeoutMs = 5000);
    void KillPowerShellProcess();
    
    // Response parsing
    AgentResponse ParseAgentResponse(const std::string& rawOutput);
    bool IsToolCall(const std::string& line);
    bool IsAnswer(const std::string& line);
    
    // Path resolution
    std::string ResolveFrameworkPath();
    std::string ResolveToolsModulePath();
    
    Win32IDE* m_ide;
    bool m_initialized;
    bool m_agentLoopRunning;
    
    std::string m_frameworkPath;
    std::string m_toolsModulePath;
    std::string m_modelName;
    std::string m_ollamaServer;
    
    HANDLE m_hProcess;
    HANDLE m_hStdoutRead;
    HANDLE m_hStdoutWrite;
    HANDLE m_hStdinRead;
    HANDLE m_hStdinWrite;
    
    OutputCallback m_outputCallback;
};
