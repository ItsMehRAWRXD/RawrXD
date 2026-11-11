#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WINSOCKAPI_
#define _WINSOCKAPI_
#endif
#include <winsock2.h>
#include <windows.h>

#ifdef ERROR
#undef ERROR
#endif

#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <thread>
#include <atomic>
#include "../native_agent.hpp"
#include "../cpu_inference_engine.h"
#include "../agentic/BackendRouter.h"
#include "../agentic/ToolCallBridge.h"
#include "Win32IDE_AgentExecutionFSM.h"
#include "Win32IDE_AgenticLoopBridge.h"

class Win32IDE;

enum class AgentResponseType {
    TOOL_CALL,
    ANSWER,
    AGENT_ERROR,
    THINKING
};

struct AgentResponse {
    AgentResponseType type;
    std::string content;
    std::string toolName;
    std::string toolArgs;
    std::string rawOutput;
};

// Model turns → BackendRouter; tools → ToolCallBridge SSOT (SecurityGate).
class AgenticBridge {
public:
    AgenticBridge(Win32IDE* ide);
    ~AgenticBridge();

    bool Initialize(const std::string& frameworkPath, const std::string& modelName = "");
    bool IsInitialized() const { return m_initialized; }

    AgentResponse ExecuteAgentCommand(const std::string& prompt);
    bool StartAgentLoop(const std::string& initialPrompt, int maxIterations = 10);
    void StopAgentLoop();
    bool IsAgentLoopRunning() const;

    // Unified runtime owner: AgenticLoopBridge is the sole process transport.
    void EnsureLoopTransport();
    AgenticLoopBridge* LoopTransport();
    const AgenticLoopBridge* LoopTransport() const;
    bool StartAutonomousTask(
        const AgenticLoopBridge::TaskConfig& config,
        AgenticLoopBridge::ProgressCallback progress,
        AgenticLoopBridge::ToolCallback toolCb,
        AgenticLoopBridge::CompleteCallback completeCb);
    void CancelAutonomousTask();
    bool IsAutonomousRunning() const;

    std::vector<std::string> GetAvailableTools();
    std::string GetAgentStatus();

    void SetModel(const std::string& modelName);
    void SetOllamaServer(const std::string& serverUrl);
    std::string GetCurrentModel() const { return m_modelName; }
    RawrXD::Agent::BackendRouter* GetBackendRouter() { return m_router.get(); }

    using OutputCallback = std::function<void(const std::string&, const std::string&)>;
    void SetOutputCallback(OutputCallback callback);

    // Shared execution FSM (SSOT) — UI timeline observes, does not own.
    RawrXD::AgentExecutionFSM& ExecutionFSM() { return RawrXD::ProductAgentFSM(); }

private:
    std::unique_ptr<RawrXD::CPUInferenceEngine> m_nativeEngine; // /load only
    std::unique_ptr<RawrXD::NativeAgent> m_nativeAgent;         // slash meta only
    std::unique_ptr<RawrXD::Agent::BackendRouter> m_router;      // gap 9 model path
    std::unique_ptr<AgenticLoopBridge> m_loopTransport;

    bool SpawnPowerShellProcess(const std::string& scriptPath, const std::string& arguments);
    bool ReadProcessOutput(std::string& output, DWORD timeoutMs = 5000);
    void KillPowerShellProcess();

    AgentResponse ParseAgentResponse(const std::string& rawOutput);
    bool IsToolCall(const std::string& line);
    bool IsAnswer(const std::string& line);
    AgentResponse ChatViaBackendRouter(const std::string& prompt);
    AgentResponse DispatchToolLine(const std::string& line);

    std::string ResolveFrameworkPath();
    std::string ResolveToolsModulePath();

    Win32IDE* m_ide;
    bool m_initialized;
    std::atomic<bool> m_agentLoopRunning{false};

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
    std::thread m_agentThread;
};
