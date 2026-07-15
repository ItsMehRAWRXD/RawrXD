//=============================================================================
// RawrXD DAP Integration Bridge
// Connects DapService (DebugBackend wrapper) to Win32IDE's existing DAP server
//=============================================================================
#pragma once

#include "../debug/DapService.hpp"
#include "Win32IDE_DAPServer.h"
#include <windows.h>
#include <functional>

namespace RawrXD {
namespace Win32 {

//=============================================================================
// DAP Integration Bridge
// Bridges the production DapService with Win32IDE's UI and DAP server
//=============================================================================

class DAPIntegrationBridge {
public:
    DAPIntegrationBridge(Win32IDE* ide, Win32IDE_DAPServer* server);
    ~DAPIntegrationBridge();

    // Initialize the bridge - call once during IDE startup
    bool Initialize();
    
    // Shutdown - call during IDE shutdown
    void Shutdown();
    
    // Check if debugging is active
    bool IsDebugging() const;
    
    // Get current debug state
    Debug::DapState GetState() const;

    // Launch configuration for the current project
    struct LaunchConfig {
        std::wstring program;
        std::wstring workingDirectory;
        std::vector<std::wstring> args;
        bool stopOnEntry = false;
    };
    
    // Start debugging
    bool StartDebugging(const LaunchConfig& config);
    
    // Attach to running process
    bool AttachToProcess(DWORD processId);
    
    // Stop debugging
    void StopDebugging();
    
    // Execution control
    void Continue();
    void Pause();
    void StepInto();
    void StepOver();
    void StepOut();
    
    // Breakpoint management
    void ToggleBreakpoint(const std::wstring& file, int line);
    void ClearAllBreakpoints();
    
    // Stack trace access
    const std::vector<Debug::StackFrame>& GetStackTrace() const;
    void SelectFrame(int frameId);
    
    // Variable access
    void RequestVariables(int variablesReference);
    const std::vector<Debug::Variable>& GetVariables() const;

private:
    Win32IDE* m_ide;
    Win32IDE_DAPServer* m_server;
    Debug::DapService* m_service;
    
    // Callback handlers
    void OnStateChanged(Debug::DapState oldState, Debug::DapState newState);
    void OnStopped(const std::string& reason, uint32_t threadId, const std::string& description);
    void OnContinued(uint32_t threadId);
    void OnStackTraceReceived(const std::vector<Debug::StackFrame>& frames);
    void OnVariablesReceived(int reference, const std::vector<Debug::Variable>& vars);
    void OnOutput(Debug::OutputChannel channel, const std::string& data);
    void OnError(const std::string& error, bool fatal);
    
    // UI update helpers
    void UpdateCallStackPanel();
    void UpdateVariablesPanel();
    void UpdateDebugToolbar();
    void ShowCurrentLine();
    void ClearDebugUI();
};

//=============================================================================
// Global Access
//=============================================================================

DAPIntegrationBridge* GetDAPBridge();
void SetDAPBridge(DAPIntegrationBridge* bridge);

} // namespace Win32
} // namespace RawrXD
