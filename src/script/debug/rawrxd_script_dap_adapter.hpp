// ============================================================================
// rawrxd_script_dap_adapter.hpp — RawrXD-Script Debug Adapter
// ============================================================================
// DAP (Debug Adapter Protocol) implementation for RawrXD-Script JavaScript VM
// Hooks into the MASM interpreter for step debugging
//
// Copyright (c) 2026 RawrXD Project — All rights reserved.
// ============================================================================

#pragma once

#include "debugger/DAPAdapter.h"
#include "script/masm/interpreter.hpp"
#include "script/trace_collector_masm.hpp"

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>
#include <mutex>

namespace RawrXD {
namespace Script {
namespace Debug {

// ============================================================================
// RawrXD-Script Debug State
// ============================================================================

enum class VMDebugState {
    Running,
    Paused,
    Stepping,
    Breakpoint,
    Exception,
    Exited
};

struct ScriptBreakpoint {
    uint32_t id;
    std::string file;
    uint32_t line;
    uint64_t bytecodeOffset;
    bool verified;
};

struct ScriptStackFrame {
    uint32_t id;
    std::string name;
    std::string file;
    uint32_t line;
    uint32_t column;
    uint64_t bytecodeOffset;
    std::vector<std::pair<std::string, std::string>> variables;  // name -> value
};

// ============================================================================
// RawrXD-Script DAP Adapter
// ============================================================================

class RawrXDScriptDAPAdapter {
public:
    using EventCallback = std::function<void(const std::string& eventType, 
                                                const nlohmann::json& eventBody)>;

    RawrXDScriptDAPAdapter();
    ~RawrXDScriptDAPAdapter();

    // Initialize with interpreter instance
    bool Initialize(Script::Interpreter* interpreter);
    void Shutdown();

    // DAP Request Handlers
    nlohmann::json OnInitialize(const nlohmann::json& request);
    nlohmann::json OnLaunch(const nlohmann::json& request);
    nlohmann::json OnAttach(const nlohmann::json& request);
    nlohmann::json OnDisconnect(const nlohmann::json& request);
    nlohmann::json OnSetBreakpoints(const nlohmann::json& request);
    nlohmann::json OnContinue(const nlohmann::json& request);
    nlohmann::json OnNext(const nlohmann::json& request);
    nlohmann::json OnStepIn(const nlohmann::json& request);
    nlohmann::json OnStepOut(const nlohmann::json& request);
    nlohmann::json OnPause(const nlohmann::json& request);
    nlohmann::json OnStackTrace(const nlohmann::json& request);
    nlohmann::json OnScopes(const nlohmann::json& request);
    nlohmann::json OnVariables(const nlohmann::json& request);
    nlohmann::json OnEvaluate(const nlohmann::json& request);

    // VM Event Handlers (called by interpreter)
    void OnVMBreakpointHit(uint64_t bytecodeOffset);
    void OnVMStepComplete(uint64_t bytecodeOffset);
    void OnVMException(const std::string& message);
    void OnVMOutput(const std::string& message);
    void OnVMExited(int exitCode);

    // State queries
    VMDebugState GetState() const { return m_state; }
    bool IsDebugging() const { return m_state != VMDebugState::Exited; }
    
    // Set event callback for sending DAP events
    void SetEventCallback(EventCallback callback) { m_eventCallback = callback; }

    // Register with DAP server
    void RegisterWithDAPServer(::RawrXD::DAP::DAPAdapter* server);

private:
    Script::Interpreter* m_interpreter = nullptr;
    VMDebugState m_state = VMDebugState::Exited;
    EventCallback m_eventCallback;
    
    // Breakpoint management
    std::vector<ScriptBreakpoint> m_breakpoints;
    std::mutex m_breakpointsMutex;
    uint32_t m_nextBreakpointId = 1;
    
    // Stack trace cache
    std::vector<ScriptStackFrame> m_stackFrames;
    std::mutex m_stackMutex;
    
    // Source mapping
    std::unordered_map<std::string, std::vector<uint64_t>> m_sourceLineToOffset;
    std::unordered_map<uint64_t, std::pair<std::string, uint32_t>> m_offsetToSourceLine;
    
    // Configuration
    struct {
        std::string program;
        std::string args;
        std::string cwd;
        bool stopOnEntry = true;
    } m_config;

    // Helper methods
    void SendEvent(const std::string& eventType, const nlohmann::json& body);
    uint64_t SourceLineToBytecodeOffset(const std::string& file, uint32_t line);
    std::pair<std::string, uint32_t> BytecodeOffsetToSourceLine(uint64_t offset);
    std::vector<ScriptStackFrame> BuildStackFrames();
    void UpdateStackFrames();
    
    // Variable formatting
    std::string FormatValue(uint64_t nanBoxedValue);
    std::string FormatRegister(const std::string& name, uint64_t value);
};

// ============================================================================
// Global Access
// ============================================================================

RawrXDScriptDAPAdapter* GetRawrXDScriptDAPAdapter();
bool InitializeRawrXDScriptDebugging(Script::Interpreter* interpreter);
void ShutdownRawrXDScriptDebugging();

} // namespace Debug
} // namespace Script
} // namespace RawrXD
