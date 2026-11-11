/*===========================================================================
 * IDEDebuggerAdapter.h
 * Thin adapter between Win32 IDE and RawrXD Debugger Backend
 * 
 * NO DUPLICATE DEBUGGER LOGIC - Just routes IDE commands to DebuggerManager
 *===========================================================================*/

#pragma once

#include "../debugger/Debugger_Backend.h"
#include "IDEDebuggerTypes.h"
#include <memory>
#include <functional>

// Forward declaration
struct RawrXD_IDE;

namespace RawrXD {
namespace IDE {

/*===========================================================================
 * Debugger Event Callbacks
 * Called by debugger backend to notify IDE of state changes
 *=========================================================================*/
struct DebuggerCallbacks {
    // Execution events
    std::function<void(uint64_t address)> OnBreakpointHit;
    std::function<void()> OnStepComplete;
    std::function<void(int exitCode)> OnProcessExit;
    std::function<void(const std::wstring& message)> OnException;
    
    // State change events
    std::function<void()> OnStackChanged;
    std::function<void(uint32_t tid)> OnThreadChanged;
    std::function<void(bool started)> OnDebugSessionChanged;
    
    // Full state update (for triple-buffered UI)
    std::function<void(DebugStatePayload* payload)> OnStateChanged;
};

/*===========================================================================
 * IDE Debugger Adapter
 * Bridges Win32 IDE UI to the real debugger backend
 *=========================================================================*/
class IDEDebuggerAdapter {
public:
    IDEDebuggerAdapter();
    ~IDEDebuggerAdapter();

    // Initialize with IDE instance
    bool Initialize(RawrXD_IDE* ide);
    void Shutdown();

    // Set callbacks for IDE notifications
    void SetCallbacks(const DebuggerCallbacks& callbacks);

    // Session Control
    bool StartDebugging(const std::wstring& executable);
    bool AttachToProcess(uint32_t pid);
    bool StopDebugging();
    bool RestartDebugging();
    bool IsDebugging() const;

    // Execution Control
    bool Continue();
    bool StepOver();
    bool StepInto();
    bool StepOut();
    bool Break();

    // Breakpoints
    bool ToggleBreakpoint(const std::wstring& filePath, uint32_t lineNumber);
    bool RemoveBreakpoint(uint64_t breakpointId);
    void ClearAllBreakpoints();

    // Stack & Variables
    std::vector<Debugger::StackFrame> GetCallStack();
    std::vector<Debugger::RegisterValue> GetRegisters();
    std::vector<Debugger::LocalVariable> GetLocalVariables(uint32_t frameNumber = 0);

    // Error Navigation
    void NavigateToNextError();
    void NavigateToPreviousError();
    void ClearErrorList();

    // Event Callbacks (called by debugger backend)
    void OnBreakpointHit(const Debugger::Breakpoint& bp);
    void OnStepComplete();
    void OnProcessExit(int exitCode);
    void OnException(const std::wstring& exception);

private:
    RawrXD_IDE* ide_ = nullptr;
    std::unique_ptr<Debugger::DebugSession> debugSession_;
    bool isDebugging_ = false;
    DebuggerCallbacks callbacks_;
    
    // Error navigation state
    std::vector<Debugger::StackFrame> currentStack_;
    size_t currentFrameIndex_ = 0;
};

} // namespace IDE
} // namespace RawrXD

// C-compatible exports for Win32 IDE
extern "C" {
    void* IDEDebugger_Create();
    void IDEDebugger_Destroy(void* adapter);
    
    int IDEDebugger_Start(void* adapter, const wchar_t* executable);
    int IDEDebugger_Attach(void* adapter, uint32_t pid);
    int IDEDebugger_Stop(void* adapter);
    int IDEDebugger_Restart(void* adapter);
    
    int IDEDebugger_Continue(void* adapter);
    int IDEDebugger_StepOver(void* adapter);
    int IDEDebugger_StepInto(void* adapter);
    int IDEDebugger_StepOut(void* adapter);
    
    int IDEDebugger_ToggleBreakpoint(void* adapter, const wchar_t* filePath, uint32_t line);
    int IDEDebugger_ClearBreakpoints(void* adapter);
    
    int IDEDebugger_IsDebugging(void* adapter);
}
