/*===========================================================================
 * IDEDebuggerAdapter.cpp
 * Thin adapter implementation - delegates ALL work to DebuggerManager
 *===========================================================================*/

#include "IDEDebuggerAdapter.h"
#include "RawrXD_IDE_Win32.h"
#include <sstream>

namespace RawrXD {
namespace IDE {

/*===========================================================================
 * Construction / Destruction
 *=========================================================================*/

IDEDebuggerAdapter::IDEDebuggerAdapter() = default;

IDEDebuggerAdapter::~IDEDebuggerAdapter() {
    Shutdown();
}

/*===========================================================================
 * Initialization
 *=========================================================================*/

bool IDEDebuggerAdapter::Initialize(RawrXD_IDE* ide) {
    ide_ = ide;
    debugSession_ = std::make_unique<Debugger::DebugSession>();
    
    // Set up event callback from debugger backend
    debugSession_->SetEventCallback([this](Debugger::DebugEventType event, 
                                           const void* eventData,
                                           Debugger::DebugSession* session) {
        (void)session;
        switch (event) {
        case Debugger::DebugEventType::Breakpoint:
            if (eventData) {
                OnBreakpointHit(*static_cast<const Debugger::Breakpoint*>(eventData));
            }
            break;
        case Debugger::DebugEventType::StepComplete:
            OnStepComplete();
            break;
        case Debugger::DebugEventType::ProcessExit:
            OnProcessExit(0);
            break;
        case Debugger::DebugEventType::Exception:
            if (eventData) {
                OnException(*static_cast<const std::wstring*>(eventData));
            }
            break;
        default:
            break;
        }
    });
    
    return true;
}

void IDEDebuggerAdapter::SetCallbacks(const DebuggerCallbacks& callbacks) {
    callbacks_ = callbacks;
}

void IDEDebuggerAdapter::Shutdown() {
    if (debugSession_) {
        debugSession_->Shutdown();
        debugSession_.reset();
    }
    ide_ = nullptr;
    isDebugging_ = false;
}

/*===========================================================================
 * Session Control
 *=========================================================================*/

bool IDEDebuggerAdapter::StartDebugging(const std::wstring& executable) {
    if (!debugSession_) return false;
    
    // Derive exe from current file if needed
    std::wstring exePath = executable;
    if (exePath.empty() && ide_) {
        // Get exe from current file
        exePath = ide_->currentFilePath;
        size_t dotPos = exePath.find_last_of(L'.');
        if (dotPos != std::wstring::npos) {
            exePath = exePath.substr(0, dotPos) + L".exe";
        }
    }
    
    if (!debugSession_->LaunchProcess(exePath, L"", L"")) {
        return false;
    }
    
    isDebugging_ = true;
    return true;
}

bool IDEDebuggerAdapter::AttachToProcess(uint32_t pid) {
    if (!debugSession_) return false;
    return debugSession_->AttachToProcess(pid);
}

bool IDEDebuggerAdapter::StopDebugging() {
    if (!debugSession_) return false;
    debugSession_->Terminate();
    isDebugging_ = false;
    return true;
}

bool IDEDebuggerAdapter::RestartDebugging() {
    StopDebugging();
    return StartDebugging(L"");
}

bool IDEDebuggerAdapter::IsDebugging() const {
    return isDebugging_ && debugSession_ && debugSession_->IsActive();
}

/*===========================================================================
 * Execution Control
 *=========================================================================*/

bool IDEDebuggerAdapter::Continue() {
    if (!debugSession_) return false;
    return debugSession_->ContinueExecution();
}

bool IDEDebuggerAdapter::StepOver() {
    if (!debugSession_) return false;
    return debugSession_->StepOver();
}

bool IDEDebuggerAdapter::StepInto() {
    if (!debugSession_) return false;
    return debugSession_->StepInto();
}

bool IDEDebuggerAdapter::StepOut() {
    if (!debugSession_) return false;
    return debugSession_->StepOut();
}

bool IDEDebuggerAdapter::Break() {
    if (!debugSession_) return false;
    return debugSession_->BreakExecution();
}

/*===========================================================================
 * Breakpoints
 *=========================================================================*/

bool IDEDebuggerAdapter::ToggleBreakpoint(const std::wstring& filePath, uint32_t lineNumber) {
    if (!debugSession_) return false;
    
    // Check if breakpoint exists
    auto bps = debugSession_->GetBreakpoints();
    for (const auto& bp : bps) {
        if (bp.filePath == filePath && bp.lineNumber == lineNumber) {
            // Remove existing
            return debugSession_->RemoveBreakpoint(bp.id);
        }
    }
    
    // Add new
    return debugSession_->SetBreakpoint(filePath, lineNumber);
}

bool IDEDebuggerAdapter::RemoveBreakpoint(uint64_t breakpointId) {
    if (!debugSession_) return false;
    return debugSession_->RemoveBreakpoint(breakpointId);
}

void IDEDebuggerAdapter::ClearAllBreakpoints() {
    if (!debugSession_) return;
    auto bps = debugSession_->GetBreakpoints();
    for (const auto& bp : bps) {
        debugSession_->RemoveBreakpoint(bp.id);
    }
}

/*===========================================================================
 * Stack & Variables
 *=========================================================================*/

std::vector<Debugger::StackFrame> IDEDebuggerAdapter::GetCallStack() {
    if (!debugSession_) return {};
    debugSession_->RefreshStackFrames();
    // Return empty for now - would populate from DebugSession
    return {};
}

std::vector<Debugger::RegisterValue> IDEDebuggerAdapter::GetRegisters() {
    if (!debugSession_) return {};
    debugSession_->RefreshRegisters();
    // Return empty for now - would populate from DebugSession
    return {};
}

std::vector<Debugger::LocalVariable> IDEDebuggerAdapter::GetLocalVariables(uint32_t frameNumber) {
    if (!debugSession_) return {};
    debugSession_->RefreshLocalVariables();
    (void)frameNumber;
    // Return empty for now - would populate from DebugSession
    return {};
}

/*===========================================================================
 * Error Navigation
 *=========================================================================*/

void IDEDebuggerAdapter::NavigateToNextError() {
    // TODO: Integrate with build error parser
}

void IDEDebuggerAdapter::NavigateToPreviousError() {
    // TODO: Integrate with build error parser
}

void IDEDebuggerAdapter::ClearErrorList() {
    // TODO: Clear build errors
}

/*===========================================================================
 * Event Callbacks
 *=========================================================================*/

void IDEDebuggerAdapter::OnBreakpointHit(const Debugger::Breakpoint& bp) {
    // Forward to IDE via callback
    if (callbacks_.OnBreakpointHit) {
        callbacks_.OnBreakpointHit(bp.address);
    }
    
    if (!ide_) return;
    
    std::wstringstream msg;
    msg << L"[Debug] Breakpoint hit at " << bp.filePath << L":" << bp.lineNumber << L"\r\n";
    RawrXD_IDE_OutputAppend(ide_, msg.str().c_str());
    
    // Navigate to breakpoint location
    if (!bp.filePath.empty()) {
        RawrXD_IDE_LoadFile(ide_, bp.filePath.c_str());
        // Go to line
        int pos = (int)SendMessageW(ide_->hWndEditor, EM_LINEINDEX, bp.lineNumber - 1, 0);
        SendMessageW(ide_->hWndEditor, EM_SETSEL, pos, pos);
        SendMessageW(ide_->hWndEditor, EM_SCROLLCARET, 0, 0);
    }
}

void IDEDebuggerAdapter::OnStepComplete() {
    if (callbacks_.OnStepComplete) {
        callbacks_.OnStepComplete();
    }
    
    if (!ide_) return;
    RawrXD_IDE_OutputAppend(ide_, L"[Debug] Step complete\r\n");
}

void IDEDebuggerAdapter::OnProcessExit(int exitCode) {
    if (callbacks_.OnProcessExit) {
        callbacks_.OnProcessExit(exitCode);
    }
    
    if (!ide_) return;
    
    std::wstringstream msg;
    msg << L"=== DEBUG PROCESS EXITED (code " << exitCode << L") ===\r\n";
    RawrXD_IDE_OutputAppend(ide_, msg.str().c_str());
    
    isDebugging_ = false;
    
    if (callbacks_.OnDebugSessionChanged) {
        callbacks_.OnDebugSessionChanged(false);
    }
}

void IDEDebuggerAdapter::OnException(const std::wstring& exception) {
    if (callbacks_.OnException) {
        callbacks_.OnException(exception);
    }
    
    if (!ide_) return;
    
    std::wstringstream msg;
    msg << L"[Debug] EXCEPTION: " << exception << L"\r\n";
    RawrXD_IDE_OutputAppend(ide_, msg.str().c_str());
}

} // namespace IDE
} // namespace RawrXD
