//=============================================================================
// RawrXD Debug Bridge Implementation
// Thread-safe communication between Debug Backend and UI
//=============================================================================
#include "DebugBridge.hpp"
#include "DebugBackend.h"
#include "DebugUI.hpp"

namespace RawrXD {
namespace DebugUI {

//=============================================================================
// DebugBridge Implementation
//=============================================================================

DebugBridge& DebugBridge::Instance() {
    static DebugBridge inst;
    return inst;
}

void DebugBridge::Initialize(HWND hUIWindow) {
    m_hUIWindow = hUIWindow;
    InitializeCriticalSection(&m_cs);
}

void DebugBridge::Shutdown() {
    DeleteCriticalSection(&m_cs);
    m_hUIWindow = nullptr;
    m_session = nullptr;
}

void DebugBridge::PostEvent(DebugBridgeEvent* event) {
    // This is called from the BACKEND THREAD
    // We must use PostMessage to marshal to the UI thread
    if (m_hUIWindow && IsWindow(m_hUIWindow)) {
        // Pass event pointer as LPARAM - UI thread will own deletion
        PostMessage(m_hUIWindow, WM_APP_DEBUG_EVENT, 
                   (WPARAM)event->type, (LPARAM)event);
    } else {
        // No UI window, clean up
        delete event;
    }
}

void DebugBridge::ProcessEvent(DebugBridgeEvent* event) {
    // This is called from the UI THREAD
    // Safe to touch UI here
    if (m_eventCallback) {
        m_eventCallback(event);
    }
    
    // Route to UI manager
    auto& ui = DebugUIManager::Instance();
    switch (event->type) {
        case DebugBridgeEventType::BreakpointHit:
            ui.OnBreakpointHit(event->breakpoint.address);
            break;
        case DebugBridgeEventType::Exception:
            ui.OnException(event->exception.code, event->exception.address);
            break;
        case DebugBridgeEventType::SingleStep:
        case DebugBridgeEventType::StepComplete:
            ui.OnStepComplete();
            break;
        case DebugBridgeEventType::ProcessExited:
            ui.OnProcessExit((uint32_t)event->processExit.exitCode);
            break;
        case DebugBridgeEventType::DllLoaded:
            ui.OnDllLoad(event->dllLoad.path, event->dllLoad.baseAddress);
            break;
        default:
            break;
    }
    
    // Clean up event data
    delete event->registers;
    delete[] event->callStack;
    delete event;
}

void DebugBridge::SetEventCallback(EventCallback callback) {
    m_eventCallback = callback;
}

void DebugBridge::AttachSession(DebugSession* session) {
    Lock();
    m_session = session;
    Unlock();
}

void DebugBridge::DetachSession() {
    Lock();
    m_session = nullptr;
    Unlock();
}

//=============================================================================
// Thread-Safe Backend Wrappers
//=============================================================================

bool DebugBridge::ReadMemory(uint64_t addr, void* buffer, size_t size) {
    Lock();
    bool result = false;
    if (m_session) {
        result = m_session->ReadMemory(addr, buffer, size);
    }
    Unlock();
    return result;
}

bool DebugBridge::WriteMemory(uint64_t addr, const void* buffer, size_t size) {
    Lock();
    bool result = false;
    if (m_session) {
        result = m_session->WriteMemory(addr, buffer, size);
    }
    Unlock();
    return result;
}

bool DebugBridge::GetCallStack(StackFrame* frames, int maxFrames, int* outCount) {
    Lock();
    bool result = false;
    *outCount = 0;
    if (m_session) {
        auto stack = m_session->GetCallStack();
        int count = (int)stack.size();
        if (count > maxFrames) count = maxFrames;
        for (int i = 0; i < count; ++i) {
            frames[i] = stack[i];
        }
        *outCount = count;
        result = true;
    }
    Unlock();
    return result;
}

bool DebugBridge::GetRegisters(RegisterContext* ctx) {
    Lock();
    bool result = false;
    if (m_session) {
        result = m_session->GetRegisters(*ctx);
    }
    Unlock();
    return result;
}

bool DebugBridge::SetRegisters(const RegisterContext* ctx) {
    Lock();
    bool result = false;
    if (m_session) {
        result = m_session->SetRegisters(*ctx);
    }
    Unlock();
    return result;
}

bool DebugBridge::Continue() {
    Lock();
    bool result = false;
    if (m_session) {
        result = m_session->ContinueExecution();
    }
    Unlock();
    return result;
}

bool DebugBridge::StepInto() {
    Lock();
    bool result = false;
    if (m_session) {
        result = m_session->StepInto();
    }
    Unlock();
    return result;
}

bool DebugBridge::StepOver() {
    Lock();
    bool result = false;
    if (m_session) {
        result = m_session->StepOver();
    }
    Unlock();
    return result;
}

bool DebugBridge::StepOut() {
    Lock();
    bool result = false;
    if (m_session) {
        result = m_session->StepOut();
    }
    Unlock();
    return result;
}

bool DebugBridge::Break() {
    Lock();
    bool result = false;
    if (m_session) {
        result = m_session->BreakExecution();
    }
    Unlock();
    return result;
}

} // namespace DebugUI
} // namespace RawrXD
