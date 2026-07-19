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
    
    // Assign sequence number and timestamp
    event->sequence = ++m_sequenceCounter;
    event->submitTimestamp = GetTickCount64();
    
    // Record in telemetry
    m_telemetry.RecordSubmit(event->sequence);
    
    // Check if we should coalesce (drop stale events)
    if (ShouldCoalesceEvent(event)) {
        m_telemetry.RecordDrop();
        delete event->registers;
        delete[] event->callStack;
        delete event;
        return;
    }
    
    if (m_hUIWindow && IsWindow(m_hUIWindow)) {
        // Pass event pointer as LPARAM - UI thread will own deletion
        PostMessage(m_hUIWindow, WM_APP_DEBUG_EVENT, 
                   (WPARAM)event->type, (LPARAM)event);
    } else {
        // No UI window, clean up
        delete event;
    }
}

bool DebugBridge::ShouldCoalesceEvent(DebugBridgeEvent* newEvent) {
    // Coalescing strategy: if UI is more than 10 events behind,
    // drop non-critical events (single step, output, etc.)
    uint64_t gaps = m_telemetry.GetSequenceGaps();
    
    if (gaps > 10) {
        // UI is falling behind - coalesce non-critical events
        switch (newEvent->type) {
            case DebugBridgeEventType::SingleStep:
            case DebugBridgeEventType::OutputDebugString:
                return true; // Drop these events
            default:
                break;
        }
    }
    
    return false;
}

void DebugBridge::ProcessEvent(DebugBridgeEvent* event) {
    // This is called from the UI THREAD
    // Safe to touch UI here
    
    // Record render timestamp and calculate state age
    event->renderTimestamp = GetTickCount64();
    uint64_t stateAgeMs = event->GetStateAgeMs();
    
    // Update telemetry
    m_telemetry.RecordRender(event->sequence, stateAgeMs);
    
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

void DebugBridge::LogTelemetrySummary() {
    uint64_t submitted = m_telemetry.submittedSequence.load();
    uint64_t rendered = m_telemetry.renderedSequence.load();
    uint64_t gaps = m_telemetry.GetSequenceGaps();
    uint64_t dropped = m_telemetry.droppedEvents.load();
    uint64_t total = m_telemetry.totalEvents.load();
    uint64_t lastAge = m_telemetry.lastStateAgeMs.load();
    uint64_t maxAge = m_telemetry.maxStateAgeMs.load();
    uint64_t arena = m_telemetry.arenaHighWater.load();
    
    char buffer[512];
    snprintf(buffer, sizeof(buffer),
        "[DebugTelemetry] Submitted: %llu | Rendered: %llu | Gaps: %llu | "
        "Dropped: %llu | Total: %llu | LastAge: %llums | MaxAge: %llums | Arena: %llu",
        (unsigned long long)submitted,
        (unsigned long long)rendered,
        (unsigned long long)gaps,
        (unsigned long long)dropped,
        (unsigned long long)total,
        (unsigned long long)lastAge,
        (unsigned long long)maxAge,
        (unsigned long long)arena);
    
    OutputDebugStringA(buffer);
    OutputDebugStringA("\n");
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
