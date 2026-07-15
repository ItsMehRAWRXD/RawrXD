// Win32IDE_UI_EventBridge.cpp
// Phase 24: The Cockpit - UI Integration Implementation
// ============================================================================

#include "ui/Win32IDE_UI_EventBridge.h"
#include "debugger/Debugger_Backend.h"
#include "lsp/LSP_Diagnostics.h"
#include <queue>
#include <mutex>

namespace RawrXD {
namespace UI {

// ============================================================================
// Thread-Safe Event Queue
// ============================================================================
template<typename T>
class ThreadSafeQueue {
public:
    void Push(T item) {
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.push(std::move(item));
    }

    bool Pop(T& item) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (queue_.empty()) return false;
        item = std::move(queue_.front());
        queue_.pop();
        return true;
    }

    bool Empty() {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.empty();
    }

private:
    std::queue<T> queue_;
    std::mutex mutex_;
};

// ============================================================================
// UI Event Bridge Implementation
// ============================================================================
struct PendingDebugEvent {
    DebugUIEventType type;
    BreakpointHitEvent data;
};

struct PendingDiagnosticsEvent {
    DiagnosticsUIEventType type;
    DiagnosticsUpdateEvent data;
};

class UIEventBridge::Impl {
public:
    Debugger::DebugSession* debugSession_ = nullptr;
    class ProblemsAggregator* problemsAggregator_ = nullptr;

    std::vector<DebugEventHandler> debugHandlers_;
    std::vector<DiagnosticsHandler> diagnosticsHandlers_;

    ThreadSafeQueue<PendingDebugEvent> pendingDebugEvents_;
    ThreadSafeQueue<PendingDiagnosticsEvent> pendingDiagnosticsEvents_;

    // Debugger callback wrapper
    static void DebuggerCallbackWrapper(Debugger::DebugEventType event, const void* data, Debugger::DebugSession* session);
    void HandleDebuggerEvent(Debugger::DebugEventType event, const void* data);
};

UIEventBridge::UIEventBridge() : pImpl_(std::make_unique<Impl>()) {}
UIEventBridge::~UIEventBridge() = default;

bool UIEventBridge::Initialize(
    Debugger::DebugSession* debugSession,
    class ProblemsAggregator* problemsAggregator) {
    
    pImpl_->debugSession_ = debugSession;
    pImpl_->problemsAggregator_ = problemsAggregator;

    if (debugSession) {
        // Subscribe to debugger events
        debugSession->SetEventCallback([](Debugger::DebugEventType event, const void* data, Debugger::DebugSession* session) {
            auto* bridge = GetUIEventBridge();
            if (bridge) {
                bridge->pImpl_->HandleDebuggerEvent(event, data);
            }
        });
    }

    return true;
}

void UIEventBridge::Shutdown() {
    pImpl_->debugSession_ = nullptr;
    pImpl_->problemsHandlers_.clear();
    pImpl_->diagnosticsHandlers_.clear();
}

void UIEventBridge::SubscribeToDebugEvents(DebugEventHandler handler) {
    pImpl_->debugHandlers_.push_back(handler);
}

void UIEventBridge::SubscribeToDiagnostics(DiagnosticsHandler handler) {
    pImpl_->diagnosticsHandlers_.push_back(handler);
}

// ============================================================================
// Backend Event Handlers (called from debugger thread)
// ============================================================================
void UIEventBridge::Impl::HandleDebuggerEvent(Debugger::DebugEventType event, const void* data) {
    PendingDebugEvent pending;
    
    switch (event) {
        case Debugger::DebugEventType::Breakpoint: {
            pending.type = DebugUIEventType::BreakpointHit;
            uint64_t addr = data ? *reinterpret_cast<const uint64_t*>(data) : 0;
            pending.data.address = addr;
            
            // Get current location info
            if (debugSession_) {
                auto frames = debugSession_->GetCallStack(1);
                if (!frames.empty()) {
                    pending.data.filePath = frames[0].filePath;
                    pending.data.lineNumber = frames[0].lineNumber;
                    pending.data.functionName = frames[0].functionName;
                }
            }
            pendingDebugEvents_.Push(pending);
            break;
        }
        
        case Debugger::DebugEventType::StepComplete:
            pending.type = DebugUIEventType::StepComplete;
            pendingDebugEvents_.Push(pending);
            break;
            
        case Debugger::DebugEventType::ProcessExit:
            pending.type = DebugUIEventType::ProcessExited;
            pendingDebugEvents_.Push(pending);
            break;
            
        default:
            break;
    }
}

void UIEventBridge::OnDebuggerBreakpointHit(uint64_t address, const std::wstring& file, uint32_t line) {
    PendingDebugEvent pending;
    pending.type = DebugUIEventType::BreakpointHit;
    pending.data.address = address;
    pending.data.filePath = file;
    pending.data.lineNumber = line;
    pImpl_->pendingDebugEvents_.Push(pending);
}

void UIEventBridge::OnDebuggerStepComplete() {
    PendingDebugEvent pending;
    pending.type = DebugUIEventType::StepComplete;
    pImpl_->pendingDebugEvents_.Push(pending);
}

void UIEventBridge::OnDebuggerProcessStarted() {
    PendingDebugEvent pending;
    pending.type = DebugUIEventType::ProcessStarted;
    pImpl_->pendingDebugEvents_.Push(pending);
}

void UIEventBridge::OnDebuggerProcessExited(uint32_t exitCode) {
    PendingDebugEvent pending;
    pending.type = DebugUIEventType::ProcessExited;
    pImpl_->pendingDebugEvents_.Push(pending);
}

void UIEventBridge::OnDiagnosticsUpdated(
    const std::wstring& file,
    const std::vector<LSP::Diagnostic>& diagnostics) {
    
    PendingDiagnosticsEvent pending;
    pending.type = DiagnosticsUIEventType::DiagnosticsUpdated;
    pending.data.filePath = file;
    // Note: diagnostics would need to be copied here
    pendingDiagnosticsEvents_.Push(pending);
}

// ============================================================================
// UI Action Handlers (called from UI thread)
// ============================================================================
void UIEventBridge::OnGutterClicked(const std::wstring& filePath, uint32_t lineNumber) {
    if (!pImpl_->debugSession_) return;
    
    // Toggle breakpoint at this location
    auto bps = pImpl_->debugSession_->GetBreakpoints();
    bool found = false;
    
    for (const auto& bp : bps) {
        if (bp.filePath == filePath && bp.lineNumber == lineNumber) {
            // Remove existing breakpoint
            pImpl_->debugSession_->RemoveBreakpoint(bp.id);
            found = true;
            break;
        }
    }
    
    if (!found) {
        // Set new breakpoint
        pImpl_->debugSession_->SetBreakpoint(filePath, lineNumber);
    }
    
    // Notify UI to refresh gutter
    PendingDebugEvent pending;
    pending.type = DebugUIEventType::BreakpointToggled;
    pending.data.filePath = filePath;
    pending.data.lineNumber = lineNumber;
    pImpl_->pendingDebugEvents_.Push(pending);
}

void UIEventBridge::OnCallStackFrameSelected(size_t frameIndex) {
    if (!pImpl_->debugSession_) return;
    
    auto frames = pImpl_->debugSession_->GetCallStack();
    if (frameIndex < frames.size()) {
        // Navigate editor to this frame's location
        const auto& frame = frames[frameIndex];
        // This would trigger editor navigation
        // Editor::NavigateTo(frame.filePath, frame.lineNumber);
    }
}

void UIEventBridge::OnProblemDoubleClicked(const std::wstring& filePath, uint32_t lineNumber) {
    // Navigate editor to problem location
    // Editor::NavigateTo(filePath, lineNumber);
    // Editor::SetFocus();
}

// ============================================================================
// Event Processing (must be called on UI thread)
// ============================================================================
void UIEventBridge::ProcessPendingEvents() {
    // Process debug events
    PendingDebugEvent debugEvent;
    while (pImpl_->pendingDebugEvents_.Pop(debugEvent)) {
        for (auto& handler : pImpl_->debugHandlers_) {
            handler(debugEvent.type, &debugEvent.data);
        }
    }
    
    // Process diagnostics events
    PendingDiagnosticsEvent diagEvent;
    while (pImpl_->pendingDiagnosticsEvents_.Pop(diagEvent)) {
        for (auto& handler : pImpl_->diagnosticsHandlers_) {
            handler(diagEvent.type, &diagEvent.data);
        }
    }
}

// ============================================================================
// Global Access
// ============================================================================
static std::unique_ptr<UIEventBridge> g_eventBridge;

UIEventBridge* GetUIEventBridge() {
    return g_eventBridge.get();
}

bool InitializeUIEventBridge(
    Debugger::DebugSession* debugSession,
    class ProblemsAggregator* aggregator) {
    
    g_eventBridge = std::make_unique<UIEventBridge>();
    return g_eventBridge->Initialize(debugSession, aggregator);
}

void ShutdownUIEventBridge() {
    if (g_eventBridge) {
        g_eventBridge->Shutdown();
        g_eventBridge.reset();
    }
}

} // namespace UI
} // namespace RawrXD
