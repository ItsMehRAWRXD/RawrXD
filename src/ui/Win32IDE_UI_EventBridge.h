// Win32IDE_UI_EventBridge.h
// Phase 24: The Cockpit - UI Integration Layer
// ============================================================================
// Bridges backend events (Debugger, LSP) to UI updates (panels, gutters)
// ============================================================================

#pragma once

#include <windows.h>
#include <functional>
#include <memory>
#include <vector>
#include <string>

// Forward declarations
namespace RawrXD {
    namespace Debugger { class DebugSession; struct StackFrame; struct Breakpoint; }
    namespace LSP { struct Diagnostic; }
}

namespace RawrXD {
namespace UI {

// ============================================================================
// UI Event Types
// ============================================================================
enum class DebugUIEventType {
    BreakpointHit,        // Debugger stopped at breakpoint
    StepComplete,         // Single step finished
    ProcessStarted,       // Debuggee launched
    ProcessExited,        // Debuggee terminated
    ModuleLoaded,         // DLL loaded
    BreakpointToggled,    // User clicked gutter
};

enum class DiagnosticsUIEventType {
    DiagnosticsUpdated,   // New diagnostics available
    DiagnosticSelected,   // User clicked problem
    ClearDiagnostics,     // Clear all markers
};

// ============================================================================
// Event Data Structures
// ============================================================================
struct BreakpointHitEvent {
    uint64_t address;
    std::wstring filePath;
    uint32_t lineNumber;
    std::wstring functionName;
};

struct DiagnosticsUpdateEvent {
    std::wstring filePath;
    std::vector<LSP::Diagnostic> diagnostics;
};

// ============================================================================
// UI Event Bridge
// ============================================================================
class UIEventBridge {
public:
    using DebugEventHandler = std::function<void(DebugUIEventType, const void*)>;
    using DiagnosticsHandler = std::function<void(DiagnosticsUIEventType, const void*)>;

    UIEventBridge();
    ~UIEventBridge();

    // Initialize with backend sessions
    bool Initialize(
        Debugger::DebugSession* debugSession,
        class ProblemsAggregator* problemsAggregator
    );

    void Shutdown();

    // Event subscription
    void SubscribeToDebugEvents(DebugEventHandler handler);
    void SubscribeToDiagnostics(DiagnosticsHandler handler);

    // Backend event injection (called by DebugSession callbacks)
    void OnDebuggerBreakpointHit(uint64_t address, const std::wstring& file, uint32_t line);
    void OnDebuggerStepComplete();
    void OnDebuggerProcessStarted();
    void OnDebuggerProcessExited(uint32_t exitCode);
    void OnDiagnosticsUpdated(const std::wstring& file, const std::vector<LSP::Diagnostic>& diagnostics);

    // UI action handlers (called by UI components)
    void OnGutterClicked(const std::wstring& filePath, uint32_t lineNumber);
    void OnCallStackFrameSelected(size_t frameIndex);
    void OnProblemDoubleClicked(const std::wstring& filePath, uint32_t lineNumber);

    // Synchronization
    void ProcessPendingEvents();  // Call on UI thread

private:
    class Impl;
    std::unique_ptr<Impl> pImpl_;
};

// ============================================================================
// Global Event Bridge Access
// ============================================================================
UIEventBridge* GetUIEventBridge();
bool InitializeUIEventBridge(Debugger::DebugSession* debugSession, class ProblemsAggregator* aggregator);
void ShutdownUIEventBridge();

} // namespace UI
} // namespace RawrXD
