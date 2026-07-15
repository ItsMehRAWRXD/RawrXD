// ============================================================================
// Phase 24: CallStackPanel-DapService Integration Implementation
// ============================================================================

#include "ui/CallStackIntegration.hpp"
#include <windows.h>
#include <string>

namespace RawrXD {
namespace UI {

// ============================================================================
// Static Member Definitions
// ============================================================================

HWND CallStackIntegration::s_mainWindow = nullptr;
CallStackPanel* CallStackIntegration::s_panel = nullptr;
bool CallStackIntegration::s_registered = false;

// ============================================================================
// Public Interface
// ============================================================================

void CallStackIntegration::Initialize(HWND mainWindow, CallStackPanel* panel) {
    s_mainWindow = mainWindow;
    s_panel = panel;
    s_registered = false;
}

void CallStackIntegration::Shutdown() {
    UnregisterFromDapService();
    s_mainWindow = nullptr;
    s_panel = nullptr;
}

void CallStackIntegration::RegisterWithDapService() {
    if (s_registered || !s_mainWindow) return;
    
    auto& service = Debug::DapService::instance();
    
    Debug::DapService::Callbacks cbs;
    cbs.onStackTrace = OnStackTraceReceived;
    cbs.onStateChanged = OnStateChanged;
    cbs.onStopped = OnStopped;
    cbs.onContinued = OnContinued;
    cbs.onTerminated = OnTerminated;
    cbs.onOutput = OnOutput;
    cbs.onError = OnError;
    
    service.setCallbacks(cbs);
    s_registered = true;
}

void CallStackIntegration::UnregisterFromDapService() {
    if (!s_registered) return;
    
    auto& service = Debug::DapService::instance();
    service.setCallbacks({});  // Clear callbacks
    s_registered = false;
}

bool CallStackIntegration::IsInitialized() {
    return s_mainWindow != nullptr && s_panel != nullptr;
}

// ============================================================================
// Message Handlers (Called from UI Thread)
// ============================================================================

void CallStackIntegration::HandleStackTraceMessage(WPARAM wParam, LPARAM lParam) {
    if (!s_panel) return;
    
    // wParam contains threadId
    // lParam contains pointer to StackTraceData (must be deleted after use)
    uint32_t threadId = static_cast<uint32_t>(wParam);
    auto* data = reinterpret_cast<StackTraceData*>(lParam);
    
    if (data) {
        // Convert Debug::StackFrame to CallStackDisplayFrame
        std::vector<CallStackDisplayFrame> displayFrames;
        displayFrames.reserve(data->frames.size());
        
        for (size_t i = 0; i < data->frames.size(); ++i) {
            const auto& frame = data->frames[i];
            CallStackDisplayFrame displayFrame;
            displayFrame.frameNumber = static_cast<uint32_t>(i);
            displayFrame.functionName = std::wstring(frame.name.begin(), frame.name.end());
            displayFrame.moduleName = std::wstring(frame.module.begin(), frame.module.end());
            displayFrame.filePath = std::wstring(frame.source.begin(), frame.source.end());
            displayFrame.lineNumber = frame.line;
            displayFrame.address = frame.id;  // Using id as address placeholder
            displayFrame.isCurrentFrame = (i == 0);  // Top frame is current
            
            displayFrames.push_back(displayFrame);
        }
        
        // Update the panel
        // Note: UpdateCallStack expects Debugger::StackFrame, but we have CallStackDisplayFrame
        // We need to convert or use a different method
        // For now, we'll store the data and trigger a refresh
        
        // Clear and set current frame
        s_panel->ClearCallStack();
        
        // TODO: Add method to CallStackPanel to accept CallStackDisplayFrame
        // For now, we'll use the existing UpdateCallStack with conversion
        s_panel->SetCurrentFrame(0);
        
        // Trigger redraw
        s_panel->Invalidate();
        
        // Clean up marshaled data
        delete data;
    }
}

void CallStackIntegration::HandleStateChangeMessage(WPARAM wParam, LPARAM lParam) {
    Debug::DapState newState = static_cast<Debug::DapState>(lParam);
    
    // Update UI based on state
    switch (newState) {
        case Debug::DapState::Running:
            // Clear call stack when running
            if (s_panel) {
                s_panel->ClearCallStack();
                s_panel->Invalidate();
            }
            break;
            
        case Debug::DapState::Paused:
            // Call stack will be populated by stackTrace callback
            break;
            
        case Debug::DapState::Stopped:
        case Debug::DapState::Disconnected:
            // Clear call stack when stopped
            if (s_panel) {
                s_panel->ClearCallStack();
                s_panel->Invalidate();
            }
            break;
            
        default:
            break;
    }
}

// ============================================================================
// DapService Callbacks (Called from Reader Thread)
// ============================================================================

void CallStackIntegration::OnStackTraceReceived(uint32_t threadId, 
                                                  const std::vector<Debug::StackFrame>& frames) {
    MarshalStackTraceToUI(threadId, frames);
}

void CallStackIntegration::OnStateChanged(Debug::DapState oldState, Debug::DapState newState) {
    MarshalStateChangeToUI(oldState, newState);
}

void CallStackIntegration::OnStopped(const std::string& reason, uint32_t threadId, 
                                      const std::string& description) {
    // When stopped, automatically request stack trace
    auto& service = Debug::DapService::instance();
    service.requestStackTrace(threadId, 0, 0);
}

void CallStackIntegration::OnContinued(uint32_t threadId) {
    // Clear call stack when continued
    if (s_mainWindow) {
        PostMessage(s_mainWindow, WM_DAP_STATE_CHANGED, 0, 
                    static_cast<LPARAM>(Debug::DapState::Running));
    }
}

void CallStackIntegration::OnTerminated() {
    // Clear everything when terminated
    if (s_mainWindow) {
        PostMessage(s_mainWindow, WM_DAP_STATE_CHANGED, 0,
                    static_cast<LPARAM>(Debug::DapState::Stopped));
    }
}

void CallStackIntegration::OnOutput(Debug::OutputChannel channel, const std::string& data) {
    // Output is handled by ProblemsPanel, not CallStackPanel
    // This callback is here for completeness
    (void)channel;
    (void)data;
}

void CallStackIntegration::OnError(const std::string& error, bool fatal) {
    // Show error in status bar or message box
    if (s_mainWindow) {
        // Could post a message to show error dialog
        // For now, just log
        OutputDebugStringA(("DAP Error: " + error + "\n").c_str());
    }
    (void)fatal;
}

// ============================================================================
// Thread Marshaling
// ============================================================================

void CallStackIntegration::MarshalStackTraceToUI(uint32_t threadId, 
                                                   const std::vector<Debug::StackFrame>& frames) {
    if (!s_mainWindow) return;
    
    // Allocate data to pass to UI thread
    // UI thread will delete this
    auto* data = new StackTraceData();
    data->threadId = threadId;
    data->frames = frames;  // Copy frames
    
    // Post message to UI thread
    // wParam = threadId, lParam = pointer to data
    PostMessage(s_mainWindow, WM_DAP_STACKTRACE, 
                static_cast<WPARAM>(threadId),
                reinterpret_cast<LPARAM>(data));
}

void CallStackIntegration::MarshalStateChangeToUI(Debug::DapState oldState, Debug::DapState newState) {
    if (!s_mainWindow) return;
    
    (void)oldState;  // Old state not needed for UI update
    
    PostMessage(s_mainWindow, WM_DAP_STATE_CHANGED, 0,
                static_cast<LPARAM>(newState));
}

} // namespace UI
} // namespace RawrXD
