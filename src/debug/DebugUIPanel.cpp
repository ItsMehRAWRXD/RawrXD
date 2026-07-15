// DebugUIPanel.cpp
// Phase 24: RawrXD IDE Debugger UI Implementation
// ============================================================================
// Bridges DapService events to Win32 UI panels
// ============================================================================

#include "DebugUIPanel.hpp"
#include <windowsx.h>
#include <commctrl.h>
#include <string>

#pragma comment(lib, "comctl32.lib")

namespace RawrXD {
namespace Debug {
namespace UI {

// ============================================================================
// DebugUIController Implementation
// ============================================================================
DebugUIController& DebugUIController::instance() {
    static DebugUIController instance;
    return instance;
}

bool DebugUIController::Initialize(HWND hwndParent) {
    if (initialized_) return true;
    
    hwndParent_ = hwndParent;
    
    // Initialize common controls
    INITCOMMONCONTROLSEX iccex;
    iccex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    iccex.dwICC = ICC_LISTVIEW_CLASSES | ICC_TREEVIEW_CLASSES | ICC_BAR_CLASSES;
    InitCommonControlsEx(&iccex);
    
    // Create panels
    callStackPanel_ = std::make_unique<CallStackPanel>();
    variablesPanel_ = std::make_unique<VariablesPanel>();
    breakpointsPanel_ = std::make_unique<BreakpointsPanel>();
    outputPanel_ = std::make_unique<DebugOutputPanel>();
    toolbar_ = std::make_unique<DebugToolbar>();
    
    // Get client area
    RECT rcClient;
    GetClientRect(hwndParent_, &rcClient);
    int width = rcClient.right - rcClient.left;
    int height = rcClient.bottom - rcClient.top;
    
    // Create toolbar at top
    toolbar_>Create(hwndParent_, 0, 0, width);
    toolbar_>onContinue = [this]() { OnUserContinue(); };
    toolbar_>onPause = [this]() { OnUserPause(); };
    toolbar_>onStepOver = [this]() { OnUserStepOver(); };
    toolbar_>onStepInto = [this]() { OnUserStepInto(); };
    toolbar_>onStepOut = [this]() { OnUserStepOut(); };
    
    // Create panels docked to bottom
    int panelHeight = 200;
    int panelY = height - panelHeight;
    
    callStackPanel_>Create(hwndParent_, 0, panelY, width / 3, panelHeight);
    callStackPanel_>onFrameSelected = [this](uint32_t frameId) { OnUserSelectFrame(frameId); };
    
    variablesPanel_>Create(hwndParent_, width / 3, panelY, width / 3, panelHeight);
    
    breakpointsPanel_>Create(hwndParent_, 2 * width / 3, panelY, width / 3, panelHeight);
    
    outputPanel_>Create(hwndParent_, 0, panelY - 150, width, 150);
    
    initialized_ = true;
    return true;
}

void DebugUIController::Shutdown() {
    if (!initialized_) return;
    
    DetachFromDapService();
    
    toolbar_>Destroy();
    callStackPanel_>Destroy();
    variablesPanel_>Destroy();
    breakpointsPanel_>Destroy();
    outputPanel_>Destroy();
    
    initialized_ = false;
}

void DebugUIController::AttachToDapService(DapService* service) {
    dapService_ = service;
    SetupDapCallbacks();
}

void DebugUIController::DetachFromDapService() {
    ClearDapCallbacks();
    dapService_ = nullptr;
}

void DebugUIController::SetupDapCallbacks() {
    if (!dapService_) return;
    
    dapService_>onStateChange([this](DapState oldState, DapState newState) {
        MarshalToUIThread([this, newState]() { OnStateChanged(oldState, newState); });
    });
    
    dapService_>onStopped([this](const std::string& reason, uint32_t threadId, const std::string& desc) {
        MarshalToUIThread([this, threadId, reason, desc]() { OnStopped(threadId, reason, desc); });
    });
    
    dapService_>onContinued([this](uint32_t threadId) {
        MarshalToUIThread([this, threadId]() { OnContinued(threadId); });
    });
    
    dapService_>onStackTrace([this](uint32_t threadId, const std::vector<StackFrame>& frames) {
        MarshalToUIThread([this, threadId, frames]() { OnStackTraceReceived(threadId, frames); });
    });
    
    dapService_>onVariables([this](uint32_t ref, const std::vector<Variable>& vars) {
        MarshalToUIThread([this, ref, vars]() { OnVariablesReceived(ref, vars); });
    });
    
    dapService_>onBreakpoint([this](const Breakpoint& bp) {
        MarshalToUIThread([this, bp]() { OnBreakpointChanged(bp); });
    });
    
    dapService_>onOutput([this](OutputChannel ch, const std::string& data) {
        MarshalToUIThread([this, ch, data]() { OnOutput(ch, data); });
    });
    
    dapService_>onTerminated([this]() {
        MarshalToUIThread([this]() { OnTerminated(); });
    });
    
    dapService_>onError([this](const std::string& error, bool fatal) {
        MarshalToUIThread([this, error, fatal]() { OnError(error, fatal); });
    });
}

void DebugUIController::ClearDapCallbacks() {
    if (!dapService_) return;
    
    dapService_>onStateChange(nullptr);
    dapService_>onStopped(nullptr);
    dapService_>onContinued(nullptr);
    dapService_>onStackTrace(nullptr);
    dapService_>onVariables(nullptr);
    dapService_>onBreakpoint(nullptr);
    dapService_>onOutput(nullptr);
    dapService_>onTerminated(nullptr);
    dapService_>onError(nullptr);
}

void DebugUIController::MarshalToUIThread(std::function<void()> action) {
    // Store action and post message to main thread
    // In real implementation, use PostMessage with a custom message
    // For now, execute directly (assuming we're on UI thread)
    action();
}

// ============================================================================
// Event Handlers
// ============================================================================
void DebugUIController::OnStopped(uint64_t threadId, const std::string& reason, 
                                   const std::string& description) {
    currentThreadId_ = threadId;
    currentState_ = DapState::Paused;
    
    // Update toolbar
    toolbar_>SetState(DapState::Paused);
    
    // Request stack trace
    if (dapService_) {
        dapService_>requestStackTrace(static_cast<uint32_t>(threadId), 0, 20);
    }
    
    // Show panels
    ShowCallStackPanel(true);
    ShowVariablesPanel(true);
    
    // Log
    if (outputPanel_) {
        std::string msg = "Stopped: " + reason + " (Thread " + std::to_string(threadId) + ")\n";
        outputPanel_>AppendOutput(OutputChannel::Console, msg);
    }
}

void DebugUIController::OnContinued(uint64_t threadId) {
    currentState_ = DapState::Running;
    toolbar_>SetState(DapState::Running);
    
    // Clear highlight
    callStackPanel_>Clear();
    variablesPanel_>Clear();
}

void DebugUIController::OnStackTraceReceived(uint32_t threadId, 
                                            const std::vector<StackFrame>& frames) {
    callStackPanel_>SetStackFrames(frames);
    
    // Auto-select first frame
    if (!frames.empty()) {
        selectedFrameId_ = frames[0].id;
        OnUserSelectFrame(selectedFrameId_);
    }
}

void DebugUIController::OnVariablesReceived(uint32_t variablesReference, 
                                           const std::vector<Variable>& vars) {
    variablesPanel_>SetVariables(vars);
}

void DebugUIController::OnBreakpointChanged(const Breakpoint& bp) {
    if (bp.verified) {
        breakpointsPanel_>UpdateBreakpoint(bp);
    } else {
        breakpointsPanel_>RemoveBreakpoint(bp.id);
    }
}

void DebugUIController::OnOutput(OutputChannel channel, const std::string& data) {
    outputPanel_>AppendOutput(channel, data);
}

void DebugUIController::OnTerminated() {
    currentState_ = DapState::Stopped;
    toolbar_>SetState(DapState::Stopped);
    
    callStackPanel_>Clear();
    variablesPanel_>Clear();
    breakpointsPanel_>Clear();
}

void DebugUIController::OnStateChanged(DapState oldState, DapState newState) {
    currentState_ = newState;
    toolbar_>SetState(newState);
}

void DebugUIController::OnError(const std::string& error, bool fatal) {
    if (outputPanel_) {
        outputPanel_>AppendOutput(OutputChannel::Stderr, "Error: " + error + "\n");
    }
    
    if (fatal) {
        MessageBoxA(hwndParent_, error.c_str(), "Debug Error", MB_OK | MB_ICONERROR);
    }
}

// ============================================================================
// User Actions
// ============================================================================
void DebugUIController::OnUserContinue() {
    if (dapService_) {
        dapService_>continueExecution(static_cast<uint32_t>(currentThreadId_));
    }
}

void DebugUIController::OnUserPause() {
    if (dapService_) {
        dapService_>pause();
    }
}

void DebugUIController::OnUserStepOver() {
    if (dapService_) {
        dapService_>stepOver(static_cast<uint32_t>(currentThreadId_));
    }
}

void DebugUIController::OnUserStepInto() {
    if (dapService_) {
        dapService_>stepInto(static_cast<uint32_t>(currentThreadId_));
    }
}

void DebugUIController::OnUserStepOut() {
    if (dapService_) {
        dapService_>stepOut(static_cast<uint32_t>(currentThreadId_));
    }
}

void DebugUIController::OnUserSetBreakpoint(const std::string& file, uint32_t line) {
    if (dapService_) {
        dapService_>setBreakpoint(file, line, "");
    }
}

void DebugUIController::OnUserRemoveBreakpoint(const std::string& file, uint32_t line) {
    // Find and remove breakpoint
    if (dapService_) {
        // Implementation depends on breakpoint tracking
    }
}

void DebugUIController::OnUserSelectFrame(uint32_t frameId) {
    selectedFrameId_ = frameId;
    callStackPanel_>SelectFrame(frameId);
    
    // Request scopes/variables for this frame
    if (dapService_) {
        // First get scopes
        // Then get variables for each scope
    }
}

void DebugUIController::OnUserEvaluateExpression(const std::string& expression) {
    if (dapService_) {
        dapService_>evaluate(expression, selectedFrameId_);
    }
}

// ============================================================================
// Panel Visibility
// ============================================================================
void DebugUIController::ShowCallStackPanel(bool show) {
    if (callStackPanel_) callStackPanel_>Show(show);
}

void DebugUIController::ShowVariablesPanel(bool show) {
    if (variablesPanel_) variablesPanel_>Show(show);
}

void DebugUIController::ShowBreakpointsPanel(bool show) {
    if (breakpointsPanel_) breakpointsPanel_>Show(show);
}

void DebugUIController::ShowDebugOutputPanel(bool show) {
    if (outputPanel_) outputPanel_>Show(show);
}

void DebugUIController::ShowDebugToolbar(bool show) {
    if (toolbar_) toolbar_>Show(show);
}

bool DebugUIController::IsDebugging() const {
    return currentState_ != DapState::Disconnected && 
           currentState_ != DapState::Stopped;
}

DapState DebugUIController::GetState() const {
    return currentState_;
}

// ============================================================================
// CallStackPanel Implementation
// ============================================================================
CallStackPanel::CallStackPanel() = default;
CallStackPanel::~CallStackPanel() = default;

bool CallStackPanel::Create(HWND hwndParent, int x, int y, int width, int height) {
    // Create container window
    hwnd_ = CreateWindowExW(WS_EX_CLIENTEDGE, L"STATIC", L"Call Stack",
                           WS_VISIBLE | WS_CHILD | SS_LEFT,
                           x, y, width, height,
                           hwndParent, nullptr, GetModuleHandle(nullptr), nullptr);
    
    if (!hwnd_) return false;
    
    // Create ListView
    hwndList_ = CreateWindowExW(0, WC_LISTVIEWW, L"",
                               WS_VISIBLE | WS_CHILD | LVS_REPORT | LVS_SINGLESEL,
                               0, 20, width, height - 20,
                               hwnd_, nullptr, GetModuleHandle(nullptr), nullptr);
    
    if (!hwndList_) return false;
    
    // Set up columns
    LVCOLUMNW col = {};
    col.mask = LVCF_TEXT | LVCF_WIDTH;
    
    col.pszText = const_cast<LPWSTR>(L"Name");
    col.cx = width * 0.5;
    ListView_InsertColumn(hwndList_, 0, &col);
    
    col.pszText = const_cast<LPWSTR>(L"File");
    col.cx = width * 0.3;
    ListView_InsertColumn(hwndList_, 1, &col);
    
    col.pszText = const_cast<LPWSTR>(L"Line");
    col.cx = width * 0.2;
    ListView_InsertColumn(hwndList_, 2, &col);
    
    return true;
}

void CallStackPanel::Destroy() {
    if (hwnd_) {
        DestroyWindow(hwnd_);
        hwnd_ = nullptr;
        hwndList_ = nullptr;
    }
}

void CallStackPanel::SetStackFrames(const std::vector<StackFrame>& frames) {
    frames_ = frames;

    // Clear existing
    ListView_DeleteAllItems(hwndList_);

    // Add items
    for (size_t i = 0; i < frames_.size(); i++) {
        auto& frame = frames_[i];

        // Ensure wide strings are initialized (stored in frame, persist with frames_)
        frame.EnsureWideStrings();

        LVITEMW item = {};
        item.mask = LVIF_TEXT;
        item.iItem = static_cast<int>(i);
        item.pszText = const_cast<LPWSTR>(frame.wname.c_str());
        ListView_InsertItem(hwndList_, &item);

        // Extract filename from path
        std::wstring wFileName;
        size_t pos = frame.source.find_last_of("\\/");
        if (pos != std::string::npos) {
            wFileName = frame.wsource.substr(pos + 1);
        } else {
            wFileName = frame.wsource;
        }
        ListView_SetItemText(hwndList_, i, 1, const_cast<LPWSTR>(wFileName.c_str()));

        // Store line number string persistently in frame
        frame.lineStr = std::to_wstring(frame.line);
        ListView_SetItemText(hwndList_, i, 2, const_cast<LPWSTR>(frame.lineStr.c_str()));
    }
}

void CallStackPanel::Clear() {
    frames_.clear();
    ListView_DeleteAllItems(hwndList_);
}

void CallStackPanel::SelectFrame(uint32_t frameId) {
    // Find and select the frame
    for (size_t i = 0; i < frames_.size(); i++) {
        if (frames_[i].id == frameId) {
            ListView_SetItemState(hwndList_, i, LVIS_SELECTED | LVIS_FOCUSED, 
                                 LVIS_SELECTED | LVIS_FOCUSED);
            ListView_EnsureVisible(hwndList_, i, FALSE);
            break;
        }
    }
}

void CallStackPanel::Show(bool show) {
    ShowWindow(hwnd_, show ? SW_SHOW : SW_HIDE);
}

bool CallStackPanel::IsVisible() const {
    return IsWindowVisible(hwnd_) == TRUE;
}

// ============================================================================
// DebugToolbar Implementation
// ============================================================================
DebugToolbar::DebugToolbar() = default;
DebugToolbar::~DebugToolbar() = default;

bool DebugToolbar::Create(HWND hwndParent, int x, int y, int width) {
    hwnd_ = CreateWindowExW(0, TOOLBARCLASSNAMEW, nullptr,
                           WS_VISIBLE | WS_CHILD | TBSTYLE_FLAT | TBSTYLE_TOOLTIPS,
                           x, y, width, 30,
                           hwndParent, nullptr, GetModuleHandle(nullptr), nullptr);
    
    if (!hwnd_) return false;
    
    // Send TB_BUTTONSTRUCTSIZE message
    SendMessage(hwnd_, TB_BUTTONSTRUCTSIZE, sizeof(TBBUTTON), 0);
    
    // Add buttons
    TBBUTTON buttons[] = {
        { 0, ID_DEBUG_CONTINUE, TBSTATE_ENABLED, BTNS_BUTTON, {0}, 0, (INT_PTR)L"Continue" },
        { 1, ID_DEBUG_PAUSE, TBSTATE_ENABLED, BTNS_BUTTON, {0}, 0, (INT_PTR)L"Pause" },
        { 0, 0, 0, BTNS_SEP, {0}, 0, 0 },
        { 2, ID_DEBUG_STEP_OVER, TBSTATE_ENABLED, BTNS_BUTTON, {0}, 0, (INT_PTR)L"Step Over" },
        { 3, ID_DEBUG_STEP_INTO, TBSTATE_ENABLED, BTNS_BUTTON, {0}, 0, (INT_PTR)L"Step Into" },
        { 4, ID_DEBUG_STEP_OUT, TBSTATE_ENABLED, BTNS_BUTTON, {0}, 0, (INT_PTR)L"Step Out" },
        { 0, 0, 0, BTNS_SEP, {0}, 0, 0 },
        { 5, ID_DEBUG_STOP, TBSTATE_ENABLED, BTNS_BUTTON, {0}, 0, (INT_PTR)L"Stop" },
    };
    
    SendMessage(hwnd_, TB_ADDBUTTONS, ARRAYSIZE(buttons), (LPARAM)buttons);
    
    // Auto-size
    SendMessage(hwnd_, TB_AUTOSIZE, 0, 0);
    
    return true;
}

void DebugToolbar::Destroy() {
    if (hwnd_) {
        DestroyWindow(hwnd_);
        hwnd_ = nullptr;
    }
}

void DebugToolbar::SetState(DapState state) {
    currentState_ = state;
    
    // Enable/disable buttons based on state
    bool isRunning = (state == DapState::Running);
    bool isPaused = (state == DapState::Paused);
    bool isActive = (state != DapState::Disconnected && state != DapState::Stopped);
    
    SendMessage(hwnd_, TB_ENABLEBUTTON, ID_DEBUG_CONTINUE, isPaused ? TRUE : FALSE);
    SendMessage(hwnd_, TB_ENABLEBUTTON, ID_DEBUG_PAUSE, isRunning ? TRUE : FALSE);
    SendMessage(hwnd_, TB_ENABLEBUTTON, ID_DEBUG_STEP_OVER, isPaused ? TRUE : FALSE);
    SendMessage(hwnd_, TB_ENABLEBUTTON, ID_DEBUG_STEP_INTO, isPaused ? TRUE : FALSE);
    SendMessage(hwnd_, TB_ENABLEBUTTON, ID_DEBUG_STEP_OUT, isPaused ? TRUE : FALSE);
    SendMessage(hwnd_, TB_ENABLEBUTTON, ID_DEBUG_STOP, isActive ? TRUE : FALSE);
}

void DebugToolbar::Show(bool show) {
    ShowWindow(hwnd_, show ? SW_SHOW : SW_HIDE);
}

bool DebugToolbar::IsVisible() const {
    return IsWindowVisible(hwnd_) == TRUE;
}

// Command IDs
#define ID_DEBUG_CONTINUE   1001
#define ID_DEBUG_PAUSE      1002
#define ID_DEBUG_STEP_OVER  1003
#define ID_DEBUG_STEP_INTO  1004
#define ID_DEBUG_STEP_OUT   1005
#define ID_DEBUG_STOP       1006
#define ID_DEBUG_RESTART    1007

} // namespace UI
} // namespace Debug
} // namespace RawrXD
