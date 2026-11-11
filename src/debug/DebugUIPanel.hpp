// DebugUIPanel.hpp
// Phase 24: RawrXD IDE Debugger UI Integration
// ============================================================================
// Bridges DapService events to Win32 UI panels
// ============================================================================

#pragma once

#include "DapService.hpp"
#include <windows.h>
#include <commctrl.h>
#include <string>
#include <vector>
#include <functional>

namespace RawrXD {
namespace Debug {
namespace UI {

// Forward declarations
class CallStackPanel;
class VariablesPanel;
class BreakpointsPanel;
class DebugOutputPanel;
class DebugToolbar;

// ============================================================================
// Debug UI Controller
// ============================================================================
class DebugUIController {
public:
    static DebugUIController& instance();
    
    // Initialization
    bool Initialize(HWND hwndParent);
    void Shutdown();
    
    // Panel management
    void ShowCallStackPanel(bool show);
    void ShowVariablesPanel(bool show);
    void ShowBreakpointsPanel(bool show);
    void ShowDebugOutputPanel(bool show);
    void ShowDebugToolbar(bool show);
    
    // DAP Service integration
    void AttachToDapService(DapService* service);
    void DetachFromDapService();
    
    // Event handlers (called by DapService)
    void OnStopped(uint64_t threadId, const std::string& reason, const std::string& description);
    void OnContinued(uint64_t threadId);
    void OnStackTraceReceived(uint32_t threadId, const std::vector<StackFrame>& frames);
    void OnVariablesReceived(uint32_t variablesReference, const std::vector<Variable>& vars);
    void OnBreakpointChanged(const Breakpoint& bp);
    void OnOutput(OutputChannel channel, const std::string& data);
    void OnTerminated();
    void OnStateChanged(DapState oldState, DapState newState);
    void OnError(const std::string& error, bool fatal);
    
    // User actions (called by UI)
    void OnUserContinue();
    void OnUserPause();
    void OnUserStepOver();
    void OnUserStepInto();
    void OnUserStepOut();
    void OnUserSetBreakpoint(const std::string& file, uint32_t line);
    void OnUserRemoveBreakpoint(const std::string& file, uint32_t line);
    void OnUserSelectFrame(uint32_t frameId);
    void OnUserEvaluateExpression(const std::string& expression);
    
    // Status
    bool IsDebugging() const;
    DapState GetState() const;
    
private:
    DebugUIController() = default;
    ~DebugUIController() = default;
    
    DapService* dapService_ = nullptr;
    
    // UI Panels
    std::unique_ptr<CallStackPanel> callStackPanel_;
    std::unique_ptr<VariablesPanel> variablesPanel_;
    std::unique_ptr<BreakpointsPanel> breakpointsPanel_;
    std::unique_ptr<DebugOutputPanel> outputPanel_;
    std::unique_ptr<DebugToolbar> toolbar_;
    
    HWND hwndParent_ = nullptr;
    bool initialized_ = false;
    
    // Current state
    DapState currentState_ = DapState::Disconnected;
    uint64_t currentThreadId_ = 0;
    uint32_t selectedFrameId_ = 0;
    
    // Thread marshalling
    void MarshalToUIThread(std::function<void()> action);
    static LRESULT CALLBACK MarshalWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    
    void SetupDapCallbacks();
    void ClearDapCallbacks();
};

// ============================================================================
// Call Stack Panel
// ============================================================================
class CallStackPanel {
public:
    CallStackPanel();
    ~CallStackPanel();
    
    bool Create(HWND hwndParent, int x, int y, int width, int height);
    void Destroy();
    
    void SetStackFrames(const std::vector<StackFrame>& frames);
    void Clear();
    void SelectFrame(uint32_t frameId);
    
    void Show(bool show);
    bool IsVisible() const;
    
    // Callback when user selects a frame
    std::function<void(uint32_t frameId)> onFrameSelected;
    
private:
    HWND hwnd_ = nullptr;
    HWND hwndList_ = nullptr;
    std::vector<StackFrame> frames_;
    
    static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    void OnNotify(NMHDR* pnmh);
    void OnItemChanged(int itemIndex);
};

// ============================================================================
// Variables Panel
// ============================================================================
class VariablesPanel {
public:
    VariablesPanel();
    ~VariablesPanel();
    
    bool Create(HWND hwndParent, int x, int y, int width, int height);
    void Destroy();
    
    void SetVariables(const std::vector<Variable>& vars);
    void Clear();
    void ExpandVariable(uint32_t variablesReference);
    
    void Show(bool show);
    bool IsVisible() const;
    
private:
    HWND hwnd_ = nullptr;
    HWND hwndTree_ = nullptr;
};

// ============================================================================
// Breakpoints Panel
// ============================================================================
class BreakpointsPanel {
public:
    BreakpointsPanel();
    ~BreakpointsPanel();
    
    bool Create(HWND hwndParent, int x, int y, int width, int height);
    void Destroy();
    
    void AddBreakpoint(const Breakpoint& bp);
    void RemoveBreakpoint(uint32_t breakpointId);
    void UpdateBreakpoint(const Breakpoint& bp);
    void Clear();
    
    void Show(bool show);
    bool IsVisible() const;
    
private:
    HWND hwnd_ = nullptr;
    HWND hwndList_ = nullptr;
    std::map<uint32_t, Breakpoint> breakpoints_;
};

// ============================================================================
// Debug Output Panel
// ============================================================================
class DebugOutputPanel {
public:
    DebugOutputPanel();
    ~DebugOutputPanel();
    
    bool Create(HWND hwndParent, int x, int y, int width, int height);
    void Destroy();
    
    void AppendOutput(OutputChannel channel, const std::string& text);
    void Clear();
    
    void Show(bool show);
    bool IsVisible() const;
    
private:
    HWND hwnd_ = nullptr;
    HWND hwndEdit_ = nullptr;
};

// ============================================================================
// Debug Toolbar
// ============================================================================
class DebugToolbar {
public:
    DebugToolbar();
    ~DebugToolbar();
    
    bool Create(HWND hwndParent, int x, int y, int width);
    void Destroy();
    
    void SetState(DapState state);
    void EnableButton(int buttonId, bool enable);
    
    void Show(bool show);
    bool IsVisible() const;
    
    // Callbacks
    std::function<void()> onContinue;
    std::function<void()> onPause;
    std::function<void()> onStepOver;
    std::function<void()> onStepInto;
    std::function<void()> onStepOut;
    std::function<void()> onStop;
    std::function<void()> onRestart;
    
private:
    HWND hwnd_ = nullptr;
    HWND hwndToolbar_ = nullptr;
    DapState currentState_ = DapState::Disconnected;
    
    static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    void OnCommand(int cmd);
};

// ============================================================================
// Utility Functions
// ============================================================================
void ShowDebugWindow(HWND hwndParent);
void HideDebugWindow();
bool IsDebugWindowVisible();

} // namespace UI
} // namespace Debug
} // namespace RawrXD
