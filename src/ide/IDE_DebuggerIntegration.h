/*===========================================================================
 * IDE_DebuggerIntegration.h
 * RawrXD IDE Debugger UI Integration
 * 
 * Win32 UI components for debugger:
 * - Register viewer panel
 * - Memory viewer panel
 * - Breakpoint margin
 * - Debug toolbar
 *===========================================================================*/

#ifndef IDE_DEBUGGER_INTEGRATION_H
#define IDE_DEBUGGER_INTEGRATION_H

#include <windows.h>
#include <string>
#include "DebuggerService.h"

namespace RawrXD {

// Window message for debug events
#define WM_DEBUG_EVENT      (WM_USER + 100)
#define WM_DEBUG_UPDATE     (WM_USER + 101)

// Debug command IDs (for toolbar/menu)
#define ID_DEBUG_START          40001
#define ID_DEBUG_STOP           40002
#define ID_DEBUG_PAUSE          40003
#define ID_DEBUG_CONTINUE       40004
#define ID_DEBUG_STEP_INTO      40005
#define ID_DEBUG_STEP_OVER      40006
#define ID_DEBUG_STEP_OUT       40007
#define ID_DEBUG_TOGGLE_BP      40008
#define ID_DEBUG_SHOW_REGISTERS 40009
#define ID_DEBUG_SHOW_MEMORY    40010
#define ID_DEBUG_SHOW_CALLSTACK 40011

/*===========================================================================
 * DEBUG TOOLBAR
 *===========================================================================*/

class DebugToolbar {
public:
    DebugToolbar();
    ~DebugToolbar();
    
    bool Create(HWND parentWnd, int x, int y, int width, int height);
    void Destroy();
    
    void UpdateState(DebugState state);
    void EnableButton(int cmdId, bool enable);
    
    HWND GetHandle() const { return m_hwnd; }
    
    // Command handlers
    void OnStart();
    void OnStop();
    void OnPause();
    void OnContinue();
    void OnStepInto();
    void OnStepOver();
    void OnStepOut();
    void OnToggleBreakpoint();

private:
    HWND m_hwnd;
    HWND m_parent;
    HIMAGELIST m_imageList;
    
    struct Button {
        int id;
        int imageIndex;
        const char* tooltip;
        bool enabled;
    };
    
    static Button s_buttons[];
    static const int s_buttonCount;
};

/*===========================================================================
 * REGISTER VIEWER PANEL
 *===========================================================================*/

class RegisterViewerPanel {
public:
    RegisterViewerPanel();
    ~RegisterViewerPanel();
    
    bool Create(HWND parentWnd, int x, int y, int width, int height);
    void Destroy();
    
    void UpdateRegisters(const RegisterSet& regs);
    void Clear();
    
    void Show(bool show);
    bool IsVisible() const;
    
    HWND GetHandle() const { return m_hwnd; }

private:
    static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    LRESULT HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam);
    
    void Paint(HDC hdc);
    void DrawRegister(HDC hdc, int x, int& y, const char* name, uint64_t value, bool modified);
    
    HWND m_hwnd;
    HWND m_parent;
    RegisterSet m_currentRegs;
    RegisterSet m_previousRegs;
    HFONT m_font;
    HFONT m_fontBold;
    
    static const int s_regCount = 17;
    static const char* s_regNames[s_regCount];
};

/*===========================================================================
 * MEMORY VIEWER PANEL
 *===========================================================================*/

class MemoryViewerPanel {
public:
    MemoryViewerPanel();
    ~MemoryViewerPanel();
    
    bool Create(HWND parentWnd, int x, int y, int width, int height);
    void Destroy();
    
    void SetAddress(uint64_t address);
    void Refresh();
    void Clear();
    
    void Show(bool show);
    bool IsVisible() const;
    
    HWND GetHandle() const { return m_hwnd; }

private:
    static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    LRESULT HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam);
    
    void Paint(HDC hdc);
    void OnScroll(int scrollCode, int pos);
    void OnAddressChange();
    
    HWND m_hwnd;
    HWND m_parent;
    HWND m_editAddress;
    HWND m_scrollbar;
    
    uint64_t m_baseAddress;
    std::vector<uint8_t> m_memoryData;
    int m_lineCount;
    int m_visibleLines;
    
    HFONT m_font;
    HFONT m_fontFixed;
    
    static const int s_bytesPerLine = 16;
    static const int s_maxLines = 1024;
};

/*===========================================================================
 * CALL STACK PANEL
 *===========================================================================*/

class CallStackPanel {
public:
    CallStackPanel();
    ~CallStackPanel();
    
    bool Create(HWND parentWnd, int x, int y, int width, int height);
    void Destroy();
    
    void UpdateStack(const std::vector<StackFrame>& frames);
    void Clear();
    
    void Show(bool show);
    bool IsVisible() const;
    
    int GetSelectedFrame() const;
    
    HWND GetHandle() const { return m_hwnd; }

private:
    static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    LRESULT HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam);
    
    void OnDoubleClick(int index);
    
    HWND m_hwnd;
    HWND m_parent;
    HWND m_listView;
    std::vector<StackFrame> m_frames;
    
    HFONT m_font;
};

/*===========================================================================
 * BREAKPOINT MARGIN
 *===========================================================================*/

class BreakpointMargin {
public:
    BreakpointMargin();
    
    void AttachToEditor(HWND editorWnd);
    void Detach();
    
    void ToggleBreakpoint(int line);
    bool HasBreakpoint(int line) const;
    void ClearAllBreakpoints();
    
    void Paint(HDC hdc, const RECT& rect, int firstLine, int lineCount);
    bool OnMouseClick(int x, int y, int line);
    
    void SetCurrentLine(int line);
    void ClearCurrentLine();

private:
    HWND m_editorWnd;
    int m_marginWidth;
    int m_currentLine;
    
    static const int BP_MARGIN_WIDTH = 24;
};

/*===========================================================================
 * DEBUGGER UI MANAGER
 *===========================================================================*/

class DebuggerUIManager {
public:
    static DebuggerUIManager& GetInstance();
    
    bool Initialize(HWND mainWnd);
    void Shutdown();
    
    // Window procedure integration
    bool OnCommand(int cmdId);
    bool OnDebugEvent(WPARAM wParam, LPARAM lParam);
    void OnDebugUpdate();
    
    // Keyboard shortcuts
    bool OnKeyDown(int vkCode, bool ctrl, bool shift);
    
    // State updates
    void UpdateDebugState(DebugState state);
    void UpdateRegisterView();
    void UpdateMemoryView();
    void UpdateCallStack();
    
    // Panel visibility
    void ShowRegisterPanel(bool show);
    void ShowMemoryPanel(bool show);
    void ShowCallStackPanel(bool show);
    void TogglePanels();
    
    // Access to panels
    DebugToolbar* GetToolbar() { return &m_toolbar; }
    RegisterViewerPanel* GetRegisterPanel() { return &m_regPanel; }
    MemoryViewerPanel* GetMemoryPanel() { return &m_memPanel; }
    CallStackPanel* GetCallStackPanel() { return &m_stackPanel; }

private:
    DebuggerUIManager();
    ~DebuggerUIManager();
    
    DebugToolbar m_toolbar;
    RegisterViewerPanel m_regPanel;
    MemoryViewerPanel m_memPanel;
    CallStackPanel m_stackPanel;
    
    HWND m_mainWnd;
    bool m_initialized;
    
    // Event callback
    static void OnDebugEventCallback(const DebugEvent& event);
    static void OnStateChangeCallback(DebugState oldState, DebugState newState);
};

/*===========================================================================
 * INTEGRATION HELPERS
 *===========================================================================*/

// Initialize debugger subsystem
bool IDE_InitDebugger(HWND mainWnd);

// Shutdown debugger subsystem
void IDE_ShutdownDebugger();

// Handle WM_COMMAND for debug commands
bool IDE_HandleDebugCommand(int cmdId);

// Handle WM_DEBUG_EVENT
bool IDE_HandleDebugEvent(WPARAM wParam, LPARAM lParam);

// Handle keyboard shortcuts
bool IDE_HandleDebugKeys(int vkCode, bool ctrl, bool shift);

// Update UI for current debug state
void IDE_UpdateDebugUI();

// Show/hide debug panels
void IDE_ShowDebugPanels(bool show);

} // namespace RawrXD

#endif // IDE_DEBUGGER_INTEGRATION_H
