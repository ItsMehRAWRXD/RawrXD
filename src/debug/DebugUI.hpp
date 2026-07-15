//=============================================================================
// RawrXD Debug UI Integration — Phase 24
// Pure Win32, Zero External Dependencies
// Wires Debugger_Backend.cpp to IDE visual panels
//=============================================================================
#pragma once

#include <windows.h>
#include <commctrl.h>

// Forward declare backend types (from Debugger_Backend.cpp)
struct DebugSession;
struct StackFrame;
struct RegisterContext;
enum class DebugEventType;

namespace RawrXD {
namespace DebugUI {

//=============================================================================
// Panel Window Classes
//=============================================================================

// Breakpoint Gutter — drawn in editor margin
class BreakpointGutter {
public:
    static constexpr int GUTTER_WIDTH = 16;
    
    void Initialize(HWND hEditor);
    void Shutdown();
    
    // Toggle breakpoint at line
    void ToggleBreakpoint(int line);
    void ClearBreakpoint(int line);
    bool HasBreakpoint(int line) const;
    
    // Paint gutter region
    void OnPaint(HDC hdc, const RECT& rcGutter, int firstLine, int lineCount);
    
    // Hit test: returns line number or -1
    int HitTest(int x, int y) const;
    
    // Sync with backend
    void SyncWithBackend(DebugSession* session);
    
private:
    HWND m_hEditor = nullptr;
    int* m_breakLines = nullptr;  // Dynamic array, no STL
    int m_bpCapacity = 0;
    int m_bpCount = 0;
    
    void GrowBreakpointArray();
    int FindBreakpointIndex(int line) const;
};

// Call Stack Panel — TreeView in sidebar
class CallStackPanel {
public:
    void Initialize(HWND hParent, int x, int y, int w, int h);
    void Shutdown();
    
    void Update(const StackFrame* frames, int count);
    void Clear();
    
    // Selection changed callback
    void SetSelectionCallback(void (*callback)(int frameIndex, void* user), void* user);
    
    HWND GetHwnd() const { return m_hWnd; }
    
private:
    HWND m_hWnd = nullptr;
    HWND m_hTree = nullptr;
    void (*m_onSelect)(int, void*) = nullptr;
    void* m_user = nullptr;
    
    static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
    void OnCreate();
    void OnSize(int w, int h);
    void OnNotify(NMHDR* pnmh);
};

// Register View Panel
class RegisterPanel {
public:
    void Initialize(HWND hParent, int x, int y, int w, int h);
    void Shutdown();
    
    void Update(const RegisterContext* ctx);
    void Clear();
    
    // Toggle hex/decimal display
    void ToggleFormat();
    
    HWND GetHwnd() const { return m_hWnd; }
    
private:
    HWND m_hWnd = nullptr;
    HWND m_hList = nullptr;
    bool m_hexMode = true;
    
    static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
    void OnCreate();
    void OnSize(int w, int h);
    void PopulateList(const RegisterContext* ctx);
};

// Memory View Panel — hex dump with edit
class MemoryPanel {
public:
    void Initialize(HWND hParent, int x, int y, int w, int h);
    void Shutdown();
    
    void SetAddress(uint64_t addr);
    void Refresh(DebugSession* session);
    void SetEditMode(bool edit);
    
    HWND GetHwnd() const { return m_hWnd; }
    
private:
    HWND m_hWnd = nullptr;
    HWND m_hEdit = nullptr;      // Address input
    HWND m_hHex = nullptr;       // Hex dump (owner-drawn)
    uint64_t m_address = 0;
    uint8_t m_buffer[256] = {};
    bool m_editMode = false;
    int m_bytesPerRow = 16;
    
    static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
    void OnCreate();
    void OnSize(int w, int h);
    void OnPaint(HDC hdc);
    void OnLButtonDown(int x, int y);
    void OnChar(WPARAM ch);
};

// Debug Toolbar — Play/Step/Stop buttons
class DebugToolbar {
public:
    void Initialize(HWND hParent, int x, int y, int w, int h);
    void Shutdown();
    
    void SetRunning(bool running);
    void SetAttached(bool attached);
    
    // Callbacks
    void SetCallbacks(
        void (*onGo)(void*),
        void (*onStep)(void*),
        void (*onStepOver)(void*),
        void (*onStop)(void*),
        void* user
    );
    
    HWND GetHwnd() const { return m_hWnd; }
    
private:
    HWND m_hWnd = nullptr;
    HWND m_hBtnGo = nullptr;
    HWND m_hBtnStep = nullptr;
    HWND m_hBtnStepOver = nullptr;
    HWND m_hBtnStop = nullptr;
    
    void (*m_onGo)(void*) = nullptr;
    void (*m_onStep)(void*) = nullptr;
    void (*m_onStepOver)(void*) = nullptr;
    void (*m_onStop)(void*) = nullptr;
    void* m_user = nullptr;
    
    static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
    void OnCommand(int id);
};

// Debug Event Log — Output panel
class DebugEventLog {
public:
    void Initialize(HWND hParent, int x, int y, int w, int h);
    void Shutdown();
    
    void Log(const char* message);
    void LogException(uint32_t code, uint64_t addr);
    void LogBreakpoint(uint64_t addr);
    void LogDllLoad(const wchar_t* path, uint64_t base);
    void Clear();
    
    HWND GetHwnd() const { return m_hWnd; }
    
private:
    HWND m_hWnd = nullptr;
    HWND m_hEdit = nullptr;
    int m_lineCount = 0;
    static constexpr int MAX_LINES = 1000;
    
    void AppendText(const char* text);
    void TrimOldLines();
};

//=============================================================================
// Debug UI Manager — Orchestrates all panels
//=============================================================================
class DebugUIManager {
public:
    static DebugUIManager& Instance();
    
    bool Initialize(HWND hMainWindow);
    void Shutdown();
    
    // Backend connection
    void AttachSession(DebugSession* session);
    void DetachSession();
    
    // Event handlers from backend
    void OnBreakpointHit(uint64_t addr);
    void OnException(uint32_t code, uint64_t addr);
    void OnStepComplete();
    void OnProcessExit(uint32_t code);
    void OnDllLoad(const wchar_t* path, uint64_t base);
    
    // Layout
    void OnMainResize(int width, int height);
    void ShowPanels(bool show);
    bool ArePanelsVisible() const;
    
    // Panel accessors
    BreakpointGutter& GetGutter() { return m_gutter; }
    CallStackPanel& GetCallStack() { return m_callstack; }
    RegisterPanel& GetRegisters() { return m_registers; }
    MemoryPanel& GetMemory() { return m_memory; }
    DebugToolbar& GetToolbar() { return m_toolbar; }
    DebugEventLog& GetEventLog() { return m_eventLog; }
    
private:
    DebugUIManager() = default;
    
    HWND m_hMain = nullptr;
    DebugSession* m_session = nullptr;
    bool m_visible = false;
    
    // Panel instances
    BreakpointGutter m_gutter;
    CallStackPanel m_callstack;
    RegisterPanel m_registers;
    MemoryPanel m_memory;
    DebugToolbar m_toolbar;
    DebugEventLog m_eventLog;
    
    // Layout rects
    RECT m_rcToolbar;
    RECT m_rcCallStack;
    RECT m_rcRegisters;
    RECT m_rcMemory;
    RECT m_rcEventLog;
    
    void CalculateLayout(int width, int height);
    void CreatePanelWindows();
    void DestroyPanelWindows();
};

} // namespace DebugUI
} // namespace RawrXD
