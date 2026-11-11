// Win32IDE_Omega1Integration.cpp
// OMEGA-1 v2.0 IDE Integration for RawrXD Win32IDE
// Bridges editor events → IPC → ghost text rendering

#include "../../include/Omega1IDEIntegration.h"
#include "../win32app/Win32IDE.h"
#include <windows.h>
#include <commctrl.h>

// Static integration instance
static Omega1IDEIntegration* s_omega1Integration = nullptr;
static HWND s_hwndEditor = nullptr;
static HWND s_hwndStatusBar = nullptr;

// Custom window messages for OMEGA-1 integration
#define WM_OMEGA1_GHOST_TEXT    (WM_USER + 0x7001)
#define WM_OMEGA1_CLEAR_GHOST   (WM_USER + 0x7002)
#define WM_OMEGA1_STATUS_UPDATE (WM_USER + 0x7003)

// Forward declarations
LRESULT CALLBACK Omega1EditorSubclassProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam, 
                                            UINT_PTR uIdSubclass, DWORD_PTR dwRefData);
static void InitializeOmega1Integration(HWND hwndEditor, HWND hwndStatusBar);
static void ShutdownOmega1Integration();

// =============================================================================
// Public API for Win32IDE
// =============================================================================

extern "C" {

// Called by Win32IDE after editor creation
__declspec(dllexport) void Win32IDE_InitOmega1Integration(HWND hwndEditor, HWND hwndStatusBar)
{
    if (!hwndEditor || !hwndStatusBar)
        return;
    
    s_hwndEditor = hwndEditor;
    s_hwndStatusBar = hwndStatusBar;
    
    InitializeOmega1Integration(hwndEditor, hwndStatusBar);
}

// Called by Win32IDE before destruction
__declspec(dllexport) void Win32IDE_ShutdownOmega1Integration()
{
    ShutdownOmega1Integration();
    s_hwndEditor = nullptr;
    s_hwndStatusBar = nullptr;
}

// Called by Win32IDE to handle custom messages
__declspec(dllexport) bool Win32IDE_HandleOmega1Message(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (!s_omega1Integration)
        return false;
    
    switch (msg)
    {
        case WM_OMEGA1_GHOST_TEXT:
        {
            // wParam = line, lParam = col
            uint32_t line = (uint32_t)wParam;
            uint32_t col = (uint32_t)lParam;
            // Trigger ghost text display at position
            return true;
        }
        
        case WM_OMEGA1_CLEAR_GHOST:
        {
            s_omega1Integration->RejectGhostText();
            return true;
        }
        
        case WM_OMEGA1_STATUS_UPDATE:
        {
            s_omega1Integration->UpdateStatusBar();
            return true;
        }
    }
    
    return s_omega1Integration->HandleMessage(msg, wParam, lParam);
}

// Check if ghost text is currently visible
__declspec(dllexport) bool Win32IDE_IsGhostTextVisible()
{
    return s_omega1Integration ? s_omega1Integration->IsGhostTextVisible() : false;
}

// Accept current ghost text (called on Tab key)
__declspec(dllexport) bool Win32IDE_AcceptGhostText()
{
    return s_omega1Integration ? s_omega1Integration->AcceptGhostText() : false;
}

// Reject current ghost text (called on Escape or typing)
__declspec(dllexport) bool Win32IDE_RejectGhostText()
{
    return s_omega1Integration ? s_omega1Integration->RejectGhostText() : false;
}

} // extern "C"

// =============================================================================
// Implementation
// =============================================================================

static void InitializeOmega1Integration(HWND hwndEditor, HWND hwndStatusBar)
{
    if (s_omega1Integration)
        return; // Already initialized
    
    s_omega1Integration = new Omega1IDEIntegration();
    
    Omega1IntegrationConfig config;
    config.completionDelayMs = 300;      // 300ms debounce
    config.maxTokens = 64;               // Default completion length
    config.temperature = 0.7f;
    config.topP = 0.9f;
    config.enableStreaming = true;
    config.stopOnNewline = true;
    
    if (!s_omega1Integration->Initialize(hwndEditor, config))
    {
        delete s_omega1Integration;
        s_omega1Integration = nullptr;
        OutputDebugStringA("[Omega1] Failed to initialize integration\n");
        return;
    }
    
    // Subclass the editor window to intercept messages
    SetWindowSubclass(hwndEditor, Omega1EditorSubclassProc, 0, 0);
    
    OutputDebugStringA("[Omega1] Integration initialized successfully\n");
}

static void ShutdownOmega1Integration()
{
    if (!s_omega1Integration)
        return;
    
    // Remove subclassing
    if (s_hwndEditor)
        RemoveWindowSubclass(s_hwndEditor, Omega1EditorSubclassProc, 0);
    
    s_omega1Integration->Shutdown();
    delete s_omega1Integration;
    s_omega1Integration = nullptr;
    
    OutputDebugStringA("[Omega1] Integration shutdown\n");
}

// =============================================================================
// Editor Window Subclass Procedure
// Intercepts keystrokes and editor events for OMEGA-1 integration
// =============================================================================

LRESULT CALLBACK Omega1EditorSubclassProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam,
                                            UINT_PTR uIdSubclass, DWORD_PTR dwRefData)
{
    if (!s_omega1Integration)
        return DefSubclassProc(hwnd, msg, wParam, lParam);
    
    switch (msg)
    {
        case WM_CHAR:
        {
            // Any character typed rejects ghost text and triggers new completion
            if (s_omega1Integration->IsGhostTextVisible())
            {
                s_omega1Integration->RejectGhostText();
            }
            
            // Queue completion request
            // Get cursor position from editor
            DWORD pos = SendMessage(hwnd, EM_GETSEL, 0, 0);
            int line = SendMessage(hwnd, EM_LINEFROMCHAR, (WPARAM)LOWORD(pos), 0);
            int col = LOWORD(pos) - SendMessage(hwnd, EM_LINEINDEX, line, 0);
            
            s_omega1Integration->OnEditorTextChanged(line, col);
            break;
        }
        
        case WM_KEYDOWN:
        {
            switch (wParam)
            {
                case VK_TAB:
                    // Tab accepts ghost text
                    if (s_omega1Integration->IsGhostTextVisible())
                    {
                        s_omega1Integration->AcceptGhostText();
                        return 0; // Handled
                    }
                    break;
                    
                case VK_ESCAPE:
                    // Escape rejects ghost text
                    if (s_omega1Integration->IsGhostTextVisible())
                    {
                        s_omega1Integration->RejectGhostText();
                        return 0; // Handled
                    }
                    break;
            }
            break;
        }
        
        case WM_KILLFOCUS:
        {
            s_omega1Integration->OnEditorBlur();
            break;
        }
        
        case WM_SETFOCUS:
        {
            s_omega1Integration->OnEditorFocus();
            break;
        }
        
        case WM_PAINT:
        {
            // Let default paint happen first
            LRESULT result = DefSubclassProc(hwnd, msg, wParam, lParam);
            
            // Then overlay ghost text
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            s_omega1Integration->RenderGhostText(hdc);
            EndPaint(hwnd, &ps);
            
            return result;
        }
    }
    
    return DefSubclassProc(hwnd, msg, wParam, lParam);
}
