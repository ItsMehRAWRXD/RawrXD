// ============================================================================
// IDE_Integration_Example.cpp - Complete Ghost Text + AI Integration
// ============================================================================
// Add this to your RawrXD_IDE_Win32.cpp or equivalent
// ============================================================================

#include "GhostTextWndProc.hpp"
#include "../deep2/GhostTextSystem.hpp"
#include "../deep2/Deep2Engine.h"
#include <Windows.h>
#include <Scintilla.h>

// ============================================================================
// GLOBALS - Add to your IDE globals
// ============================================================================

// Ghost text system
Deep2::GhostTextSystem* g_pGhostText = nullptr;

// IDE window handles (your existing globals)
HWND g_hMainWindow = nullptr;
HWND g_hMainEditor = nullptr;

// AI runtime bridge (your existing)
class RuntimeBridge;
RuntimeBridge* g_pRuntimeBridge = nullptr;

// ============================================================================
// MENU COMMAND HANDLER - Add to your WM_COMMAND switch
// ============================================================================

void HandleMenuCommand(HWND hwnd, int idm) {
    switch (idm) {
        // === AI GENERATION CONTROL ===
        case IDM_AI_STOP_GENERATION: {
            // Stop AI generation
            if (g_pRuntimeBridge) {
                g_pRuntimeBridge->CancelGeneration();
            }
            // Also dismiss any ghost text
            GhostText_Dismiss();
            break;
        }
        
        // === GHOST TEXT COMMANDS ===
        case IDM_AI_SHOW_COMPLETION: {
            // Trigger AI completion manually
            if (g_pRuntimeBridge) {
                // Get current position
                LRESULT pos = SendMessage(g_hMainEditor, SCI_GETCURRENTPOS, 0, 0);
                LRESULT line = SendMessage(g_hMainEditor, SCI_LINEFROMPOSITION, pos, 0);
                LRESULT col = SendMessage(g_hMainEditor, SCI_GETCOLUMN, pos, 0);
                
                // Request completion from AI
                g_pRuntimeBridge->RequestCompletion(static_cast<int>(line), 
                                                     static_cast<int>(col));
            }
            break;
        }
        
        case IDM_AI_ACCEPT_COMPLETION: {
            // Accept current ghost text
            if (GhostText_IsShowing()) {
                GhostText_Accept();
            }
            break;
        }
        
        case IDM_AI_DISMISS_COMPLETION: {
            // Dismiss ghost text
            GhostText_Dismiss();
            break;
        }
        
        // ... rest of your menu commands
    }
}

// ============================================================================
// ACCELERATOR TABLE - Add to your .rc file or create programmatically
// ============================================================================

/*
// In your resource.h:
#define IDM_AI_STOP_GENERATION  0xE100
#define IDM_AI_SHOW_COMPLETION  0xE101
#define IDM_AI_ACCEPT_COMPLETION 0xE102
#define IDM_AI_DISMISS_COMPLETION 0xE103

// In your .rc file:
IDR_MAINACCEL ACCELERATORS
BEGIN
    "S",    IDM_FILE_SAVE,          VIRTKEY, CONTROL
    "O",    IDM_FILE_OPEN,          VIRTKEY, CONTROL
    VK_F5,  IDM_BUILD_RUN,          VIRTKEY
    VK_CANCEL, IDM_AI_STOP_GENERATION, VIRTKEY, CONTROL  // Ctrl+Break
    VK_SPACE, IDM_AI_SHOW_COMPLETION, VIRTKEY, CONTROL   // Ctrl+Space
    VK_TAB,   IDM_AI_ACCEPT_COMPLETION, VIRTKEY          // Tab (when ghost showing)
    VK_ESCAPE, IDM_AI_DISMISS_COMPLETION, VIRTKEY         // Esc (when ghost showing)
END
*/

// ============================================================================
// INITIALIZATION - Call during IDE startup
// ============================================================================

bool InitializeGhostText(HWND hMainWindow, HWND hEditor) {
    // Create ghost text system
    g_pGhostText = new Deep2::GhostTextSystem();
    if (!g_pGhostText->Initialize(hEditor)) {
        delete g_pGhostText;
        g_pGhostText = nullptr;
        return false;
    }
    
    // Install window procedure hooks
    if (!GhostText_Install(hMainWindow, hEditor)) {
        delete g_pGhostText;
        g_pGhostText = nullptr;
        return false;
    }
    
    // Store globals
    g_hMainWindow = hMainWindow;
    g_hMainEditor = hEditor;
    
    return true;
}

// ============================================================================
// SHUTDOWN - Call during IDE cleanup
// ============================================================================

void ShutdownGhostText() {
    GhostText_Uninstall(g_hMainWindow, g_hMainEditor);
    
    if (g_pGhostText) {
        delete g_pGhostText;
        g_pGhostText = nullptr;
    }
}

// ============================================================================
// AI COMPLETION CALLBACK - Wire to your AI runtime
// ============================================================================

// Call this when AI generates a completion
void OnAICompletionReceived(const char* completion, int insertPos) {
    GhostText_OnAICompletion(completion, insertPos);
}

// Call this when AI streaming starts
void OnAIStreamStarted() {
    GhostText_OnAIStreamStart();
}

// Call this when AI streaming ends
void OnAIStreamEnded() {
    GhostText_OnAIStreamEnd();
}

// ============================================================================
// EDITOR SUBCLASS - Alternative to GhostTextWndProc.cpp
// ============================================================================
// If you prefer to handle everything in your existing WndProc:

LRESULT CALLBACK Your_IDE_WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_KEYDOWN: {
            // Handle ghost text keys
            if (GhostText_IsShowing()) {
                switch (wParam) {
                    case VK_TAB:
                        // Tab accepts ghost text
                        GhostText_Accept();
                        return 0; // Don't pass to editor
                        
                    case VK_ESCAPE:
                        // Escape dismisses ghost text
                        GhostText_Dismiss();
                        return 0;
                        
                    case VK_RIGHT:
                        // Right arrow at end of ghost text accepts
                        if (g_hMainEditor) {
                            LRESULT pos = SendMessage(g_hMainEditor, SCI_GETCURRENTPOS, 0, 0);
                            const char* suggestion = GhostText_GetCurrentSuggestion();
                            if (suggestion) {
                                // Check if at end of ghost text
                                // (simplified - you'd track the anchor position)
                                GhostText_Accept();
                                return 0;
                            }
                        }
                        break;
                        
                    case VK_RETURN:
                    case VK_UP:
                    case VK_DOWN:
                    case VK_PRIOR:
                    case VK_NEXT:
                    case VK_HOME:
                    case VK_END:
                        // Navigation keys dismiss ghost text
                        GhostText_Dismiss();
                        break;
                }
                
                // Any character key dismisses ghost text
                if ((wParam >= VK_SPACE && wParam <= VK_Z) ||
                    (wParam >= VK_NUMPAD0 && wParam <= VK_DIVIDE)) {
                    GhostText_Dismiss();
                }
            }
            break;
        }
        
        case WM_CHAR: {
            // Character input dismisses ghost text
            if (GhostText_IsShowing()) {
                GhostText_Dismiss();
            }
            break;
        }
        
        case WM_LBUTTONDOWN:
        case WM_RBUTTONDOWN:
        case WM_MBUTTONDOWN: {
            // Mouse click dismisses ghost text
            if (GhostText_IsShowing()) {
                GhostText_Dismiss();
            }
            break;
        }
        
        case WM_VSCROLL:
        case WM_HSCROLL:
        case WM_MOUSEWHEEL: {
            // Scrolling dismisses ghost text
            if (GhostText_IsShowing()) {
                GhostText_Dismiss();
            }
            break;
        }
        
        case WM_KILLFOCUS: {
            // Losing focus dismisses ghost text
            if (GhostText_IsShowing()) {
                GhostText_Dismiss();
            }
            break;
        }
        
        case WM_COMMAND: {
            HandleMenuCommand(hwnd, LOWORD(wParam));
            break;
        }
    }
    
    // Call your original window procedure
    // return CallWindowProc(g_pOriginalProc, hwnd, msg, wParam, lParam);
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

// ============================================================================
// SCIINTILLA PAINT INTEGRATION - Add to your editor subclass
// ============================================================================

LRESULT CALLBACK Your_Scintilla_Subclass(HWND hwnd, UINT msg, WPARAM wParam, 
                                           LPARAM lParam, UINT_PTR uIdSubclass,
                                           DWORD_PTR dwRefData) {
    switch (msg) {
        case WM_PAINT: {
            // Let Scintilla paint first
            LRESULT result = DefSubclassProc(hwnd, msg, wParam, lParam);
            
            // Paint ghost text on top
            if (g_pGhostText && g_pGhostText->IsVisible()) {
                PAINTSTRUCT ps;
                HDC hdc = BeginPaint(hwnd, &ps);
                
                // Get caret position
                LRESULT pos = SendMessage(hwnd, SCI_GETCURRENTPOS, 0, 0);
                LRESULT x = SendMessage(hwnd, SCI_POINTXFROMPOSITION, 0, pos);
                LRESULT y = SendMessage(hwnd, SCI_POINTYFROMPOSITION, 0, pos);
                LRESULT lineHeight = SendMessage(hwnd, SCI_TEXTHEIGHT, 0, 0);
                
                // Paint ghost text
                g_pGhostText->PaintAtCaret(hdc, static_cast<int>(x), 
                                           static_cast<int>(y), 
                                           static_cast<int>(lineHeight));
                
                EndPaint(hwnd, &ps);
            }
            
            return result;
        }
    }
    
    return DefSubclassProc(hwnd, msg, wParam, lParam);
}

// ============================================================================
// USAGE EXAMPLE - In your IDE initialization
// ============================================================================

/*
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nCmdShow) {
    // ... create main window and editor ...
    
    HWND hMainWnd = CreateWindow(...);
    HWND hEditor = CreateWindowEx(..., "Scintilla", ...);
    
    // Initialize ghost text
    if (!InitializeGhostText(hMainWnd, hEditor)) {
        MessageBox(hMainWnd, "Failed to initialize ghost text", "Error", MB_OK);
    }
    
    // ... rest of initialization ...
    
    // Cleanup
    ShutdownGhostText();
    return 0;
}
*/

// ============================================================================
// MENU SETUP EXAMPLE
// ============================================================================

/*
void SetupAIMenu(HMENU hMenuBar) {
    HMENU hAIMenu = CreatePopupMenu();
    
    AppendMenu(hAIMenu, MF_STRING, IDM_AI_SHOW_COMPLETION, 
                "Show Completion\tCtrl+Space");
    AppendMenu(hAIMenu, MF_STRING, IDM_AI_ACCEPT_COMPLETION, 
                "Accept Completion\tTab");
    AppendMenu(hAIMenu, MF_STRING, IDM_AI_DISMISS_COMPLETION, 
                "Dismiss Completion\tEsc");
    AppendMenu(hAIMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenu(hAIMenu, MF_STRING, IDM_AI_STOP_GENERATION, 
                "Stop Generation\tCtrl+Break");
    
    AppendMenu(hMenuBar, MF_POPUP, (UINT_PTR)hAIMenu, "&AI");
}
*/
