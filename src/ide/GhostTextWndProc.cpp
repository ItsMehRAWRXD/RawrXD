// ============================================================================
// GhostTextWndProc.cpp - Ghost Text Window Procedure Integration
// ============================================================================
// Wires ghost text into the IDE's main window procedure for Scintilla
// Handles: Tab/ESC to accept/dismiss, caret tracking, paint integration
// ============================================================================

#include "../deep2/GhostTextSystem.hpp"
#include <Windows.h>
#include <Scintilla.h>
#include <string>

// External references - link to your IDE's globals
extern HWND g_hMainEditor;        // Your Scintilla editor handle
extern HWND g_hMainWindow;        // Your IDE main window
extern Deep2::GhostTextSystem* g_pGhostText;  // Global ghost text instance

// Forward declarations
LRESULT CALLBACK IDE_WindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
static WNDPROC g_pOriginalIDEProc = nullptr;

// Ghost text state tracking
struct GhostTextState {
    bool showing = false;
    std::string currentSuggestion;
    int anchorPos = -1;           // Where ghost text starts
    int caretPos = -1;            // Current caret when shown
    bool pendingDismiss = false;  // Flag for async dismiss
};
static GhostTextState g_ghostState;

// ============================================================================
// Ghost Text Subclass Procedure - Attach to IDE Main Window
// ============================================================================
LRESULT CALLBACK GhostText_IDESubclassProc(HWND hwnd, UINT msg, WPARAM wParam, 
                                            LPARAM lParam, UINT_PTR uIdSubclass, 
                                            DWORD_PTR dwRefData) {
    
    switch (msg) {
        // === KEYBOARD HANDLING ===
        case WM_KEYDOWN: {
            // Check if ghost text is showing
            if (!g_ghostState.showing || !g_pGhostText) {
                break; // Pass through to original handler
            }
            
            switch (wParam) {
                case VK_TAB: {
                    // TAB = Accept ghost text
                    if (g_pGhostText->AcceptSuggestion()) {
                        g_ghostState.showing = false;
                        g_ghostState.currentSuggestion.clear();
                        
                        // Notify IDE that text was inserted
                        // Post custom message if needed
                        return 0; // Handled, don't pass to editor
                    }
                    break;
                }
                
                case VK_ESCAPE: {
                    // ESC = Dismiss ghost text
                    if (g_pGhostText->DismissSuggestion()) {
                        g_ghostState.showing = false;
                        g_ghostState.currentSuggestion.clear();
                        
                        // Force editor repaint to clear ghost text
                        if (g_hMainEditor) {
                            InvalidateRect(g_hMainEditor, nullptr, FALSE);
                        }
                        return 0; // Handled
                    }
                    break;
                }
                
                case VK_RIGHT: {
                    // Right arrow - partial accept if at end of ghost text
                    // Check if caret is at ghost text boundary
                    if (g_hMainEditor) {
                        LRESULT caretPos = SendMessage(g_hMainEditor, SCI_GETCURRENTPOS, 0, 0);
                        if (caretPos == g_ghostState.anchorPos + g_ghostState.currentSuggestion.length()) {
                            // At end of ghost text - accept it
                            if (g_pGhostText->AcceptSuggestion()) {
                                g_ghostState.showing = false;
                                g_ghostState.currentSuggestion.clear();
                            }
                        }
                    }
                    break;
                }
                
                case VK_RETURN:
                case VK_UP:
                case VK_DOWN:
                case VK_PRIOR:
                case VK_NEXT:
                case VK_HOME:
                case VK_END: {
                    // Navigation keys dismiss ghost text
                    if (g_pGhostText->DismissSuggestion()) {
                        g_ghostState.showing = false;
                        g_ghostState.currentSuggestion.clear();
                        InvalidateRect(g_hMainEditor, nullptr, FALSE);
                    }
                    break;
                }
            }
            
            // Any other key dismisses ghost text (will be typed)
            if (g_ghostState.showing) {
                // Check if it's a character key
                if ((wParam >= VK_SPACE && wParam <= VK_Z) || 
                    (wParam >= VK_NUMPAD0 && wParam <= VK_DIVIDE)) {
                    g_pGhostText->DismissSuggestion();
                    g_ghostState.showing = false;
                    g_ghostState.currentSuggestion.clear();
                    InvalidateRect(g_hMainEditor, nullptr, FALSE);
                }
            }
            break;
        }
        
        case WM_CHAR: {
            // Character input dismisses ghost text
            if (g_ghostState.showing && g_pGhostText) {
                g_pGhostText->DismissSuggestion();
                g_ghostState.showing = false;
                g_ghostState.currentSuggestion.clear();
                InvalidateRect(g_hMainEditor, nullptr, FALSE);
            }
            break;
        }
        
        // === MOUSE HANDLING ===
        case WM_LBUTTONDOWN:
        case WM_RBUTTONDOWN:
        case WM_MBUTTONDOWN: {
            // Mouse click dismisses ghost text
            if (g_ghostState.showing && g_pGhostText) {
                g_pGhostText->DismissSuggestion();
                g_ghostState.showing = false;
                g_ghostState.currentSuggestion.clear();
                InvalidateRect(g_hMainEditor, nullptr, FALSE);
            }
            break;
        }
        
        // === SCROLL HANDLING ===
        case WM_VSCROLL:
        case WM_HSCROLL:
        case WM_MOUSEWHEEL: {
            // Scrolling dismisses ghost text
            if (g_ghostState.showing && g_pGhostText) {
                g_pGhostText->DismissSuggestion();
                g_ghostState.showing = false;
                g_ghostState.currentSuggestion.clear();
            }
            break;
        }
        
        // === FOCUS HANDLING ===
        case WM_KILLFOCUS: {
            // Losing focus dismisses ghost text
            if (g_ghostState.showing && g_pGhostText) {
                g_pGhostText->DismissSuggestion();
                g_ghostState.showing = false;
                g_ghostState.currentSuggestion.clear();
            }
            break;
        }
        
        // === CUSTOM GHOST TEXT MESSAGES ===
        case WM_USER + 0x1000: { // UWM_SHOW_GHOST_TEXT
            // wParam = caret position, lParam = pointer to string
            if (g_pGhostText && lParam) {
                const char* suggestion = reinterpret_cast<const char*>(lParam);
                int pos = static_cast<int>(wParam);
                
                g_ghostState.anchorPos = pos;
                g_ghostState.caretPos = pos;
                g_ghostState.currentSuggestion = suggestion;
                g_ghostState.showing = true;
                
                // Show ghost text at position
                g_pGhostText->ShowSuggestion(pos, suggestion);
                
                // Force repaint
                InvalidateRect(g_hMainEditor, nullptr, FALSE);
            }
            return 0;
        }
        
        case WM_USER + 0x1001: { // UWM_DISMISS_GHOST_TEXT
            if (g_pGhostText) {
                g_pGhostText->DismissSuggestion();
                g_ghostState.showing = false;
                g_ghostState.currentSuggestion.clear();
                InvalidateRect(g_hMainEditor, nullptr, FALSE);
            }
            return 0;
        }
        
        case WM_USER + 0x1002: { // UWM_ACCEPT_GHOST_TEXT
            if (g_pGhostText) {
                bool accepted = g_pGhostText->AcceptSuggestion();
                if (accepted) {
                    g_ghostState.showing = false;
                    g_ghostState.currentSuggestion.clear();
                }
                return accepted ? 1 : 0;
            }
            return 0;
        }
    }
    
    // Pass to original window procedure
    return DefSubclassProc(hwnd, msg, wParam, lParam);
}

// ============================================================================
// Scintilla Subclass Procedure - For Paint Integration
// ============================================================================
LRESULT CALLBACK GhostText_ScintillaSubclassProc(HWND hwnd, UINT msg, WPARAM wParam,
                                                   LPARAM lParam, UINT_PTR uIdSubclass,
                                                   DWORD_PTR dwRefData) {
    switch (msg) {
        case WM_PAINT: {
            // Let Scintilla paint first
            LRESULT result = DefSubclassProc(hwnd, msg, wParam, lParam);
            
            // Then paint ghost text on top
            if (g_ghostState.showing && g_pGhostText && g_pGhostText->IsVisible()) {
                PAINTSTRUCT ps;
                HDC hdc = BeginPaint(hwnd, &ps);
                
                // Get caret position for ghost text
                LRESULT caretPos = SendMessage(hwnd, SCI_GETCURRENTPOS, 0, 0);
                
                // Convert to point
                LRESULT x = SendMessage(hwnd, SCI_POINTXFROMPOSITION, 0, caretPos);
                LRESULT y = SendMessage(hwnd, SCI_POINTYFROMPOSITION, 0, caretPos);
                
                // Get line height
                LRESULT lineHeight = SendMessage(hwnd, SCI_TEXTHEIGHT, 0, 0);
                
                // Paint ghost text
                if (g_pGhostText) {
                    g_pGhostText->PaintAtCaret(hdc, static_cast<int>(x), static_cast<int>(y), 
                                                static_cast<int>(lineHeight));
                }
                
                EndPaint(hwnd, &ps);
            }
            
            return result;
        }
        
        case WM_KEYDOWN: {
            // Handle ghost text keys in editor too
            if (g_ghostState.showing) {
                switch (wParam) {
                    case VK_TAB:
                        PostMessage(g_hMainWindow, WM_USER + 0x1002, 0, 0); // Accept
                        return 0;
                    case VK_ESCAPE:
                        PostMessage(g_hMainWindow, WM_USER + 0x1001, 0, 0); // Dismiss
                        return 0;
                }
            }
            break;
        }
    }
    
    return DefSubclassProc(hwnd, msg, wParam, lParam);
}

// ============================================================================
// Public API - Install Ghost Text Handling
// ============================================================================

bool GhostText_Install(HWND hMainWindow, HWND hEditor) {
    if (!hMainWindow || !hEditor) return false;
    
    g_hMainWindow = hMainWindow;
    g_hMainEditor = hEditor;
    
    // Subclass main window for keyboard/mouse handling
    BOOL result = SetWindowSubclass(hMainWindow, GhostText_IDESubclassProc, 
                                     1, 0);
    if (!result) return false;
    
    // Subclass Scintilla for paint integration
    result = SetWindowSubclass(hEditor, GhostText_ScintillaSubclassProc,
                               2, 0);
    if (!result) {
        RemoveWindowSubclass(hMainWindow, GhostText_IDESubclassProc, 1);
        return false;
    }
    
    return true;
}

void GhostText_Uninstall(HWND hMainWindow, HWND hEditor) {
    if (hMainWindow) {
        RemoveWindowSubclass(hMainWindow, GhostText_IDESESubclassProc, 1);
    }
    if (hEditor) {
        RemoveWindowSubclass(hEditor, GhostText_ScintillaSubclassProc, 2);
    }
}

// ============================================================================
// Public API - Show Ghost Text
// ============================================================================

void GhostText_ShowSuggestion(int caretPos, const char* suggestion) {
    if (!g_hMainWindow || !suggestion) return;
    
    // Post message to show ghost text (thread-safe)
    PostMessage(g_hMainWindow, WM_USER + 0x1000, 
                static_cast<WPARAM>(caretPos),
                reinterpret_cast<LPARAM>(suggestion));
}

void GhostText_Dismiss() {
    if (!g_hMainWindow) return;
    PostMessage(g_hMainWindow, WM_USER + 0x1001, 0, 0);
}

bool GhostText_Accept() {
    if (!g_hMainWindow) return false;
    LRESULT result = SendMessage(g_hMainWindow, WM_USER + 0x1002, 0, 0);
    return result != 0;
}

bool GhostText_IsShowing() {
    return g_ghostState.showing;
}

const char* GhostText_GetCurrentSuggestion() {
    return g_ghostState.showing ? g_ghostState.currentSuggestion.c_str() : nullptr;
}

// ============================================================================
// Integration with AI Runtime
// ============================================================================

// Call this when AI generates a completion suggestion
void GhostText_OnAICompletion(const char* completion, int insertPos) {
    if (!completion || !*completion) return;
    
    // Initialize ghost text system if needed
    if (!g_pGhostText) {
        g_pGhostText = new Deep2::GhostTextSystem();
        if (!g_pGhostText->Initialize(g_hMainEditor)) {
            delete g_pGhostText;
            g_pGhostText = nullptr;
            return;
        }
    }
    
    // Show the suggestion
    GhostText_ShowSuggestion(insertPos, completion);
}

// Call this when AI streaming starts (dismiss any existing ghost text)
void GhostText_OnAIStreamStart() {
    GhostText_Dismiss();
}

// Call this when AI streaming ends
void GhostText_OnAIStreamEnd() {
    // Ghost text already handled during streaming
}

} // extern "C" or namespace
