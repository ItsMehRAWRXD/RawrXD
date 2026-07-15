// GhostText_TimerHook.cpp
// Win32 Message Loop Integration for Ghost Text Debounce Timer
// Integrates with existing Win32IDE_Main.cpp

#include <windows.h>
#include <cstdio>
#include <cstring>

// ============================================================================
// CONFIGURATION
// ============================================================================
constexpr UINT GHOST_TEXT_TIMER_ID = 0xBEEF;      // Unique timer ID
constexpr UINT DEBOUNCE_DELAY_MS = 300;           // 300ms debounce (Copilot-style)

// ============================================================================
// EXTERNAL BRIDGE FUNCTIONS (from Bridge_Mock_Suggestion.asm)
// ============================================================================
extern "C" {
    int Bridge_GetSuggestionText(const char* contextLine, int cursorCol, 
                                  char* outBuffer, int bufferSize);
    void Bridge_RequestSuggestion(void);
    int Bridge_IsSuggestionReady(void);
    void Bridge_ClearSuggestion(void);
}

// ============================================================================
// GHOST TEXT STATE
// ============================================================================
struct GhostTextState {
    bool active;                    // Is ghost text currently showing?
    bool timerRunning;              // Is debounce timer active?
    int cursorLine;                 // Line where suggestion was triggered
    int cursorCol;                  // Column where suggestion starts
    char suggestionText[256];       // Current suggestion text
    DWORD timestamp;                // When suggestion was received
};

static GhostTextState g_ghostState = { false, false, 0, 0, {0}, 0 };

// ============================================================================
// EDITOR INTERFACE (stubs - implement with your actual editor)
// ============================================================================
class IEditorWindow {
public:
    virtual const char* GetCurrentLineText() = 0;
    virtual int GetCursorLine() = 0;
    virtual int GetCursorColumn() = 0;
    virtual void InsertText(const char* text, int len) = 0;
    virtual void Invalidate() = 0;
};

static IEditorWindow* g_pEditor = nullptr;

void SetEditorWindow(IEditorWindow* pEditor) {
    g_pEditor = pEditor;
}

// ============================================================================
// GHOST TEXT TIMER MANAGEMENT
// ============================================================================

// Call this from WM_KEYDOWN/WM_CHAR in your WndProc
void GhostText_OnKeystroke(HWND hwndEditor) {
    // Kill any existing timer
    if (g_ghostState.timerRunning) {
        KillTimer(hwndEditor, GHOST_TEXT_TIMER_ID);
    }
    
    // Hide current ghost text (user is typing)
    if (g_ghostState.active) {
        g_ghostState.active = false;
        Bridge_ClearSuggestion();
        if (g_pEditor) g_pEditor->Invalidate();
    }
    
    // Start debounce timer
    SetTimer(hwndEditor, GHOST_TEXT_TIMER_ID, DEBOUNCE_DELAY_MS, nullptr);
    g_ghostState.timerRunning = true;
}

// Call this from WM_TIMER in your WndProc
void GhostText_OnTimer(HWND hwndEditor, WPARAM timerId) {
    if (timerId != GHOST_TEXT_TIMER_ID) return;
    
    g_ghostState.timerRunning = false;
    
    if (!g_pEditor) return;
    
    // Request suggestion from bridge
    Bridge_RequestSuggestion();
    
    // Get current cursor position
    g_ghostState.cursorLine = g_pEditor->GetCursorLine();
    g_ghostState.cursorCol = g_pEditor->GetCursorColumn();
    
    // Try to get suggestion
    const char* contextLine = g_pEditor->GetCurrentLineText();
    int len = Bridge_GetSuggestionText(contextLine, g_ghostState.cursorCol,
                                       g_ghostState.suggestionText, 
                                       sizeof(g_ghostState.suggestionText));
    
    if (len > 0) {
        // Show ghost text
        g_ghostState.active = true;
        g_ghostState.timestamp = GetTickCount();
        g_pEditor->Invalidate();
    }
}

// Call this from WM_KEYDOWN for Tab/Escape handling
bool GhostText_OnKeyDown(HWND hwndEditor, WPARAM vk) {
    if (!g_ghostState.active) return false; // Not handled
    
    switch (vk) {
        case VK_TAB: {
            // Accept full suggestion
            if (g_pEditor) {
                g_pEditor->InsertText(g_ghostState.suggestionText, 
                                      (int)strlen(g_ghostState.suggestionText));
            }
            g_ghostState.active = false;
            Bridge_ClearSuggestion();
            if (g_pEditor) g_pEditor->Invalidate();
            return true; // Handled
        }
        
        case VK_ESCAPE: {
            // Dismiss suggestion
            g_ghostState.active = false;
            Bridge_ClearSuggestion();
            if (g_pEditor) g_pEditor->Invalidate();
            return true; // Handled
        }
        
        case VK_RIGHT: {
            // Check for Ctrl+Right (partial accept)
            if (GetAsyncKeyState(VK_CONTROL) & 0x8000) {
                // Accept next word
                char* p = g_ghostState.suggestionText;
                int wordLen = 0;
                
                // Skip leading spaces
                while (*p == ' ') { p++; wordLen++; }
                
                // Find word boundary
                while (*p && *p != ' ' && *p != '
') {
                    p++;
                    wordLen++;
                }
                
                if (wordLen > 0 && g_pEditor) {
                    char wordBuf[64];
                    strncpy_s(wordBuf, g_ghostState.suggestionText, wordLen);
                    wordBuf[wordLen] = '\0';
                    g_pEditor->InsertText(wordBuf, wordLen);
                    
                    // Remove accepted portion from suggestion
                    memmove(g_ghostState.suggestionText, p, strlen(p) + 1);
                    
                    if (strlen(g_ghostState.suggestionText) == 0) {
                        g_ghostState.active = false;
                        Bridge_ClearSuggestion();
                    }
                    
                    g_pEditor->Invalidate();
                }
                return true; // Handled
            }
            break;
        }
    }
    
    return false; // Not handled
}

// ============================================================================
// GHOST TEXT RENDERING
// ============================================================================

// Call this from your WM_PAINT handler after drawing editor content
void GhostText_Render(HDC hdc, int cursorScreenX, int cursorScreenY,
                        int lineHeight, const RECT& clipRect) {
    if (!g_ghostState.active) return;
    
    // Save DC state
    int oldBkMode = SetBkMode(hdc, TRANSPARENT);
    COLORREF oldColor = SetTextColor(hdc, RGB(128, 128, 128)); // Gray
    
    // Create italic font for ghost text
    HFONT hFont = (HFONT)GetCurrentObject(hdc, OBJ_FONT);
    LOGFONT lf = {};
    GetObject(hFont, sizeof(lf), &lf);
    lf.lfItalic = TRUE;
    HFONT hGhostFont = CreateFontIndirect(&lf);
    HFONT hOldFont = (HFONT)SelectObject(hdc, hGhostFont);
    
    // Draw ghost text at cursor position
    RECT textRect = clipRect;
    textRect.left = cursorScreenX;
    textRect.top = cursorScreenY;
    textRect.bottom = cursorScreenY + lineHeight;
    
    DrawTextA(hdc, g_ghostState.suggestionText, -1, &textRect,
              DT_LEFT | DT_NOPREFIX | DT_SINGLELINE);
    
    // Restore DC state
    SelectObject(hdc, hOldFont);
    DeleteObject(hGhostFont);
    SetTextColor(hdc, oldColor);
    SetBkMode(hdc, oldBkMode);
}

// ============================================================================
// INTEGRATION EXAMPLE: WndProc Handler
// ============================================================================
/*
// Add these cases to your existing WndProc:

LRESULT CALLBACK EditorWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_KEYDOWN: {
            // Let ghost text handle Tab/Escape first
            if (GhostText_OnKeyDown(hwnd, wParam)) {
                return 0; // Handled
            }
            // ... your existing key handling ...
            break;
        }
        
        case WM_CHAR: {
            // Any character typed resets ghost text timer
            GhostText_OnKeystroke(hwnd);
            // ... your existing char handling ...
            break;
        }
        
        case WM_TIMER: {
            GhostText_OnTimer(hwnd, wParam);
            // ... handle other timers ...
            break;
        }
        
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            
            // ... your existing paint code ...
            
            // Render ghost text on top
            int cursorX = GetCursorScreenX(); // Your implementation
            int cursorY = GetCursorScreenY(); // Your implementation
            int lineH = GetLineHeight();      // Your implementation
            
            GhostText_Render(hdc, cursorX, cursorY, lineH, ps.rcPaint);
            
            EndPaint(hwnd, &ps);
            return 0;
        }
    }
    
    return DefWindowProc(hwnd, msg, wParam, lParam);
}
*/

// ============================================================================
// BUILD INSTRUCTIONS
// ============================================================================
/*
1. Assemble the bridge:
   ml64.exe /c /W3 /nologo /Fo Bridge_Mock_Suggestion.obj Bridge_Mock_Suggestion.asm

2. Compile this file:
   cl.exe /O2 /EHsc /c GhostText_TimerHook.cpp

3. Link with your IDE:
   link.exe ... GhostText_TimerHook.obj Bridge_Mock_Suggestion.obj ...

4. Integrate WndProc handlers (see example above)

5. Test: Type in editor, wait 300ms, see gray " = 0;" appear
   Press Tab to accept, Esc to dismiss, Ctrl+Right for partial accept
*/
