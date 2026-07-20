/*===========================================================================
 * RawrXD_IDE_Win32_GhostText_Integration_Patch.cpp
 * 
 * This file shows the modifications needed to RawrXD_IDE_Win32.cpp
 * to integrate the GhostTextEngine wiring.
 * 
 * Apply these changes to the main IDE window procedure and initialization.
 *===========================================================================*/

/* 
 * ============================================================================
 * SECTION 1: ADD TO INCLUDES (at top of RawrXD_IDE_Win32.cpp)
 * ============================================================================
 */

#include "GhostTextIntegration_Wiring.h"

/*
 * ============================================================================
 * SECTION 2: ADD TO WM_CREATE HANDLER (in RawrXD_IDE_WndProc)
 * ============================================================================
 */

case WM_CREATE: {
    // ... existing initialization code ...
    
    /* Initialize GhostTextEngine integration */
    if (RawrXD_GhostText_IsAvailable()) {
        if (RawrXD_GhostText_Init(ide)) {
            RawrXD_IDE_OutputAppend(ide, L"[GhostText] AI completion ready\r\n");
        } else {
            RawrXD_IDE_OutputAppend(ide, L"[GhostText] Initialization failed\r\n");
        }
    }
    
    // ... rest of initialization ...
    break;
}

/*
 * ============================================================================
 * SECTION 3: ADD TO WM_DESTROY HANDLER
 * ============================================================================
 */

case WM_DESTROY: {
    // Shutdown GhostText integration
    RawrXD_GhostText_Shutdown(ide);
    
    // ... existing cleanup code ...
    break;
}

/*
 * ============================================================================
 * SECTION 4: MODIFY WM_TIMER HANDLER
 * ============================================================================
 */

case WM_TIMER: {
    // Route GhostText debounce timer
    RawrXD_GhostText_OnTimer(ide, wParam);
    
    // ... existing timer handling ...
    break;
}

/*
 * ============================================================================
 * SECTION 5: ADD CUSTOM MESSAGE HANDLERS (before default case)
 * ============================================================================
 */

// Handle GhostText custom messages
case WM_GHOST_SUGGESTION:      // (WM_USER + 0x1000)
case WM_GHOST_DISMISS:        // (WM_USER + 0x1001)
case WM_GHOST_ACCEPT:         // (WM_USER + 0x1002)
{
    return RawrXD_GhostText_OnCustomMessage(ide, message, wParam, lParam);
}

/*
 * ============================================================================
 * SECTION 6: MODIFY WM_KEYDOWN HANDLER
 * ============================================================================
 */

case WM_KEYDOWN: {
    // Route to GhostText first (returns TRUE if handled)
    if (RawrXD_GhostText_OnKeyDown(ide, wParam)) {
        return 0;  // Key was consumed by GhostText
    }
    
    // ... existing key handling (debug keys, etc.) ...
    
    break;
}

/*
 * ============================================================================
 * SECTION 7: ADD TO WM_PAINT HANDLER (for editor)
 * ============================================================================
 */

// In the editor subclass procedure (RawrXD_IDE_EditorWndProc):
case WM_PAINT: {
    PAINTSTRUCT ps;
    HDC hdc = BeginPaint(hwnd, &ps);
    
    // ... existing paint code ...
    
    // Paint ghost text overlay
    RECT editorRect;
    GetClientRect(hwnd, &editorRect);
    RawrXD_GhostText_OnPaint(ide, hdc, &editorRect);
    
    EndPaint(hwnd, &ps);
    return 0;
}

/*
 * ============================================================================
 * SECTION 8: ADD TO EN_CHANGE HANDLER (Edit control notification)
 * ============================================================================
 */

// In WM_COMMAND handler, case EN_CHANGE:
case EN_CHANGE: {
    if (lParam == (LPARAM)ide->hWndEditor) {
        // Notify GhostText of text change
        RawrXD_GhostText_OnTextChanged(ide);
        
        // ... existing EN_CHANGE handling ...
    }
    break;
}

/*
 * ============================================================================
 * SECTION 9: ADD TO EDITOR SUBCLASS PROCEDURE
 * ============================================================================
 */

// RawrXD_IDE_EditorWndProc - add these cases:

LRESULT CALLBACK RawrXD_IDE_EditorWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    RawrXD_IDE* ide = RawrXD_IDE_GetFromHwnd(GetParent(hwnd));
    if (!ide) return DefWindowProc(hwnd, msg, wParam, lParam);
    
    switch (msg) {
        case WM_KEYDOWN:
            // GhostText gets first chance at keys when suggestion is active
            if (RawrXD_GhostText_OnKeyDown(ide, wParam)) {
                return 0;
            }
            break;
            
        case WM_CHAR:
            // Check if character should dismiss ghost text
            if (wParam == VK_ESCAPE) {
                RawrXD_GhostText_ForceDismiss(ide);
            }
            break;
            
        case WM_PAINT:
            // Let default paint happen first
            {
                LRESULT result = CallWindowProc(ide->origEditorProc, hwnd, msg, wParam, lParam);
                
                // Then paint ghost text overlay
                PAINTSTRUCT ps;
                HDC hdc = BeginPaint(hwnd, &ps);
                RECT rect;
                GetClientRect(hwnd, &rect);
                RawrXD_GhostText_OnPaint(ide, hdc, &rect);
                EndPaint(hwnd, &ps);
                
                return result;
            }
    }
    
    return CallWindowProc(ide->origEditorProc, hwnd, msg, wParam, lParam);
}

/*
 * ============================================================================
 * SECTION 10: ADD TO IDE STRUCT (RawrXD_IDE in RawrXD_IDE_Win32.h)
 * ============================================================================
 */

struct RawrXD_IDE {
    // ... existing fields ...
    
    // GhostText integration
    GhostTextEngine* ghostEngine;           // Ghost text completion engine
    LONG editorVersion;                     // Atomic version for stale detection
    
    // ... rest of struct ...
};

/*
 * ============================================================================
 * SECTION 11: ADD INITIALIZATION TO IDE_Init()
 * ============================================================================
 */

BOOL RawrXD_IDE_Init(RawrXD_IDE* ide, HINSTANCE hInstance, int nCmdShow)
{
    // ... existing initialization ...
    
    // Initialize editor version for GhostText
    ide->editorVersion = 0;
    ide->ghostEngine = nullptr;
    
    // ... rest of initialization ...
}

/*
 * ============================================================================
 * SECTION 12: UTILITY FUNCTIONS TO ADD
 * ============================================================================
 */

/**
 * Get editor content for GhostText inference
 */
BOOL RawrXD_IDE_GetEditorContent(RawrXD_IDE* ide, char* buffer, int bufferSize,
                                  int* outCursorLine, int* outCursorCol)
{
    if (!ide || !ide->hWndEditor) return FALSE;
    
    // Get text from editor
    int textLen = GetWindowTextA(ide->hWndEditor, buffer, bufferSize);
    if (textLen == 0) return FALSE;
    
    // Get cursor position
    DWORD selStart, selEnd;
    SendMessage(ide->hWndEditor, EM_GETSEL, (WPARAM)&selStart, (LPARAM)&selEnd);
    
    // Calculate line/column
    *outCursorLine = (int)SendMessage(ide->hWndEditor, EM_LINEFROMCHAR, selStart, 0);
    *outCursorCol = selStart - (int)SendMessage(ide->hWndEditor, EM_LINEINDEX, *outCursorLine, 0);
    
    return TRUE;
}

/**
 * Insert text at cursor position
 */
void RawrXD_IDE_InsertText(RawrXD_IDE* ide, const char* text)
{
    if (!ide || !ide->hWndEditor || !text) return;
    
    // Replace current selection with text
    SendMessageA(ide->hWndEditor, EM_REPLACESEL, TRUE, (LPARAM)text);
}

/**
 * Get current line text
 */
void RawrXD_IDE_GetCurrentLineText(RawrXD_IDE* ide, char* buffer, int bufferSize)
{
    if (!ide || !ide->hWndEditor) {
        buffer[0] = '\0';
        return;
    }
    
    int line = (int)SendMessage(ide->hWndEditor, EM_LINEFROMCHAR, -1, 0);
    *(WORD*)buffer = bufferSize;  // EM_GETLINE requires size in first word
    int len = (int)SendMessageA(ide->hWndEditor, EM_GETLINE, line, (LPARAM)buffer);
    buffer[len] = '\0';
}

/**
 * Get cursor column
 */
int RawrXD_IDE_GetCursorColumn(RawrXD_IDE* ide)
{
    if (!ide || !ide->hWndEditor) return 0;
    
    DWORD selStart;
    SendMessage(ide->hWndEditor, EM_GETSEL, (WPARAM)&selStart, nullptr);
    
    int line = (int)SendMessage(ide->hWndEditor, EM_LINEFROMCHAR, selStart, 0);
    int lineStart = (int)SendMessage(ide->hWndEditor, EM_LINEINDEX, line, 0);
    
    return selStart - lineStart;
}

/**
 * Get line height for ghost text positioning
 */
int RawrXD_IDE_GetLineHeight(RawrXD_IDE* ide)
{
    if (!ide || !ide->hWndEditor) return 16;
    
    HDC hdc = GetDC(ide->hWndEditor);
    TEXTMETRIC tm;
    GetTextMetrics(hdc, &tm);
    ReleaseDC(ide->hWndEditor, hdc);
    
    return tm.tmHeight + tm.tmExternalLeading;
}

/**
 * Get character width for ghost text positioning
 */
int RawrXD_IDE_GetCharWidth(RawrXD_IDE* ide)
{
    if (!ide || !ide->hWndEditor) return 8;
    
    HDC hdc = GetDC(ide->hWndEditor);
    SIZE size;
    GetTextExtentPoint32A(hdc, " ", 1, &size);
    ReleaseDC(ide->hWndEditor, hdc);
    
    return size.cx;
}

/**
 * Get scroll position
 */
POINT RawrXD_IDE_GetScrollPosition(RawrXD_IDE* ide)
{
    POINT pt = {0, 0};
    if (!ide || !ide->hWndEditor) return pt;
    
    pt.x = (int)SendMessage(ide->hWndEditor, EM_GETSCROLLPOS, 0, (LPARAM)&pt);
    return pt;
}

/**
 * Get cursor screen position
 */
POINT RawrXD_IDE_GetCursorScreenPos(RawrXD_IDE* ide)
{
    POINT pt = {0, 0};
    if (!ide || !ide->hWndEditor) return pt;
    
    // Get cursor position in client coordinates
    DWORD selStart;
    SendMessage(ide->hWndEditor, EM_GETSEL, (WPARAM)&selStart, nullptr);
    
    // EM_POSFROMCHAR gives us the position
    LRESULT pos = SendMessage(ide->hWndEditor, EM_POSFROMCHAR, selStart, 0);
    pt.x = LOWORD(pos);
    pt.y = HIWORD(pos);
    
    return pt;
}

/**
 * Lookup IDE from window handle
 */
RawrXD_IDE* RawrXD_IDE_GetFromHwnd(HWND hwnd)
{
    // This would typically use GetWindowLongPtr with GWLP_USERDATA
    // or a global IDE instance
    return (RawrXD_IDE*)GetWindowLongPtr(hwnd, GWLP_USERDATA);
}

/*
 * ============================================================================
 * END OF INTEGRATION PATCH
 * ============================================================================
 */
