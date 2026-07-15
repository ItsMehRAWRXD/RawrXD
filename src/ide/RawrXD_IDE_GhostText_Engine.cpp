// ============================================================================
// RawrXD_IDE_GhostText_Engine.cpp — Native Win32 Ghost Text / Inline Completion
// Zero dependencies, pure Win32 GDI + custom text renderer
// Integrates with existing RawrXD IDE editor component
// ============================================================================
// Ghost text appears as dimmed/gray text after the cursor, suggesting code
// that the user can accept with Tab or dismiss by continuing to type.
//
// Architecture:
//   Editor Buffer → GhostTextEngine → Suggestion Request → LLM/Local Model
//                                         ↓
//   Editor Paint ← GhostTextOverlay ← Suggestion Response
// ============================================================================

#include <windows.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <atomic>
#include <chrono>

// ============================================================================
// GHOST TEXT ENGINE — Native Implementation (no VS Code API)
// ============================================================================

struct GhostSuggestion {
    std::string text;           // The suggested text
    int triggerLine;            // Line where suggestion was triggered
    int triggerCol;             // Column where suggestion starts
    bool isMultiLine;           // Does suggestion contain newlines?
    DWORD timestamp;            // When suggestion was received
    float confidence;           // 0.0-1.0 confidence score
    bool visible;               // Currently showing?
};

class GhostTextEngine {
public:
    GhostTextEngine(HWND hwndEditor) : m_hwnd(hwndEditor), m_active(false), m_lastRequest(0) {}
    
    // Called when user types — requests suggestion asynchronously
    void onTextChanged(const char* buffer, int cursorLine, int cursorCol) {
        // Debounce: don't request on every keystroke
        DWORD now = GetTickCount();
        if (now - m_lastRequest < 150) return; // 150ms debounce
        m_lastRequest = now;
        
        // Extract context (previous 5 lines + current line prefix)
        std::string context = extractContext(buffer, cursorLine, cursorCol);
        
        // Async request to inference engine
        requestSuggestion(context, cursorLine, cursorCol);
    }
    
    // Called when suggestion arrives from model
    void onSuggestionReceived(const std::string& text, int line, int col, float confidence) {
        if (confidence < 0.3f) { // Threshold for showing
            hideSuggestion();
            return;
        }
        
        m_current.text = text;
        m_current.triggerLine = line;
        m_current.triggerCol = col;
        m_current.isMultiLine = (text.find('\n') != std::string::npos);
        m_current.timestamp = GetTickCount();
        m_current.confidence = confidence;
        m_current.visible = true;
        m_active = true;
        
        // Invalidate editor region to trigger paint
        invalidateGhostRegion();
    }
    
    // Accept suggestion (Tab key)
    bool acceptSuggestion(std::string& outText) {
        if (!m_active || !m_current.visible) return false;
        outText = m_current.text;
        hideSuggestion();
        return true;
    }
    
    // Partial accept — word by word (Ctrl+Right)
    bool acceptPartial(std::string& outText) {
        if (!m_active || !m_current.visible) return false;
        
        // Find next word boundary
        size_t pos = 0;
        while (pos < m_current.text.size() && m_current.text[pos] == ' ') ++pos;
        while (pos < m_current.text.size() && m_current.text[pos] != ' ' && m_current.text[pos] != '\n') ++pos;
        
        outText = m_current.text.substr(0, pos);
        m_current.text = m_current.text.substr(pos);
        m_current.triggerCol += (int)outText.size(); // Adjust for partial
        
        if (m_current.text.empty()) hideSuggestion();
        else invalidateGhostRegion();
        
        return true;
    }
    
    // Dismiss suggestion (Esc or typing mismatch)
    void hideSuggestion() {
        if (!m_active) return;
        m_active = false;
        m_current.visible = false;
        invalidateGhostRegion();
    }
    
    // Check if suggestion should be dismissed (user typed something else)
    void checkDismiss(const char* currentLine, int cursorCol) {
        if (!m_active) return;
        
        // If cursor moved before trigger point, dismiss
        if (cursorCol < m_current.triggerCol) {
            hideSuggestion();
            return;
        }
        
        // If typed text doesn't match suggestion prefix, dismiss
        int prefixLen = cursorCol - m_current.triggerCol;
        if (prefixLen > 0 && prefixLen <= (int)m_current.text.size()) {
            std::string typed(currentLine + m_current.triggerCol, prefixLen);
            std::string expected = m_current.text.substr(0, prefixLen);
            if (typed != expected) {
                hideSuggestion();
            }
        }
    }
    
    // Paint ghost text into editor DC
    void paintGhostText(HDC hdc, const RECT& editorRect, 
                        int lineHeight, int charWidth,
                        int scrollX, int scrollY,
                        int cursorScreenX, int cursorScreenY) {
        if (!m_active || !m_current.visible) return;
        
        // Calculate ghost text position (starts at cursor)
        int x = cursorScreenX;
        int y = cursorScreenY;
        
        // Set ghost text styling — dimmed gray
        COLORREF ghostColor = RGB(128, 128, 128); // Medium gray
        COLORREF oldColor = SetTextColor(hdc, ghostColor);
        
        // Use italic font for ghost text
        HFONT hFont = (HFONT)GetCurrentObject(hdc, OBJ_FONT);
        LOGFONTA lf = {};
        GetObjectA(hFont, sizeof(lf), &lf);
        lf.lfItalic = TRUE;
        HFONT hGhostFont = CreateFontIndirectA(&lf);
        HFONT hOldFont = (HFONT)SelectObject(hdc, hGhostFont);
        
        // Set background mode transparent
        int oldBkMode = SetBkMode(hdc, TRANSPARENT);
        
        // Draw each line of suggestion
        const char* p = m_current.text.c_str();
        while (*p) {
            const char* lineEnd = strchr(p, '\n');
            std::string line;
            if (lineEnd) {
                line = std::string(p, lineEnd - p);
                p = lineEnd + 1;
            } else {
                line = p;
                p += strlen(p);
            }
            
            // Clip to editor bounds
            RECT clipRect = editorRect;
            clipRect.left = x;
            clipRect.top = y;
            clipRect.bottom = y + lineHeight;
            
            DrawTextA(hdc, line.c_str(), (int)line.size(), &clipRect, 
                      DT_LEFT | DT_NOPREFIX | DT_SINGLELINE);
            
            y += lineHeight;
        }
        
        // Restore state
        SetBkMode(hdc, oldBkMode);
        SelectObject(hdc, hOldFont);
        DeleteObject(hGhostFont);
        SetTextColor(hdc, oldColor);
    }
    
    bool isActive() const { return m_active; }
    const GhostSuggestion& getCurrent() const { return m_current; }
    
private:
    HWND m_hwnd;
    GhostSuggestion m_current;
    bool m_active;
    DWORD m_lastRequest;
    
    std::string extractContext(const char* buffer, int cursorLine, int cursorCol) {
        // Simple context extraction — last 5 lines + current line prefix
        std::string context;
        const char* p = buffer;
        int line = 0;
        
        while (*p && line < cursorLine - 5) {
            if (*p == '\n') ++line;
            ++p;
        }
        
        // Copy up to cursor position
        const char* cursorPos = p;
        for (int i = 0; i < cursorCol && *cursorPos && *cursorPos != '\n'; ++i) {
            ++cursorPos;
        }
        
        context = std::string(p, cursorPos - p);
        return context;
    }
    
    void requestSuggestion(const std::string& context, int line, int col) {
        // TODO: Wire to your inference engine
        // This would call into your LLM client or local model
        // For now, simulate with a placeholder
        
        // Async callback would call onSuggestionReceived()
        // Example: m_inferenceClient->completeAsync(context, callback);
    }
    
    void invalidateGhostRegion() {
        if (!m_hwnd) return;
        RECT rc;
        GetClientRect(m_hwnd, &rc);
        InvalidateRect(m_hwnd, &rc, FALSE);
    }
};

// ============================================================================
// EDITOR WINDOW PROC — Integration Point
// ============================================================================
// Add this to your existing editor WndProc
// ============================================================================

// Per-editor-instance data
struct EditorData {
    GhostTextEngine* ghostEngine;
    char* buffer;
    int cursorLine;
    int cursorCol;
    // ... existing editor state
};

// Message handlers to add:

LRESULT HandleEditorKeyDown(HWND hwnd, WPARAM wParam, LPARAM lParam, EditorData* ed) {
    switch (wParam) {
        case VK_TAB: {
            // Try to accept ghost text first
            std::string accepted;
            if (ed->ghostEngine && ed->ghostEngine->acceptSuggestion(accepted)) {
                // Insert accepted text at cursor
                insertTextAtCursor(ed, accepted.c_str());
                return 0; // Handled
            }
            break;
        }
        case VK_ESCAPE: {
            if (ed->ghostEngine) {
                ed->ghostEngine->hideSuggestion();
                return 0;
            }
            break;
        }
        case VK_RIGHT: {
            if (GetAsyncKeyState(VK_CONTROL) < 0) { // Ctrl+Right
                std::string accepted;
                if (ed->ghostEngine && ed->ghostEngine->acceptPartial(accepted)) {
                    insertTextAtCursor(ed, accepted.c_str());
                    return 0;
                }
            }
            break;
        }
    }
    return DefWindowProc(hwnd, WM_KEYDOWN, wParam, lParam);
}

LRESULT HandleEditorChar(HWND hwnd, WPARAM wParam, LPARAM lParam, EditorData* ed) {
    // Normal character insertion
    char ch = (char)wParam;
    insertCharAtCursor(ed, ch);
    
    // Update ghost text engine
    if (ed->ghostEngine) {
        ed->ghostEngine->onTextChanged(ed->buffer, ed->cursorLine, ed->cursorCol);
        ed->ghostEngine->checkDismiss(getCurrentLine(ed), ed->cursorCol);
    }
    
    return 0;
}

LRESULT HandleEditorPaint(HWND hwnd, HDC hdc, EditorData* ed) {
    // ... existing paint code ...
    
    // Paint ghost text overlay
    if (ed->ghostEngine) {
        RECT rc;
        GetClientRect(hwnd, &rc);
        
        int cursorScreenX = getCursorScreenX(ed);
        int cursorScreenY = getCursorScreenY(ed);
        
        ed->ghostEngine->paintGhostText(hdc, rc, 
            getLineHeight(ed), getCharWidth(ed),
            getScrollX(ed), getScrollY(ed),
            cursorScreenX, cursorScreenY);
    }
    
    return 0;
}

// Stub functions — implement with your existing editor logic
void insertTextAtCursor(EditorData* ed, const char* text) { (void)ed; (void)text; /* your impl */ }
void insertCharAtCursor(EditorData* ed, char ch) { (void)ed; (void)ch; /* your impl */ }
const char* getCurrentLine(EditorData* ed) { (void)ed; return ""; /* your impl */ }
int getCursorScreenX(EditorData* ed) { (void)ed; return 0; /* your impl */ }
int getCursorScreenY(EditorData* ed) { (void)ed; return 0; /* your impl */ }
int getLineHeight(EditorData* ed) { (void)ed; return 20; /* your impl */ }
int getCharWidth(EditorData* ed) { (void)ed; return 8; /* your impl */ }
int getScrollX(EditorData* ed) { (void)ed; return 0; /* your impl */ }
int getScrollY(EditorData* ed) { (void)ed; return 0; /* your impl */ }

// ============================================================================
// FULL IDE AUDIT CHECKLIST
// ============================================================================
/*

RAW RXD IDE — COMPLETE SYSTEMS AUDIT
======================================

CORE EDITOR
-----------
[ ] Text buffer (gap buffer / piece table)
[ ] Syntax highlighting (lexer-driven)
[ ] Line numbers
[ ] Code folding
[ ] Find/Replace (regex support)
[ ] Multi-cursor editing
[ ] Undo/Redo (command pattern)
[ ] Auto-indent
[ ] Bracket matching
[ ] Word wrap
[ ] Minimap
[ ] Scrollbar annotations
[ ] GHOST TEXT / INLINE COMPLETIONS ← YOU ARE HERE

FILE SYSTEM
-----------
[ ] File explorer (tree view)
[ ] File watcher (directory monitoring)
[ ] New/Rename/Delete files
[ ] Drag & drop
[ ] Git integration (status in explorer)
[ ] Quick open (Ctrl+P style)
[ ] Recent files

TERMINAL
--------
[ ] Integrated terminal (Win32 console)
[ ] Multiple tabs
[ ] Shell integration
[ ] Output parsing (clickable errors)

DEBUGGING
---------
[ ] Breakpoints (toggle, conditional)
[ ] Step over / into / out
[ ] Call stack view
[ ] Variables / Watch
[ ] Memory view
[ ] Register view (r0-r15 for RawrXD-Script)
[ ] Disassembly view
[ ] DAP adapter integration ← DONE

LSP / INTELLISENSE
------------------
[ ] Language server client
[ ] Auto-completion (Ctrl+Space)
[ ] Hover information
[ ] Go to definition
[ ] Find references
[ ] Rename symbol
[ ] Diagnostics (squiggles)
[ ] Code actions (quick fixes)
[ ] Signature help
[ ] Document symbols (outline)
[ ] Workspace symbols
[ ] GHOST TEXT / INLINE SUGGESTIONS ← MISSING

AI INTEGRATION
--------------
[ ] Copilot-style chat panel
[ ] Streaming responses
[ ] Code generation
[ ] Inline editing (Cmd+K)
[ ] Agent mode (multi-file)
[ ] Model selection dialog
[ ] Local inference (GGUF)
[ ] Ollama integration
[ ] GHOST TEXT from AI models ← MISSING

BUILD SYSTEM
------------
[ ] CMake integration
[ ] MASM compilation
[ ] Error parsing
[ ] Task runner
[ ] Problem matcher

GIT INTEGRATION
---------------
[ ] Source control panel
[ ] Diff viewer
[ ] Blame annotations
[ ] Branch management
[ ] Commit graph
[ ] Staging / unstaging

EXTENSIONS
----------
[ ] Extension host
[ ] API surface
[ ] VS Code extension compatibility
[ ] RawrXD-Script extension ← IN PROGRESS

PERFORMANCE
-----------
[ ] Large file handling (>100MB)
[ ] Lazy loading
[ ] Virtual scrolling
[ ] Background parsing
[ ] Memory profiling

TESTING
-------
[ ] Unit test runner
[ ] Test explorer
[ ] Coverage visualization
[ ] Golden Master regression ← DONE

*/

// ============================================================================
// MAIN — Demo / Test
// ============================================================================
int main(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("RawrXD IDE Ghost Text Engine\n");
    printf("============================\n");
    printf("Features:\n");
    printf("  - Debounced suggestion requests (150ms)\n");
    printf("  - Confidence threshold (0.3)\n");
    printf("  - Tab to accept full suggestion\n");
    printf("  - Ctrl+Right to accept word-by-word\n");
    printf("  - Esc to dismiss\n");
    printf("  - Auto-dismiss on mismatch\n");
    printf("  - Multi-line suggestion support\n");
    printf("  - Gray italic ghost text rendering\n");
    printf("\n");
    printf("Integration: Add HandleEditorKeyDown, HandleEditorChar,\n");
    printf("  HandleEditorPaint to your existing WndProc.\n");
    printf("\n");
    printf("Wire requestSuggestion() to your inference engine.\n");
    
    return 0;
}
