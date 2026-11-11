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

// This file now just includes the implementation from the new location
// for backward compatibility with existing build scripts
#include "RawrXD_IDE_GhostText_Engine_Implementation.cpp"
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
    RawrXD::IDE::SovereignBridge* m_bridge;
    std::atomic<bool> m_requestInFlight{false};
    
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
        // Prevent multiple concurrent requests
        if (m_requestInFlight.exchange(true)) {
            return;
        }
        
        // Check if Sovereign Runtime is available
        if (!m_bridge || !m_bridge->IsRuntimeAvailable()) {
            m_requestInFlight = false;
            return;
        }
        
        // Launch async inference request
        // Capture by value for thread safety
        std::thread inferenceThread([this, context, line, col]() {
            // Configure for code completion
            RawrXD::IDE::SovereignConfig config;
            config.maxTokens = 64;           // Short completions
            config.autonomous = false;       // Direct inference, no agent loop
            config.validate = false;         // Skip validation for speed
            config.timeoutMs = 5000;         // 5 second timeout for UX
            
            // Build FIM (Fill-In-Middle) style prompt for code completion
            // Format: <PRE> prefix <SUF> suffix <MID>
            std::string fimPrompt = "<PRE> " + context + " <SUF> <MID>";
            
            // Execute inference
            RawrXD::IDE::SovereignResult result = m_bridge->Validate(fimPrompt, config);
            
            if (result.IsSuccess() && !result.output.empty()) {
                // Parse the completion from output
                std::string completion = result.output;
                
                // Clean up the completion - extract just the generated code
                // Remove any trailing newlines or prompt artifacts
                while (!completion.empty() && 
                       (completion.back() == '\n' || completion.back() == '\r')) {
                    completion.pop_back();
                }
                
                // Calculate confidence based on output quality
                float confidence = 0.5f;
                if (completion.length() > 0 && completion.length() < 256) {
                    confidence = 0.7f;  // Good length
                }
                if (result.exitCode == 0) {
                    confidence += 0.2f;  // Clean exit
                }
                
                // Post result back to UI thread
                // Use PostMessage for thread-safe UI update
                struct GhostResult {
                    std::string text;
                    int line;
                    int col;
                    float confidence;
                };
                
                GhostResult* gr = new GhostResult{completion, line, col, confidence};
                PostMessage(m_hwnd, WM_USER + 0x1000, (WPARAM)gr, 0);
            }
            
            m_requestInFlight = false;
        });
        
        inferenceThread.detach();
    }
    
    // Handle async inference result (called from UI thread via PostMessage)
    void handleInferenceResult(const std::string& text, int line, int col, float confidence) {
        onSuggestionReceived(text, line, col, confidence);
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

// Custom message for async inference results
#define WM_GHOST_SUGGESTION (WM_USER + 0x1000)

// Message handler for ghost text messages
LRESULT HandleGhostTextMessage(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam, EditorData* ed) {
    if (msg == WM_GHOST_SUGGESTION && ed->ghostEngine) {
        // Unpack the result
        struct GhostResult {
            std::string text;
            int line;
            int col;
            float confidence;
        };
        GhostResult* gr = (GhostResult*)wParam;
        if (gr) {
            ed->ghostEngine->onSuggestionReceived(gr->text, gr->line, gr->col, gr->confidence);
            delete gr;
        }
        return 0;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

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
