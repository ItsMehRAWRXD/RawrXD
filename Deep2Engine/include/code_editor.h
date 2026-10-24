#pragma once
// code_editor.h - Native Win32/C++20 code editor control with syntax highlighting.
//
// A self-drawn editor control built on top of the Win32 API, using:
//   - BufferModel (gap buffer text storage)
//   - SyntaxEngine (C++ / PowerShell / generic lexers)
//   - Custom painting for syntax-highlighted text + line number gutter
//
// No Qt. No Rich Edit dependency. Pure Win32 + GDI.
//
// Usage:
//   CodeEditor editor(hwndParent, id);
//   editor.setText("int main() { return 0; }");
//   editor.setLanguage("cpp");
//   HWND h = editor.hwnd();

#pragma once
#include <windows.h>
#include <string>
#include <string_view>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <atomic>

#include "editor_buffer.h"   // BufferModel
#include "syntax_engine.h"   // SyntaxEngine, SyntaxToken, LanguagePluginBase

// Forward declaration of BufferModel (defined in editor_buffer.h)
// (included above)

// ---------------------------------------------------------------------------
// Syntax token color map
// ---------------------------------------------------------------------------
struct SyntaxColor {
    COLORREF color;   // RGB text color
    bool bold = false;
    bool italic = false;
};

// ---------------------------------------------------------------------------
// CodeEditor - a single editor pane
// ---------------------------------------------------------------------------
class CodeEditor {
public:
    CodeEditor(HWND hwndParent, int controlId);
    ~CodeEditor();

    HWND hwnd() const { return m_hwnd; }
    int id() const { return m_controlId; }

    // Set the buffer contents from a UTF-8 string
    void setText(std::string_view text);

    // Get the buffer contents as UTF-8
    std::string getText() const;

    // Load a file from disk
    bool loadFile(const std::wstring& path);

    // Save the buffer to disk
    bool saveFile(const std::wstring& path) const;

    // Set the current file path (for display in tab)
    void setFilePath(const std::wstring& path);
    const std::wstring& filePath() const { return m_filePath; }

    // Set language for syntax highlighting ("cpp", "powershell", "text", etc.)
    void setLanguage(const std::string& languageId);
    const std::string& language() const { return m_languageId; }

    // Mark buffer as modified / clean
    void setModified(bool modified = true);
    bool isModified() const { return m_modified; }

    // Get current cursor position (0-based, logical)
    size_t cursorPos() const { return m_cursorPos; }
    void setCursorPos(size_t pos);

    // Get selected text range
    size_t selStart() const { return m_selStart; }
    size_t selEnd() const { return m_selEnd; }
    bool hasSelection() const { return m_selStart != m_selEnd; }

    // Font
    HFONT font() const { return m_hFont; }
    void setFont(HFONT hFont);

    // Line height in pixels (for layout)
    int lineHeight() const { return m_lineHeight; }
    int charWidth() const { return m_charWidth; }

    // Redraw the editor
    void invalidate();

    // Window procedure - call from parent's WM_NOTIFY/WM_COMMAND or subclass proc
    static LRESULT CALLBACK s_wndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
    LRESULT wndProc(UINT msg, WPARAM wParam, LPARAM lParam);

    // Ghost text (Cursor-style inline code completion)
    void showGhostText(const std::string& text);
    void clearGhostText();
    bool hasGhostText() const { return m_ghostVisible; }
    void acceptGhostText();
    void dismissGhostText();
    const std::string& ghostText() const { return m_ghostText; }

private:
    // Paint the editor (text + syntax highlighting + selection + cursor)
    void paint(HDC hdc, const RECT& clip);

    // Paint line number gutter
    void paintGutter(HDC hdc, const RECT& clip);

    // Paint the visible text range
    void paintText(HDC hdc, const RECT& clip);

    // Compute visible line range from scroll position
    void computeVisibleRange(int& firstLine, int& lastLine, int& topY) const;

    // Convert logical char pos to (line, col)
    void posToLineCol(size_t pos, int& line, int& col) const;

    // Convert (line, col) to logical char pos
    size_t lineColToPos(int line, int col) const;

    // Scroll to make cursor visible
    void ensureCursorVisible();

    // Recompute layout (wrap, line heights, etc.)
    void recomputeLayout();

    // Get syntax color for a token type
    COLORREF tokenColor(int type) const;

    // Members
    HWND m_hwnd = nullptr;
    HWND m_hwndParent = nullptr;
    int m_controlId = 0;

    // Text buffer + syntax engine
    BufferModel m_buffer;
    SyntaxEngine m_syntaxEngine;
    std::string m_languageId = "cpp";

    // Layout
    HFONT m_hFont = nullptr;
    int m_charWidth = 8;     // average char width
    int m_lineHeight = 16;   // line height
    int m_gutterWidth = 48;  // line number gutter width
    int m_hScroll = 0;       // horizontal scroll offset (chars)
    int m_vScroll = 0;       // vertical scroll offset (lines)

    // Selection + cursor
    size_t m_cursorPos = 0;
    size_t m_selStart = 0;
    size_t m_selEnd = 0;
    bool m_modified = false;

    // File
    std::wstring m_filePath;

    // Syntax colors (type -> color)
    std::map<int, SyntaxColor> m_syntaxColors;

    // Cached tokens for visible range (invalidated on text/scroll change)
    mutable std::vector<SyntaxToken> m_visibleTokens;
    mutable bool m_tokensDirty = true;

    // Ghost text state
    std::string m_ghostText;
    size_t m_ghostPos = 0;        // cursor position where ghost text starts
    COLORREF m_ghostColor = RGB(128, 128, 128);  // gray
    bool m_ghostVisible = false;

    std::mutex m_paintMutex;
};

// ---------------------------------------------------------------------------
// Syntax theme defaults
// ---------------------------------------------------------------------------
inline void initDefaultSyntaxColors(std::map<int, SyntaxColor>& colors) {
    colors[0] = { RGB(0, 0, 0), false, false };   // plain text
    colors[1] = { RGB(0, 0, 255), false, false };   // number
    colors[2] = { RGB(0, 0, 0), false, false };   // identifier
    colors[3] = { RGB(0, 0, 255), true, false };    // keyword (blue bold)
    colors[4] = { RGB(163, 21, 21), false, false }; // string (dark red)
    colors[5] = { RGB(0, 128, 0), false, false };   // comment (green)
    colors[6] = { RGB(128, 0, 128), false, false }; // preprocessor (purple)
    colors[7] = { RGB(0, 0, 0), false, false };   // punctuation
}
