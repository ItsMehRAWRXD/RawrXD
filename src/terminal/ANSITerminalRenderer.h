// ============================================================================
// ANSITerminalRenderer.h - Production ANSI Escape Sequence Parser & Renderer
// ============================================================================
// Features: Full ANSI color support, cursor control, scrollback, theming
// ============================================================================

#pragma once

#include <Windows.h>
#include <string>
#include <vector>
#include <deque>
#include <unordered_map>
#include <functional>

namespace RawrXD {
namespace Terminal {

// ANSI Color codes
enum class ANSIColor : uint8_t {
    Black = 0,
    Red = 1,
    Green = 2,
    Yellow = 3,
    Blue = 4,
    Magenta = 5,
    Cyan = 6,
    White = 7,
    BrightBlack = 8,
    BrightRed = 9,
    BrightGreen = 10,
    BrightYellow = 11,
    BrightBlue = 12,
    BrightMagenta = 13,
    BrightCyan = 14,
    BrightWhite = 15,
    Default = 255
};

// Text attributes
struct TextAttributes {
    ANSIColor fg = ANSIColor::Default;
    ANSIColor bg = ANSIColor::Default;
    bool bold = false;
    bool dim = false;
    bool italic = false;
    bool underline = false;
    bool blink = false;
    bool reverse = false;
    bool hidden = false;
    bool strikethrough = false;

    bool operator==(const TextAttributes& other) const {
        return fg == other.fg && bg == other.bg && bold == other.bold &&
               dim == other.dim && italic == other.italic && underline == other.underline &&
               blink == other.blink && reverse == other.reverse && hidden == other.hidden &&
               strikethrough == other.strikethrough;
    }
};

// Terminal cell (character + attributes)
struct TerminalCell {
    wchar_t ch = L' ';
    TextAttributes attrs;
    bool dirty = true;
};

// Terminal theme
struct TerminalTheme {
    // Standard 16 colors
    COLORREF colors[16] = {
        RGB(0, 0, 0),       // Black
        RGB(205, 49, 49),   // Red
        RGB(13, 188, 121),  // Green
        RGB(229, 229, 16),  // Yellow
        RGB(36, 114, 200),  // Blue
        RGB(188, 63, 188),  // Magenta
        RGB(17, 168, 205),  // Cyan
        RGB(229, 229, 229), // White
        RGB(102, 102, 102), // Bright Black
        RGB(241, 76, 76),   // Bright Red
        RGB(35, 209, 139),  // Bright Green
        RGB(245, 245, 67),  // Bright Yellow
        RGB(59, 142, 234),  // Bright Blue
        RGB(214, 112, 214), // Bright Magenta
        RGB(41, 184, 219),  // Bright Cyan
        RGB(255, 255, 255)  // Bright White
    };

    COLORREF defaultFg = RGB(229, 229, 229);
    COLORREF defaultBg = RGB(30, 30, 30);
    COLORREF cursorFg = RGB(0, 0, 0);
    COLORREF cursorBg = RGB(229, 229, 229);
    COLORREF selectionBg = RGB(0, 120, 215);

    // Font settings
    std::wstring fontName = L"Consolas";
    int fontSize = 11;
    bool bold = false;
};

// Scrollback buffer
struct ScrollbackBuffer {
    std::deque<std::vector<TerminalCell>> lines;
    size_t maxLines = 10000;

    void AddLine(const std::vector<TerminalCell>& line);
    void Clear();
    size_t Size() const { return lines.size(); }
    const std::vector<TerminalCell>* GetLine(size_t index) const;
};

// ============================================================================
// ANSITerminalRenderer - Production Terminal Renderer
// ============================================================================

class ANSITerminalRenderer {
public:
    ANSITerminalRenderer();
    ~ANSITerminalRenderer();

    // Initialize with window handle
    bool Initialize(HWND hwnd);
    void Shutdown();
    bool IsInitialized() const { return m_initialized; }

    // Resize terminal
    void Resize(int width, int height);
    void SetGridSize(int cols, int rows);

    // Process ANSI output
    void ProcessOutput(const std::string& output);
    void ProcessOutput(const char* data, size_t len);

    // Render to screen
    void Render(HDC hdc);
    void Render();
    void Invalidate();

    // Theme
    void SetTheme(const TerminalTheme& theme);
    const TerminalTheme& GetTheme() const { return m_theme; }

    // Scrollback
    void ScrollUp(int lines = 1);
    void ScrollDown(int lines = 1);
    void ScrollToTop();
    void ScrollToBottom();
    bool CanScrollUp() const;
    bool CanScrollDown() const;
    void ClearScrollback();

    // Cursor
    void ShowCursor(bool show);
    void SetCursorBlink(bool blink);
    void MoveCursor(int row, int col);
    void GetCursorPos(int& row, int& col) const;

    // Selection
    void StartSelection(int row, int col);
    void UpdateSelection(int row, int col);
    void EndSelection();
    void ClearSelection();
    std::string GetSelectedText() const;
    bool HasSelection() const;

    // Copy/Paste
    void CopyToClipboard();
    void PasteFromClipboard();

    // Input handling
    void OnKeyDown(WPARAM key, LPARAM lParam);
    void OnChar(WPARAM ch);
    void OnMouseDown(int x, int y);
    void OnMouseMove(int x, int y);
    void OnMouseUp(int x, int y);
    void OnMouseWheel(int delta);

    // Callbacks
    using InputCallback = std::function<void(const std::string& input)>;
    using ResizeCallback = std::function<void(int cols, int rows)>;
    using BellCallback = std::function<void()>;

    void SetInputCallback(InputCallback cb) { m_inputCallback = std::move(cb); }
    void SetResizeCallback(ResizeCallback cb) { m_resizeCallback = std::move(cb); }
    void SetBellCallback(BellCallback cb) { m_bellCallback = std::move(cb); }

    // Get terminal dimensions
    int GetCols() const { return m_cols; }
    int GetRows() const { return m_rows; }
    int GetVisibleRows() const { return m_visibleRows; }

    // Clear screen
    void ClearScreen();
    void ClearLine();
    void ClearLineFromCursor();
    void ClearLineToCursor();

    // Save/restore cursor
    void SaveCursor();
    void RestoreCursor();

    // Set window title (if supported)
    void SetTitle(const std::string& title);
    std::string GetTitle() const { return m_title; }

private:
    HWND m_hwnd = nullptr;
    HDC m_memDC = nullptr;
    HBITMAP m_memBitmap = nullptr;
    HFONT m_font = nullptr;
    HFONT m_boldFont = nullptr;
    bool m_initialized = false;

    // Grid dimensions
    int m_cols = 80;
    int m_rows = 24;
    int m_visibleRows = 24;
    int m_scrollOffset = 0;

    // Cell dimensions
    int m_cellWidth = 8;
    int m_cellHeight = 16;

    // Screen buffer (current visible area)
    std::vector<std::vector<TerminalCell>> m_screen;

    // Scrollback buffer
    ScrollbackBuffer m_scrollback;

    // Current attributes
    TextAttributes m_currentAttrs;

    // Cursor position (0-based)
    int m_cursorRow = 0;
    int m_cursorCol = 0;
    bool m_cursorVisible = true;
    bool m_cursorBlink = true;
    bool m_cursorBlinkState = true;
    DWORD m_lastBlinkTime = 0;

    // Saved cursor position
    int m_savedRow = 0;
    int m_savedCol = 0;

    // Selection
    bool m_selecting = false;
    int m_selStartRow = -1, m_selStartCol = -1;
    int m_selEndRow = -1, m_selEndCol = -1;

    // Parser state
    std::string m_parseBuffer;
    bool m_inEscape = false;
    bool m_inCSI = false;
    bool m_inOSC = false;
    std::vector<int> m_csiParams;

    // Theme
    TerminalTheme m_theme;
    std::string m_title;

    // Callbacks
    InputCallback m_inputCallback;
    ResizeCallback m_resizeCallback;
    BellCallback m_bellCallback;

    // Initialization
    bool CreateMemoryDC();
    void DestroyMemoryDC();
    bool CreateFonts();
    void DestroyFonts();
    void CalculateCellSize();
    void AllocateScreen();

    // ANSI parsing
    void ParseByte(char c);
    void ProcessEscape(char c);
    void ProcessCSI();
    void ProcessOSC();
    void ExecuteCSI(int cmd);
    void ExecuteOSC(const std::string& params);

    // SGR (Select Graphic Rendition)
    void ProcessSGR(const std::vector<int>& params);

    // Cursor movement
    void MoveCursorUp(int n);
    void MoveCursorDown(int n);
    void MoveCursorForward(int n);
    void MoveCursorBackward(int n);
    void MoveCursorNextLine(int n);
    void MoveCursorPrevLine(int n);
    void SetCursorColumn(int col);
    void SetCursorRow(int row);

    // Scrolling
    void ScrollUp();
    void ScrollDown();
    void InsertLines(int n);
    void DeleteLines(int n);

    // Character output
    void OutputChar(wchar_t ch);
    void OutputString(const std::wstring& str);
    void WrapCursor();

    // Rendering
    void RenderCell(HDC hdc, int row, int col);
    void RenderCursor(HDC hdc);
    void RenderSelection(HDC hdc);
    COLORREF GetFGColor(const TextAttributes& attrs) const;
    COLORREF GetBGColor(const TextAttributes& attrs) const;

    // Utility
    void NormalizeSelection();
    bool IsInSelection(int row, int col) const;
    std::wstring UTF8ToWide(const std::string& utf8);
    std::string WideToUTF8(const std::wstring& wide);
    void MarkDirty(int row, int col);
    void MarkRowDirty(int row);
    void MarkAllDirty();
};

// ============================================================================
// C API
// ============================================================================

extern "C" {
    void* ANSITerminal_Create();
    void ANSITerminal_Destroy(void* term);
    int ANSITerminal_Initialize(void* term, HWND hwnd);
    void ANSITerminal_Shutdown(void* term);
    void ANSITerminal_Resize(void* term, int width, int height);
    void ANSITerminal_ProcessOutput(void* term, const char* data, int len);
    void ANSITerminal_Render(void* term, HDC hdc);
    void ANSITerminal_ScrollUp(void* term, int lines);
    void ANSITerminal_ScrollDown(void* term, int lines);
    void ANSITerminal_ClearScrollback(void* term);
    void ANSITerminal_SetInputCallback(void* term, void (*callback)(const char* input));
    int ANSITerminal_GetCols(void* term);
    int ANSITerminal_GetRows(void* term);
}

} // namespace Terminal
} // namespace RawrXD
