// ============================================================================
// ANSIParser.hpp - Production ANSI Escape Sequence Parser
// ============================================================================
// Parses ANSI escape sequences (colors, cursor movement, clear) from terminal
// output and renders them with proper styling. Fully production-ready.
// ============================================================================

#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include <cstdint>
#include <memory>
#include <functional>

namespace rawrxd::terminal {

// ============================================================================
// Color - RGB color with alpha support
// ============================================================================
struct Color {
    uint8_t r = 0, g = 0, b = 0, a = 255;
    
    Color() = default;
    Color(uint8_t red, uint8_t green, uint8_t blue, uint8_t alpha = 255)
        : r(red), g(green), b(blue), a(alpha) {}
    explicit Color(COLORREF rgb)
        : r(GetRValue(rgb)), g(GetGValue(rgb)), b(GetBValue(rgb)), a(255) {}
    
    COLORREF ToCOLORREF() const { return RGB(r, g, b); }
    
    static Color From8Bit(uint8_t index);
    static Color FromRGB(uint8_t r, uint8_t g, uint8_t b) { return Color(r, g, b); }
    
    bool operator==(const Color& other) const {
        return r == other.r && g == other.g && b == other.b && a == other.a;
    }
    bool operator!=(const Color& other) const { return !(*this == other); }
};

// ============================================================================
// TextStyle - Complete text styling information
// ============================================================================
struct TextStyle {
    Color fg{255, 255, 255};           // Foreground color
    Color bg{0, 0, 0};                 // Background color
    bool bold = false;                  // Bold/bright
    bool faint = false;                 // Dim/faint
    bool italic = false;                // Italic
    bool underline = false;             // Underline
    bool blink = false;                 // Blink (rarely supported)
    bool reverse = false;               // Reverse video
    bool conceal = false;               // Concealed/hidden
    bool strikethrough = false;         // Strikethrough
    
    // Extended underline styles (SGR 4:x)
    enum UnderlineStyle { None, Single, Double, Curly, Dotted, Dashed };
    UnderlineStyle underlineStyle = None;
    
    // Hyperlink support (OSC 8)
    std::string hyperlinkId;
    std::string hyperlinkUrl;
    
    bool IsDefault() const {
        return fg == Color(255,255,255) && bg == Color(0,0,0) &&
               !bold && !faint && !italic && !underline &&
               !blink && !reverse && !conceal && !strikethrough;
    }
    
    void Reset() {
        fg = Color(255, 255, 255);
        bg = Color(0, 0, 0);
        bold = faint = italic = underline = blink = reverse = conceal = strikethrough = false;
        underlineStyle = None;
        hyperlinkId.clear();
        hyperlinkUrl.clear();
    }
    
    TextStyle Reversed() const {
        TextStyle result = *this;
        std::swap(result.fg, result.bg);
        return result;
    }
};

// ============================================================================
// TextFragment - A styled text segment
// ============================================================================
struct TextFragment {
    std::string text;
    TextStyle style;
    size_t originalStart = 0;  // Position in original input
    size_t originalEnd = 0;
    
    TextFragment() = default;
    TextFragment(const std::string& t, const TextStyle& s, size_t start = 0, size_t end = 0)
        : text(t), style(s), originalStart(start), originalEnd(end) {}
};

// ============================================================================
// CursorState - Terminal cursor position and visibility
// ============================================================================
struct CursorState {
    int row = 0;
    int col = 0;
    bool visible = true;
    bool blink = false;
    TextStyle style;  // Cursor style
};

// ============================================================================
// TerminalSize - Terminal dimensions
// ============================================================================
struct TerminalSize {
    int rows = 24;
    int cols = 80;
    int widthPixels = 0;
    int heightPixels = 0;
};

// ============================================================================
// ScreenCell - Single cell in terminal screen buffer
// ============================================================================
struct ScreenCell {
    char32_t character = ' ';
    TextStyle style;
    bool dirty = true;  // Needs redraw
    
    void Clear() {
        character = ' ';
        style.Reset();
        dirty = true;
    }
};

// ============================================================================
// ANSIParser - Production ANSI escape sequence parser
// ============================================================================
class ANSIParser {
public:
    ANSIParser();
    ~ANSIParser();

    // Disable copy, enable move
    ANSIParser(const ANSIParser&) = delete;
    ANSIParser& operator=(const ANSIParser&) = delete;
    ANSIParser(ANSIParser&&) noexcept;
    ANSIParser& operator=(ANSIParser&&) noexcept;

    // ── Configuration ──
    void SetTerminalSize(int rows, int cols);
    TerminalSize GetTerminalSize() const { return m_terminalSize; }
    void SetDefaultStyle(const TextStyle& style) { m_defaultStyle = style; }
    TextStyle GetDefaultStyle() const { return m_defaultStyle; }

    // ── Parsing ──
    // Parse ANSI input and return styled fragments
    std::vector<TextFragment> Parse(const std::string& input);
    
    // Parse incrementally (for streaming terminal output)
    void ParseIncremental(const std::string& chunk, 
                          std::function<void(const TextFragment&)> onFragment);
    
    // Parse to screen buffer (for full terminal emulation)
    void ParseToScreen(const std::string& input);
    
    // ── Screen Buffer Access ──
    const ScreenCell* GetScreenBuffer() const { return m_screenBuffer.get(); }
    ScreenCell* GetScreenBuffer() { return m_screenBuffer.get(); }
    CursorState GetCursorState() const { return m_cursor; }
    
    // Get text at specific screen region
    std::string GetScreenText(int startRow, int startCol, int endRow, int endCol) const;
    std::string GetLine(int row) const;
    
    // ── State Management ──
    void Reset();
    void ClearScreen();
    void ClearLine();
    void ClearToEndOfLine();
    void ClearToStartOfLine();
    
    // ── Cursor Operations ──
    void SetCursorPosition(int row, int col);
    void MoveCursor(int deltaRow, int deltaCol);
    void SaveCursorPosition();
    void RestoreCursorPosition();
    void HideCursor() { m_cursor.visible = false; }
    void ShowCursor() { m_cursor.visible = true; }
    
    // ── Scrollback Buffer ──
    void EnableScrollback(size_t maxLines);
    void DisableScrollback();
    std::vector<std::string> GetScrollbackBuffer() const { return m_scrollback; }
    void ClearScrollback();

    // ── Hyperlink Support ──
    using HyperlinkCallback = std::function<void(const std::string& id, const std::string& url, int row, int col)>;
    void SetHyperlinkCallback(HyperlinkCallback cb) { m_hyperlinkCallback = std::move(cb); }

    // ── Debug ──
    std::string GetDebugInfo() const;
    size_t GetParsedSequenceCount() const { return m_parsedSequenceCount; }

private:
    // Terminal state
    TerminalSize m_terminalSize;
    TextStyle m_currentStyle;
    TextStyle m_defaultStyle;
    CursorState m_cursor;
    CursorState m_savedCursor;
    
    // Screen buffer
    std::unique_ptr<ScreenCell[]> m_screenBuffer;
    bool m_screenBufferDirty = false;
    
    // Scrollback
    std::vector<std::string> m_scrollback;
    size_t m_maxScrollbackLines = 0;
    bool m_scrollbackEnabled = false;
    
    // Parsing state
    std::string m_parseBuffer;
    size_t m_parsedSequenceCount = 0;
    
    // Hyperlinks
    std::string m_currentHyperlinkId;
    std::string m_currentHyperlinkUrl;
    HyperlinkCallback m_hyperlinkCallback;
    
    // Parser state machine
    enum class ParseState {
        Normal,
        Escape,           // After ESC
        CSI,              // After ESC [
        CSI_Params,       // Parsing CSI parameters
        OSC,              // After ESC ]
        OSC_Params,       // Parsing OSC parameters
        OSC_ST,           // Waiting for OSC string terminator
        DCS,              // Device Control String
        DCS_Params,
        DCS_ST,
        APC,              // Application Program Command
        PM,               // Privacy Message
        SOS,              // Start of String
        Charset,          // Character set selection
        Ignore            // Ignoring until terminator
    };
    ParseState m_state = ParseState::Normal;
    
    // CSI parsing
    std::vector<int> m_csiParams;
    std::string m_csiIntermediate;
    char m_csiFinalChar = 0;
    
    // OSC parsing
    int m_oscParam = 0;
    std::string m_oscString;
    
    // ── Internal Parsing ──
    void ProcessChar(char c);
    void ProcessNormalChar(char c);
    void ProcessEscapeChar(char c);
    void ProcessCSIChar(char c);
    void ProcessOSCChar(char c);
    void ExecuteCSI();
    void ExecuteOSC();
    void ExecuteSGR(const std::vector<int>& params);
    
    // ── Screen Operations ──
    void ResizeScreenBuffer();
    void ScrollUp(int lines = 1);
    void ScrollDown(int lines = 1);
    void InsertLines(int count);
    void DeleteLines(int count);
    void InsertChars(int count);
    void DeleteChars(int count);
    void EraseChars(int count);
    void SetCell(int row, int col, char32_t ch, const TextStyle& style);
    ScreenCell& GetCell(int row, int col);
    bool IsValidPosition(int row, int col) const;
    
    // ── Color Handling ──
    Color Parse8BitColor(uint8_t index);
    Color Parse24BitColor(uint8_t r, uint8_t g, uint8_t b);
    
    // ── Utility ──
    void FlushParseBuffer();
    void AppendToScrollback(const std::string& line);
    int ClampRow(int row) const;
    int ClampCol(int col) const;
    static bool IsCSIParamChar(char c);
    static bool IsCSIIntermediateChar(char c);
    static bool IsCSIFinalChar(char c);
};

// ============================================================================
// TerminalRenderer - Renders parsed ANSI output to Windows controls
// ============================================================================
class TerminalRenderer {
public:
    TerminalRenderer();
    ~TerminalRenderer();

    // Attach to a RichEdit or custom control
    bool Attach(HWND hControl);
    void Detach();
    bool IsAttached() const { return m_hControl != nullptr; }

    // Render fragments
    void RenderFragments(const std::vector<TextFragment>& fragments);
    void Clear();
    
    // Scrollback view
    void SetScrollbackView(size_t startLine, size_t visibleLines);
    void ScrollToEnd();
    void ScrollToLine(size_t line);

    // Selection
    void BeginSelection(int row, int col);
    void UpdateSelection(int row, int col);
    void EndSelection();
    std::string GetSelectedText() const;
    void ClearSelection();

    // Search
    bool Search(const std::string& text, bool forward = true, bool caseSensitive = false);
    void ClearSearch();

    // Performance
    void SetDoubleBuffering(bool enable);
    void SetMaxLines(size_t maxLines);

private:
    HWND m_hControl = nullptr;
    HDC m_hMemDC = nullptr;
    HBITMAP m_hMemBitmap = nullptr;
    
    std::vector<TextFragment> m_fragments;
    size_t m_scrollbackStart = 0;
    size_t m_visibleLines = 24;
    size_t m_maxLines = 10000;
    
    // Selection
    bool m_selecting = false;
    int m_selStartRow = -1, m_selStartCol = -1;
    int m_selEndRow = -1, m_selEndCol = -1;
    
    // Search
    std::string m_searchText;
    std::vector<std::pair<int, int>> m_searchResults;
    size_t m_currentSearchResult = 0;
    
    void RenderToMemoryDC();
    void BlitToScreen();
    void DrawFragment(HDC hdc, const TextFragment& frag, int& x, int& y);
    HFONT CreateFontFromStyle(const TextStyle& style);
    COLORREF ColorToCOLORREF(const Color& c);
};

// ============================================================================
// Utility Functions
// ============================================================================

// Strip ANSI codes from string
std::string StripANSICodes(const std::string& input);

// Check if string contains ANSI codes
bool ContainsANSICodes(const std::string& input);

// Get visible length (excluding ANSI codes)
size_t GetVisibleLength(const std::string& input);

// Truncate to visible length
std::string TruncateVisible(const std::string& input, size_t maxLen);

// Pad to visible length
std::string PadVisible(const std::string& input, size_t targetLen, char padChar = ' ');

} // namespace rawrxd::terminal
