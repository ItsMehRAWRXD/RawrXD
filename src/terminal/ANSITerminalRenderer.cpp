// ============================================================================
// ANSITerminalRenderer.cpp - Production ANSI Terminal Implementation
// ============================================================================
// Full support for ANSI escape sequences, colors, cursor control, scrollback
// ============================================================================

#include "ANSITerminalRenderer.h"
#include <sstream>
#include <algorithm>
#include <cstring>

namespace RawrXD {
namespace Terminal {

// ============================================================================
// ScrollbackBuffer Implementation
// ============================================================================

void ScrollbackBuffer::AddLine(const std::vector<TerminalCell>& line) {
    lines.push_back(line);
    while (lines.size() > maxLines) {
        lines.pop_front();
    }
}

void ScrollbackBuffer::Clear() {
    lines.clear();
}

const std::vector<TerminalCell>* ScrollbackBuffer::GetLine(size_t index) const {
    if (index >= lines.size()) return nullptr;
    return &lines[index];
}

// ============================================================================
// Construction/Destruction
// ============================================================================

ANSITerminalRenderer::ANSITerminalRenderer() = default;

ANSITerminalRenderer::~ANSITerminalRenderer() {
    Shutdown();
}

// ============================================================================
// Initialization
// ============================================================================

bool ANSITerminalRenderer::Initialize(HWND hwnd) {
    if (m_initialized) return true;

    m_hwnd = hwnd;

    if (!CreateMemoryDC()) return false;
    if (!CreateFonts()) return false;

    CalculateCellSize();
    AllocateScreen();

    m_initialized = true;
    return true;
}

void ANSITerminalRenderer::Shutdown() {
    DestroyMemoryDC();
    DestroyFonts();
    m_initialized = false;
    m_hwnd = nullptr;
}

bool ANSITerminalRenderer::CreateMemoryDC() {
    if (!m_hwnd) return false;

    HDC hdc = GetDC(m_hwnd);
    if (!hdc) return false;

    RECT rc;
    GetClientRect(m_hwnd, &rc);

    m_memDC = CreateCompatibleDC(hdc);
    if (!m_memDC) {
        ReleaseDC(m_hwnd, hdc);
        return false;
    }

    m_memBitmap = CreateCompatibleBitmap(hdc, rc.right, rc.bottom);
    if (!m_memBitmap) {
        DeleteDC(m_memDC);
        m_memDC = nullptr;
        ReleaseDC(m_hwnd, hdc);
        return false;
    }

    SelectObject(m_memDC, m_memBitmap);
    ReleaseDC(m_hwnd, hdc);

    return true;
}

void ANSITerminalRenderer::DestroyMemoryDC() {
    if (m_memBitmap) {
        DeleteObject(m_memBitmap);
        m_memBitmap = nullptr;
    }
    if (m_memDC) {
        DeleteDC(m_memDC);
        m_memDC = nullptr;
    }
}

bool ANSITerminalRenderer::CreateFonts() {
    m_font = CreateFontW(
        -m_theme.fontSize, 0, 0, 0,
        m_theme.bold ? FW_BOLD : FW_NORMAL,
        FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN,
        m_theme.fontName.c_str()
    );

    m_boldFont = CreateFontW(
        -m_theme.fontSize, 0, 0, 0,
        FW_BOLD,
        FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN,
        m_theme.fontName.c_str()
    );

    return m_font != nullptr;
}

void ANSITerminalRenderer::DestroyFonts() {
    if (m_font) {
        DeleteObject(m_font);
        m_font = nullptr;
    }
    if (m_boldFont) {
        DeleteObject(m_boldFont);
        m_boldFont = nullptr;
    }
}

void ANSITerminalRenderer::CalculateCellSize() {
    if (!m_memDC || !m_font) return;

    HFONT oldFont = (HFONT)SelectObject(m_memDC, m_font);

    TEXTMETRICW tm;
    GetTextMetricsW(m_memDC, &tm);

    m_cellHeight = tm.tmHeight + tm.tmExternalLeading;
    m_cellWidth = tm.tmAveCharWidth;

    SelectObject(m_memDC, oldFont);
}

void ANSITerminalRenderer::AllocateScreen() {
    m_screen.resize(m_rows);
    for (auto& row : m_screen) {
        row.resize(m_cols);
        for (auto& cell : row) {
            cell.ch = L' ';
            cell.attrs = m_currentAttrs;
            cell.dirty = true;
        }
    }
}

// ============================================================================
// Resizing
// ============================================================================

void ANSITerminalRenderer::Resize(int width, int height) {
    if (!m_initialized) return;

    DestroyMemoryDC();
    CreateMemoryDC();

    int newCols = width / m_cellWidth;
    int newRows = height / m_cellHeight;

    if (newCols != m_cols || newRows != m_rows) {
        SetGridSize(newCols, newRows);
    }

    InvalidateRect(m_hwnd, nullptr, FALSE);
}

void ANSITerminalRenderer::SetGridSize(int cols, int rows) {
    if (cols < 1) cols = 1;
    if (rows < 1) rows = 1;

    // Save old screen
    auto oldScreen = m_screen;
    int oldCols = m_cols;
    int oldRows = m_rows;

    m_cols = cols;
    m_rows = rows;
    m_visibleRows = rows;

    AllocateScreen();

    // Copy old content
    int copyRows = std::min(oldRows, m_rows);
    int copyCols = std::min(oldCols, m_cols);

    for (int r = 0; r < copyRows; r++) {
        for (int c = 0; c < copyCols; c++) {
            m_screen[r][c] = oldScreen[r][c];
        }
    }

    // Ensure cursor is valid
    if (m_cursorRow >= m_rows) m_cursorRow = m_rows - 1;
    if (m_cursorCol >= m_cols) m_cursorCol = m_cols - 1;

    if (m_resizeCallback) {
        m_resizeCallback(m_cols, m_rows);
    }
}

// ============================================================================
// ANSI Processing
// ============================================================================

void ANSITerminalRenderer::ProcessOutput(const std::string& output) {
    ProcessOutput(output.c_str(), output.size());
}

void ANSITerminalRenderer::ProcessOutput(const char* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        ParseByte(data[i]);
    }
    Invalidate();
}

void ANSITerminalRenderer::ParseByte(char c) {
    if (m_inOSC) {
        if (c == '\x07' || c == '\x1b') {
            m_inOSC = false;
            if (!m_parseBuffer.empty() && m_parseBuffer[0] == ']') {
                ProcessOSC();
            }
            m_parseBuffer.clear();
        } else {
            m_parseBuffer += c;
        }
        return;
    }

    if (m_inCSI) {
        if ((c >= '0' && c <= '9') || c == ';' || c == ':') {
            m_parseBuffer += c;
        } else if (c >= '@' && c <= '~') {
            m_inCSI = false;
            ProcessCSI();
            ExecuteCSI(c);
            m_parseBuffer.clear();
        } else if (c >= ' ' && c <= '/') {
            // Intermediate bytes
            m_parseBuffer += c;
        } else {
            m_inCSI = false;
            m_parseBuffer.clear();
        }
        return;
    }

    if (m_inEscape) {
        m_inEscape = false;
        switch (c) {
            case '[':
                m_inCSI = true;
                m_parseBuffer.clear();
                break;
            case ']':
                m_inOSC = true;
                m_parseBuffer.clear();
                break;
            case '(':  // Select G0 charset
            case ')':  // Select G1 charset
            case '*':  // Select G2 charset
            case '+':  // Select G3 charset
                // Ignore charset selection for now
                break;
            case '7':  // Save cursor
                SaveCursor();
                break;
            case '8':  // Restore cursor
                RestoreCursor();
                break;
            case 'c':  // Reset terminal
                ClearScreen();
                break;
            case 'M':  // Reverse index
                if (m_cursorRow > 0) {
                    m_cursorRow--;
                } else {
                    ScrollDown();
                }
                break;
            default:
                break;
        }
        return;
    }

    if (c == '\x1b') {
        m_inEscape = true;
        return;
    }

    if (c == '\r') {
        m_cursorCol = 0;
        return;
    }

    if (c == '\n') {
        m_cursorCol = 0;
        m_cursorRow++;
        if (m_cursorRow >= m_rows) {
            ScrollUp();
            m_cursorRow = m_rows - 1;
        }
        return;
    }

    if (c == '\t') {
        int nextTab = ((m_cursorCol / 8) + 1) * 8;
        while (m_cursorCol < nextTab && m_cursorCol < m_cols) {
            OutputChar(L' ');
        }
        return;
    }

    if (c == '\x07') {
        if (m_bellCallback) m_bellCallback();
        return;
    }

    if (c == '\x08') {  // Backspace
        if (m_cursorCol > 0) {
            m_cursorCol--;
        }
        return;
    }

    // Regular character
    if (c >= 0x20 && c < 0x7F) {
        OutputChar(static_cast<wchar_t>(c));
    }
}

void ANSITerminalRenderer::ProcessCSI() {
    m_csiParams.clear();

    std::string paramStr;
    for (char c : m_parseBuffer) {
        if (c >= '0' && c <= '9') {
            paramStr += c;
        } else if (c == ';' || c == ':') {
            if (!paramStr.empty()) {
                m_csiParams.push_back(std::stoi(paramStr));
                paramStr.clear();
            }
        }
    }

    if (!paramStr.empty()) {
        m_csiParams.push_back(std::stoi(paramStr));
    }

    if (m_csiParams.empty()) {
        m_csiParams.push_back(0);
    }
}

void ANSITerminalRenderer::ProcessOSC() {
    // OSC sequences: ESC ] Ps ; Pt BEL or ESC ] Ps ; Pt ESC \
    size_t semicolon = m_parseBuffer.find(';');
    if (semicolon == std::string::npos) return;

    int ps = std::stoi(m_parseBuffer.substr(1, semicolon - 1));
    std::string pt = m_parseBuffer.substr(semicolon + 1);

    switch (ps) {
        case 0:  // Set window title and icon
        case 2:  // Set window title
            SetTitle(pt);
            break;
        // Add more OSC handlers as needed
    }
}

void ANSITerminalRenderer::ExecuteCSI(int cmd) {
    switch (cmd) {
        case 'm':  // SGR
            ProcessSGR(m_csiParams);
            break;
        case 'H':  // Cursor position
        case 'f':
            MoveCursor(
                m_csiParams.size() > 0 ? m_csiParams[0] : 1,
                m_csiParams.size() > 1 ? m_csiParams[1] : 1
            );
            break;
        case 'A':  // Cursor up
            MoveCursorUp(m_csiParams.empty() ? 1 : m_csiParams[0]);
            break;
        case 'B':  // Cursor down
            MoveCursorDown(m_csiParams.empty() ? 1 : m_csiParams[0]);
            break;
        case 'C':  // Cursor forward
            MoveCursorForward(m_csiParams.empty() ? 1 : m_csiParams[0]);
            break;
        case 'D':  // Cursor backward
            MoveCursorBackward(m_csiParams.empty() ? 1 : m_csiParams[0]);
            break;
        case 'E':  // Cursor next line
            MoveCursorNextLine(m_csiParams.empty() ? 1 : m_csiParams[0]);
            break;
        case 'F':  // Cursor previous line
            MoveCursorPrevLine(m_csiParams.empty() ? 1 : m_csiParams[0]);
            break;
        case 'G':  // Cursor horizontal absolute
            SetCursorColumn(m_csiParams.empty() ? 1 : m_csiParams[0]);
            break;
        case 'J':  // Erase display
            switch (m_csiParams.empty() ? 0 : m_csiParams[0]) {
                case 0:
                    // Clear from cursor to end
                    for (int c = m_cursorCol; c < m_cols; c++) {
                        m_screen[m_cursorRow][c].ch = L' ';
                        m_screen[m_cursorRow][c].attrs = m_currentAttrs;
                    }
                    for (int r = m_cursorRow + 1; r < m_rows; r++) {
                        for (auto& cell : m_screen[r]) {
                            cell.ch = L' ';
                            cell.attrs = m_currentAttrs;
                        }
                    }
                    break;
                case 1:
                    // Clear from beginning to cursor
                    for (int r = 0; r < m_cursorRow; r++) {
                        for (auto& cell : m_screen[r]) {
                            cell.ch = L' ';
                            cell.attrs = m_currentAttrs;
                        }
                    }
                    for (int c = 0; c <= m_cursorCol; c++) {
                        m_screen[m_cursorRow][c].ch = L' ';
                        m_screen[m_cursorRow][c].attrs = m_currentAttrs;
                    }
                    break;
                case 2:
                case 3:
                    ClearScreen();
                    break;
            }
            break;
        case 'K':  // Erase line
            switch (m_csiParams.empty() ? 0 : m_csiParams[0]) {
                case 0:
                    ClearLineFromCursor();
                    break;
                case 1:
                    ClearLineToCursor();
                    break;
                case 2:
                    ClearLine();
                    break;
            }
            break;
        case 'L':  // Insert lines
            InsertLines(m_csiParams.empty() ? 1 : m_csiParams[0]);
            break;
        case 'M':  // Delete lines
            DeleteLines(m_csiParams.empty() ? 1 : m_csiParams[0]);
            break;
        case 'P':  // Delete characters
            {
                int n = m_csiParams.empty() ? 1 : m_csiParams[0];
                for (int c = m_cursorCol; c < m_cols - n; c++) {
                    m_screen[m_cursorRow][c] = m_screen[m_cursorRow][c + n];
                }
                for (int c = m_cols - n; c < m_cols; c++) {
                    m_screen[m_cursorRow][c].ch = L' ';
                    m_screen[m_cursorRow][c].attrs = m_currentAttrs;
                }
            }
            break;
        case '@':  // Insert characters
            {
                int n = m_csiParams.empty() ? 1 : m_csiParams[0];
                for (int c = m_cols - 1; c >= m_cursorCol + n; c--) {
                    m_screen[m_cursorRow][c] = m_screen[m_cursorRow][c - n];
                }
                for (int c = m_cursorCol; c < m_cursorCol + n && c < m_cols; c++) {
                    m_screen[m_cursorRow][c].ch = L' ';
                    m_screen[m_cursorRow][c].attrs = m_currentAttrs;
                }
            }
            break;
        case 'S':  // Scroll up
            ScrollUp(m_csiParams.empty() ? 1 : m_csiParams[0]);
            break;
        case 'T':  // Scroll down
            ScrollDown(m_csiParams.empty() ? 1 : m_csiParams[0]);
            break;
        case 's':  // Save cursor
            SaveCursor();
            break;
        case 'u':  // Restore cursor
            RestoreCursor();
            break;
        case 'd':  // Vertical position absolute
            SetCursorRow(m_csiParams.empty() ? 1 : m_csiParams[0]);
            break;
        case 'h':  // Set mode
        case 'l':  // Reset mode
            // Handle various modes (insert, echo, etc.)
            break;
    }
}

void ANSITerminalRenderer::ProcessSGR(const std::vector<int>& params) {
    if (params.empty()) {
        m_currentAttrs = TextAttributes();
        return;
    }

    for (size_t i = 0; i < params.size(); i++) {
        int code = params[i];

        switch (code) {
            case 0:  // Reset
                m_currentAttrs = TextAttributes();
                break;
            case 1:  // Bold
                m_currentAttrs.bold = true;
                break;
            case 2:  // Dim
                m_currentAttrs.dim = true;
                break;
            case 3:  // Italic
                m_currentAttrs.italic = true;
                break;
            case 4:  // Underline
                m_currentAttrs.underline = true;
                break;
            case 5:  // Blink
            case 6:  // Rapid blink
                m_currentAttrs.blink = true;
                break;
            case 7:  // Reverse
                m_currentAttrs.reverse = true;
                break;
            case 8:  // Hidden
                m_currentAttrs.hidden = true;
                break;
            case 9:  // Strikethrough
                m_currentAttrs.strikethrough = true;
                break;
            case 22:  // Normal intensity
                m_currentAttrs.bold = false;
                m_currentAttrs.dim = false;
                break;
            case 23:  // Not italic
                m_currentAttrs.italic = false;
                break;
            case 24:  // Not underlined
                m_currentAttrs.underline = false;
                break;
            case 25:  // Not blinking
                m_currentAttrs.blink = false;
                break;
            case 27:  // Not reversed
                m_currentAttrs.reverse = false;
                break;
            case 28:  // Not hidden
                m_currentAttrs.hidden = false;
                break;
            case 29:  // Not strikethrough
                m_currentAttrs.strikethrough = false;
                break;
            case 30: case 31: case 32: case 33:
            case 34: case 35: case 36: case 37:
                m_currentAttrs.fg = static_cast<ANSIColor>(code - 30);
                break;
            case 38:  // Extended foreground color
                if (i + 2 < params.size() && params[i + 1] == 5) {
                    m_currentAttrs.fg = static_cast<ANSIColor>(params[i + 2]);
                    i += 2;
                }
                break;
            case 39:  // Default foreground
                m_currentAttrs.fg = ANSIColor::Default;
                break;
            case 40: case 41: case 42: case 43:
            case 44: case 45: case 46: case 47:
                m_currentAttrs.bg = static_cast<ANSIColor>(code - 40);
                break;
            case 48:  // Extended background color
                if (i + 2 < params.size() && params[i + 1] == 5) {
                    m_currentAttrs.bg = static_cast<ANSIColor>(params[i + 2]);
                    i += 2;
                }
                break;
            case 49:  // Default background
                m_currentAttrs.bg = ANSIColor::Default;
                break;
            case 90: case 91: case 92: case 93:
            case 94: case 95: case 96: case 97:
                m_currentAttrs.fg = static_cast<ANSIColor>(code - 90 + 8);
                break;
            case 100: case 101: case 102: case 103:
            case 104: case 105: case 106: case 107:
                m_currentAttrs.bg = static_cast<ANSIColor>(code - 100 + 8);
                break;
        }
    }
}

// ============================================================================
// Cursor Movement
// ============================================================================

void ANSITerminalRenderer::MoveCursor(int row, int col) {
    m_cursorRow = std::max(1, std::min(row, m_rows)) - 1;
    m_cursorCol = std::max(1, std::min(col, m_cols)) - 1;
}

void ANSITerminalRenderer::MoveCursorUp(int n) {
    if (n < 1) n = 1;
    m_cursorRow = std::max(0, m_cursorRow - n);
}

void ANSITerminalRenderer::MoveCursorDown(int n) {
    if (n < 1) n = 1;
    m_cursorRow = std::min(m_rows - 1, m_cursorRow + n);
}

void ANSITerminalRenderer::MoveCursorForward(int n) {
    if (n < 1) n = 1;
    m_cursorCol = std::min(m_cols - 1, m_cursorCol + n);
}

void ANSITerminalRenderer::MoveCursorBackward(int n) {
    if (n < 1) n = 1;
    m_cursorCol = std::max(0, m_cursorCol - n);
}

void ANSITerminalRenderer::MoveCursorNextLine(int n) {
    if (n < 1) n = 1;
    m_cursorRow = std::min(m_rows - 1, m_cursorRow + n);
    m_cursorCol = 0;
}

void ANSITerminalRenderer::MoveCursorPrevLine(int n) {
    if (n < 1) n = 1;
    m_cursorRow = std::max(0, m_cursorRow - n);
    m_cursorCol = 0;
}

void ANSITerminalRenderer::SetCursorColumn(int col) {
    m_cursorCol = std::max(1, std::min(col, m_cols)) - 1;
}

void ANSITerminalRenderer::SetCursorRow(int row) {
    m_cursorRow = std::max(1, std::min(row, m_rows)) - 1;
}

void ANSITerminalRenderer::SaveCursor() {
    m_savedRow = m_cursorRow;
    m_savedCol = m_cursorCol;
}

void ANSITerminalRenderer::RestoreCursor() {
    m_cursorRow = m_savedRow;
    m_cursorCol = m_savedCol;
}

void ANSITerminalRenderer::GetCursorPos(int& row, int& col) const {
    row = m_cursorRow + 1;
    col = m_cursorCol + 1;
}

// ============================================================================
// Scrolling
// ============================================================================

void ANSITerminalRenderer::ScrollUp(int lines) {
    if (lines < 1) lines = 1;

    for (int i = 0; i < lines; i++) {
        // Save top line to scrollback
        m_scrollback.AddLine(m_screen[0]);

        // Scroll up
        for (int r = 0; r < m_rows - 1; r++) {
            m_screen[r] = m_screen[r + 1];
        }

        // Clear bottom line
        for (auto& cell : m_screen[m_rows - 1]) {
            cell.ch = L' ';
            cell.attrs = m_currentAttrs;
            cell.dirty = true;
        }
    }
}

void ANSITerminalRenderer::ScrollDown(int lines) {
    if (lines < 1) lines = 1;

    for (int i = 0; i < lines; i++) {
        // Scroll down
        for (int r = m_rows - 1; r > 0; r--) {
            m_screen[r] = m_screen[r - 1];
        }

        // Clear top line
        for (auto& cell : m_screen[0]) {
            cell.ch = L' ';
            cell.attrs = m_currentAttrs;
            cell.dirty = true;
        }
    }
}

void ANSITerminalRenderer::InsertLines(int n) {
    if (n < 1) n = 1;
    if (n > m_rows - m_cursorRow) n = m_rows - m_cursorRow;

    // Move lines down
    for (int r = m_rows - 1; r >= m_cursorRow + n; r--) {
        m_screen[r] = m_screen[r - n];
    }

    // Clear inserted lines
    for (int r = m_cursorRow; r < m_cursorRow + n; r++) {
        for (auto& cell : m_screen[r]) {
            cell.ch = L' ';
            cell.attrs = m_currentAttrs;
            cell.dirty = true;
        }
    }
}

void ANSITerminalRenderer::DeleteLines(int n) {
    if (n < 1) n = 1;
    if (n > m_rows - m_cursorRow) n = m_rows - m_cursorRow;

    // Move lines up
    for (int r = m_cursorRow; r < m_rows - n; r++) {
        m_screen[r] = m_screen[r + n];
    }

    // Clear bottom lines
    for (int r = m_rows - n; r < m_rows; r++) {
        for (auto& cell : m_screen[r]) {
            cell.ch = L' ';
            cell.attrs = m_currentAttrs;
            cell.dirty = true;
        }
    }
}

void ANSITerminalRenderer::ScrollUp() {
    ScrollUp(1);
}

void ANSITerminalRenderer::ScrollDown() {
    ScrollDown(1);
}

// ============================================================================
// Character Output
// ============================================================================

void ANSITerminalRenderer::OutputChar(wchar_t ch) {
    if (m_cursorCol >= m_cols) {
        WrapCursor();
    }

    m_screen[m_cursorRow][m_cursorCol].ch = ch;
    m_screen[m_cursorRow][m_cursorCol].attrs = m_currentAttrs;
    m_screen[m_cursorRow][m_cursorCol].dirty = true;

    m_cursorCol++;
}

void ANSITerminalRenderer::OutputString(const std::wstring& str) {
    for (wchar_t ch : str) {
        OutputChar(ch);
    }
}

void ANSITerminalRenderer::WrapCursor() {
    m_cursorCol = 0;
    m_cursorRow++;
    if (m_cursorRow >= m_rows) {
        ScrollUp();
        m_cursorRow = m_rows - 1;
    }
}

// ============================================================================
// Clearing
// ============================================================================

void ANSITerminalRenderer::ClearScreen() {
    for (auto& row : m_screen) {
        for (auto& cell : row) {
            cell.ch = L' ';
            cell.attrs = m_currentAttrs;
            cell.dirty = true;
        }
    }
    m_cursorRow = 0;
    m_cursorCol = 0;
}

void ANSITerminalRenderer::ClearLine() {
    for (auto& cell : m_screen[m_cursorRow]) {
        cell.ch = L' ';
        cell.attrs = m_currentAttrs;
        cell.dirty = true;
    }
}

void ANSITerminalRenderer::ClearLineFromCursor() {
    for (int c = m_cursorCol; c < m_cols; c++) {
        m_screen[m_cursorRow][c].ch = L' ';
        m_screen[m_cursorRow][c].attrs = m_currentAttrs;
        m_screen[m_cursorRow][c].dirty = true;
    }
}

void ANSITerminalRenderer::ClearLineToCursor() {
    for (int c = 0; c <= m_cursorCol; c++) {
        m_screen[m_cursorRow][c].ch = L' ';
        m_screen[m_cursorRow][c].attrs = m_currentAttrs;
        m_screen[m_cursorRow][c].dirty = true;
    }
}

// ============================================================================
// Rendering
// ============================================================================

void ANSITerminalRenderer::Render(HDC hdc) {
    if (!m_memDC) return;

    // Update blink state
    DWORD now = GetTickCount();
    if (now - m_lastBlinkTime > 500) {
        m_cursorBlinkState = !m_cursorBlinkState;
        m_lastBlinkTime = now;
    }

    // Render to memory DC
    HFONT oldFont = (HFONT)SelectObject(m_memDC, m_font);

    // Background
    RECT bgRect = {0, 0, m_cols * m_cellWidth, m_rows * m_cellHeight};
    FillRect(m_memDC, &bgRect, (HBRUSH)GetStockObject(BLACK_BRUSH));

    // Render cells
    for (int r = 0; r < m_rows; r++) {
        for (int c = 0; c < m_cols; c++) {
            RenderCell(m_memDC, r, c);
        }
    }

    // Render cursor
    if (m_cursorVisible && (!m_cursorBlink || m_cursorBlinkState)) {
        RenderCursor(m_memDC);
    }

    // Render selection
    if (HasSelection()) {
        RenderSelection(m_memDC);
    }

    SelectObject(m_memDC, oldFont);

    // Copy to screen
    BitBlt(hdc, 0, 0, m_cols * m_cellWidth, m_rows * m_cellHeight,
           m_memDC, 0, 0, SRCCOPY);
}

void ANSITerminalRenderer::Render() {
    if (!m_hwnd) return;
    HDC hdc = GetDC(m_hwnd);
    if (hdc) {
        Render(hdc);
        ReleaseDC(m_hwnd, hdc);
    }
}

void ANSITerminalRenderer::Invalidate() {
    if (m_hwnd) {
        InvalidateRect(m_hwnd, nullptr, FALSE);
    }
}

void ANSITerminalRenderer::RenderCell(HDC hdc, int row, int col) {
    const TerminalCell& cell = m_screen[row][col];

    int x = col * m_cellWidth;
    int y = row * m_cellHeight;

    // Get colors
    COLORREF fg = GetFGColor(cell.attrs);
    COLORREF bg = GetBGColor(cell.attrs);

    // Background
    RECT cellRect = {x, y, x + m_cellWidth, y + m_cellHeight};
    SetBkColor(hdc, bg);
    ExtTextOutW(hdc, x, y, ETO_OPAQUE, &cellRect, nullptr, 0, nullptr);

    // Character
    if (cell.ch != L' ') {
        HFONT font = (cell.attrs.bold) ? m_boldFont : m_font;
        SelectObject(hdc, font);

        SetTextColor(hdc, fg);
        SetBkMode(hdc, TRANSPARENT);

        wchar_t ch = cell.ch;
        ExtTextOutW(hdc, x, y, 0, nullptr, &ch, 1, nullptr);
    }
}

void ANSITerminalRenderer::RenderCursor(HDC hdc) {
    int x = m_cursorCol * m_cellWidth;
    int y = m_cursorRow * m_cellHeight;

    RECT cursorRect = {x, y, x + m_cellWidth, y + m_cellHeight};

    // Invert colors at cursor position
    SetBkColor(hdc, m_theme.cursorBg);
    SetTextColor(hdc, m_theme.cursorFg);

    const TerminalCell& cell = m_screen[m_cursorRow][m_cursorCol];
    wchar_t ch = cell.ch;

    ExtTextOutW(hdc, x, y, ETO_OPAQUE, &cursorRect, &ch, 1, nullptr);
}

void ANSITerminalRenderer::RenderSelection(HDC hdc) {
    int startRow = m_selStartRow;
    int startCol = m_selStartCol;
    int endRow = m_selEndRow;
    int endCol = m_selEndCol;

    if (startRow > endRow || (startRow == endRow && startCol > endCol)) {
        std::swap(startRow, endRow);
        std::swap(startCol, endCol);
    }

    for (int r = startRow; r <= endRow; r++) {
        int cStart = (r == startRow) ? startCol : 0;
        int cEnd = (r == endRow) ? endCol : m_cols - 1;

        int x = cStart * m_cellWidth;
        int y = r * m_cellHeight;
        int width = (cEnd - cStart + 1) * m_cellWidth;

        RECT selRect = {x, y, x + width, y + m_cellHeight};

        SetBkColor(hdc, m_theme.selectionBg);
        ExtTextOutW(hdc, x, y, ETO_OPAQUE, &selRect, nullptr, 0, nullptr);

        // Redraw selected text
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, m_theme.defaultFg);
        for (int c = cStart; c <= cEnd; c++) {
            wchar_t ch = m_screen[r][c].ch;
            ExtTextOutW(hdc, c * m_cellWidth, y, 0, nullptr, &ch, 1, nullptr);
        }
    }
}

COLORREF ANSITerminalRenderer::GetFGColor(const TextAttributes& attrs) const {
    if (attrs.hidden) return GetBGColor(attrs);
    if (attrs.reverse) return GetBGColor(attrs);

    if (attrs.fg == ANSIColor::Default) {
        return m_theme.defaultFg;
    }

    int idx = static_cast<int>(attrs.fg);
    if (idx >= 0 && idx < 16) {
        return m_theme.colors[idx];
    }

    return m_theme.defaultFg;
}

COLORREF ANSITerminalRenderer::GetBGColor(const TextAttributes& attrs) const {
    if (attrs.reverse) return GetFGColor(attrs);

    if (attrs.bg == ANSIColor::Default) {
        return m_theme.defaultBg;
    }

    int idx = static_cast<int>(attrs.bg);
    if (idx >= 0 && idx < 16) {
        return m_theme.colors[idx];
    }

    return m_theme.defaultBg;
}

// ============================================================================
// Scrollback
// ============================================================================

void ANSITerminalRenderer::ScrollUp() {
    if (m_scrollOffset < static_cast<int>(m_scrollback.Size())) {
        m_scrollOffset++;
    }
}

void ANSITerminalRenderer::ScrollDown() {
    if (m_scrollOffset > 0) {
        m_scrollOffset--;
    }
}

void ANSITerminalRenderer::ScrollToTop() {
    m_scrollOffset = static_cast<int>(m_scrollback.Size());
}

void ANSITerminalRenderer::ScrollToBottom() {
    m_scrollOffset = 0;
}

bool ANSITerminalRenderer::CanScrollUp() const {
    return m_scrollOffset < static_cast<int>(m_scrollback.Size());
}

bool ANSITerminalRenderer::CanScrollDown() const {
    return m_scrollOffset > 0;
}

void ANSITerminalRenderer::ClearScrollback() {
    m_scrollback.Clear();
    m_scrollOffset = 0;
}

// ============================================================================
// Selection
// ============================================================================

void ANSITerminalRenderer::StartSelection(int row, int col) {
    m_selecting = true;
    m_selStartRow = row;
    m_selStartCol = col;
    m_selEndRow = row;
    m_selEndCol = col;
}

void ANSITerminalRenderer::UpdateSelection(int row, int col) {
    if (!m_selecting) return;
    m_selEndRow = row;
    m_selEndCol = col;
}

void ANSITerminalRenderer::EndSelection() {
    m_selecting = false;
    NormalizeSelection();
}

void ANSITerminalRenderer::ClearSelection() {
    m_selecting = false;
    m_selStartRow = m_selStartCol = -1;
    m_selEndRow = m_selEndCol = -1;
}

bool ANSITerminalRenderer::HasSelection() const {
    return m_selStartRow >= 0 && m_selEndRow >= 0;
}

void ANSITerminalRenderer::NormalizeSelection() {
    if (m_selStartRow > m_selEndRow ||
        (m_selStartRow == m_selEndRow && m_selStartCol > m_selEndCol)) {
        std::swap(m_selStartRow, m_selEndRow);
        std::swap(m_selStartCol, m_selEndCol);
    }
}

bool ANSITerminalRenderer::IsInSelection(int row, int col) const {
    if (!HasSelection()) return false;

    int startRow = m_selStartRow;
    int startCol = m_selStartCol;
    int endRow = m_selEndRow;
    int endCol = m_selEndCol;

    if (startRow > endRow || (startRow == endRow && startCol > endCol)) {
        std::swap(startRow, endRow);
        std::swap(startCol, endCol);
    }

    if (row < startRow || row > endRow) return false;
    if (row == startRow && col < startCol) return false;
    if (row == endRow && col > endCol) return false;

    return true;
}

std::string ANSITerminalRenderer::GetSelectedText() const {
    if (!HasSelection()) return "";

    std::wstring result;

    int startRow = m_selStartRow;
    int startCol = m_selStartCol;
    int endRow = m_selEndRow;
    int endCol = m_selEndCol;

    if (startRow > endRow || (startRow == endRow && startCol > endCol)) {
        std::swap(startRow, endRow);
        std::swap(startCol, endCol);
    }

    for (int r = startRow; r <= endRow; r++) {
        int cStart = (r == startRow) ? startCol : 0;
        int cEnd = (r == endRow) ? endCol : m_cols - 1;

        for (int c = cStart; c <= cEnd; c++) {
            result += m_screen[r][c].ch;
        }

        if (r < endRow) {
            result += L'\n';
        }
    }

    return WideToUTF8(result);
}

// ============================================================================
// Clipboard
// ============================================================================

void ANSITerminalRenderer::CopyToClipboard() {
    std::string text = GetSelectedText();
    if (text.empty()) return;

    if (!OpenClipboard(m_hwnd)) return;
    EmptyClipboard();

    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, text.size() + 1);
    if (hMem) {
        char* pMem = static_cast<char*>(GlobalLock(hMem));
        memcpy(pMem, text.c_str(), text.size() + 1);
        GlobalUnlock(hMem);
        SetClipboardData(CF_TEXT, hMem);
    }

    CloseClipboard();
}

void ANSITerminalRenderer::PasteFromClipboard() {
    if (!OpenClipboard(m_hwnd)) return;

    HANDLE hData = GetClipboardData(CF_TEXT);
    if (hData) {
        char* pData = static_cast<char*>(GlobalLock(hData));
        if (pData) {
            if (m_inputCallback) {
                m_inputCallback(pData);
            }
            GlobalUnlock(hData);
        }
    }

    CloseClipboard();
}

// ============================================================================
// Input Handling
// ============================================================================

void ANSITerminalRenderer::OnKeyDown(WPARAM key, LPARAM lParam) {
    bool ctrl = GetKeyState(VK_CONTROL) < 0;
    bool shift = GetKeyState(VK_SHIFT) < 0;

    switch (key) {
        case VK_UP:
            if (ctrl) {
                ScrollUp();
            } else if (m_inputCallback) {
                m_inputCallback("\x1b[A");
            }
            break;
        case VK_DOWN:
            if (ctrl) {
                ScrollDown();
            } else if (m_inputCallback) {
                m_inputCallback("\x1b[B");
            }
            break;
        case VK_RIGHT:
            if (m_inputCallback) {
                m_inputCallback("\x1b[C");
            }
            break;
        case VK_LEFT:
            if (m_inputCallback) {
                m_inputCallback("\x1b[D");
            }
            break;
        case VK_HOME:
            if (m_inputCallback) {
                m_inputCallback(ctrl ? "\x1b[1;5H" : "\x1b[H");
            }
            break;
        case VK_END:
            if (m_inputCallback) {
                m_inputCallback(ctrl ? "\x1b[1;5F" : "\x1b[F");
            }
            break;
        case VK_PRIOR:  // Page Up
            if (ctrl) {
                ScrollUp(10);
            } else if (m_inputCallback) {
                m_inputCallback("\x1b[5~");
            }
            break;
        case VK_NEXT:  // Page Down
            if (ctrl) {
                ScrollDown(10);
            } else if (m_inputCallback) {
                m_inputCallback("\x1b[6~");
            }
            break;
        case VK_INSERT:
            if (m_inputCallback) {
                m_inputCallback("\x1b[2~");
            }
            break;
        case VK_DELETE:
            if (m_inputCallback) {
                m_inputCallback("\x1b[3~");
            }
            break;
        case VK_RETURN:
            if (m_inputCallback) {
                m_inputCallback("\r");
            }
            break;
        case VK_BACK:
            if (m_inputCallback) {
                m_inputCallback("\x7f");
            }
            break;
        case VK_TAB:
            if (m_inputCallback) {
                m_inputCallback(shift ? "\x1b[Z" : "\t");
            }
            break;
        case 'C':
            if (ctrl) {
                CopyToClipboard();
            } else if (m_inputCallback) {
                m_inputCallback("c");
            }
            break;
        case 'V':
            if (ctrl) {
                PasteFromClipboard();
            } else if (m_inputCallback) {
                m_inputCallback("v");
            }
            break;
        case 'A':
            if (ctrl) {
                // Select all
                StartSelection(0, 0);
                UpdateSelection(m_rows - 1, m_cols - 1);
                EndSelection();
            } else if (m_inputCallback) {
                m_inputCallback("a");
            }
            break;
    }
}

void ANSITerminalRenderer::OnChar(WPARAM ch) {
    if (m_inputCallback && ch >= 32 && ch < 127) {
        std::string input;
        input += static_cast<char>(ch);
        m_inputCallback(input);
    }
}

void ANSITerminalRenderer::OnMouseDown(int x, int y) {
    int col = x / m_cellWidth;
    int row = y / m_cellHeight;

    if (row >= 0 && row < m_rows && col >= 0 && col < m_cols) {
        ClearSelection();
        StartSelection(row, col);
    }
}

void ANSITerminalRenderer::OnMouseMove(int x, int y) {
    if (!m_selecting) return;

    int col = x / m_cellWidth;
    int row = y / m_cellHeight;

    col = std::max(0, std::min(col, m_cols - 1));
    row = std::max(0, std::min(row, m_rows - 1));

    UpdateSelection(row, col);
    Invalidate();
}

void ANSITerminalRenderer::OnMouseUp(int x, int y) {
    if (m_selecting) {
        EndSelection();
        Invalidate();
    }
}

void ANSITerminalRenderer::OnMouseWheel(int delta) {
    if (delta > 0) {
        ScrollUp(3);
    } else {
        ScrollDown(3);
    }
    Invalidate();
}

void ANSITerminalRenderer::OnScroll() {
    Invalidate();
}

void ANSITerminalRenderer::OnResize() {
    if (!m_hwnd) return;

    RECT rc;
    GetClientRect(m_hwnd, &rc);
    Resize(rc.right, rc.bottom);
}

void ANSITerminalRenderer::OnFocusLost() {
    m_selecting = false;
}

// ============================================================================
// Theme
// ============================================================================

void ANSITerminalRenderer::SetTheme(const TerminalTheme& theme) {
    m_theme = theme;
    DestroyFonts();
    CreateFonts();
    CalculateCellSize();
    MarkAllDirty();
    Invalidate();
}

void ANSITerminalRenderer::MarkAllDirty() {
    for (auto& row : m_screen) {
        for (auto& cell : row) {
            cell.dirty = true;
        }
    }
}

void ANSITerminalRenderer::MarkDirty(int row, int col) {
    if (row >= 0 && row < m_rows && col >= 0 && col < m_cols) {
        m_screen[row][col].dirty = true;
    }
}

void ANSITerminalRenderer::MarkRowDirty(int row) {
    if (row >= 0 && row < m_rows) {
        for (auto& cell : m_screen[row]) {
            cell.dirty = true;
        }
    }
}

// ============================================================================
// Title
// ============================================================================

void ANSITerminalRenderer::SetTitle(const std::string& title) {
    m_title = title;
    if (m_hwnd) {
        SetWindowTextA(m_hwnd, title.c_str());
    }
}

// ============================================================================
// Utility
// ============================================================================

std::wstring ANSITerminalRenderer::UTF8ToWide(const std::string& utf8) {
    if (utf8.empty()) return L"";

    int size = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, nullptr, 0);
    if (size <= 0) return L"";

    std::wstring wide(size - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, &wide[0], size);
    return wide;
}

std::string ANSITerminalRenderer::WideToUTF8(const std::wstring& wide) {
    if (wide.empty()) return "";

    int size = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (size <= 0) return "";

    std::string utf8(size - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, &utf8[0], size, nullptr, nullptr);
    return utf8;
}

// ============================================================================
// C API
// ============================================================================

extern "C" {

void* ANSITerminal_Create() {
    return new ANSITerminalRenderer();
}

void ANSITerminal_Destroy(void* term) {
    delete static_cast<ANSITerminalRenderer*>(term);
}

int ANSITerminal_Initialize(void* term, HWND hwnd) {
    auto* t = static_cast<ANSITerminalRenderer*>(term);
    return t->Initialize(hwnd) ? 1 : 0;
}

void ANSITerminal_Shutdown(void* term) {
    auto* t = static_cast<ANSITerminalRenderer*>(term);
    t->Shutdown();
}

void ANSITerminal_Resize(void* term, int width, int height) {
    auto* t = static_cast<ANSITerminalRenderer*>(term);
    t->Resize(width, height);
}

void ANSITerminal_ProcessOutput(void* term, const char* data, int len) {
    auto* t = static_cast<ANSITerminalRenderer*>(term);
    t->ProcessOutput(data, len);
}

void ANSITerminal_Render(void* term, HDC hdc) {
    auto* t = static_cast<ANSITerminalRenderer*>(term);
    t->Render(hdc);
}

void ANSITerminal_ScrollUp(void* term, int lines) {
    auto* t = static_cast<ANSITerminalRenderer*>(term);
    for (int i = 0; i < lines; i++) {
        t->ScrollUp();
    }
}

void ANSITerminal_ScrollDown(void* term, int lines) {
    auto* t = static_cast<ANSITerminalRenderer*>(term);
    for (int i = 0; i < lines; i++) {
        t->ScrollDown();
    }
}

void ANSITerminal_ClearScrollback(void* term) {
    auto* t = static_cast<ANSITerminalRenderer*>(term);
    t->ClearScrollback();
}

void ANSITerminal_SetInputCallback(void* term, void (*callback)(const char* input)) {
    auto* t = static_cast<ANSITerminalRenderer*>(term);
    t->SetInputCallback([callback](const std::string& input) {
        callback(input.c_str());
    });
}

int ANSITerminal_GetCols(void* term) {
    auto* t = static_cast<ANSITerminalRenderer*>(term);
    return t->GetCols();
}

int ANSITerminal_GetRows(void* term) {
    auto* t = static_cast<ANSITerminalRenderer*>(term);
    return t->GetRows();
}

} // extern "C"

} // namespace Terminal
} // namespace RawrXD
