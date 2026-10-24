// ============================================================================
// code_editor.cpp - Native Win32/C++20 code editor control
//
// A self-drawn editor control with syntax highlighting, line numbers,
// selection, and basic text editing. Built on BufferModel + SyntaxEngine.
// Zero Qt dependency.
// ============================================================================

#include "code_editor.h"

#include <windowsx.h>
#include <commctrl.h>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cmath>

// ---------------------------------------------------------------------------
// Window class registration
// ---------------------------------------------------------------------------
static const wchar_t* kEditorClassName = L"RawrXD_CodeEditor_Class";
static bool g_classRegistered = false;

static void ensureEditorClassRegistered(HINSTANCE hInstance) {
    if (g_classRegistered) return;
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW | CS_DBLCLKS;
    wc.lpfnWndProc = CodeEditor::s_wndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(nullptr, IDC_IBEAM);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = kEditorClassName;
    RegisterClassExW(&wc);
    g_classRegistered = true;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
static std::string utf16ToUtf8(const std::wstring& wstr) {
    if (wstr.empty()) return {};
    int needed = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(), nullptr, 0, nullptr, nullptr);
    std::string out(needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(), out.data(), needed, nullptr, nullptr);
    return out;
}

static std::wstring utf8ToUtf16(const std::string& str) {
    if (str.empty()) return L"";
    int needed = MultiByteToWideChar(CP_UTF8, 0, str.data(), (int)str.size(), nullptr, 0);
    std::wstring out(needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.data(), (int)str.size(), out.data(), needed);
    return out;
}

// ---------------------------------------------------------------------------
// CodeEditor implementation
// ---------------------------------------------------------------------------
CodeEditor::CodeEditor(HWND hwndParent, int controlId)
    : m_hwndParent(hwndParent), m_controlId(controlId) {
    HINSTANCE hInst = (HINSTANCE)GetWindowLongPtrW(hwndParent, GWLP_HINSTANCE);
    ensureEditorClassRegistered(hInst);

    RECT rc;
    GetClientRect(hwndParent, &rc);

    m_hwnd = CreateWindowExW(
        WS_EX_CLIENTEDGE,
        kEditorClassName,
        L"",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | WS_CLIPCHILDREN,
        0, 0, rc.right - rc.left, rc.bottom - rc.top,
        hwndParent, (HMENU)(INT_PTR)controlId, hInst, this);

    // Default font: Consolas or fixedsys
    m_hFont = (HFONT)GetStockObject(ANSI_FIXED_FONT);
    // Try Consolas
    HFONT hConsolas = CreateFontW(
        -14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        DEFAULT_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas");
    if (hConsolas) {
        DeleteObject(m_hFont);
        m_hFont = hConsolas;
    }

    // Initialize default syntax colors
    initDefaultSyntaxColors(m_syntaxColors);

    // Set up language plugins
    m_syntaxEngine.setLanguage(new CppLanguagePlugin());
}

CodeEditor::~CodeEditor() {
    if (m_hFont) DeleteObject(m_hFont);
    if (m_hwnd) DestroyWindow(m_hwnd);
}

void CodeEditor::setText(std::string_view text) {
    m_buffer.set(text);
    m_cursorPos = 0;
    m_selStart = 0;
    m_selEnd = 0;
    m_modified = false;
    m_tokensDirty = true;
    m_vScroll = 0;
    m_hScroll = 0;
    InvalidateRect(m_hwnd, nullptr, TRUE);
}

std::string CodeEditor::getText() const {
    return m_buffer.snapshot();
}

bool CodeEditor::loadFile(const std::wstring& path) {
    std::wifstream ifs(path);
    if (!ifs.is_open()) return false;
    std::wstringstream ss;
    ss << ifs.rdbuf();
    std::wstring wcontent = ss.str();
    ifs.close();

    std::string content = utf16ToUtf8(wcontent);
    setText(content);
    m_filePath = path;

    // Detect language from extension
    size_t dot = path.find_last_of(L'.');
    if (dot != std::wstring::npos) {
        std::wstring ext = path.substr(dot + 1);
        if (ext == L"cpp" || ext == L"cc" || ext == L"cxx" || ext == L"h" || ext == L"hpp") {
            setLanguage("cpp");
        } else if (ext == L"ps1" || ext == L"psm1") {
            setLanguage("powershell");
        } else {
            setLanguage("text");
        }
    }
    return true;
}

bool CodeEditor::saveFile(const std::wstring& path) const {
    std::string content = getText();
    std::wstring wcontent = utf8ToUtf16(content);
    std::wofstream ofs(path);
    if (!ofs.is_open()) return false;
    ofs << wcontent;
    ofs.close();
    return true;
}

void CodeEditor::setFilePath(const std::wstring& path) {
    m_filePath = path;
}

void CodeEditor::setLanguage(const std::string& languageId) {
    m_languageId = languageId;
    if (languageId == "cpp") {
        m_syntaxEngine.setLanguage(new CppLanguagePlugin());
    } else if (languageId == "powershell") {
        m_syntaxEngine.setLanguage(new PowerShellLanguagePlugin());
    } else {
        m_syntaxEngine.setLanguage(new GenericLanguagePlugin());
    }
    m_tokensDirty = true;
    InvalidateRect(m_hwnd, nullptr, TRUE);
}

void CodeEditor::setModified(bool modified) {
    if (m_modified != modified) {
        m_modified = modified;
        // Notify parent via WM_COMMAND
        if (m_hwndParent) {
            PostMessageW(m_hwndParent, WM_COMMAND,
                MAKEWPARAM(m_controlId, modified ? EN_CHANGE : 0), (LPARAM)m_hwnd);
        }
    }
}

void CodeEditor::setCursorPos(size_t pos) {
    if (pos > m_buffer.size()) pos = m_buffer.size();
    m_cursorPos = pos;
    ensureCursorVisible();
    InvalidateRect(m_hwnd, nullptr, TRUE);
}

void CodeEditor::setFont(HFONT hFont) {
    if (m_hFont && m_hFont != (HFONT)GetStockObject(DEFAULT_GUI_FONT) &&
        m_hFont != (HFONT)GetStockObject(ANSI_FIXED_FONT) &&
        m_hFont != (HFONT)GetStockObject(ANSI_VAR_FONT) &&
        m_hFont != (HFONT)GetStockObject(SYSTEM_FONT) &&
        m_hFont != (HFONT)GetStockObject(SYSTEM_FIXED_FONT) &&
        m_hFont != (HFONT)GetStockObject(DEVICE_DEFAULT_FONT)) {
        DeleteObject(m_hFont);
    }
    m_hFont = hFont;
    recomputeLayout();
    InvalidateRect(m_hwnd, nullptr, TRUE);
}

void CodeEditor::invalidate() {
    InvalidateRect(m_hwnd, nullptr, TRUE);
}

void CodeEditor::recomputeLayout() {
    HDC hdc = GetDC(m_hwnd);
    if (m_hFont) SelectObject(hdc, m_hFont);
    TEXTMETRICW tm = {};
    GetTextMetricsW(hdc, &tm);
    m_charWidth = max(4, tm.tmAveCharWidth);
    m_lineHeight = tm.tmHeight + tm.tmExternalLeading;
    ReleaseDC(m_hwnd, hdc);

    // Gutter width: up to 6 digits + padding
    m_gutterWidth = 48;
}

void CodeEditor::showGhostText(const std::string& text) {
    m_ghostText = text;
    m_ghostPos = m_cursorPos;
    m_ghostVisible = true;
    InvalidateRect(m_hwnd, nullptr, TRUE);
}

void CodeEditor::clearGhostText() {
    m_ghostText.clear();
    m_ghostPos = 0;
    m_ghostVisible = false;
    InvalidateRect(m_hwnd, nullptr, TRUE);
}

void CodeEditor::acceptGhostText() {
    if (!m_ghostVisible || m_ghostText.empty()) return;

    // Insert ghost text at cursor position
    m_buffer.insert(m_cursorPos, m_ghostText);
    m_cursorPos += m_ghostText.size();
    m_selStart = m_selEnd = m_cursorPos;
    setModified(true);
    clearGhostText();
    InvalidateRect(m_hwnd, nullptr, TRUE);
}

void CodeEditor::dismissGhostText() {
    clearGhostText();
}

COLORREF CodeEditor::tokenColor(int type) const {
    auto it = m_syntaxColors.find(type);
    if (it != m_syntaxColors.end()) return it->second.color;
    return RGB(0, 0, 0);
}

void CodeEditor::posToLineCol(size_t pos, int& line, int& col) const {
    line = 0;
    col = 0;
    size_t lineStart = 0;
    while (lineStart < pos && lineStart < m_buffer.size()) {
        // Find next newline
        size_t nl = m_buffer.getText(lineStart, m_buffer.size() - lineStart).find('\n');
        if (nl == std::string::npos) break;
        lineStart += nl + 1;
        line++;
    }
    col = (int)(pos - lineStart);
}

size_t CodeEditor::lineColToPos(int line, int col) const {
    size_t lineStart = 0;
    size_t pos = 0;
    for (int i = 0; i < line; i++) {
        std::string lineText = m_buffer.getLine(i);
        lineStart += lineText.size() + 1; // +1 for newline
        pos = lineStart;
    }
    pos += (size_t)col;
    if (pos > m_buffer.size()) pos = m_buffer.size();
    return pos;
}

void CodeEditor::ensureCursorVisible() {
    int line, col;
    posToLineCol(m_cursorPos, line, col);
    // Make sure line is within visible range
    int firstLine, lastLine, topY;
    computeVisibleRange(firstLine, lastLine, topY);
    if (line < firstLine) {
        m_vScroll = line;
    } else if (line > lastLine) {
        m_vScroll = line - (lastLine - firstLine);
    }
    if (m_vScroll < 0) m_vScroll = 0;
    InvalidateRect(m_hwnd, nullptr, TRUE);
}

void CodeEditor::computeVisibleRange(int& firstLine, int& lastLine, int& topY) const {
    RECT rc;
    GetClientRect(m_hwnd, &rc);
    int clientHeight = rc.bottom - rc.top;
    int textAreaHeight = clientHeight;
    int linesVisible = textAreaHeight / m_lineHeight;
    if (linesVisible < 1) linesVisible = 1;

    firstLine = m_vScroll;
    lastLine = m_vScroll + linesVisible - 1;
    topY = 0;
}

void CodeEditor::paintGutter(HDC hdc, const RECT& clip) {
    int firstLine, lastLine, topY;
    computeVisibleRange(firstLine, lastLine, topY);

    RECT rc;
    GetClientRect(m_hwnd, &rc);
    int gutterRight = m_gutterWidth - 4;

    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, RGB(128, 128, 128));

    // Draw gutter background
    RECT gutterRect = { rc.left, rc.top, m_gutterWidth, rc.bottom };
    FillRect(hdc, &gutterRect, (HBRUSH)(COLOR_BTNFACE + 1));

    // Draw gutter divider line
    MoveToEx(hdc, m_gutterWidth, rc.top, nullptr);
    LineTo(hdc, m_gutterWidth, rc.bottom);

    // Draw line numbers
    int line = firstLine;
    int y = topY;
    while (line <= lastLine && y < rc.bottom) {
        wchar_t buf[32];
        swprintf_s(buf, L"%d", line + 1);
        SIZE size = {};
        GetTextExtentPoint32W(hdc, buf, (int)wcslen(buf), &size);
        int x = gutterRight - (int)size.cx - 4;
        TextOutW(hdc, x, y + (m_lineHeight - (int)size.cy) / 2, buf, (int)wcslen(buf));
        y += m_lineHeight;
        line++;
    }
}

void CodeEditor::paintText(HDC hdc, const RECT& clip) {
    RECT rc;
    GetClientRect(m_hwnd, &rc);
    int textLeft = m_gutterWidth + 4;
    int textRight = rc.right - rc.left;
    int clientHeight = rc.bottom - rc.top;

    int firstLine, lastLine, topY;
    computeVisibleRange(firstLine, lastLine, topY);

    // Select font
    HFONT hOldFont = (HFONT)SelectObject(hdc, m_hFont);
    SetBkMode(hdc, TRANSPARENT);

    int y = topY;
    for (int line = firstLine; line <= lastLine && y < clientHeight; line++) {
        std::string lineText = m_buffer.getLine((size_t)line);
        if (lineText.empty()) {
            y += m_lineHeight;
            continue;
        }

        // Tokenize this line
        std::vector<SyntaxToken> tokens;
        m_syntaxEngine.tokenize(lineText, tokens);

        // Convert line text to wide for drawing
        std::wstring wline = utf8ToUtf16(lineText);

        int x = textLeft - m_hScroll * m_charWidth;

        // Draw selection highlight first
        if (hasSelection()) {
            size_t lineStart = 0;
            // Compute logical start of this line
            size_t logicalLineStart = 0;
            for (int l = 0; l < line; l++) {
                logicalLineStart += m_buffer.getLine(l).size() + 1;
            }
            size_t lineEnd = logicalLineStart + lineText.size();

            size_t selS = min(m_selStart, m_selEnd);
            size_t selE = max(m_selStart, m_selEnd);

            if (selE > logicalLineStart && selS < lineEnd) {
                size_t drawStart = max(selS, logicalLineStart) - logicalLineStart;
                size_t drawEnd = min(selE, lineEnd) - logicalLineStart;

                // Convert char offsets to pixel x
                std::string beforeSel = lineText.substr(0, drawStart);
                std::string selText = lineText.substr(drawStart, drawEnd - drawStart);
                std::wstring wBefore = utf8ToUtf16(beforeSel);
                std::wstring wSel = utf8ToUtf16(selText);

                SIZE selSize = {};
                GetTextExtentPoint32W(hdc, wBefore.c_str(), (int)wBefore.size(), &selSize);
                SIZE selTextSize = {};
                GetTextExtentPoint32W(hdc, wSel.c_str(), (int)wSel.size(), &selTextSize);

                RECT selRect = { textLeft + selSize.cx - m_hScroll * m_charWidth, y,
                                textLeft + selSize.cx + selTextSize.cx - m_hScroll * m_charWidth, y + m_lineHeight };
                FillRect(hdc, &selRect, (HBRUSH)(COLOR_HIGHLIGHT + 1));
                SetTextColor(hdc, RGB(255, 255, 255));
                SetBkColor(hdc, RGB(0, 120, 215));
            }
        }

        // Draw each token
        size_t charOffset = 0;
        for (const auto& tk : tokens) {
            if (tk.start < charOffset) continue; // safety
            // Skip any gap between tokens (punctuation not captured)
            size_t gap = tk.start - charOffset;
            if (gap > 0) {
                // Draw gap as plain text (punctuation)
                std::string gapText = lineText.substr(charOffset, gap);
                std::wstring wgap = utf8ToUtf16(gapText);
                SetTextColor(hdc, RGB(0, 0, 0));
                TextOutW(hdc, x, y, wgap.c_str(), (int)wgap.size());
                SIZE gapSize = {};
                GetTextExtentPoint32W(hdc, wgap.c_str(), (int)wgap.size(), &gapSize);
                x += (int)gapSize.cx;
                charOffset += gap;
            }

            std::string tokenText = lineText.substr(tk.start, tk.length);
            std::wstring wtok = utf8ToUtf16(tokenText);

            COLORREF color = tokenColor(tk.type);
            bool bold = false;
            auto it = m_syntaxColors.find(tk.type);
            if (it != m_syntaxColors.end()) bold = it->second.bold;

            HFONT hFont = m_hFont;
            if (bold) {
                LOGFONTW lf = {};
                GetObjectW(m_hFont, sizeof(lf), &lf);
                lf.lfWeight = FW_BOLD;
                hFont = CreateFontIndirectW(&lf);
            }

            SelectObject(hdc, hFont);
            SetTextColor(hdc, color);
            TextOutW(hdc, x, y, wtok.c_str(), (int)wtok.size());

            SIZE tokSize = {};
            GetTextExtentPoint32W(hdc, wtok.c_str(), (int)wtok.size(), &tokSize);
            x += (int)tokSize.cx;
            charOffset += tk.length;

            if (hFont != m_hFont) DeleteObject(hFont);
        }

        // Draw remaining plain text after last token
        if (charOffset < lineText.size()) {
            std::string rest = lineText.substr(charOffset);
            std::wstring wrest = utf8ToUtf16(rest);
            SetTextColor(hdc, RGB(0, 0, 0));
            TextOutW(hdc, x, y, wrest.c_str(), (int)wrest.size());
        }

        // Draw ghost text at cursor position on the cursor's line
        if (m_ghostVisible && !m_ghostText.empty()) {
            size_t logicalLineStart = 0;
            for (int l = 0; l < line; l++) {
                logicalLineStart += m_buffer.getLine(l).size() + 1;
            }
            if (m_cursorPos >= logicalLineStart && m_cursorPos < logicalLineStart + lineText.size()) {
                // Cursor is on this line - draw ghost text right after cursor
                size_t charInLine = m_cursorPos - logicalLineStart;
                std::string beforeGhost = lineText.substr(0, charInLine);
                std::wstring wBefore = utf8ToUtf16(beforeGhost);
                SIZE beforeSize = {};
                GetTextExtentPoint32W(hdc, wBefore.c_str(), (int)wBefore.size(), &beforeSize);
                int ghostX = textLeft + beforeSize.cx - m_hScroll * m_charWidth;
                std::wstring wGhost = utf8ToUtf16(m_ghostText);
                SetTextColor(hdc, m_ghostColor);
                SetBkMode(hdc, TRANSPARENT);
                TextOutW(hdc, ghostX, y, wGhost.c_str(), (int)wGhost.size());
            }
        }

        y += m_lineHeight;
    }

    SelectObject(hdc, hOldFont);
}

void CodeEditor::paint(HDC hdc, const RECT& clip) {
    paintGutter(hdc, clip);
    paintText(hdc, clip);
}

LRESULT CALLBACK CodeEditor::s_wndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_NCCREATE) {
        CREATESTRUCTW* cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
        CodeEditor* self = static_cast<CodeEditor*>(cs->lpCreateParams);
        SetWindowLongPtrW(hWnd, GWLP_USERDATA, (LONG_PTR)self);
        self->m_hwnd = hWnd;
        return DefWindowProcW(hWnd, msg, wParam, lParam);
    }

    CodeEditor* self = reinterpret_cast<CodeEditor*>(GetWindowLongPtrW(hWnd, GWLP_USERDATA));
    if (self) {
        return self->wndProc(msg, wParam, lParam);
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

LRESULT CodeEditor::wndProc(UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(m_hwnd, &ps);
            paint(hdc, ps.rcPaint);
            EndPaint(m_hwnd, &ps);
            return 0;
        }
        case WM_SIZE:
            recomputeLayout();
            InvalidateRect(m_hwnd, nullptr, TRUE);
            return 0;
        case WM_SETFOCUS:
            InvalidateRect(m_hwnd, nullptr, TRUE);
            return 0;
        case WM_KILLFOCUS:
            InvalidateRect(m_hwnd, nullptr, TRUE);
            return 0;
        case WM_VSCROLL: {
            int delta = 0;
            switch (LOWORD(wParam)) {
                case SB_LINEUP: delta = -1; break;
                case SB_LINEDOWN: delta = 1; break;
                case SB_PAGEUP: delta = -10; break;
                case SB_PAGEDOWN: delta = 10; break;
                case SB_TOP: m_vScroll = 0; break;
                case SB_BOTTOM: m_vScroll = 100000; break;
                case SB_THUMBTRACK: m_vScroll = HIWORD(wParam); break;
            }
            m_vScroll += delta;
            if (m_vScroll < 0) m_vScroll = 0;
            SCROLLINFO si = {};
            si.cbSize = sizeof(si);
            si.fMask = SIF_POS;
            si.nPos = m_vScroll;
            SetScrollInfo(m_hwnd, SB_VERT, &si, TRUE);
            InvalidateRect(m_hwnd, nullptr, TRUE);
            return 0;
        }
        case WM_HSCROLL: {
            int delta = 0;
            switch (LOWORD(wParam)) {
                case SB_LINELEFT: delta = -1; break;
                case SB_LINERIGHT: delta = 1; break;
                case SB_PAGELEFT: delta = -20; break;
                case SB_PAGERIGHT: delta = 20; break;
                case SB_LEFT: m_hScroll = 0; break;
                case SB_RIGHT: m_hScroll = 10000; break;
                case SB_THUMBTRACK: m_hScroll = HIWORD(wParam); break;
            }
            m_hScroll += delta;
            if (m_hScroll < 0) m_hScroll = 0;
            SCROLLINFO si = {};
            si.cbSize = sizeof(si);
            si.fMask = SIF_POS;
            si.nPos = m_hScroll;
            SetScrollInfo(m_hwnd, SB_HORZ, &si, TRUE);
            InvalidateRect(m_hwnd, nullptr, TRUE);
            return 0;
        }
        case WM_MOUSEWHEEL: {
            int zDelta = GET_WHEEL_DELTA_WPARAM(wParam);
            int lines = -zDelta / WHEEL_DELTA;
            m_vScroll += lines;
            if (m_vScroll < 0) m_vScroll = 0;
            SCROLLINFO si = {};
            si.cbSize = sizeof(si);
            si.fMask = SIF_POS;
            si.nPos = m_vScroll;
            SetScrollInfo(m_hwnd, SB_VERT, &si, TRUE);
            InvalidateRect(m_hwnd, nullptr, TRUE);
            return 0;
        }
        case WM_LBUTTONDOWN: {
            SetFocus(m_hwnd);
            SetCapture(m_hwnd);
            int x = GET_X_LPARAM(lParam) - m_gutterWidth - 4 + m_hScroll * m_charWidth;
            int y = GET_Y_LPARAM(lParam) + m_vScroll * m_lineHeight;
            if (x < 0) x = 0;
            if (y < 0) y = 0;

            // Convert pixel to logical position
            std::string allText = m_buffer.snapshot();
            size_t pos = 0;
            int px = 0, py = 0;
            HDC hdc = GetDC(m_hwnd);
            if (m_hFont) SelectObject(hdc, m_hFont);

            // Simple approach: convert line/col from pixel
            int line = y / m_lineHeight;
            size_t lineStart = 0;
            for (int l = 0; l < line; l++) {
                std::string ltext = m_buffer.getLine(l);
                lineStart += ltext.size() + 1;
            }
            std::string lineText = m_buffer.getLine(line);
            // Find char at pixel x
            size_t charIdx = 0;
            int charX = 0;
            for (size_t i = 0; i < lineText.size(); i++) {
                std::string ch(1, lineText[i]);
                std::wstring wch = utf8ToUtf16(ch);
                SIZE sz = {};
                GetTextExtentPoint32W(hdc, wch.c_str(), 1, &sz);
                if (charX + sz.cx / 2 > x) break;
                charX += sz.cx;
                charIdx = i + 1;
            }
            ReleaseDC(m_hwnd, hdc);

            setCursorPos(lineStart + charIdx);
            m_selStart = m_cursorPos;
            m_selEnd = m_cursorPos;
            return 0;
        }
        case WM_KEYDOWN: {
            bool handled = false;
            switch (wParam) {
                case VK_LEFT:
                    if (hasGhostText()) dismissGhostText();
                    if (m_cursorPos > 0) {
                        m_cursorPos--;
                        if (GetAsyncKeyState(VK_SHIFT) & 0x8000) {
                            if (m_selStart == m_selEnd) m_selStart = m_cursorPos + 1;
                            m_selEnd = m_cursorPos;
                        } else {
                            m_selStart = m_selEnd = m_cursorPos;
                        }
                    }
                    handled = true;
                    break;
                case VK_RIGHT:
                    if (m_cursorPos < m_buffer.size()) {
                        m_cursorPos++;
                        if (GetAsyncKeyState(VK_SHIFT) & 0x8000) {
                            if (m_selStart == m_selEnd) m_selStart = m_cursorPos - 1;
                            m_selEnd = m_cursorPos;
                        } else {
                            m_selStart = m_selEnd = m_cursorPos;
                        }
                    }
                    handled = true;
                    break;
                case VK_UP: {
                    int line, col;
                    posToLineCol(m_cursorPos, line, col);
                    if (line > 0) {
                        std::string prevLine = m_buffer.getLine(line - 1);
                        int newCol = min(col, (int)prevLine.size());
                        size_t newPos = lineColToPos(line - 1, newCol);
                        m_cursorPos = newPos;
                        if (GetAsyncKeyState(VK_SHIFT) & 0x8000) {
                            if (m_selStart == m_selEnd) m_selStart = m_cursorPos;
                            m_selEnd = newPos;
                        } else {
                            m_selStart = m_selEnd = newPos;
                        }
                    }
                    handled = true;
                    break;
                }
                case VK_DOWN: {
                    int line, col;
                    posToLineCol(m_cursorPos, line, col);
                    std::string curLine = m_buffer.getLine(line);
                    if (line + 1 < (int)m_buffer.lineCount()) {
                        std::string nextLine = m_buffer.getLine(line + 1);
                        int newCol = min(col, (int)nextLine.size());
                        size_t newPos = lineColToPos(line + 1, newCol);
                        m_cursorPos = newPos;
                        if (GetAsyncKeyState(VK_SHIFT) & 0x8000) {
                            if (m_selStart == m_selEnd) m_selStart = m_cursorPos;
                            m_selEnd = newPos;
                        } else {
                            m_selStart = m_selEnd = newPos;
                        }
                    }
                    handled = true;
                    break;
                }
                case VK_HOME:
                    if (hasGhostText()) dismissGhostText();
                    m_cursorPos = lineColToPos(0, 0);
                    m_selStart = m_selEnd = m_cursorPos;
                    handled = true;
                    break;
                case VK_END: {
                    int line, col;
                    posToLineCol(m_cursorPos, line, col);
                    std::string lineText = m_buffer.getLine(line);
                    m_cursorPos = lineColToPos(line, lineText.size());
                    m_selStart = m_selEnd = m_cursorPos;
                    handled = true;
                    break;
                }
                case VK_RETURN: {
                    // Insert newline at cursor
                    m_buffer.insert(m_cursorPos, "\n");
                    m_cursorPos++;
                    m_selStart = m_selEnd = m_cursorPos;
                    setModified(true);
                    handled = true;
                    break;
                }
                case VK_BACK: {
                    if (m_cursorPos > 0 && !hasSelection()) {
                        m_buffer.erase(m_cursorPos - 1, 1);
                        m_cursorPos--;
                        m_selStart = m_selEnd = m_cursorPos;
                        setModified(true);
                    } else if (hasSelection()) {
                        size_t s = min(m_selStart, m_selEnd);
                        size_t e = max(m_selStart, m_selEnd);
                        m_buffer.erase(s, e - s);
                        m_cursorPos = s;
                        m_selStart = m_selEnd = s;
                        setModified(true);
                    }
                    handled = true;
                    break;
                }
                case VK_DELETE: {
                    if (m_cursorPos < m_buffer.size() && !hasSelection()) {
                        m_buffer.erase(m_cursorPos, 1);
                        m_selStart = m_selEnd = m_cursorPos;
                        setModified(true);
                    } else if (hasSelection()) {
                        size_t s = min(m_selStart, m_selEnd);
                        size_t e = max(m_selStart, m_selEnd);
                        m_buffer.erase(s, e - s);
                        m_cursorPos = s;
                        m_selStart = m_selEnd = s;
                        setModified(true);
                    }
                    handled = true;
                    break;
                }
                case VK_TAB:
                    if (hasGhostText()) {
                        acceptGhostText();
                    } else {
                        m_buffer.insert(m_cursorPos, "    ");
                        m_cursorPos += 4;
                        m_selStart = m_selEnd = m_cursorPos;
                        setModified(true);
                    }
                    handled = true;
                    break;
                case VK_SPACE:
                    if (GetAsyncKeyState(VK_CONTROL) & 0x8000) {
                        // Ctrl+Space: request completion via parent window
                        if (m_hwndParent) {
                            PostMessageW(m_hwndParent, WM_APP + 100, 0, 0);
                        }
                        handled = true;
                        break;
                    }
                    break;
                case VK_ESCAPE:
                    if (hasGhostText()) {
                        dismissGhostText();
                    } else {
                        m_selStart = m_selEnd = m_cursorPos;
                    }
                    handled = true;
                    break;
                case VK_CONTROL:
                    break;
                default:
                    // Printable characters - dismiss ghost text first
                    if (hasGhostText()) dismissGhostText();
                    if (wParam >= 0x20 && wParam <= 0x7E) {
                        char ch = (char)wParam;
                        if (GetAsyncKeyState(VK_SHIFT) & 0x8000) {
                            ch = (char)toupper((unsigned char)ch);
                        }
                        std::string s(1, ch);
                        m_buffer.insert(m_cursorPos, s);
                        m_cursorPos++;
                        m_selStart = m_selEnd = m_cursorPos;
                        setModified(true);
                        handled = true;
                    }
                    break;
            }
            if (handled) {
                ensureCursorVisible();
                InvalidateRect(m_hwnd, nullptr, TRUE);
            }
            return 0;
        }
        case WM_CHAR:
            // Handled in WM_KEYDOWN for simplicity
            return 0;
        case WM_GETDLGCODE:
            return DLGC_WANTALLKEYS;
        default:
            return DefWindowProcW(m_hwnd, msg, wParam, lParam);
    }
}
