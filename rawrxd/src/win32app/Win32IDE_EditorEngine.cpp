// Win32IDE_EditorEngine.cpp — native code editor with line numbers, syntax highlight, cursor, selection
#include <windows.h>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstring>
#include <cctype>
#include <cstdio>
#include <functional>

namespace RawrXD::IDE {

// ── Forward declarations from Core ───────────────────────────────────────────
HFONT IDECore_MonoFont();
COLORREF IDECore_ColBg();
COLORREF IDECore_ColText();
COLORREF IDECore_ColAccent();

// ── Editor state ─────────────────────────────────────────────────────────────
struct EditorState {
    std::vector<std::string> lines;
    int  cursorLine  = 0;
    int  cursorCol   = 0;
    int  selStartLine = -1, selStartCol = -1;
    int  selEndLine   = -1, selEndCol   = -1;
    int  scrollLine  = 0;
    int  scrollCol   = 0;
    bool modified    = false;
    std::string filePath;
    int  charW = 8, charH = 16;
    int  lineNumW = 48;
    HWND hwnd = nullptr;
};

static EditorState g_editor;

// ── Syntax token types ────────────────────────────────────────────────────────
enum class TokType { Normal, Keyword, String, Comment, Number, Preprocessor };

static const char* s_keywords[] = {
    "auto","break","case","catch","class","const","continue","default","delete",
    "do","double","else","enum","explicit","extern","false","float","for",
    "friend","goto","if","inline","int","long","namespace","new","nullptr",
    "operator","private","protected","public","register","return","short",
    "signed","sizeof","static","struct","switch","template","this","throw",
    "true","try","typedef","typename","union","unsigned","using","virtual",
    "void","volatile","while","override","final","constexpr","noexcept",
    "decltype","auto","static_assert","thread_local","alignas","alignof",
    nullptr
};

static bool isKeyword(const std::string& w)
{
    for (int i = 0; s_keywords[i]; ++i)
        if (w == s_keywords[i]) return true;
    return false;
}

struct Token { int start, len; TokType type; };

static std::vector<Token> tokenizeLine(const std::string& line)
{
    std::vector<Token> toks;
    int n = (int)line.size();
    int i = 0;
    while (i < n) {
        // Line comment
        if (i + 1 < n && line[i] == '/' && line[i+1] == '/') {
            toks.push_back({i, n - i, TokType::Comment});
            break;
        }
        // Preprocessor
        if (line[i] == '#') {
            toks.push_back({i, n - i, TokType::Preprocessor});
            break;
        }
        // String
        if (line[i] == '"' || line[i] == '\'') {
            char q = line[i]; int j = i + 1;
            while (j < n && line[j] != q) { if (line[j] == '\\') ++j; ++j; }
            if (j < n) ++j;
            toks.push_back({i, j - i, TokType::String});
            i = j; continue;
        }
        // Number
        if (isdigit((unsigned char)line[i])) {
            int j = i;
            while (j < n && (isalnum((unsigned char)line[j]) || line[j] == '.' || line[j] == 'x' || line[j] == 'X')) ++j;
            toks.push_back({i, j - i, TokType::Number});
            i = j; continue;
        }
        // Identifier / keyword
        if (isalpha((unsigned char)line[i]) || line[i] == '_') {
            int j = i;
            while (j < n && (isalnum((unsigned char)line[j]) || line[j] == '_')) ++j;
            std::string word = line.substr(i, j - i);
            toks.push_back({i, j - i, isKeyword(word) ? TokType::Keyword : TokType::Normal});
            i = j; continue;
        }
        toks.push_back({i, 1, TokType::Normal});
        ++i;
    }
    return toks;
}

static COLORREF tokColor(TokType t)
{
    switch (t) {
        case TokType::Keyword:      return RGB(86,  156, 214);
        case TokType::String:       return RGB(206, 145, 120);
        case TokType::Comment:      return RGB(106, 153, 85);
        case TokType::Number:       return RGB(181, 206, 168);
        case TokType::Preprocessor: return RGB(155, 155, 100);
        default:                    return RGB(212, 212, 212);
    }
}

// ── Paint ─────────────────────────────────────────────────────────────────────
static void EditorPaint(HWND hwnd)
{
    PAINTSTRUCT ps;
    HDC hdc = BeginPaint(hwnd, &ps);

    RECT rc; GetClientRect(hwnd, &rc);
    int W = rc.right, H = rc.bottom;

    // Double-buffer
    HDC memDC = CreateCompatibleDC(hdc);
    HBITMAP bmp = CreateCompatibleBitmap(hdc, W, H);
    HBITMAP oldBmp = (HBITMAP)SelectObject(memDC, bmp);

    // Background
    HBRUSH bgBrush = CreateSolidBrush(RGB(30, 30, 30));
    FillRect(memDC, &rc, bgBrush);
    DeleteObject(bgBrush);

    // Line number gutter
    HBRUSH gutterBrush = CreateSolidBrush(RGB(37, 37, 38));
    RECT gutterRc = {0, 0, g_editor.lineNumW, H};
    FillRect(memDC, &gutterRc, gutterBrush);
    DeleteObject(gutterBrush);

    HFONT font = IDECore_MonoFont();
    HFONT oldFont = (HFONT)SelectObject(memDC, font);
    SetBkMode(memDC, TRANSPARENT);

    TEXTMETRICA tm;
    GetTextMetricsA(memDC, &tm);
    g_editor.charH = tm.tmHeight + tm.tmExternalLeading;
    g_editor.charW = tm.tmAveCharWidth;

    int visLines = H / g_editor.charH + 1;
    int totalLines = (int)g_editor.lines.size();

    for (int li = g_editor.scrollLine; li < std::min(totalLines, g_editor.scrollLine + visLines); ++li) {
        int y = (li - g_editor.scrollLine) * g_editor.charH;

        // Line number
        char lnBuf[16];
        snprintf(lnBuf, sizeof(lnBuf), "%4d", li + 1);
        SetTextColor(memDC, RGB(133, 133, 133));
        RECT lnRc = {0, y, g_editor.lineNumW - 4, y + g_editor.charH};
        DrawTextA(memDC, lnBuf, -1, &lnRc, DT_RIGHT | DT_VCENTER | DT_SINGLELINE);

        // Selection highlight
        if (g_editor.selStartLine >= 0 && li >= g_editor.selStartLine && li <= g_editor.selEndLine) {
            int sx = g_editor.lineNumW;
            int ex = g_editor.lineNumW + (int)g_editor.lines[li].size() * g_editor.charW;
            if (li == g_editor.selStartLine) sx = g_editor.lineNumW + g_editor.selStartCol * g_editor.charW;
            if (li == g_editor.selEndLine)   ex = g_editor.lineNumW + g_editor.selEndCol   * g_editor.charW;
            RECT selRc = {sx, y, ex, y + g_editor.charH};
            HBRUSH selBrush = CreateSolidBrush(RGB(38, 79, 120));
            FillRect(memDC, &selRc, selBrush);
            DeleteObject(selBrush);
        }

        // Tokens
        const std::string& line = g_editor.lines[li];
        auto tokens = tokenizeLine(line);
        for (auto& tok : tokens) {
            int x = g_editor.lineNumW + (tok.start - g_editor.scrollCol) * g_editor.charW;
            if (x + tok.len * g_editor.charW < 0) continue;
            if (x > W) break;
            SetTextColor(memDC, tokColor(tok.type));
            RECT tRc = {x, y, W, y + g_editor.charH};
            std::string piece = line.substr(tok.start, tok.len);
            DrawTextA(memDC, piece.c_str(), (int)piece.size(), &tRc, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOCLIP);
        }

        // Cursor
        if (li == g_editor.cursorLine) {
            int cx = g_editor.lineNumW + (g_editor.cursorCol - g_editor.scrollCol) * g_editor.charW;
            RECT curRc = {cx, y, cx + 2, y + g_editor.charH};
            HBRUSH curBrush = CreateSolidBrush(RGB(220, 220, 220));
            FillRect(memDC, &curRc, curBrush);
            DeleteObject(curBrush);
        }
    }

    SelectObject(memDC, oldFont);
    BitBlt(hdc, 0, 0, W, H, memDC, 0, 0, SRCCOPY);
    SelectObject(memDC, oldBmp);
    DeleteObject(bmp);
    DeleteDC(memDC);
    EndPaint(hwnd, &ps);
}

// ── Input handling ────────────────────────────────────────────────────────────
static void EditorInsertChar(char c)
{
    if (g_editor.lines.empty()) g_editor.lines.push_back("");
    auto& line = g_editor.lines[g_editor.cursorLine];
    int col = std::min(g_editor.cursorCol, (int)line.size());
    line.insert(line.begin() + col, c);
    ++g_editor.cursorCol;
    g_editor.modified = true;
}

static void EditorNewLine()
{
    if (g_editor.lines.empty()) { g_editor.lines.push_back(""); return; }
    auto& line = g_editor.lines[g_editor.cursorLine];
    int col = std::min(g_editor.cursorCol, (int)line.size());
    std::string rest = line.substr(col);
    line.resize(col);
    g_editor.lines.insert(g_editor.lines.begin() + g_editor.cursorLine + 1, rest);
    ++g_editor.cursorLine;
    g_editor.cursorCol = 0;
    g_editor.modified = true;
}

static void EditorBackspace()
{
    if (g_editor.lines.empty()) return;
    if (g_editor.cursorCol > 0) {
        auto& line = g_editor.lines[g_editor.cursorLine];
        int col = std::min(g_editor.cursorCol, (int)line.size());
        if (col > 0) { line.erase(line.begin() + col - 1); --g_editor.cursorCol; }
    } else if (g_editor.cursorLine > 0) {
        std::string cur = g_editor.lines[g_editor.cursorLine];
        g_editor.lines.erase(g_editor.lines.begin() + g_editor.cursorLine);
        --g_editor.cursorLine;
        g_editor.cursorCol = (int)g_editor.lines[g_editor.cursorLine].size();
        g_editor.lines[g_editor.cursorLine] += cur;
    }
    g_editor.modified = true;
}

static void EditorScrollToCursor(HWND hwnd)
{
    RECT rc; GetClientRect(hwnd, &rc);
    int visLines = rc.bottom / std::max(1, g_editor.charH);
    if (g_editor.cursorLine < g_editor.scrollLine)
        g_editor.scrollLine = g_editor.cursorLine;
    if (g_editor.cursorLine >= g_editor.scrollLine + visLines)
        g_editor.scrollLine = g_editor.cursorLine - visLines + 1;
}

// ── Window procedure ──────────────────────────────────────────────────────────
static LRESULT CALLBACK EditorWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_PAINT:
        EditorPaint(hwnd);
        return 0;

    case WM_ERASEBKGND:
        return 1;

    case WM_SETFOCUS:
        CreateCaret(hwnd, nullptr, 2, g_editor.charH);
        ShowCaret(hwnd);
        return 0;

    case WM_KILLFOCUS:
        DestroyCaret();
        return 0;

    case WM_CHAR:
        if (wParam == '\r' || wParam == '\n') {
            EditorNewLine();
        } else if (wParam == '\b') {
            EditorBackspace();
        } else if (wParam >= 32) {
            EditorInsertChar((char)wParam);
        }
        EditorScrollToCursor(hwnd);
        InvalidateRect(hwnd, nullptr, FALSE);
        return 0;

    case WM_KEYDOWN:
        switch (wParam) {
        case VK_UP:
            if (g_editor.cursorLine > 0) {
                --g_editor.cursorLine;
                g_editor.cursorCol = std::min(g_editor.cursorCol,
                    (int)g_editor.lines[g_editor.cursorLine].size());
            }
            break;
        case VK_DOWN:
            if (g_editor.cursorLine + 1 < (int)g_editor.lines.size()) {
                ++g_editor.cursorLine;
                g_editor.cursorCol = std::min(g_editor.cursorCol,
                    (int)g_editor.lines[g_editor.cursorLine].size());
            }
            break;
        case VK_LEFT:
            if (g_editor.cursorCol > 0) --g_editor.cursorCol;
            else if (g_editor.cursorLine > 0) {
                --g_editor.cursorLine;
                g_editor.cursorCol = (int)g_editor.lines[g_editor.cursorLine].size();
            }
            break;
        case VK_RIGHT:
            if (!g_editor.lines.empty() &&
                g_editor.cursorCol < (int)g_editor.lines[g_editor.cursorLine].size())
                ++g_editor.cursorCol;
            else if (g_editor.cursorLine + 1 < (int)g_editor.lines.size()) {
                ++g_editor.cursorLine; g_editor.cursorCol = 0;
            }
            break;
        case VK_HOME: g_editor.cursorCol = 0; break;
        case VK_END:
            if (!g_editor.lines.empty())
                g_editor.cursorCol = (int)g_editor.lines[g_editor.cursorLine].size();
            break;
        case VK_PRIOR: // Page Up
            g_editor.cursorLine = std::max(0, g_editor.cursorLine - 20);
            break;
        case VK_NEXT: // Page Down
            g_editor.cursorLine = std::min((int)g_editor.lines.size() - 1,
                                           g_editor.cursorLine + 20);
            break;
        case VK_DELETE:
            if (!g_editor.lines.empty()) {
                auto& line = g_editor.lines[g_editor.cursorLine];
                int col = std::min(g_editor.cursorCol, (int)line.size());
                if (col < (int)line.size()) {
                    line.erase(line.begin() + col);
                    g_editor.modified = true;
                } else if (g_editor.cursorLine + 1 < (int)g_editor.lines.size()) {
                    line += g_editor.lines[g_editor.cursorLine + 1];
                    g_editor.lines.erase(g_editor.lines.begin() + g_editor.cursorLine + 1);
                    g_editor.modified = true;
                }
            }
            break;
        }
        EditorScrollToCursor(hwnd);
        InvalidateRect(hwnd, nullptr, FALSE);
        return 0;

    case WM_MOUSEWHEEL: {
        int delta = GET_WHEEL_DELTA_WPARAM(wParam);
        g_editor.scrollLine -= delta / WHEEL_DELTA * 3;
        g_editor.scrollLine = std::max(0, std::min(g_editor.scrollLine,
            (int)g_editor.lines.size() - 1));
        InvalidateRect(hwnd, nullptr, FALSE);
        return 0;
    }

    case WM_LBUTTONDOWN: {
        int mx = LOWORD(lParam), my = HIWORD(lParam);
        int li = g_editor.scrollLine + my / std::max(1, g_editor.charH);
        int col = (mx - g_editor.lineNumW) / std::max(1, g_editor.charW) + g_editor.scrollCol;
        li  = std::max(0, std::min(li,  (int)g_editor.lines.size() - 1));
        col = std::max(0, std::min(col, (int)g_editor.lines[li].size()));
        g_editor.cursorLine = li;
        g_editor.cursorCol  = col;
        SetFocus(hwnd);
        InvalidateRect(hwnd, nullptr, FALSE);
        return 0;
    }

    case WM_SIZE:
        InvalidateRect(hwnd, nullptr, FALSE);
        return 0;
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

// ── Public API ────────────────────────────────────────────────────────────────
void EditorEngine_Register(HINSTANCE hInst)
{
    WNDCLASSEXA wc = {};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = EditorWndProc;
    wc.hInstance     = hInst;
    wc.lpszClassName = "RawrXDEditor";
    wc.hCursor       = LoadCursor(nullptr, IDC_IBEAM);
    wc.hbrBackground = nullptr;
    RegisterClassExA(&wc);
}

HWND EditorEngine_Create(HWND parent, int x, int y, int w, int h, HINSTANCE hInst)
{
    g_editor.lines.push_back("// RawrXD IDE — ready");
    g_editor.lines.push_back("");
    HWND hwnd = CreateWindowExA(0, "RawrXDEditor", nullptr,
        WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
        x, y, w, h, parent, nullptr, hInst, nullptr);
    g_editor.hwnd = hwnd;
    return hwnd;
}

bool EditorEngine_OpenFile(const std::string& path)
{
    std::ifstream f(path);
    if (!f) return false;
    g_editor.lines.clear();
    std::string line;
    while (std::getline(f, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        g_editor.lines.push_back(line);
    }
    if (g_editor.lines.empty()) g_editor.lines.push_back("");
    g_editor.filePath    = path;
    g_editor.cursorLine  = 0;
    g_editor.cursorCol   = 0;
    g_editor.scrollLine  = 0;
    g_editor.modified    = false;
    if (g_editor.hwnd) InvalidateRect(g_editor.hwnd, nullptr, FALSE);
    return true;
}

bool EditorEngine_SaveFile(const std::string& path)
{
    std::string p = path.empty() ? g_editor.filePath : path;
    if (p.empty()) return false;
    std::ofstream f(p);
    if (!f) return false;
    for (auto& line : g_editor.lines) f << line << "\n";
    g_editor.modified = false;
    if (!path.empty()) g_editor.filePath = path;
    return true;
}

void EditorEngine_SetText(const std::string& text)
{
    g_editor.lines.clear();
    std::istringstream ss(text);
    std::string line;
    while (std::getline(ss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        g_editor.lines.push_back(line);
    }
    if (g_editor.lines.empty()) g_editor.lines.push_back("");
    g_editor.cursorLine = 0; g_editor.cursorCol = 0; g_editor.scrollLine = 0;
    if (g_editor.hwnd) InvalidateRect(g_editor.hwnd, nullptr, FALSE);
}

std::string EditorEngine_GetText()
{
    std::string out;
    for (size_t i = 0; i < g_editor.lines.size(); ++i) {
        out += g_editor.lines[i];
        if (i + 1 < g_editor.lines.size()) out += "\n";
    }
    return out;
}

void EditorEngine_AppendText(const std::string& text)
{
    if (g_editor.lines.empty()) g_editor.lines.push_back("");
    std::istringstream ss(text);
    std::string line;
    bool first = true;
    while (std::getline(ss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (first) { g_editor.lines.back() += line; first = false; }
        else g_editor.lines.push_back(line);
    }
    g_editor.cursorLine = (int)g_editor.lines.size() - 1;
    g_editor.cursorCol  = (int)g_editor.lines.back().size();
    if (g_editor.hwnd) {
        EditorScrollToCursor(g_editor.hwnd);
        InvalidateRect(g_editor.hwnd, nullptr, FALSE);
    }
}

bool EditorEngine_IsModified() { return g_editor.modified; }
const std::string& EditorEngine_FilePath() { return g_editor.filePath; }

// ── Selection / Find / Replace ───────────────────────────────────────────────
void EditorEngine_SelectAll()
{
    if (g_editor.lines.empty()) return;
    g_editor.selStartLine = 0;
    g_editor.selStartCol  = 0;
    g_editor.selEndLine   = (int)g_editor.lines.size() - 1;
    g_editor.selEndCol    = (int)g_editor.lines.back().size();
    g_editor.cursorLine   = g_editor.selEndLine;
    g_editor.cursorCol    = g_editor.selEndCol;
    if (g_editor.hwnd) InvalidateRect(g_editor.hwnd, nullptr, FALSE);
}

void EditorEngine_ClearSelection()
{
    g_editor.selStartLine = -1; g_editor.selStartCol = -1;
    g_editor.selEndLine   = -1; g_editor.selEndCol   = -1;
    if (g_editor.hwnd) InvalidateRect(g_editor.hwnd, nullptr, FALSE);
}

bool EditorEngine_Find(const std::string& what, bool matchCase)
{
    if (what.empty() || g_editor.lines.empty()) return false;
    // Search from current cursor position onward
    int startL = g_editor.cursorLine;
    int startC = g_editor.cursorCol;
    for (int li = startL; li < (int)g_editor.lines.size(); ++li) {
        const std::string& line = g_editor.lines[li];
        size_t from = (li == startL) ? startC : 0;
        std::string hay = matchCase ? line : line;
        std::string ndl = matchCase ? what : what;
        if (!matchCase) {
            std::transform(hay.begin(), hay.end(), hay.begin(), ::tolower);
            std::transform(ndl.begin(), ndl.end(), ndl.begin(), ::tolower);
        }
        size_t pos = hay.find(ndl, from);
        if (pos != std::string::npos) {
            g_editor.selStartLine = li;
            g_editor.selStartCol  = (int)pos;
            g_editor.selEndLine   = li;
            g_editor.selEndCol    = (int)(pos + what.size());
            g_editor.cursorLine   = g_editor.selEndLine;
            g_editor.cursorCol    = g_editor.selEndCol;
            if (g_editor.hwnd) {
                EditorScrollToCursor(g_editor.hwnd);
                InvalidateRect(g_editor.hwnd, nullptr, FALSE);
            }
            return true;
        }
    }
    return false;
}

bool EditorEngine_Replace(const std::string& what, const std::string& replacement, bool matchCase)
{
    if (what.empty() || g_editor.lines.empty()) return false;
    // Replace first occurrence from cursor onward
    int startL = g_editor.cursorLine;
    int startC = g_editor.cursorCol;
    for (int li = startL; li < (int)g_editor.lines.size(); ++li) {
        std::string& line = g_editor.lines[li];
        size_t from = (li == startL) ? startC : 0;
        std::string hay = matchCase ? line : line;
        std::string ndl = matchCase ? what : what;
        if (!matchCase) {
            std::transform(hay.begin(), hay.end(), hay.begin(), ::tolower);
            std::transform(ndl.begin(), ndl.end(), ndl.begin(), ::tolower);
        }
        size_t pos = hay.find(ndl, from);
        if (pos != std::string::npos) {
            line.replace(pos, what.size(), replacement);
            g_editor.selStartLine = li;
            g_editor.selStartCol  = (int)pos;
            g_editor.selEndLine   = li;
            g_editor.selEndCol    = (int)(pos + replacement.size());
            g_editor.cursorLine   = g_editor.selEndLine;
            g_editor.cursorCol    = g_editor.selEndCol;
            g_editor.modified = true;
            if (g_editor.hwnd) {
                EditorScrollToCursor(g_editor.hwnd);
                InvalidateRect(g_editor.hwnd, nullptr, FALSE);
            }
            return true;
        }
    }
    return false;
}

int EditorEngine_ReplaceAll(const std::string& what, const std::string& replacement, bool matchCase)
{
    if (what.empty() || g_editor.lines.empty()) return 0;
    int count = 0;
    for (auto& line : g_editor.lines) {
        size_t from = 0;
        for (;;) {
            std::string hay = matchCase ? line : line;
            std::string ndl = matchCase ? what : what;
            if (!matchCase) {
                std::transform(hay.begin(), hay.end(), hay.begin(), ::tolower);
                std::transform(ndl.begin(), ndl.end(), ndl.begin(), ::tolower);
            }
            size_t pos = hay.find(ndl, from);
            if (pos == std::string::npos) break;
            line.replace(pos, what.size(), replacement);
            from = pos + replacement.size();
            ++count;
        }
    }
    if (count > 0) {
        g_editor.modified = true;
        g_editor.selStartLine = -1; g_editor.selStartCol = -1;
        g_editor.selEndLine   = -1; g_editor.selEndCol   = -1;
        if (g_editor.hwnd) InvalidateRect(g_editor.hwnd, nullptr, FALSE);
    }
    return count;
}

} // namespace RawrXD::IDE
