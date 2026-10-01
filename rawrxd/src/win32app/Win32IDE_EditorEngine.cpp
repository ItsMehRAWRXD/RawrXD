// Win32IDE_EditorEngine.cpp — native code editor with line numbers, syntax highlight, cursor, selection
#include <windows.h>
#include <windowsx.h>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstring>
#include <cctype>
#include <cstdio>
#include <functional>

// RAWRXD_IDE_CHECKPOINT_ROLLBACK_AUTHORITY_001
#include "agentic/CheckpointRollbackAuthority.h"

namespace RawrXD::IDE {

// ── Forward declarations from Core ───────────────────────────────────────────
HFONT IDECore_MonoFont();
COLORREF IDECore_ColBg();
COLORREF IDECore_ColText();
COLORREF IDECore_ColAccent();

// ── Forward declarations to the ghost-text engine ────────────────────────────
// RAWRXD_IDE_GHOSTTEXT_RENDER_001: EditorPaint calls GhostText_Paint, and the
// window procedure calls GhostText_Accept/GhostText_Dismiss on Tab/Escape.
// Defined in Win32IDE_GhostText.cpp.
void GhostText_Paint(HDC hdc, int cursorX, int cursorY, int charH, int charW);
std::string GhostText_Accept();
void        GhostText_Dismiss();
void        GhostText_RequestCompletion(const std::string& linePrefix, int line, int col);

// ── Editor state ─────────────────────────────────────────────────────────────
// RAWRXD_IDE_EDITOR_SELECTION_001
// selStart/selEnd form an ordered range. The fixed anchor is selStart; a caret
// move with SHIFT held moves selEnd, and a mouse drag moves selEnd too. Every
// mutation deletes an active selection first, so typing over a highlighted
// range behaves like a real editor instead of appending to it.
struct EditorState {
    std::vector<std::string> lines;
    int  cursorLine  = 0;
    int  cursorCol   = 0;
    int  selStartLine = -1, selStartCol = -1;
    int  selEndLine   = -1, selEndCol   = -1;
    int  anchorLine   = -1, anchorCol   = -1;
    bool dragging     = false;
    int  scrollLine  = 0;
    int  scrollCol   = 0;
    bool modified    = false;
    std::string filePath;
    int  charW = 8, charH = 16;
    int  lineNumW = 48;
    HWND hwnd = nullptr;
};

static EditorState g_editor;

// RAWRXD_IDE_UNDO_COVERAGE_001
// The editor notifies the undo owner after every content mutation. The owner
// (Win32IDE_Commands) coalesces a burst of keystrokes into one snapshot via a
// short timer, so undo is fed by typing instead of only by Cut/Paste.
static void (*g_mutationHook)() = nullptr;

// Debounce window, in ms, before a keystroke burst becomes one undo snapshot.
static const UINT_PTR kUndoDebounceTimerId = 1;
static const UINT     kUndoDebounceMs     = 250;

static void EditorNotifyMutation()
{
    if (g_editor.hwnd)
        SetTimer(g_editor.hwnd, kUndoDebounceTimerId, kUndoDebounceMs, nullptr);
}

void EditorEngine_RegisterMutationHook(void (*fn)())
{
    g_mutationHook = fn;
}

// ── Selection helpers ────────────────────────────────────────────────────────
static bool EditorHasSelection()
{
    return g_editor.selStartLine >= 0 && g_editor.selEndLine >= 0 &&
           (g_editor.selStartLine != g_editor.selEndLine ||
            g_editor.selStartCol  != g_editor.selEndCol);
}

static void EditorOrderSelection()
{
    if (!EditorHasSelection()) return;
    const int sL = g_editor.selStartLine, sC = g_editor.selStartCol;
    const int eL = g_editor.selEndLine,   eC = g_editor.selEndCol;
    if (eL < sL || (eL == sL && eC < sC)) {
        g_editor.selStartLine = eL; g_editor.selStartCol = eC;
        g_editor.selEndLine   = sL; g_editor.selEndCol   = sC;
    }
}

static void EditorClearSelection()
{
    g_editor.selStartLine = -1; g_editor.selStartCol = -1;
    g_editor.selEndLine   = -1; g_editor.selEndCol   = -1;
    g_editor.anchorLine   = -1; g_editor.anchorCol   = -1;
}

// ── Caret movement ───────────────────────────────────────────────────────────
// shiftExtend==true anchors a selection at the current caret and drags its end
// to the destination; otherwise any existing selection is discarded first.
static void EditorMoveCaret(int line, int col, bool shiftExtend)
{
    if (g_editor.lines.empty()) g_editor.lines.push_back("");
    line = std::max(0, std::min(line,  (int)g_editor.lines.size() - 1));
    col  = std::max(0, std::min(col,   (int)g_editor.lines[line].size()));

    if (shiftExtend) {
        if (g_editor.anchorLine < 0) {
            g_editor.anchorLine   = g_editor.cursorLine;
            g_editor.anchorCol    = g_editor.cursorCol;
            g_editor.selStartLine = g_editor.anchorLine;
            g_editor.selStartCol  = g_editor.anchorCol;
        }
        g_editor.selEndLine = line;
        g_editor.selEndCol  = col;
    } else {
        EditorClearSelection();
    }
    g_editor.cursorLine = line;
    g_editor.cursorCol  = col;
    EditorOrderSelection();
}

// Deletes the active selection and leaves the caret at its start.
// Returns true when a selection was actually removed.
static bool EditorDeleteSelection()
{
    if (!EditorHasSelection()) return false;
    EditorOrderSelection();
    int sl = g_editor.selStartLine, sc = g_editor.selStartCol;
    int el = g_editor.selEndLine,   ec = g_editor.selEndCol;
    if (sl < 0 || sl >= (int)g_editor.lines.size()) { EditorClearSelection(); return false; }
    ec = std::min(ec, (int)g_editor.lines[el].size());
    sc = std::min(sc, (int)g_editor.lines[sl].size());

    std::string tail = g_editor.lines[el].substr(ec);
    g_editor.lines[sl].resize(sc);
    g_editor.lines[sl] += tail;
    if (el > sl)
        g_editor.lines.erase(g_editor.lines.begin() + sl + 1,
                             g_editor.lines.begin() + el + 1);
    g_editor.cursorLine = sl;
    g_editor.cursorCol  = sc;
    EditorClearSelection();
    g_editor.modified   = true;
    return true;
}

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
        // RAWRXD_IDE_GHOSTTEXT_RENDER_001
        // The ghost-text suggestion is produced by the LSP/AI bridge and stored
        // by the ghost-text engine, but nothing ever drew it: GhostText_Paint()
        // had zero callers, so the flagship inline-completion feature was
        // computed and then never appeared on screen. Draw it inline at the
        // caret, on the caret's row, after the tokens so it reads as trailing
        // suggestion text rather than buffer content.
        if (li == g_editor.cursorLine) {
            int gx = g_editor.lineNumW + (g_editor.cursorCol - g_editor.scrollCol) * g_editor.charW;
            GhostText_Paint(memDC, gx, y, g_editor.charH, g_editor.charW);
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
// RAWRXD_IDE_UNDO_COVERAGE_001
// Every mutating path below calls EditorNotifyMutation(). The undo stack used
// to be fed only by Cut and Paste, so one Ctrl+Z after typing reverted the
// whole buffer to the file-open snapshot — silent data loss, not a cosmetic gap.
static void EditorInsertChar(char c)
{
    if (g_editor.lines.empty()) g_editor.lines.push_back("");
    if (EditorDeleteSelection()) { /* replaced the range */ }
    auto& line = g_editor.lines[g_editor.cursorLine];
    int col = std::min(g_editor.cursorCol, (int)line.size());
    line.insert(line.begin() + col, c);
    ++g_editor.cursorCol;
    g_editor.modified = true;
    EditorNotifyMutation();
}

static void EditorNewLine()
{
    if (g_editor.lines.empty()) { g_editor.lines.push_back(""); EditorNotifyMutation(); return; }
    if (EditorDeleteSelection()) { /* replaced the range */ }
    auto& line = g_editor.lines[g_editor.cursorLine];
    int col = std::min(g_editor.cursorCol, (int)line.size());
    std::string rest = line.substr(col);
    line.resize(col);
    g_editor.lines.insert(g_editor.lines.begin() + g_editor.cursorLine + 1, rest);
    ++g_editor.cursorLine;
    g_editor.cursorCol = 0;
    g_editor.modified = true;
    EditorNotifyMutation();
}

static void EditorBackspace()
{
    if (g_editor.lines.empty()) return;
    if (EditorDeleteSelection()) { EditorNotifyMutation(); return; }
    if (g_editor.cursorCol > 0) {
        auto& line = g_editor.lines[g_editor.cursorLine];
        int col = std::min(g_editor.cursorCol, (int)line.size());
        if (col > 0) { line.erase(line.begin() + col - 1); --g_editor.cursorCol; g_editor.modified = true; }
    } else if (g_editor.cursorLine > 0) {
        std::string cur = g_editor.lines[g_editor.cursorLine];
        g_editor.lines.erase(g_editor.lines.begin() + g_editor.cursorLine);
        --g_editor.cursorLine;
        g_editor.cursorCol = (int)g_editor.lines[g_editor.cursorLine].size();
        g_editor.lines[g_editor.cursorLine] += cur;
        g_editor.modified = true;
    }
    EditorNotifyMutation();
}

static void EditorDeleteForward()
{
    if (g_editor.lines.empty()) return;
    if (EditorDeleteSelection()) { EditorNotifyMutation(); return; }
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
    EditorNotifyMutation();
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
        // RAWRXD_IDE_GHOSTTEXT_RENDER_001: ask the completion engine for a
        // suggestion anchored at the new caret position.
        if (g_editor.cursorLine < (int)g_editor.lines.size())
            GhostText_RequestCompletion(g_editor.lines[g_editor.cursorLine],
                                        g_editor.cursorLine, g_editor.cursorCol);
        InvalidateRect(hwnd, nullptr, FALSE);
        return 0;

    case WM_TIMER:
        // RAWRXD_IDE_UNDO_COVERAGE_001: the debounce window after a keystroke
        // burst closed, so it is now one undo step rather than many.
        if (wParam == kUndoDebounceTimerId) {
            KillTimer(hwnd, kUndoDebounceTimerId);
            if (g_mutationHook) g_mutationHook();
            return 0;
        }
        break;

    case WM_KEYDOWN:
    {
        // RAWRXD_IDE_EDITOR_SELECTION_001: shift-extended caret movement.
        // Without this, nothing but SelectAll/Find could ever produce a
        // selection, so Cut/Copy had no range to act on.
        const bool shift = (GetKeyState(VK_SHIFT) & 0x8000) != 0;
        int nl = g_editor.cursorLine, nc = g_editor.cursorCol;

        switch (wParam) {
        case VK_UP:
            if (nl > 0) { --nl; nc = std::min(nc, (int)g_editor.lines[nl].size()); }
            break;
        case VK_DOWN:
            if (nl + 1 < (int)g_editor.lines.size()) {
                ++nl; nc = std::min(nc, (int)g_editor.lines[nl].size());
            }
            break;
        case VK_LEFT:
            if (nc > 0) --nc;
            else if (nl > 0) { --nl; nc = (int)g_editor.lines[nl].size(); }
            break;
        case VK_RIGHT:
            if (!g_editor.lines.empty() && nc < (int)g_editor.lines[nl].size())
                ++nc;
            else if (nl + 1 < (int)g_editor.lines.size()) { ++nl; nc = 0; }
            break;
        case VK_HOME: nc = 0; break;
        case VK_END:
            if (!g_editor.lines.empty()) nc = (int)g_editor.lines[nl].size();
            break;
        case VK_PRIOR: // Page Up
            nl = std::max(0, nl - 20);
            nc = std::min(nc, (int)g_editor.lines[nl].size());
            break;
        case VK_NEXT: // Page Down
            nl = std::min((int)g_editor.lines.size() - 1, nl + 20);
            nc = std::min(nc, (int)g_editor.lines[nl].size());
            break;
        case VK_DELETE:
            EditorDeleteForward();
            EditorScrollToCursor(hwnd);
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;

        // RAWRXD_IDE_GHOSTTEXT_RENDER_001: Tab accepts the inline suggestion,
        // Escape dismisses it. Both previously did nothing at all.
        case VK_TAB: {
            std::string s = GhostText_Accept();
            if (!s.empty()) {
                if (EditorDeleteSelection()) { /* replaced the range */ }
                auto& line = g_editor.lines[g_editor.cursorLine];
                int col = std::min(g_editor.cursorCol, (int)line.size());
                line.insert(col, s);
                g_editor.cursorCol += (int)s.size();
                g_editor.modified = true;
                EditorNotifyMutation();
            }
            EditorScrollToCursor(hwnd);
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;
        }
        case VK_ESCAPE:
            GhostText_Dismiss();
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;
        }

        if (nl != g_editor.cursorLine || nc != g_editor.cursorCol ||
            (shift && wParam != VK_TAB && wParam != VK_ESCAPE))
            EditorMoveCaret(nl, nc, shift);
        EditorScrollToCursor(hwnd);
        InvalidateRect(hwnd, nullptr, FALSE);
        return 0;
    }

    case WM_MOUSEMOVE: {
        // RAWRXD_IDE_EDITOR_SELECTION_001: drag extends the selection.
        if (!(wParam & MK_LBUTTON)) break;
        int mx = GET_X_LPARAM(lParam), my = GET_Y_LPARAM(lParam);
        int li = g_editor.scrollLine + my / std::max(1, g_editor.charH);
        int col = (mx - g_editor.lineNumW) / std::max(1, g_editor.charW) + g_editor.scrollCol;
        li  = std::max(0, std::min(li,  (int)g_editor.lines.size() - 1));
        col = std::max(0, std::min(col, (int)g_editor.lines[li].size()));
        g_editor.anchorLine   = g_editor.cursorLine;
        g_editor.anchorCol    = g_editor.cursorCol;
        g_editor.selStartLine = g_editor.anchorLine;
        g_editor.selStartCol  = g_editor.anchorCol;
        g_editor.selEndLine   = li;
        g_editor.selEndCol    = col;
        g_editor.dragging     = true;
        EditorOrderSelection();
        InvalidateRect(hwnd, nullptr, FALSE);
        return 0;
    }

    case WM_LBUTTONUP:
        if (g_editor.dragging) {
            g_editor.dragging = false;
            ReleaseCapture();
            if (!EditorHasSelection()) EditorClearSelection();
            InvalidateRect(hwnd, nullptr, FALSE);
        }
        return 0;

    case WM_CAPTURECHANGED:
        g_editor.dragging = false;
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
        int mx = GET_X_LPARAM(lParam), my = GET_Y_LPARAM(lParam);
        int li = g_editor.scrollLine + my / std::max(1, g_editor.charH);
        int col = (mx - g_editor.lineNumW) / std::max(1, g_editor.charW) + g_editor.scrollCol;
        li  = std::max(0, std::min(li,  (int)g_editor.lines.size() - 1));
        col = std::max(0, std::min(col, (int)g_editor.lines[li].size()));
        if (GetKeyState(VK_SHIFT) & 0x8000) {
            // Shift-click extends the existing anchor.
            if (g_editor.anchorLine < 0) {
                g_editor.anchorLine   = g_editor.cursorLine;
                g_editor.anchorCol    = g_editor.cursorCol;
                g_editor.selStartLine = g_editor.anchorLine;
                g_editor.selStartCol  = g_editor.anchorCol;
            }
            g_editor.selEndLine = li;
            g_editor.selEndCol  = col;
            EditorOrderSelection();
        } else {
            EditorClearSelection();
            g_editor.cursorLine = li;
            g_editor.cursorCol  = col;
            g_editor.dragging   = true;
            SetCapture(hwnd);
        }
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
    // RAWRXD_IDE_EDITOR_BINARY_IO_001
    // std::ifstream in text mode plus a non-binary write path meant the editor
    // could not round-trip a file: CRLF was translated on write and stripped on
    // read, and a file containing a 0x1A (^Z) byte was silently truncated on
    // write. Both sides are now binary, and line endings are preserved
    // verbatim by the \n-splitting reader.
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    std::ostringstream ss;
    ss << f.rdbuf();
    g_editor.lines.clear();
    std::string   all = ss.str(), line;
    size_t        pos = 0;
    while (pos <= all.size()) {
        size_t nl = all.find('\n', pos);
        if (nl == std::string::npos) {
            if (pos < all.size()) g_editor.lines.push_back(all.substr(pos));
            break;
        }
        line = all.substr(pos, nl - pos);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        g_editor.lines.push_back(line);
        pos = nl + 1;
    }
    if (g_editor.lines.empty()) g_editor.lines.push_back("");
    g_editor.filePath    = path;
    g_editor.cursorLine  = 0;
    g_editor.cursorCol   = 0;
    g_editor.scrollLine  = 0;
    g_editor.scrollCol   = 0;
    g_editor.modified    = false;
    EditorClearSelection();
    if (g_editor.hwnd) InvalidateRect(g_editor.hwnd, nullptr, FALSE);
    return true;
}

bool EditorEngine_SaveFile(const std::string& path)
{
    std::string p = path.empty() ? g_editor.filePath : path;
    if (p.empty()) return false;
    // RAWRXD_IDE_CHECKPOINT_ROLLBACK_AUTHORITY_001: this used to be
    // std::ofstream(binary|trunc) + flush(), which truncates the target before
    // a single byte is written. A crash mid-save therefore destroyed the file
    // with no record that it had been modified. The authority publishes through
    // a temp file plus atomic rename, and when a checkpoint transaction is open
    // it records the pre-modification bytes, the post-modification bytes and
    // the write itself in a flushed journal.
    std::string content;
    for (auto& line : g_editor.lines) content += line + "\r\n";
    std::string error;
    if (!::rawrxd::ckpt::Transaction::WriteFile(p, content, &error)) return false;
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

// RAWRXD_IDE_CLIPBOARD_SELECTION_001
// Paste used to append to lines.back(), i.e. end-of-document, so Ctrl+V ignored
// the caret. This inserts at the caret instead, replacing the selection when
// one is active.
void EditorEngine_InsertTextAtCursor(const std::string& text)
{
    if (g_editor.lines.empty()) g_editor.lines.push_back("");
    if (EditorDeleteSelection()) { /* replaced the range */ }
    if (text.empty()) { EditorNotifyMutation(); return; }

    std::vector<std::string> parts;
    std::string   line, all = text;
    size_t        pos = 0;
    while (pos <= all.size()) {
        size_t nl = all.find('\n', pos);
        if (nl == std::string::npos) { parts.push_back(all.substr(pos)); break; }
        line = all.substr(pos, nl - pos);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        parts.push_back(line);
        pos = nl + 1;
    }
    if (parts.empty()) return;

    auto& cur = g_editor.lines[g_editor.cursorLine];
    int col   = std::min(g_editor.cursorCol, (int)cur.size());
    if (parts.size() == 1) {
        cur.insert(col, parts[0]);
        g_editor.cursorCol = col + (int)parts[0].size();
    } else {
        std::string head = cur.substr(0, col);
        std::string tail = cur.substr(col);
        cur = head + parts[0];
        g_editor.lines.insert(g_editor.lines.begin() + g_editor.cursorLine + 1,
                              parts.begin() + 1, parts.end());
        int last = g_editor.cursorLine + (int)parts.size() - 1;
        g_editor.lines[last] = parts.back() + tail;
        g_editor.cursorLine = last;
        g_editor.cursorCol  = (int)parts.back().size();
    }
    g_editor.modified = true;
    EditorNotifyMutation();
    if (g_editor.hwnd) {
        EditorScrollToCursor(g_editor.hwnd);
        InvalidateRect(g_editor.hwnd, nullptr, FALSE);
    }
}

// RAWRXD_IDE_CLIPBOARD_SELECTION_001: selection-aware clipboard surface.
// Copy/Cut previously operated on EditorEngine_GetText(), the entire buffer,
// regardless of whether anything was selected.
bool EditorEngine_HasSelection()      { return EditorHasSelection(); }

std::string EditorEngine_GetSelectionText()
{
    if (!EditorHasSelection()) return {};
    EditorOrderSelection();
    int sl = g_editor.selStartLine, sc = g_editor.selStartCol;
    int el = g_editor.selEndLine,   ec = g_editor.selEndCol;
    if (sl < 0 || el >= (int)g_editor.lines.size()) return {};
    sc = std::min(sc, (int)g_editor.lines[sl].size());
    ec = std::min(ec, (int)g_editor.lines[el].size());
    if (sl == el) return g_editor.lines[sl].substr(sc, ec - sc);

    std::string out = g_editor.lines[sl].substr(sc);
    for (int i = sl + 1; i < el; ++i) { out += "\n"; out += g_editor.lines[i]; }
    out += "\n";
    out += g_editor.lines[el].substr(0, ec);
    return out;
}

bool EditorEngine_DeleteSelection()
{
    if (!EditorDeleteSelection()) return false;
    EditorNotifyMutation();
    if (g_editor.hwnd) InvalidateRect(g_editor.hwnd, nullptr, FALSE);
    return true;
}

void EditorEngine_GetCaret(int* line, int* col)
{
    if (line) *line = g_editor.cursorLine;
    if (col)  *col  = g_editor.cursorCol;
}

void EditorEngine_SetCaret(int line, int col)
{
    if (g_editor.lines.empty()) g_editor.lines.push_back("");
    g_editor.cursorLine = std::max(0, std::min(line, (int)g_editor.lines.size() - 1));
    g_editor.cursorCol  = std::max(0, std::min(col,  (int)g_editor.lines[g_editor.cursorLine].size()));
    if (g_editor.hwnd) InvalidateRect(g_editor.hwnd, nullptr, FALSE);
}

bool EditorEngine_IsModified() { return g_editor.modified; }
const std::string& EditorEngine_FilePath() { return g_editor.filePath; }

// ── Selection / Find / Replace ───────────────────────────────────────────────
// RAWRXD_IDE_EDITOR_SELECTION_001: SelectAll sets the anchor at the start so a
// following shift-arrow or drag extends from the document head.
void EditorEngine_SelectAll()
{
    if (g_editor.lines.empty()) return;
    g_editor.selStartLine = 0;
    g_editor.selStartCol  = 0;
    g_editor.selEndLine   = (int)g_editor.lines.size() - 1;
    g_editor.selEndCol    = (int)g_editor.lines.back().size();
    g_editor.anchorLine   = 0;
    g_editor.anchorCol    = 0;
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
            g_editor.anchorLine   = g_editor.selEndLine;
            g_editor.anchorCol    = g_editor.selEndCol;
            g_editor.cursorLine   = g_editor.selEndLine;
            g_editor.cursorCol    = g_editor.selEndCol;
            EditorNotifyMutation();
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
            g_editor.anchorLine   = g_editor.selEndLine;
            g_editor.anchorCol    = g_editor.selEndCol;
            g_editor.cursorLine   = g_editor.selEndLine;
            g_editor.cursorCol    = g_editor.selEndCol;
            g_editor.modified = true;
            EditorNotifyMutation();
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
