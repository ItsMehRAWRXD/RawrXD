// Win32IDE_StatusBar.cpp — production status bar with build/run indicators, diagnostics, position
#include <windows.h>
#include <string>
#include <vector>
#include <sstream>
#include <cstdio>

namespace RawrXD::IDE {

struct StatusPart {
    int width;          // pixels, or -1 for stretch-to-fill
    std::string text;
    COLORREF fg;
    COLORREF bg;
    bool drawBorder;
};

static HWND g_hStatus = nullptr;
static std::vector<StatusPart> g_parts = {
    {180, "Ready", RGB(220,220,220), RGB(45,45,48), true},   // 0: Main status
    {120, "Build: Idle", RGB(180,180,180), RGB(45,45,48), true}, // 1: Build state
    {100, "0 errors", RGB(200,200,200), RGB(45,45,48), true},    // 2: Errors
    {100, "0 warnings", RGB(200,200,200), RGB(45,45,48), true},   // 3: Warnings
    { 90, "Ln 1, Col 1", RGB(200,200,200), RGB(45,45,48), true}, // 4: Cursor
    { 70, "UTF-8", RGB(200,200,200), RGB(45,45,48), true},       // 5: Encoding
    { 60, "INS", RGB(200,200,200), RGB(45,45,48), true},         // 6: Insert/Overwrite
    {100, "C++", RGB(200,200,200), RGB(45,45,48), true},         // 7: Language
};

static int g_totalW = 0;
static HFONT g_font = nullptr;

static HFONT GetStatusFont()
{
    if (!g_font) {
        g_font = CreateFontA(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                             DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                             CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");
    }
    return g_font;
}

static void StatusPaint(HWND hwnd)
{
    PAINTSTRUCT ps;
    HDC hdc = BeginPaint(hwnd, &ps);
    RECT rc; GetClientRect(hwnd, &rc);
    int W = rc.right, H = rc.bottom;

    HDC mem = CreateCompatibleDC(hdc);
    HBITMAP bmp = CreateCompatibleBitmap(hdc, W, H);
    HBITMAP oldBmp = (HBITMAP)SelectObject(mem, bmp);

    // Background
    HBRUSH bgBrush = CreateSolidBrush(RGB(45, 45, 48));
    FillRect(mem, &rc, bgBrush);
    DeleteObject(bgBrush);

    // Top border (lighter)
    HPEN borderPen = CreatePen(PS_SOLID, 1, RGB(60, 60, 63));
    HPEN oldPen = (HPEN)SelectObject(mem, borderPen);
    MoveToEx(mem, 0, 0, nullptr);
    LineTo(mem, W, 0);
    SelectObject(mem, oldPen);
    DeleteObject(borderPen);

    HFONT font = GetStatusFont();
    HFONT oldFont = (HFONT)SelectObject(mem, font);
    SetBkMode(mem, TRANSPARENT);

    int x = 0;
    for (size_t i = 0; i < g_parts.size(); ++i) {
        auto& p = g_parts[i];
        int pw = (p.width < 0) ? (W - x) : p.width;
        if (pw <= 0) break;
        if (x + pw > W) pw = W - x;

        RECT pr = {x, 1, x + pw, H};

        // Background
        HBRUSH pb = CreateSolidBrush(p.bg);
        FillRect(mem, &pr, pb);
        DeleteObject(pb);

        // Right border
        if (i + 1 < g_parts.size()) {
            HPEN pen = CreatePen(PS_SOLID, 1, RGB(60, 60, 63));
            HPEN op = (HPEN)SelectObject(mem, pen);
            MoveToEx(mem, x + pw - 1, 2, nullptr);
            LineTo(mem, x + pw - 1, H - 2);
            SelectObject(mem, op);
            DeleteObject(pen);
        }

        // Text
        SetTextColor(mem, p.fg);
        RECT tr = {x + 6, 1, x + pw - 4, H};
        DrawTextA(mem, p.text.c_str(), (int)p.text.size(), &tr,
                  DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOCLIP);

        x += pw;
    }

    SelectObject(mem, oldFont);
    BitBlt(hdc, 0, 0, W, H, mem, 0, 0, SRCCOPY);
    SelectObject(mem, oldBmp);
    DeleteObject(bmp);
    DeleteDC(mem);
    EndPaint(hwnd, &ps);
}

static LRESULT CALLBACK StatusWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_PAINT:
        StatusPaint(hwnd);
        return 0;
    case WM_ERASEBKGND:
        return 1;
    case WM_SIZE:
        InvalidateRect(hwnd, nullptr, FALSE);
        return 0;
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

// ── Public API ────────────────────────────────────────────────────────────────

void StatusBar_Register(HINSTANCE hInst)
{
    WNDCLASSEXA wc = {};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = StatusWndProc;
    wc.hInstance     = hInst;
    wc.lpszClassName = "RawrXDStatusBar";
    wc.hCursor       = LoadCursor(nullptr, IDC_ARROW);
    RegisterClassExA(&wc);
}

HWND StatusBar_Create(HWND parent, int x, int y, int w, int h, HINSTANCE hInst)
{
    g_hStatus = CreateWindowExA(0, "RawrXDStatusBar", nullptr,
                                WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
                                x, y, w, h, parent, nullptr, hInst, nullptr);
    g_totalW = w;
    return g_hStatus;
}

void StatusBar_SetText(int part, const std::string& text)
{
    if (part < 0 || part >= (int)g_parts.size()) return;
    if (g_parts[part].text == text) return;
    g_parts[part].text = text;
    if (g_hStatus) InvalidateRect(g_hStatus, nullptr, FALSE);
}

void StatusBar_SetBuildStatus(bool building, bool success, int errors, int warnings)
{
    if (building) {
        StatusBar_SetText(1, "Build: Running...");
        g_parts[1].fg = RGB(86, 156, 214);
    } else if (success && errors == 0) {
        StatusBar_SetText(1, "Build: Success");
        g_parts[1].fg = RGB(106, 153, 85);
    } else {
        StatusBar_SetText(1, "Build: Failed");
        g_parts[1].fg = RGB(206, 100, 100);
    }
    if (g_hStatus) InvalidateRect(g_hStatus, nullptr, FALSE);

    char buf[32];
    snprintf(buf, sizeof(buf), "%d error%s", errors, errors == 1 ? "" : "s");
    StatusBar_SetText(2, buf);
    g_parts[2].fg = errors > 0 ? RGB(206, 100, 100) : RGB(200, 200, 200);

    snprintf(buf, sizeof(buf), "%d warning%s", warnings, warnings == 1 ? "" : "s");
    StatusBar_SetText(3, buf);
    g_parts[3].fg = warnings > 0 ? RGB(206, 145, 100) : RGB(200, 200, 200);

    if (g_hStatus) InvalidateRect(g_hStatus, nullptr, FALSE);
}

void StatusBar_SetCursorPos(int line, int col)
{
    char buf[64];
    snprintf(buf, sizeof(buf), "Ln %d, Col %d", line + 1, col + 1);
    StatusBar_SetText(4, buf);
}

void StatusBar_SetEncoding(const std::string& enc)
{
    StatusBar_SetText(5, enc);
}

void StatusBar_SetInsertMode(bool insert)
{
    StatusBar_SetText(6, insert ? "INS" : "OVR");
}

void StatusBar_SetLanguage(const std::string& lang)
{
    StatusBar_SetText(7, lang);
}

void StatusBar_SetMainText(const std::string& text)
{
    StatusBar_SetText(0, text);
}

HWND StatusBar_GetHwnd() { return g_hStatus; }

void StatusBar_Resize(int W, int H)
{
    if (g_hStatus) {
        SetWindowPos(g_hStatus, nullptr, 0, H - 24, W, 24, SWP_NOZORDER | SWP_NOACTIVATE);
        g_totalW = W;
    }
}

} // namespace RawrXD::IDE
