// Win32IDE_TabManager.cpp — tab bar for open files
#include <windows.h>
#include <string>
#include <vector>
#include <algorithm>
#include <functional>
#include <cstdio>

namespace RawrXD::IDE {

HFONT IDECore_UIFont();
bool  EditorEngine_OpenFile(const std::string& path);

struct Tab {
    std::string filePath;
    std::string displayName;
    bool        modified = false;
};

struct TabManagerState {
    HWND   hwnd       = nullptr;
    std::vector<Tab> tabs;
    int    activeTab  = -1;
    int    scrollOffset = 0; // horizontal scroll in pixels
    int    tabH       = 28;
    std::function<void(const std::string&)> onSwitch;
    std::function<void(const std::string&)> onClose;
};

static TabManagerState g_tabs;

static std::string BaseName(const std::string& path)
{
    size_t p = path.find_last_of("/\\");
    return (p == std::string::npos) ? path : path.substr(p + 1);
}

// ── Paint ─────────────────────────────────────────────────────────────────────
static void TabPaint(HWND hwnd)
{
    PAINTSTRUCT ps;
    HDC hdc = BeginPaint(hwnd, &ps);
    RECT rc; GetClientRect(hwnd, &rc);
    int W = rc.right, H = rc.bottom;

    HDC mem = CreateCompatibleDC(hdc);
    HBITMAP bmp = CreateCompatibleBitmap(hdc, W, H);
    HBITMAP old = (HBITMAP)SelectObject(mem, bmp);

    HBRUSH bg = CreateSolidBrush(RGB(37, 37, 38));
    FillRect(mem, &rc, bg);
    DeleteObject(bg);

    HFONT font = IDECore_UIFont();
    HFONT oldFont = (HFONT)SelectObject(mem, font);
    SetBkMode(mem, TRANSPARENT);

    // Bottom border
    HPEN pen = CreatePen(PS_SOLID, 1, RGB(60, 60, 60));
    HPEN oldPen = (HPEN)SelectObject(mem, pen);
    MoveToEx(mem, 0, H - 1, nullptr); LineTo(mem, W, H - 1);
    SelectObject(mem, oldPen); DeleteObject(pen);

    int x = -g_tabs.scrollOffset;
    for (int i = 0; i < (int)g_tabs.tabs.size(); ++i) {
        auto& t = g_tabs.tabs[i];
        bool active = (i == g_tabs.activeTab);

        // Measure tab width
        std::string label = t.displayName + (t.modified ? " *" : "");
        SIZE sz; GetTextExtentPoint32A(mem, label.c_str(), (int)label.size(), &sz);
        int tabW = sz.cx + 32; // padding + close btn

        if (x + tabW > 0 && x < W) {
            // Tab background
            COLORREF tabBg = active ? RGB(30, 30, 30) : RGB(45, 45, 48);
            HBRUSH tabBr = CreateSolidBrush(tabBg);
            RECT tabRc = {x, 0, x + tabW, H - 1};
            FillRect(mem, &tabRc, tabBr);
            DeleteObject(tabBr);

            // Active indicator
            if (active) {
                HPEN acPen = CreatePen(PS_SOLID, 2, RGB(0, 122, 204));
                HPEN oldAcPen = (HPEN)SelectObject(mem, acPen);
                MoveToEx(mem, x, 0, nullptr); LineTo(mem, x + tabW, 0);
                SelectObject(mem, oldAcPen); DeleteObject(acPen);
            }

            // Right border
            HPEN bPen = CreatePen(PS_SOLID, 1, RGB(60, 60, 60));
            HPEN oldBPen = (HPEN)SelectObject(mem, bPen);
            MoveToEx(mem, x + tabW - 1, 0, nullptr); LineTo(mem, x + tabW - 1, H);
            SelectObject(mem, oldBPen); DeleteObject(bPen);

            // Label
            SetTextColor(mem, active ? RGB(255, 255, 255) : RGB(160, 160, 160));
            RECT lr = {x + 8, 0, x + tabW - 20, H};
            DrawTextA(mem, label.c_str(), -1, &lr, DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);

            // Close button
            SetTextColor(mem, RGB(120, 120, 120));
            RECT cr = {x + tabW - 18, 0, x + tabW - 4, H};
            DrawTextA(mem, "x", -1, &cr, DT_CENTER | DT_SINGLELINE | DT_VCENTER);
        }
        x += tabW;
    }

    SelectObject(mem, oldFont);
    BitBlt(hdc, 0, 0, W, H, mem, 0, 0, SRCCOPY);
    SelectObject(mem, old);
    DeleteObject(bmp);
    DeleteDC(mem);
    EndPaint(hwnd, &ps);
}

// ── Hit test: returns tab index and whether close btn was hit ─────────────────
static int HitTest(int mx, bool* closeHit)
{
    if (closeHit) *closeHit = false;
    HDC hdc = GetDC(g_tabs.hwnd);
    HFONT font = IDECore_UIFont();
    HFONT old = (HFONT)SelectObject(hdc, font);
    int x = -g_tabs.scrollOffset;
    for (int i = 0; i < (int)g_tabs.tabs.size(); ++i) {
        std::string label = g_tabs.tabs[i].displayName + (g_tabs.tabs[i].modified ? " *" : "");
        SIZE sz; GetTextExtentPoint32A(hdc, label.c_str(), (int)label.size(), &sz);
        int tabW = sz.cx + 32;
        if (mx >= x && mx < x + tabW) {
            if (closeHit) *closeHit = (mx >= x + tabW - 18);
            SelectObject(hdc, old);
            ReleaseDC(g_tabs.hwnd, hdc);
            return i;
        }
        x += tabW;
    }
    SelectObject(hdc, old);
    ReleaseDC(g_tabs.hwnd, hdc);
    return -1;
}

static LRESULT CALLBACK TabWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_PAINT:      TabPaint(hwnd); return 0;
    case WM_ERASEBKGND: return 1;
    case WM_SIZE:       InvalidateRect(hwnd, nullptr, FALSE); return 0;
    case WM_LBUTTONDOWN: {
        int mx = LOWORD(lParam);
        bool closeHit = false;
        int idx = HitTest(mx, &closeHit);
        if (idx >= 0) {
            if (closeHit) {
                std::string path = g_tabs.tabs[idx].filePath;
                g_tabs.tabs.erase(g_tabs.tabs.begin() + idx);
                if (g_tabs.activeTab >= (int)g_tabs.tabs.size())
                    g_tabs.activeTab = (int)g_tabs.tabs.size() - 1;
                if (g_tabs.activeTab >= 0)
                    EditorEngine_OpenFile(g_tabs.tabs[g_tabs.activeTab].filePath);
                if (g_tabs.onClose) g_tabs.onClose(path);
            } else {
                g_tabs.activeTab = idx;
                EditorEngine_OpenFile(g_tabs.tabs[idx].filePath);
                if (g_tabs.onSwitch) g_tabs.onSwitch(g_tabs.tabs[idx].filePath);
            }
            InvalidateRect(hwnd, nullptr, FALSE);
        }
        return 0;
    }
    case WM_MOUSEWHEEL: {
        int delta = GET_WHEEL_DELTA_WPARAM(wParam);
        g_tabs.scrollOffset -= delta / WHEEL_DELTA * 40;
        g_tabs.scrollOffset = std::max(0, g_tabs.scrollOffset);
        InvalidateRect(hwnd, nullptr, FALSE);
        return 0;
    }
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

// ── Public API ────────────────────────────────────────────────────────────────
void TabManager_Register(HINSTANCE hInst)
{
    WNDCLASSEXA wc = {};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = TabWndProc;
    wc.hInstance     = hInst;
    wc.lpszClassName = "RawrXDTabs";
    wc.hCursor       = LoadCursor(nullptr, IDC_ARROW);
    RegisterClassExA(&wc);
}

HWND TabManager_Create(HWND parent, int x, int y, int w, int h, HINSTANCE hInst)
{
    g_tabs.hwnd = CreateWindowExA(0, "RawrXDTabs", nullptr,
        WS_CHILD | WS_VISIBLE,
        x, y, w, h, parent, nullptr, hInst, nullptr);
    return g_tabs.hwnd;
}

void TabManager_OpenFile(const std::string& path)
{
    // Check if already open
    for (int i = 0; i < (int)g_tabs.tabs.size(); ++i) {
        if (g_tabs.tabs[i].filePath == path) {
            g_tabs.activeTab = i;
            EditorEngine_OpenFile(path);
            if (g_tabs.hwnd) InvalidateRect(g_tabs.hwnd, nullptr, FALSE);
            return;
        }
    }
    Tab t;
    t.filePath    = path;
    t.displayName = BaseName(path);
    g_tabs.tabs.push_back(t);
    g_tabs.activeTab = (int)g_tabs.tabs.size() - 1;
    EditorEngine_OpenFile(path);
    if (g_tabs.hwnd) InvalidateRect(g_tabs.hwnd, nullptr, FALSE);
}

void TabManager_SetModified(const std::string& path, bool modified)
{
    for (auto& t : g_tabs.tabs)
        if (t.filePath == path) { t.modified = modified; break; }
    if (g_tabs.hwnd) InvalidateRect(g_tabs.hwnd, nullptr, FALSE);
}

void TabManager_SetSwitchCallback(std::function<void(const std::string&)> cb) { g_tabs.onSwitch = std::move(cb); }
void TabManager_SetCloseCallback(std::function<void(const std::string&)> cb)  { g_tabs.onClose  = std::move(cb); }

int         TabManager_ActiveIndex()  { return g_tabs.activeTab; }
std::string TabManager_ActivePath()
{
    if (g_tabs.activeTab >= 0 && g_tabs.activeTab < (int)g_tabs.tabs.size())
        return g_tabs.tabs[g_tabs.activeTab].filePath;
    return "";
}

} // namespace RawrXD::IDE
