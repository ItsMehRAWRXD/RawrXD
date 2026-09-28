// Win32IDE_SearchPanel.cpp — cross-file search with results list
#include <windows.h>
#include <string>
#include <vector>
#include <algorithm>
#include <functional>
#include <fstream>
#include <filesystem>
#include <regex>
#include <thread>
#include <atomic>
#include <cstdio>

namespace RawrXD::IDE {

HFONT IDECore_UIFont();
HFONT IDECore_MonoFont();
bool  EditorEngine_OpenFile(const std::string& path);

struct SearchResult {
    std::string file;
    int         line;
    std::string text;
};

struct SearchPanelState {
    HWND   hwnd       = nullptr;
    HWND   hQuery     = nullptr;
    HWND   hSearch    = nullptr;
    HWND   hCaseCB    = nullptr;
    HWND   hRegexCB   = nullptr;
    std::vector<SearchResult> results;
    std::string rootDir;
    int    selectedResult = -1;
    int    scrollLine     = 0;
    int    lineH          = 20;
    std::atomic<bool> searching{false};
    std::function<void(const std::string&, int)> onJump;
};

static SearchPanelState g_search;

// ── Search worker ─────────────────────────────────────────────────────────────
static void SearchWorker(std::string query, std::string root, bool caseSensitive, bool useRegex)
{
    std::vector<SearchResult> results;

    auto matchLine = [&](const std::string& line) -> bool {
        if (useRegex) {
            try {
                auto flags = caseSensitive ? std::regex::ECMAScript
                                           : std::regex::ECMAScript | std::regex::icase;
                std::regex re(query, flags);
                return std::regex_search(line, re);
            } catch (...) { return false; }
        } else {
            std::string haystack = line, needle = query;
            if (!caseSensitive) {
                std::transform(haystack.begin(), haystack.end(), haystack.begin(), ::tolower);
                std::transform(needle.begin(), needle.end(), needle.begin(), ::tolower);
            }
            return haystack.find(needle) != std::string::npos;
        }
    };

    try {
        for (auto& entry : std::filesystem::recursive_directory_iterator(root,
                std::filesystem::directory_options::skip_permission_denied)) {
            if (!g_search.searching.load()) break;
            if (!entry.is_regular_file()) continue;
            auto ext = entry.path().extension().string();
            // Only search source files
            static const char* exts[] = {".cpp",".h",".hpp",".c",".cc",".cs",".py",".js",".ts",".txt",".md",nullptr};
            bool ok = false;
            for (int i = 0; exts[i]; ++i) if (ext == exts[i]) { ok = true; break; }
            if (!ok) continue;

            std::ifstream f(entry.path());
            if (!f) continue;
            std::string line;
            int lineNo = 0;
            while (std::getline(f, line)) {
                ++lineNo;
                if (!line.empty() && line.back() == '\r') line.pop_back();
                if (matchLine(line)) {
                    SearchResult r;
                    r.file = entry.path().string();
                    r.line = lineNo;
                    r.text = line;
                    results.push_back(r);
                    if (results.size() >= 2000) goto done;
                }
            }
        }
    } catch (...) {}

done:
    g_search.results = std::move(results);
    g_search.selectedResult = -1;
    g_search.scrollLine = 0;
    g_search.searching.store(false);
    if (g_search.hwnd) InvalidateRect(g_search.hwnd, nullptr, FALSE);
}

// ── Paint ─────────────────────────────────────────────────────────────────────
static void SearchPaint(HWND hwnd)
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
    HFONT mono = IDECore_MonoFont();
    HFONT oldFont = (HFONT)SelectObject(mem, font);
    SetBkMode(mem, TRANSPARENT);

    const int topH  = 60; // search bar area
    const int padX  = 6;

    // Status line
    SetTextColor(mem, RGB(150, 150, 150));
    char status[64];
    if (g_search.searching.load())
        snprintf(status, sizeof(status), "Searching...");
    else
        snprintf(status, sizeof(status), "%d result(s)", (int)g_search.results.size());
    RECT statRc = {padX, topH - 18, W - padX, topH};
    DrawTextA(mem, status, -1, &statRc, DT_LEFT | DT_SINGLELINE | DT_VCENTER);

    // Results
    int y = topH + padX - g_search.scrollLine * g_search.lineH;
    for (int i = 0; i < (int)g_search.results.size(); ++i) {
        auto& r = g_search.results[i];
        if (y + g_search.lineH < topH || y > H) { y += g_search.lineH; continue; }

        if (i == g_search.selectedResult) {
            RECT selRc = {0, y, W, y + g_search.lineH};
            HBRUSH selBr = CreateSolidBrush(RGB(38, 79, 120));
            FillRect(mem, &selRc, selBr);
            DeleteObject(selBr);
        }

        // File:line
        SelectObject(mem, font);
        SetTextColor(mem, RGB(100, 180, 255));
        char loc[512];
        // Show just filename + line for brevity
        std::string fname = r.file;
        size_t slash = fname.find_last_of("/\\");
        if (slash != std::string::npos) fname = fname.substr(slash + 1);
        snprintf(loc, sizeof(loc), "%s:%d", fname.c_str(), r.line);
        RECT locRc = {padX, y, 160, y + g_search.lineH};
        DrawTextA(mem, loc, -1, &locRc, DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);

        // Match text
        SelectObject(mem, mono);
        SetTextColor(mem, RGB(212, 212, 212));
        std::string trimmed = r.text;
        // Trim leading whitespace
        size_t ws = trimmed.find_first_not_of(" \t");
        if (ws != std::string::npos) trimmed = trimmed.substr(ws);
        RECT txtRc = {164, y, W - padX, y + g_search.lineH};
        DrawTextA(mem, trimmed.c_str(), -1, &txtRc, DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);

        y += g_search.lineH;
    }

    SelectObject(mem, oldFont);
    BitBlt(hdc, 0, 0, W, H, mem, 0, 0, SRCCOPY);
    SelectObject(mem, old);
    DeleteObject(bmp);
    DeleteDC(mem);
    EndPaint(hwnd, &ps);
}

#define IDC_SEARCH_QUERY  5001
#define IDC_SEARCH_BTN    5002
#define IDC_SEARCH_CASE   5003
#define IDC_SEARCH_REGEX  5004

static LRESULT CALLBACK SearchWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_CREATE: {
        RECT rc; GetClientRect(hwnd, &rc);
        int W = rc.right;
        HINSTANCE hInst = ((LPCREATESTRUCT)lParam)->hInstance;
        HFONT font = IDECore_UIFont();

        g_search.hQuery = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
            4, 4, W - 70, 22, hwnd, (HMENU)IDC_SEARCH_QUERY, hInst, nullptr);
        g_search.hSearch = CreateWindowExA(0, "BUTTON", "Find",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            W - 64, 4, 60, 22, hwnd, (HMENU)IDC_SEARCH_BTN, hInst, nullptr);
        g_search.hCaseCB = CreateWindowExA(0, "BUTTON", "Aa",
            WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            4, 30, 40, 18, hwnd, (HMENU)IDC_SEARCH_CASE, hInst, nullptr);
        g_search.hRegexCB = CreateWindowExA(0, "BUTTON", ".*",
            WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            50, 30, 40, 18, hwnd, (HMENU)IDC_SEARCH_REGEX, hInst, nullptr);

        SendMessage(g_search.hQuery,   WM_SETFONT, (WPARAM)font, TRUE);
        SendMessage(g_search.hSearch,  WM_SETFONT, (WPARAM)font, TRUE);
        SendMessage(g_search.hCaseCB,  WM_SETFONT, (WPARAM)font, TRUE);
        SendMessage(g_search.hRegexCB, WM_SETFONT, (WPARAM)font, TRUE);
        return 0;
    }
    case WM_SIZE: {
        int W = LOWORD(lParam);
        if (g_search.hQuery)  SetWindowPos(g_search.hQuery,  nullptr, 4, 4, W - 70, 22, SWP_NOZORDER);
        if (g_search.hSearch) SetWindowPos(g_search.hSearch, nullptr, W - 64, 4, 60, 22, SWP_NOZORDER);
        InvalidateRect(hwnd, nullptr, FALSE);
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wParam) == IDC_SEARCH_BTN) {
            char buf[512] = {};
            GetWindowTextA(g_search.hQuery, buf, sizeof(buf));
            std::string query(buf);
            if (!query.empty() && !g_search.rootDir.empty() && !g_search.searching.load()) {
                g_search.searching.store(true);
                bool cs = (SendMessage(g_search.hCaseCB,  BM_GETCHECK, 0, 0) == BST_CHECKED);
                bool rx = (SendMessage(g_search.hRegexCB, BM_GETCHECK, 0, 0) == BST_CHECKED);
                std::thread(SearchWorker, query, g_search.rootDir, cs, rx).detach();
            }
        }
        return 0;
    case WM_LBUTTONDBLCLK: {
        int my = HIWORD(lParam);
        const int topH = 60;
        int idx = (my - topH + g_search.scrollLine * g_search.lineH) / std::max(1, g_search.lineH);
        if (idx >= 0 && idx < (int)g_search.results.size()) {
            auto& r = g_search.results[idx];
            EditorEngine_OpenFile(r.file);
            if (g_search.onJump) g_search.onJump(r.file, r.line);
        }
        return 0;
    }
    case WM_LBUTTONDOWN: {
        int my = HIWORD(lParam);
        const int topH = 60;
        int idx = (my - topH + g_search.scrollLine * g_search.lineH) / std::max(1, g_search.lineH);
        if (idx >= 0 && idx < (int)g_search.results.size()) {
            g_search.selectedResult = idx;
            InvalidateRect(hwnd, nullptr, FALSE);
        }
        return 0;
    }
    case WM_MOUSEWHEEL: {
        int delta = GET_WHEEL_DELTA_WPARAM(wParam);
        g_search.scrollLine -= delta / WHEEL_DELTA * 3;
        g_search.scrollLine = std::max(0, g_search.scrollLine);
        InvalidateRect(hwnd, nullptr, FALSE);
        return 0;
    }
    case WM_PAINT:      SearchPaint(hwnd); return 0;
    case WM_ERASEBKGND: return 1;
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

// ── Public API ────────────────────────────────────────────────────────────────
void SearchPanel_Register(HINSTANCE hInst)
{
    WNDCLASSEXA wc = {};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = SearchWndProc;
    wc.hInstance     = hInst;
    wc.lpszClassName = "RawrXDSearch";
    wc.hCursor       = LoadCursor(nullptr, IDC_ARROW);
    RegisterClassExA(&wc);
}

HWND SearchPanel_Create(HWND parent, int x, int y, int w, int h, HINSTANCE hInst)
{
    g_search.hwnd = CreateWindowExA(0, "RawrXDSearch", nullptr,
        WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | CS_DBLCLKS,
        x, y, w, h, parent, nullptr, hInst, nullptr);
    return g_search.hwnd;
}

void SearchPanel_SetRoot(const std::string& dir) { g_search.rootDir = dir; }

void SearchPanel_Search(const std::string& query)
{
    if (g_search.hQuery) SetWindowTextA(g_search.hQuery, query.c_str());
    if (!query.empty() && !g_search.rootDir.empty() && !g_search.searching.load()) {
        g_search.searching.store(true);
        std::thread(SearchWorker, query, g_search.rootDir, false, false).detach();
    }
}

void SearchPanel_SetJumpCallback(std::function<void(const std::string&, int)> cb)
{
    g_search.onJump = std::move(cb);
}

const std::vector<SearchResult>& SearchPanel_GetResults() { return g_search.results; }

} // namespace RawrXD::IDE
