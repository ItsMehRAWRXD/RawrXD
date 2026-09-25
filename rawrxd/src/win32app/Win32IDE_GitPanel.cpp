// Win32IDE_GitPanel.cpp — git status, diff, log, and commit UI
#include <windows.h>
#include <string>
#include <vector>
#include <algorithm>
#include <functional>
#include <cstdio>

namespace RawrXD::IDE {

HFONT IDECore_MonoFont();
HFONT IDECore_UIFont();

// ── Run a git command, capture stdout ────────────────────────────────────────
static std::string RunGit(const std::string& args, const std::string& repoDir)
{
    std::string cmd = "git " + args;
    HANDLE hR, hW;
    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    if (!CreatePipe(&hR, &hW, &sa, 0)) return "";
    SetHandleInformation(hR, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si = {};
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput  = hW;
    si.hStdError   = hW;

    PROCESS_INFORMATION pi = {};
    if (!CreateProcessA(nullptr, (LPSTR)cmd.c_str(), nullptr, nullptr,
                        TRUE, CREATE_NO_WINDOW, nullptr,
                        repoDir.empty() ? nullptr : repoDir.c_str(), &si, &pi)) {
        CloseHandle(hR); CloseHandle(hW);
        return "";
    }
    CloseHandle(hW);

    std::string out;
    char buf[4096]; DWORD read;
    while (ReadFile(hR, buf, sizeof(buf) - 1, &read, nullptr) && read > 0) {
        buf[read] = '\0'; out += buf;
    }
    CloseHandle(hR);
    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    return out;
}

// ── Git panel state ───────────────────────────────────────────────────────────
struct GitEntry {
    char        status; // M, A, D, ?, etc.
    std::string path;
    bool        staged = false;
};

struct GitPanelState {
    HWND   hwnd        = nullptr;
    HWND   hCommitMsg  = nullptr;
    HWND   hCommitBtn  = nullptr;
    HWND   hRefreshBtn = nullptr;
    std::string repoDir;
    std::vector<GitEntry> entries;
    std::string diffText;
    int    selectedEntry = -1;
    int    scrollLine    = 0;
    int    lineH         = 20;
    std::function<void(const std::string&)> onCommit;
};

static GitPanelState g_git;

void GitPanel_Refresh();

// ── Paint ─────────────────────────────────────────────────────────────────────
static void GitPaint(HWND hwnd)
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

    const int headerH = 28;
    const int commitH = 60;
    const int listH   = H - headerH - commitH;
    const int padX    = 6;

    // Header
    SetTextColor(mem, RGB(0, 122, 204));
    RECT hdrRc = {padX, 4, W - padX, headerH};
    std::string branch = g_git.repoDir.empty() ? "Git (no repo)" :
        "Git — " + RunGit("rev-parse --abbrev-ref HEAD", g_git.repoDir);
    if (!branch.empty() && branch.back() == '\n') branch.pop_back();
    DrawTextA(mem, branch.c_str(), -1, &hdrRc, DT_LEFT | DT_SINGLELINE | DT_VCENTER);

    // File list
    int y = headerH - g_git.scrollLine * g_git.lineH;
    for (int i = 0; i < (int)g_git.entries.size(); ++i) {
        auto& e = g_git.entries[i];
        if (y + g_git.lineH < headerH || y > headerH + listH) { y += g_git.lineH; continue; }

        if (i == g_git.selectedEntry) {
            RECT selRc = {0, y, W, y + g_git.lineH};
            HBRUSH selBr = CreateSolidBrush(RGB(38, 79, 120));
            FillRect(mem, &selRc, selBr);
            DeleteObject(selBr);
        }

        COLORREF col = (e.status == 'M') ? RGB(220, 180, 80) :
                       (e.status == 'A') ? RGB(100, 200, 100) :
                       (e.status == 'D') ? RGB(220, 80, 80)   : RGB(180, 180, 180);
        SetTextColor(mem, col);
        char buf[512];
        snprintf(buf, sizeof(buf), " %c  %s", e.status, e.path.c_str());
        RECT lr = {padX, y, W - padX, y + g_git.lineH};
        DrawTextA(mem, buf, -1, &lr, DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);
        y += g_git.lineH;
    }

    // Separator
    HPEN pen = CreatePen(PS_SOLID, 1, RGB(60, 60, 60));
    HPEN oldPen = (HPEN)SelectObject(mem, pen);
    MoveToEx(mem, 0, H - commitH, nullptr); LineTo(mem, W, H - commitH);
    SelectObject(mem, oldPen); DeleteObject(pen);

    SelectObject(mem, oldFont);
    BitBlt(hdc, 0, 0, W, H, mem, 0, 0, SRCCOPY);
    SelectObject(mem, old);
    DeleteObject(bmp);
    DeleteDC(mem);
    EndPaint(hwnd, &ps);
}

#define IDC_GIT_COMMIT_MSG 4001
#define IDC_GIT_COMMIT_BTN 4002
#define IDC_GIT_REFRESH    4003

static LRESULT CALLBACK GitWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_CREATE: {
        RECT rc; GetClientRect(hwnd, &rc);
        int W = rc.right, H = rc.bottom;
        const int commitH = 60;
        HINSTANCE hInst = ((LPCREATESTRUCT)lParam)->hInstance;

        g_git.hCommitMsg = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "Commit message...",
            WS_CHILD | WS_VISIBLE | ES_MULTILINE,
            4, H - commitH + 4, W - 80, commitH - 8,
            hwnd, (HMENU)IDC_GIT_COMMIT_MSG, hInst, nullptr);
        g_git.hCommitBtn = CreateWindowExA(0, "BUTTON", "Commit",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            W - 74, H - commitH + 4, 70, 26,
            hwnd, (HMENU)IDC_GIT_COMMIT_BTN, hInst, nullptr);
        g_git.hRefreshBtn = CreateWindowExA(0, "BUTTON", "Refresh",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            W - 74, H - commitH + 34, 70, 22,
            hwnd, (HMENU)IDC_GIT_REFRESH, hInst, nullptr);

        HFONT font = IDECore_UIFont();
        SendMessage(g_git.hCommitMsg, WM_SETFONT, (WPARAM)font, TRUE);
        SendMessage(g_git.hCommitBtn, WM_SETFONT, (WPARAM)font, TRUE);
        SendMessage(g_git.hRefreshBtn, WM_SETFONT, (WPARAM)font, TRUE);
        return 0;
    }
    case WM_SIZE: {
        int W = LOWORD(lParam), H = HIWORD(lParam);
        const int commitH = 60;
        if (g_git.hCommitMsg)  SetWindowPos(g_git.hCommitMsg,  nullptr, 4, H - commitH + 4, W - 80, commitH - 8, SWP_NOZORDER);
        if (g_git.hCommitBtn)  SetWindowPos(g_git.hCommitBtn,  nullptr, W - 74, H - commitH + 4, 70, 26, SWP_NOZORDER);
        if (g_git.hRefreshBtn) SetWindowPos(g_git.hRefreshBtn, nullptr, W - 74, H - commitH + 34, 70, 22, SWP_NOZORDER);
        InvalidateRect(hwnd, nullptr, FALSE);
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wParam) == IDC_GIT_COMMIT_BTN) {
            char buf[1024] = {};
            GetWindowTextA(g_git.hCommitMsg, buf, sizeof(buf));
            std::string msg2(buf);
            if (!msg2.empty() && !g_git.repoDir.empty()) {
                RunGit("add -A", g_git.repoDir);
                RunGit("commit -m \"" + msg2 + "\"", g_git.repoDir);
                SetWindowTextA(g_git.hCommitMsg, "");
                GitPanel_Refresh();
                if (g_git.onCommit) g_git.onCommit(msg2);
            }
        } else if (LOWORD(wParam) == IDC_GIT_REFRESH) {
            GitPanel_Refresh();
        }
        return 0;
    case WM_LBUTTONDOWN: {
        int my = HIWORD(lParam);
        const int headerH = 28;
        int idx = (my - headerH + g_git.scrollLine * g_git.lineH) / std::max(1, g_git.lineH);
        if (idx >= 0 && idx < (int)g_git.entries.size()) {
            g_git.selectedEntry = idx;
            InvalidateRect(hwnd, nullptr, FALSE);
        }
        return 0;
    }
    case WM_MOUSEWHEEL: {
        int delta = GET_WHEEL_DELTA_WPARAM(wParam);
        g_git.scrollLine -= delta / WHEEL_DELTA * 3;
        g_git.scrollLine = std::max(0, g_git.scrollLine);
        InvalidateRect(hwnd, nullptr, FALSE);
        return 0;
    }
    case WM_PAINT:      GitPaint(hwnd); return 0;
    case WM_ERASEBKGND: return 1;
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

// ── Public API ────────────────────────────────────────────────────────────────
void GitPanel_Register(HINSTANCE hInst)
{
    WNDCLASSEXA wc = {};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = GitWndProc;
    wc.hInstance     = hInst;
    wc.lpszClassName = "RawrXDGit";
    wc.hCursor       = LoadCursor(nullptr, IDC_ARROW);
    RegisterClassExA(&wc);
}

HWND GitPanel_Create(HWND parent, int x, int y, int w, int h, HINSTANCE hInst)
{
    g_git.hwnd = CreateWindowExA(0, "RawrXDGit", nullptr,
        WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
        x, y, w, h, parent, nullptr, hInst, nullptr);
    return g_git.hwnd;
}

void GitPanel_SetRepo(const std::string& dir)
{
    g_git.repoDir = dir;
    GitPanel_Refresh();
}

void GitPanel_Refresh()
{
    if (g_git.repoDir.empty()) return;
    g_git.entries.clear();
    std::string status = RunGit("status --porcelain", g_git.repoDir);
    size_t pos = 0;
    while (pos < status.size()) {
        size_t nl = status.find('\n', pos);
        if (nl == std::string::npos) nl = status.size();
        std::string line = status.substr(pos, nl - pos);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.size() >= 4) {
            GitEntry e;
            e.status = (line[0] != ' ') ? line[0] : line[1];
            e.staged = (line[0] != ' ' && line[0] != '?');
            e.path   = line.substr(3);
            g_git.entries.push_back(e);
        }
        pos = nl + 1;
    }
    if (g_git.hwnd) InvalidateRect(g_git.hwnd, nullptr, FALSE);
}

std::string GitPanel_GetDiff(const std::string& file)
{
    if (g_git.repoDir.empty()) return "";
    return RunGit("diff -- \"" + file + "\"", g_git.repoDir);
}

std::string GitPanel_GetLog(int n)
{
    if (g_git.repoDir.empty()) return "";
    char buf[64]; snprintf(buf, sizeof(buf), "log --oneline -%d", n);
    return RunGit(buf, g_git.repoDir);
}

void GitPanel_SetCommitCallback(std::function<void(const std::string&)> cb)
{
    g_git.onCommit = std::move(cb);
}

} // namespace RawrXD::IDE
