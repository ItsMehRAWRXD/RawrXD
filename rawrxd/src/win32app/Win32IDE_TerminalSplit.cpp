// Win32IDE_TerminalSplit.cpp — embedded terminal panel (conpty/cmd)
#include <windows.h>
#include <string>
#include <vector>
#include <deque>
#include <algorithm>
#include <cstdio>
#include <functional>

namespace RawrXD::IDE {

HFONT IDECore_MonoFont();

struct TerminalState {
    HWND   hwnd       = nullptr;
    HWND   hInput     = nullptr;
    HANDLE hProcIn    = nullptr; // write end → child stdin
    HANDLE hProcOut   = nullptr; // read end  ← child stdout
    HANDLE hProcess   = nullptr;
    HANDLE hThread    = nullptr; // reader thread
    std::deque<std::string> lines;
    int    scrollLine = 0;
    int    charH      = 16;
    int    charW      = 8;
    std::function<void(const std::string&)> onOutput;
    bool   running    = false;
};

static TerminalState g_term;

// ── Reader thread: pumps child stdout into lines[] ────────────────────────────
static DWORD WINAPI TermReaderThread(LPVOID)
{
    char buf[4096];
    DWORD read;
    std::string partial;
    while (g_term.running && ReadFile(g_term.hProcOut, buf, sizeof(buf) - 1, &read, nullptr) && read > 0) {
        buf[read] = '\0';
        partial += buf;
        size_t pos;
        while ((pos = partial.find('\n')) != std::string::npos) {
            std::string line = partial.substr(0, pos);
            if (!line.empty() && line.back() == '\r') line.pop_back();
            partial = partial.substr(pos + 1);
            g_term.lines.push_back(line);
            if (g_term.lines.size() > 4000) g_term.lines.pop_front();
            if (g_term.onOutput) g_term.onOutput(line);
            if (g_term.hwnd) InvalidateRect(g_term.hwnd, nullptr, FALSE);
        }
        if (!partial.empty()) {
            g_term.lines.push_back(partial);
            if (g_term.lines.size() > 4000) g_term.lines.pop_front();
            if (g_term.hwnd) InvalidateRect(g_term.hwnd, nullptr, FALSE);
            partial.clear();
        }
    }
    g_term.running = false;
    return 0;
}

// ── Launch child process ──────────────────────────────────────────────────────
static bool TermLaunch(const std::string& cmd, const std::string& cwd)
{
    HANDLE hChildStdinR, hChildStdinW;
    HANDLE hChildStdoutR, hChildStdoutW;

    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    if (!CreatePipe(&hChildStdinR, &hChildStdinW, &sa, 0)) return false;
    if (!CreatePipe(&hChildStdoutR, &hChildStdoutW, &sa, 0)) {
        CloseHandle(hChildStdinR); CloseHandle(hChildStdinW); return false;
    }
    SetHandleInformation(hChildStdinW,  HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(hChildStdoutR, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si = {};
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput   = hChildStdinR;
    si.hStdOutput  = hChildStdoutW;
    si.hStdError   = hChildStdoutW;

    PROCESS_INFORMATION pi = {};
    std::string fullCmd = "cmd.exe /K " + cmd;
    if (!CreateProcessA(nullptr, (LPSTR)fullCmd.c_str(), nullptr, nullptr,
                        TRUE, CREATE_NO_WINDOW, nullptr,
                        cwd.empty() ? nullptr : cwd.c_str(), &si, &pi)) {
        CloseHandle(hChildStdinR); CloseHandle(hChildStdinW);
        CloseHandle(hChildStdoutR); CloseHandle(hChildStdoutW);
        return false;
    }

    CloseHandle(hChildStdinR);
    CloseHandle(hChildStdoutW);

    g_term.hProcIn  = hChildStdinW;
    g_term.hProcOut = hChildStdoutR;
    g_term.hProcess = pi.hProcess;
    CloseHandle(pi.hThread);

    g_term.running = true;
    DWORD tid;
    g_term.hThread = CreateThread(nullptr, 0, TermReaderThread, nullptr, 0, &tid);
    return true;
}

// ── Paint ─────────────────────────────────────────────────────────────────────
static void TermPaint(HWND hwnd)
{
    PAINTSTRUCT ps;
    HDC hdc = BeginPaint(hwnd, &ps);
    RECT rc; GetClientRect(hwnd, &rc);
    int W = rc.right, H = rc.bottom;

    HDC mem = CreateCompatibleDC(hdc);
    HBITMAP bmp = CreateCompatibleBitmap(hdc, W, H);
    HBITMAP old = (HBITMAP)SelectObject(mem, bmp);

    HBRUSH bg = CreateSolidBrush(RGB(12, 12, 12));
    FillRect(mem, &rc, bg);
    DeleteObject(bg);

    HFONT font = IDECore_MonoFont();
    HFONT oldFont = (HFONT)SelectObject(mem, font);
    SetBkMode(mem, TRANSPARENT);
    SetTextColor(mem, RGB(204, 204, 204));

    TEXTMETRICA tm;
    GetTextMetricsA(mem, &tm);
    g_term.charH = tm.tmHeight + tm.tmExternalLeading;
    g_term.charW = tm.tmAveCharWidth;

    const int inputH = 28;
    int visLines = (H - inputH) / std::max(1, g_term.charH);
    int total = (int)g_term.lines.size();
    int start = std::max(0, total - visLines - g_term.scrollLine);

    for (int i = 0; i < visLines && start + i < total; ++i) {
        int y = i * g_term.charH;
        const std::string& line = g_term.lines[start + i];
        RECT lr = {4, y, W - 4, y + g_term.charH};
        DrawTextA(mem, line.c_str(), (int)line.size(), &lr, DT_LEFT | DT_SINGLELINE | DT_NOCLIP);
    }

    SelectObject(mem, oldFont);
    BitBlt(hdc, 0, 0, W, H, mem, 0, 0, SRCCOPY);
    SelectObject(mem, old);
    DeleteObject(bmp);
    DeleteDC(mem);
    EndPaint(hwnd, &ps);
}

#define IDC_TERM_INPUT 3001

static LRESULT CALLBACK TermWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_CREATE: {
        RECT rc; GetClientRect(hwnd, &rc);
        g_term.hInput = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
            0, rc.bottom - 26, rc.right, 24,
            hwnd, (HMENU)IDC_TERM_INPUT,
            ((LPCREATESTRUCT)lParam)->hInstance, nullptr);
        SendMessage(g_term.hInput, WM_SETFONT, (WPARAM)IDECore_MonoFont(), TRUE);
        // Launch default shell
        TermLaunch("", "");
        return 0;
    }
    case WM_SIZE: {
        int W = LOWORD(lParam), H = HIWORD(lParam);
        if (g_term.hInput)
            SetWindowPos(g_term.hInput, nullptr, 0, H - 26, W, 24, SWP_NOZORDER);
        InvalidateRect(hwnd, nullptr, FALSE);
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wParam) == IDC_TERM_INPUT && HIWORD(wParam) == EN_UPDATE) {
            // handled on VK_RETURN via WM_KEYDOWN in subclass — use WM_CHAR instead
        }
        return 0;
    case WM_PAINT:      TermPaint(hwnd); return 0;
    case WM_ERASEBKGND: return 1;
    case WM_MOUSEWHEEL: {
        int delta = GET_WHEEL_DELTA_WPARAM(wParam);
        g_term.scrollLine += delta / WHEEL_DELTA * 3;
        g_term.scrollLine = std::max(0, g_term.scrollLine);
        InvalidateRect(hwnd, nullptr, FALSE);
        return 0;
    }
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

// ── Public API ────────────────────────────────────────────────────────────────
void TerminalSplit_Register(HINSTANCE hInst)
{
    WNDCLASSEXA wc = {};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = TermWndProc;
    wc.hInstance     = hInst;
    wc.lpszClassName = "RawrXDTerminal";
    wc.hCursor       = LoadCursor(nullptr, IDC_IBEAM);
    RegisterClassExA(&wc);
}

HWND TerminalSplit_Create(HWND parent, int x, int y, int w, int h, HINSTANCE hInst)
{
    g_term.hwnd = CreateWindowExA(0, "RawrXDTerminal", nullptr,
        WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
        x, y, w, h, parent, nullptr, hInst, nullptr);
    return g_term.hwnd;
}

void TerminalSplit_SendCommand(const std::string& cmd)
{
    if (!g_term.hProcIn) {
        g_term.lines.push_back("> " + cmd);
        if (g_term.hwnd) InvalidateRect(g_term.hwnd, nullptr, FALSE);
        return;
    }
    std::string line = cmd + "\r\n";
    DWORD written;
    WriteFile(g_term.hProcIn, line.c_str(), (DWORD)line.size(), &written, nullptr);
    g_term.lines.push_back("> " + cmd);
    if (g_term.hwnd) InvalidateRect(g_term.hwnd, nullptr, FALSE);
}

void TerminalSplit_AppendOutput(const std::string& text)
{
    g_term.lines.push_back(text);
    if (g_term.lines.size() > 4000) g_term.lines.pop_front();
    if (g_term.hwnd) InvalidateRect(g_term.hwnd, nullptr, FALSE);
}

void TerminalSplit_SetOutputCallback(std::function<void(const std::string&)> cb)
{
    g_term.onOutput = std::move(cb);
}

std::string TerminalSplit_GetLastLines(int n)
{
    std::string out;
    int start = std::max(0, (int)g_term.lines.size() - n);
    for (int i = start; i < (int)g_term.lines.size(); ++i)
        out += g_term.lines[i] + "\n";
    return out;
}

} // namespace RawrXD::IDE
