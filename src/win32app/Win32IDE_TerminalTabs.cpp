// Win32IDE_TerminalTabs.cpp — Integrated Terminal Tabs (Batch 4 P06)
// Multi-tab terminal with profile switching (PowerShell, CMD, Git Bash, WSL)
#include "Win32IDE.h"
#include "IDELogger.h"
#include <richedit.h>
#include <algorithm>
#include <sstream>
#include <windows.h>

struct TerminalTabInfo {
    std::string profile;
    std::string title;
    bool active = false;
    HWND hwndContent = nullptr;
    HWND hwndTabButton = nullptr;
    HWND hwndInput = nullptr;
    HANDLE hProcess = nullptr;
    HANDLE hWritePipe = nullptr;
    HANDLE hReadPipe = nullptr;
    WNDPROC origInputProc = nullptr;
    std::vector<std::string> commandHistory;
    int historyIndex = 0;
};

void Win32IDE::initTerminalTabs() {
    m_terminalTabs.clear();
    m_activeTerminalTab = -1;
    LOG_INFO("[TerminalTabs] Initialized");
}

void Win32IDE::shutdownTerminalTabs() {
    for (auto& tab : m_terminalTabs) {
        if (tab.hwndContent) {
            DestroyWindow(tab.hwndContent);
            tab.hwndContent = nullptr;
        }
        if (tab.hProcess) {
            TerminateProcess(tab.hProcess, 0);
            CloseHandle(tab.hProcess);
            tab.hProcess = nullptr;
        }
        if (tab.hWritePipe) { CloseHandle(tab.hWritePipe); tab.hWritePipe = nullptr; }
        if (tab.hReadPipe)  { CloseHandle(tab.hReadPipe);  tab.hReadPipe = nullptr; }
    }
    m_terminalTabs.clear();
    m_activeTerminalTab = -1;
    if (m_hwndTermTabBar) {
        DestroyWindow(m_hwndTermTabBar);
        m_hwndTermTabBar = nullptr;
    }
    LOG_INFO("[TerminalTabs] Shutdown");
}

void Win32IDE::createTerminalTabBar(HWND hwndParent) {
    if (m_hwndTermTabBar) return;

    RECT rcParent;
    GetClientRect(hwndParent, &rcParent);
    int tabBarH = dpiScale(30);

    m_hwndTermTabBar = CreateWindowExA(0, "STATIC", "",
        WS_CHILD | WS_VISIBLE | SS_OWNERDRAW,
        0, 0, rcParent.right, tabBarH, hwndParent,
        (HMENU)(UINT_PTR)IDC_TERMTAB_BAR, GetModuleHandle(NULL), NULL);
    SetPropA(m_hwndTermTabBar, "IDE_PTR", (HANDLE)this);
    SetWindowLongPtrA(m_hwndTermTabBar, GWLP_WNDPROC, (LONG_PTR)TermTabBarProc);

    int addBtnW = dpiScale(28), addBtnH = dpiScale(22);
    CreateWindowExA(0, "BUTTON", "+",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        dpiScale(4), dpiScale(4), addBtnW, addBtnH, m_hwndTermTabBar,
        (HMENU)(UINT_PTR)IDC_TERMTAB_ADD_BTN, GetModuleHandle(NULL), NULL);

    int cbX = dpiScale(36);
    HWND hCombo = CreateWindowExA(0, "COMBOBOX", "",
        WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
        cbX, dpiScale(3), dpiScale(110), dpiScale(200), m_hwndTermTabBar,
        (HMENU)(UINT_PTR)IDC_TERMTAB_PROFILE, GetModuleHandle(NULL), NULL);
    SendMessageA(hCombo, CB_ADDSTRING, 0, (LPARAM)"PowerShell");
    SendMessageA(hCombo, CB_ADDSTRING, 0, (LPARAM)"CMD");
    SendMessageA(hCombo, CB_ADDSTRING, 0, (LPARAM)"Git Bash");
    SendMessageA(hCombo, CB_ADDSTRING, 0, (LPARAM)"WSL");
    SendMessageA(hCombo, CB_SETCURSEL, 0, 0);

    LOG_INFO("[TerminalTabs] Tab bar created");
}

void Win32IDE::createTerminalTab(const std::string& profile) {
    TerminalTabInfo tab;
    tab.profile = profile;
    tab.title = profile + " " + std::to_string(m_terminalTabs.size() + 1);
    tab.active = false;
    tab.hProcess = nullptr;
    tab.hWritePipe = nullptr;
    tab.hReadPipe = nullptr;

    HWND hwndParent = m_hwndPowerShellPanel ? m_hwndPowerShellPanel : m_hwndMain;
    if (!m_hwndTermTabBar) {
        createTerminalTabBar(hwndParent);
    }

    RECT rcParent;
    GetClientRect(hwndParent, &rcParent);
    int tabBarH = dpiScale(30);
    int inputH  = dpiScale(24);

    COLORREF bgColor = RGB(12, 12, 12);
    const char* shellExe  = "powershell.exe";
    const char* shellArgs = "-NoLogo";

    if (profile == "PowerShell") {
        bgColor  = RGB(1, 36, 86);
        shellExe  = "powershell.exe";
        shellArgs = "-NoLogo";
    } else if (profile == "CMD") {
        bgColor  = RGB(12, 12, 12);
        shellExe  = "cmd.exe";
        shellArgs = "/K";
    } else if (profile == "Git Bash") {
        bgColor  = RGB(16, 16, 16);
        shellExe  = "bash.exe";
        shellArgs = "--login";
    } else if (profile == "WSL") {
        bgColor  = RGB(16, 16, 16);
        shellExe  = "wsl.exe";
        shellArgs = "";
    }

    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = nullptr;

    HANDLE hStdinRead  = nullptr, hStdinWrite  = nullptr;
    HANDLE hStdoutRead = nullptr, hStdoutWrite = nullptr;

    if (!CreatePipe(&hStdinRead, &hStdinWrite, &sa, 0) ||
        !CreatePipe(&hStdoutRead, &hStdoutWrite, &sa, 0)) {
        LOG_ERROR("[TerminalTabs] Failed to create pipes");
        if (hStdinRead)  CloseHandle(hStdinRead);
        if (hStdinWrite) CloseHandle(hStdinWrite);
    }

    if (hStdinWrite) SetHandleInformation(hStdinWrite, HANDLE_FLAG_INHERIT, 0);
    if (hStdoutRead) SetHandleInformation(hStdoutRead, HANDLE_FLAG_INHERIT, 0);

    bool processStarted = false;
    if (hStdinRead && hStdoutWrite) {
        std::string cmdLine = std::string("\"") + shellExe + "\"";
        if (shellArgs && shellArgs[0]) {
            cmdLine += " ";
            cmdLine += shellArgs;
        }

        STARTUPINFOA si = {};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        si.hStdInput  = hStdinRead;
        si.hStdOutput = hStdoutWrite;
        si.hStdError  = hStdoutWrite;
        si.wShowWindow = SW_HIDE;

        PROCESS_INFORMATION pi = {};
        char cmdBuf[2048] = {};
        strncpy_s(cmdBuf, cmdLine.c_str(), _TRUNCATE);

        if (CreateProcessA(nullptr, cmdBuf, nullptr, nullptr, TRUE,
                           CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
            tab.hProcess   = pi.hProcess;
            tab.hWritePipe = hStdinWrite;
            tab.hReadPipe  = hStdoutRead;
            CloseHandle(pi.hThread);
            processStarted = true;
            LOG_INFO("[TerminalTabs] Spawned shell: " + cmdLine + " (pid=" + std::to_string(pi.dwProcessId) + ")");
        } else {
            LOG_ERROR("[TerminalTabs] CreateProcess failed for: " + cmdLine + " err=" + std::to_string(GetLastError()));
        }

        CloseHandle(hStdinRead);
        CloseHandle(hStdoutWrite);
    }

    int contentH = rcParent.bottom - tabBarH - inputH - 4;
    tab.hwndContent = CreateWindowExA(WS_EX_CLIENTEDGE, "RichEdit20A", "",
        WS_CHILD | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL,
        0, tabBarH, rcParent.right, contentH,
        hwndParent,
        (HMENU)(UINT_PTR)(IDC_TERMTAB_FIRST + (int)m_terminalTabs.size()),
        GetModuleHandle(NULL), NULL);

    SendMessageA(tab.hwndContent, EM_SETBKGNDCOLOR, 0, (LPARAM)bgColor);
    HFONT termFont = CreateFontA(-dpiScale(14), 0, 0, 0, FW_NORMAL,
        FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, "Consolas");
    SendMessageA(tab.hwndContent, WM_SETFONT, (WPARAM)termFont, TRUE);

    CHARFORMATA cf = {};
    cf.cbSize = sizeof(cf);
    cf.dwMask = CFM_COLOR;
    cf.crTextColor = RGB(204, 204, 204);
    SendMessageA(tab.hwndContent, EM_SETCHARFORMAT, SCF_ALL, (LPARAM)&cf);

    SendMessageA(tab.hwndContent, EM_EXLIMITTEXT, 0, 1024 * 1024);

    tab.hwndInput = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | WS_TABSTOP,
        0, tabBarH + contentH + 2, rcParent.right, inputH,
        hwndParent, nullptr, GetModuleHandle(NULL), NULL);

    HFONT inputFont = CreateFontA(-dpiScale(13), 0, 0, 0, FW_NORMAL,
        FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, "Consolas");
    SendMessageA(tab.hwndInput, WM_SETFONT, (WPARAM)inputFont, TRUE);

    SetPropA(tab.hwndInput, "IDE_PTR", (HANDLE)this);
    SetPropA(tab.hwndInput, "TAB_IDX", (HANDLE)(LONG_PTR)m_terminalTabs.size());
    tab.origInputProc = (WNDPROC)SetWindowLongPtrA(tab.hwndInput, GWLP_WNDPROC,
        (LONG_PTR)TerminalInputSubclassProc);

    int tabIndex = (int)m_terminalTabs.size();
    int tabW = dpiScale(120);
    int tabX = dpiScale(150) + tabIndex * (tabW + dpiScale(2));
    tab.hwndTabButton = CreateWindowExA(0, "BUTTON", tab.title.c_str(),
        WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
        tabX, dpiScale(2), tabW, dpiScale(26), m_hwndTermTabBar,
        (HMENU)(UINT_PTR)(IDC_TERMTAB_FIRST + tabIndex),
        GetModuleHandle(NULL), NULL);

    m_terminalTabs.push_back(tab);
    switchTerminalTab(tabIndex);

    if (processStarted && tab.hReadPipe) {
        struct ReaderContext {
            HANDLE hReadPipe;
            HWND   hwndOutput;
        };
        auto* ctx = new ReaderContext{ tab.hReadPipe, tab.hwndContent };
        HANDLE hThread = CreateThread(nullptr, 0, TerminalReaderThread, ctx, 0, nullptr);
        if (hThread) CloseHandle(hThread);
    } else {
        std::string msg = "[" + profile + "] Shell not found or failed to start.\r\n"
                         "Executable: " + std::string(shellExe) + "\r\n"
                         "Type commands below — they will be executed via CreateProcess.\r\n";
        CHARRANGEA cr = {-1, -1};
        SendMessageA(tab.hwndContent, EM_EXSETSEL, 0, (LPARAM)&cr);
        SendMessageA(tab.hwndContent, EM_REPLACESEL, FALSE, (LPARAM)msg.c_str());
    }

    LOG_INFO("[TerminalTabs] Created tab: " + tab.title +
             (processStarted ? " (live shell)" : " (no process)"));
}

static DWORD WINAPI TerminalReaderThread(LPVOID param) {
    struct ReaderContext {
        HANDLE hReadPipe;
        HWND   hwndOutput;
    };
    auto* ctx = (ReaderContext*)param;
    HANDLE hPipe = ctx->hReadPipe;
    HWND hwndOut = ctx->hwndOutput;
    delete ctx;

    char buffer[4096];
    DWORD bytesRead;
    constexpr DWORD kMaxChunk = static_cast<DWORD>(sizeof(buffer) - 1);

    while (ReadFile(hPipe, buffer, kMaxChunk, &bytesRead, nullptr) && bytesRead > 0) {
        const size_t safeBytes = (bytesRead <= kMaxChunk) ? static_cast<size_t>(bytesRead) : static_cast<size_t>(kMaxChunk);
        buffer[safeBytes] = '\0';

        if (IsWindow(hwndOut)) {
            CHARRANGEA cr = {-1, -1};
            SendMessageA(hwndOut, EM_EXSETSEL, 0, (LPARAM)&cr);
            SendMessageA(hwndOut, EM_REPLACESEL, FALSE, (LPARAM)buffer);
            SendMessageA(hwndOut, WM_VSCROLL, SB_BOTTOM, 0);
        }
    }

    return 0;
}

LRESULT CALLBACK Win32IDE::TerminalInputSubclassProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    Win32IDE* ide = (Win32IDE*)GetPropA(hwnd, "IDE_PTR");
    int tabIdx = (int)(LONG_PTR)GetPropA(hwnd, "TAB_IDX");
    WNDPROC origProc = nullptr;

    if (ide && tabIdx >= 0 && tabIdx < (int)ide->m_terminalTabs.size()) {
        origProc = ide->m_terminalTabs[tabIdx].origInputProc;
    }

    if (msg == WM_KEYDOWN && wParam == VK_RETURN) {
        if (ide && tabIdx >= 0 && tabIdx < (int)ide->m_terminalTabs.size()) {
            auto& tab = ide->m_terminalTabs[tabIdx];

            char cmd[4096] = {};
            GetWindowTextA(hwnd, cmd, sizeof(cmd));
            SetWindowTextA(hwnd, "");

            std::string command(cmd);
            command += "\r\n";

            if (tab.hWritePipe) {
                DWORD written;
                WriteFile(tab.hWritePipe, command.c_str(), (DWORD)command.size(), &written, nullptr);
            } else {
                std::string fullCmd = "cmd.exe /C " + std::string(cmd);
                char cmdBuf[4096] = {};
                strncpy_s(cmdBuf, fullCmd.c_str(), _TRUNCATE);

                SECURITY_ATTRIBUTES sa = {};
                sa.nLength = sizeof(sa);
                sa.bInheritHandle = TRUE;

                HANDLE hReadP = nullptr, hWriteP = nullptr;
                CreatePipe(&hReadP, &hWriteP, &sa, 0);
                SetHandleInformation(hReadP, HANDLE_FLAG_INHERIT, 0);

                STARTUPINFOA si = {};
                si.cb = sizeof(si);
                si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
                si.hStdOutput = hWriteP;
                si.hStdError = hWriteP;
                si.wShowWindow = SW_HIDE;

                PROCESS_INFORMATION pi = {};
                if (CreateProcessA(nullptr, cmdBuf, nullptr, nullptr, TRUE,
                                   CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
                    CloseHandle(hWriteP);

                    std::string echo = "> " + std::string(cmd) + "\r\n";
                    CHARRANGEA cr = {-1, -1};
                    SendMessageA(tab.hwndContent, EM_EXSETSEL, 0, (LPARAM)&cr);
                    SendMessageA(tab.hwndContent, EM_REPLACESEL, FALSE, (LPARAM)echo.c_str());

                    char buf[4096];
                    DWORD bytesRead;
                    constexpr DWORD kMaxChunk = static_cast<DWORD>(sizeof(buf) - 1);
                    while (ReadFile(hReadP, buf, kMaxChunk, &bytesRead, nullptr) && bytesRead > 0) {
                        const size_t safeBytes = (bytesRead <= kMaxChunk) ? static_cast<size_t>(bytesRead) : static_cast<size_t>(kMaxChunk);
                        buf[safeBytes] = '\0';
                        cr = {-1, -1};
                        SendMessageA(tab.hwndContent, EM_EXSETSEL, 0, (LPARAM)&cr);
                        SendMessageA(tab.hwndContent, EM_REPLACESEL, FALSE, (LPARAM)buf);
                    }
                    SendMessageA(tab.hwndContent, WM_VSCROLL, SB_BOTTOM, 0);

                    WaitForSingleObject(pi.hProcess, 5000);
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                } else {
                    if (hWriteP) CloseHandle(hWriteP);
                    std::string err = "[Error] Failed to execute: " + std::string(cmd) + "\r\n";
                    CHARRANGEA cr = {-1, -1};
                    SendMessageA(tab.hwndContent, EM_EXSETSEL, 0, (LPARAM)&cr);
                    SendMessageA(tab.hwndContent, EM_REPLACESEL, FALSE, (LPARAM)err.c_str());
                }
                if (hReadP) CloseHandle(hReadP);
            }
        }
        return 0;
    }

    if (msg == WM_KEYDOWN && (wParam == VK_UP || wParam == VK_DOWN)) {
        int tabIdx = (int)(LONG_PTR)GetPropA(hwnd, "TAB_IDX");
        if (tabIdx >= 0 && tabIdx < (int)m_terminalTabs.size()) {
            auto& tab = m_terminalTabs[tabIdx];

            if (wParam == VK_UP) {
                if (!tab.commandHistory.empty()) {
                    if (tab.historyIndex > 0) {
                        tab.historyIndex--;
                    }
                    SetWindowTextA(hwnd, tab.commandHistory[tab.historyIndex].c_str());
                }
            } else {
                if (!tab.commandHistory.empty() && tab.historyIndex < tab.commandHistory.size() - 1) {
                    tab.historyIndex++;
                    SetWindowTextA(hwnd, tab.commandHistory[tab.historyIndex].c_str());
                } else {
                    tab.historyIndex = tab.commandHistory.size();
                    SetWindowTextA(hwnd, "");
                }
            }
        }
        return 0;
    }

    return origProc ? CallWindowProcA(origProc, hwnd, msg, wParam, lParam)
                    : DefWindowProcA(hwnd, msg, wParam, lParam);
}

void Win32IDE::closeTerminalTab(int index) {
    if (index < 0 || index >= (int)m_terminalTabs.size()) return;
    auto& tab = m_terminalTabs[index];

    if (tab.hwndContent) { DestroyWindow(tab.hwndContent); tab.hwndContent = nullptr; }
    if (tab.hwndTabButton) { DestroyWindow(tab.hwndTabButton); tab.hwndTabButton = nullptr; }
    if (tab.hProcess) { TerminateProcess(tab.hProcess, 0); CloseHandle(tab.hProcess); tab.hProcess = nullptr; }
    if (tab.hWritePipe) { CloseHandle(tab.hWritePipe); tab.hWritePipe = nullptr; }
    if (tab.hReadPipe) { CloseHandle(tab.hReadPipe); tab.hReadPipe = nullptr; }

    m_terminalTabs.erase(m_terminalTabs.begin() + index);

    if (m_activeTerminalTab >= (int)m_terminalTabs.size())
        m_activeTerminalTab = (int)m_terminalTabs.size() - 1;
    if (m_activeTerminalTab >= 0)
        switchTerminalTab(m_activeTerminalTab);

    updateTerminalTabBar();
    LOG_INFO("[TerminalTabs] Closed tab " + std::to_string(index));
}

void Win32IDE::switchTerminalTab(int index) {
    if (index < 0 || index >= (int)m_terminalTabs.size()) return;

    for (int i = 0; i < (int)m_terminalTabs.size(); i++) {
        m_terminalTabs[i].active = (i == index);
        if (m_terminalTabs[i].hwndContent) {
            ShowWindow(m_terminalTabs[i].hwndContent, (i == index) ? SW_SHOW : SW_HIDE);
        }
    }
    m_activeTerminalTab = index;
    updateTerminalTabBar();
    LOG_INFO("[TerminalTabs] Switched to tab " + std::to_string(index));
}

void Win32IDE::renameTerminalTab(int index, const std::string& name) {
    if (index < 0 || index >= (int)m_terminalTabs.size()) return;
    m_terminalTabs[index].title = name;
    if (m_terminalTabs[index].hwndTabButton)
        SetWindowTextA(m_terminalTabs[index].hwndTabButton, name.c_str());
    updateTerminalTabBar();
}

void Win32IDE::updateTerminalTabBar() {
    if (!m_hwndTermTabBar) return;

    int tabW = dpiScale(120);
    int x = dpiScale(150);
    for (int i = 0; i < (int)m_terminalTabs.size(); i++) {
        if (m_terminalTabs[i].hwndTabButton) {
            MoveWindow(m_terminalTabs[i].hwndTabButton, x, dpiScale(2), tabW, dpiScale(26), TRUE);
            InvalidateRect(m_terminalTabs[i].hwndTabButton, NULL, TRUE);
        }
        x += tabW + dpiScale(2);
    }
    InvalidateRect(m_hwndTermTabBar, NULL, TRUE);
}

LRESULT CALLBACK Win32IDE::TermTabBarProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    Win32IDE* ide = (Win32IDE*)GetPropA(hwnd, "IDE_PTR");
    switch (msg) {
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        RECT rc;
        GetClientRect(hwnd, &rc);
        HBRUSH bg = CreateSolidBrush(RGB(37, 37, 38));
        FillRect(hdc, &rc, bg);
        DeleteObject(bg);
        HPEN pen = CreatePen(PS_SOLID, 1, RGB(60, 60, 60));
        HPEN oldPen = (HPEN)SelectObject(hdc, pen);
        MoveToEx(hdc, 0, rc.bottom - 1, NULL);
        LineTo(hdc, rc.right, rc.bottom - 1);
        SelectObject(hdc, oldPen);
        DeleteObject(pen);
        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_COMMAND: {
        if (!ide) break;
        int id = LOWORD(wParam);
        if (id == IDC_TERMTAB_ADD_BTN) {
            HWND hCombo = GetDlgItem(hwnd, IDC_TERMTAB_PROFILE);
            int sel = (int)SendMessageA(hCombo, CB_GETCURSEL, 0, 0);
            if (sel >= 0) {
                char profile[64] = {};
                SendMessageA(hCombo, CB_GETLBTEXT, sel, (LPARAM)profile);
                ide->createTerminalTab(profile);
            }
            return 0;
        }
        int tabId = id - IDC_TERMTAB_FIRST;
        if (tabId >= 0 && tabId < (int)ide->m_terminalTabs.size()) {
            ide->switchTerminalTab(tabId);
            return 0;
        }
        break;
    }
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}
