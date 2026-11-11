// Dedicated PowerShell Panel Implementation
// Always-available PowerShell console for Win32IDE

#include "Win32IDE.h"
#include <windows.h>
#include <sstream>
#include <algorithm>
#include <string>
#include <richedit.h>
#include <cstdio>
#include <cstdarg>

#ifndef MSFTEDIT_CLASS
#define MSFTEDIT_CLASS L"RICHEDIT50W"
#endif

// Strip CSI/OSC/VT so ConPTY leftovers never paint as literal text in RichEdit.
static std::string stripVtForRichEdit(const std::string& s)
{
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size();) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        if (c == 0x1B && i + 1 < s.size()) {
            const char n = s[i + 1];
            if (n == '[') {
                i += 2;
                while (i < s.size()) {
                    const unsigned char t = static_cast<unsigned char>(s[i++]);
                    if (t >= '@' && t <= '~') break;
                }
                continue;
            }
            if (n == ']') {
                i += 2;
                while (i < s.size()) {
                    if (s[i] == 0x07) { ++i; break; }
                    if (s[i] == 0x1B && i + 1 < s.size() && s[i + 1] == '\\') {
                        i += 2;
                        break;
                    }
                    ++i;
                }
                continue;
            }
            if (n == '(' || n == ')') { i += 2; continue; }
            i += 2;
            continue;
        }
        if (c == 0x07 || c == 0x0E || c == 0x0F) { ++i; continue; }
        out.push_back(s[i++]);
    }
    return out;
}

// UTF-8 → UTF-16 for Unicode RichEdit (G panel path; fail-closed on bad UTF-8).
static std::wstring utf8ToWideLocal(const std::string& text)
{
    if (text.empty()) return {};
    // Prefer UTF-8; fall back without MB_ERR so shell CP bytes still paint.
    int needed = MultiByteToWideChar(
        CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    UINT cp = CP_UTF8;
    if (needed <= 0) {
        needed = MultiByteToWideChar(
            CP_ACP, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
        cp = CP_ACP;
    }
    if (needed <= 0) return {};
    std::wstring wide(static_cast<size_t>(needed), L'\0');
    if (MultiByteToWideChar(
            cp, 0, text.data(), static_cast<int>(text.size()), &wide[0],
            needed) != needed) {
        return {};
    }
    return wide;
}

// === PS_TRACE: Runtime-local logging for PowerShell execution tracing ===
static inline void PsTrace(const char* fmt, ...)
{
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    const char* configuredLogDir = std::getenv("RAWRXD_LOG_DIR");
    const std::string logPath = (configuredLogDir && *configuredLogDir)
        ? std::string(configuredLogDir) + "\\ps_trace.log"
        : std::string("ps_trace.log");
    FILE* file = nullptr;
    if (fopen_s(&file, logPath.c_str(), "a") == 0 && file) {
        fprintf(file, "%lu %s\n", GetCurrentThreadId(), buf);
        fflush(file);
        fclose(file);
    }
    OutputDebugStringA(buf);
}

// PowerShell Panel Control IDs — keep out of 5000-5099 build/menu band
// (IDM_BUILD_COMPILE=5001, IDM_BUILD_RUN=5002 collide with prior PS IDs).
#define IDC_PS_PANEL_CONTAINER 5600
#define IDC_PS_OUTPUT 5601
#define IDC_PS_INPUT 5602
#define IDC_PS_TOOLBAR 5603
#define IDC_PS_STATUSBAR 5604
#define IDC_PS_BTN_EXECUTE 5610
#define IDC_PS_BTN_CLEAR 5611
#define IDC_PS_BTN_STOP 5612
#define IDC_PS_BTN_HISTORY 5613
#define IDC_PS_BTN_RESTART 5614
#define IDC_PS_BTN_LOAD_RAWRXD 5615
#define IDC_PS_BTN_TOGGLE 5616

// ============================================================================
// POWERSHELL PANEL CREATION
// ============================================================================

void Win32IDE::createPowerShellPanel() {
    if (m_hwndPowerShellPanel) {
        return; // Already created
    }
    
    // Unicode container + Msftedit RichEdit (bring G panel bits; keep F dedicated session).
    // Never create WS_VISIBLE: the four-panel dock (IDC_PANEL_CONTAINER) owns the
    // bottom rectangle at launch. Showing this peer here stacks over Output/Build
    // and covers chat buttons until a later hide races onSize.
    m_hwndPowerShellPanel = CreateWindowExW(
        WS_EX_CLIENTEDGE,
        L"STATIC", L"PowerShell Console",
        WS_CHILD | WS_BORDER,
        0, 0, 800, m_powerShellPanelHeight,
        m_hwndMain,
        (HMENU)IDC_PS_PANEL_CONTAINER,
        m_hInstance,
        NULL
    );
    
    if (!m_hwndPowerShellPanel) {
        return;
    }
    
    // Store IDE pointer for callbacks
    SetPropA(m_hwndPowerShellPanel, "IDE_PTR", this);
    // The panel is a child STATIC window, so button notifications terminate at
    // that window unless it forwards WM_COMMAND.  Install the existing panel
    // procedure on the actual runtime surface instead of leaving the controls
    // visually present but inert.
    WNDPROC oldPanelProc = reinterpret_cast<WNDPROC>(SetWindowLongPtrW(
        m_hwndPowerShellPanel, GWLP_WNDPROC,
        reinterpret_cast<LONG_PTR>(PowerShellPanelProc)));
    SetPropA(m_hwndPowerShellPanel, "OLDPROC", reinterpret_cast<HANDLE>(oldPanelProc));
    
    // Create toolbar
    createPowerShellToolbar();
    
    // Create output area (Unicode RichEdit — UTF-8 shell text via W path)
    LoadLibraryW(L"Msftedit.dll");
    LoadLibraryW(L"Riched20.dll");
    
    m_hwndPowerShellOutput = CreateWindowExW(
        WS_EX_CLIENTEDGE,
        MSFTEDIT_CLASS, L"",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
        5, 35, 790, m_powerShellPanelHeight - 95,
        m_hwndPowerShellPanel,
        (HMENU)IDC_PS_OUTPUT,
        m_hInstance,
        NULL
    );
    if (!m_hwndPowerShellOutput) {
        m_hwndPowerShellOutput = CreateWindowExW(
            WS_EX_CLIENTEDGE,
            RICHEDIT_CLASSW, L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
            5, 35, 790, m_powerShellPanelHeight - 95,
            m_hwndPowerShellPanel,
            (HMENU)IDC_PS_OUTPUT,
            m_hInstance,
            NULL
        );
    }
    
    // Set output font
    HFONT hFont = CreateFontW(
        16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas"
    );
    if (m_hwndPowerShellOutput)
        SendMessageW(m_hwndPowerShellOutput, WM_SETFONT, (WPARAM)hFont, TRUE);
    
    // Set background color
    if (m_hwndPowerShellOutput)
        SendMessageW(m_hwndPowerShellOutput, EM_SETBKGNDCOLOR, 0, RGB(1, 36, 86)); // PowerShell blue
    
    // Create input area
    m_hwndPowerShellInput = CreateWindowExW(
        WS_EX_CLIENTEDGE,
        L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
        5, m_powerShellPanelHeight - 55, 690, 25,
        m_hwndPowerShellPanel,
        (HMENU)IDC_PS_INPUT,
        m_hInstance,
        NULL
    );
    
    if (m_hwndPowerShellInput)
        SendMessageW(m_hwndPowerShellInput, WM_SETFONT, (WPARAM)hFont, TRUE);
    
    // Subclass input for custom handling (Enter key, history navigation)
    SetPropA(m_hwndPowerShellInput, "IDE_PTR", this);
    WNDPROC oldProc = (WNDPROC)SetWindowLongPtrW(m_hwndPowerShellInput, GWLP_WNDPROC, (LONG_PTR)PowerShellInputProc);
    SetPropA(m_hwndPowerShellInput, "OLDPROC", (HANDLE)oldProc);
    
    // Create Execute button
    m_hwndPSBtnExecute = CreateWindowExW(
        0, L"BUTTON", L"Execute",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        700, m_powerShellPanelHeight - 55, 90, 25,
        m_hwndPowerShellPanel,
        (HMENU)IDC_PS_BTN_EXECUTE,
        m_hInstance,
        NULL
    );
    if (m_hwndPSBtnExecute)
        SendMessageW(m_hwndPSBtnExecute, WM_SETFONT, (WPARAM)hFont, TRUE);
    
    // Create status bar
    m_hwndPowerShellStatusBar = CreateWindowExW(
        0, L"STATIC", L"PowerShell Status: Ready",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        5, m_powerShellPanelHeight - 25, 790, 20,
        m_hwndPowerShellPanel,
        (HMENU)IDC_PS_STATUSBAR,
        m_hInstance,
        NULL
    );
    
    HFONT hSmallFont = CreateFontW(
        12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI"
    );
    if (m_hwndPowerShellStatusBar)
        SendMessageW(m_hwndPowerShellStatusBar, WM_SETFONT, (WPARAM)hSmallFont, TRUE);
    
    // Initialize PowerShell session
    initializePowerShellPanel();
    
    // Show welcome message
    appendPowerShellOutput("\n", RGB(0, 255, 255));
    appendPowerShellOutput("  RawrXD Integrated PowerShell Console\n", RGB(255, 255, 0));
    appendPowerShellOutput("\n", RGB(0, 255, 255));
    appendPowerShellOutput("\n", RGB(200, 200, 200));
    
    std::string version = getPowerShellVersion();
    appendPowerShellOutput("PowerShell Version: " + version + "\n", RGB(0, 255, 0));
    appendPowerShellOutput("Edition: " + getPowerShellEdition() + "\n", RGB(0, 255, 0));
    appendPowerShellOutput("\nType commands below or click 'Load RawrXD' to access RawrXD.ps1 functions\n", RGB(200, 200, 200));
    appendPowerShellOutput("\nCommands:\n", RGB(255, 255, 0));
    appendPowerShellOutput("  - Enter: Execute command\n", RGB(150, 150, 150));
    appendPowerShellOutput("  - Up/Down: Navigate history\n", RGB(150, 150, 150));
    appendPowerShellOutput("  - Ctrl+L: Clear console\n", RGB(150, 150, 150));
    appendPowerShellOutput("  - Ctrl+`: Toggle panel\n", RGB(150, 150, 150));
    appendPowerShellOutput("\n" + getPowerShellPrompt(), RGB(0, 255, 0));

    // Peer panel stays hidden. Product path uses TERMINAL on IDC_PANEL_CONTAINER;
    // exclusive peer show is only via showPowerShellPanel when the four-panel
    // dock is intentionally off. Do not TabCtrl_SetCurSel(4) — that selects
    // Build and forces a second bottom surface over the dock.
}

void Win32IDE::createPowerShellToolbar() {
    if (!m_hwndPowerShellPanel) return;
    
    // Create toolbar buttons
    int btnX = 5;
    int btnY = 5;
    int btnWidth = 90;
    int btnHeight = 25;
    int btnSpacing = 5;
    
    m_hwndPSBtnClear = CreateWindowEx(
        0, "BUTTON", "Clear",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        btnX, btnY, btnWidth, btnHeight,
        m_hwndPowerShellPanel,
        (HMENU)IDC_PS_BTN_CLEAR,
        m_hInstance, NULL
    );
    btnX += btnWidth + btnSpacing;
    
    m_hwndPSBtnStop = CreateWindowEx(
        0, "BUTTON", "Stop",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        btnX, btnY, btnWidth, btnHeight,
        m_hwndPowerShellPanel,
        (HMENU)IDC_PS_BTN_STOP,
        m_hInstance, NULL
    );
    btnX += btnWidth + btnSpacing;
    
    m_hwndPSBtnHistory = CreateWindowEx(
        0, "BUTTON", "History",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        btnX, btnY, btnWidth, btnHeight,
        m_hwndPowerShellPanel,
        (HMENU)IDC_PS_BTN_HISTORY,
        m_hInstance, NULL
    );
    btnX += btnWidth + btnSpacing;
    
    m_hwndPSBtnRestart = CreateWindowEx(
        0, "BUTTON", "Restart",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        btnX, btnY, btnWidth, btnHeight,
        m_hwndPowerShellPanel,
        (HMENU)IDC_PS_BTN_RESTART,
        m_hInstance, NULL
    );
    btnX += btnWidth + btnSpacing;
    
    m_hwndPSBtnLoadRawrXD = CreateWindowEx(
        0, "BUTTON", "Load RawrXD",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        btnX, btnY, 120, btnHeight,
        m_hwndPowerShellPanel,
        (HMENU)IDC_PS_BTN_LOAD_RAWRXD,
        m_hInstance, NULL
    );
}

void Win32IDE::initializePowerShellPanel() {
    // Start dedicated PowerShell terminal
    m_dedicatedPowerShellTerminal = std::make_unique<Win32TerminalManager>();
    
    // Set up callbacks
    m_dedicatedPowerShellTerminal->onOutput = [this](const std::string& output) {
        {
            char dbg[512];
            snprintf(dbg, sizeof(dbg), "[PS_TRACE] onOutput() callback fired, output_len=%zu, thread=%lu\n", output.length(), (unsigned long)GetCurrentThreadId());
            OutputDebugStringA(dbg);
        }
        const HWND target = m_hwndMain;
        auto* update = new PowerShellUiUpdate{
            PowerShellUiUpdate::Kind::Output, output, RGB(200, 200, 200), 0};
        if (!target || !PostMessageA(target, kRawrxdPowerShellUiUpdate, 0,
                                     reinterpret_cast<LPARAM>(update))) {
            delete update;
        }
    };
    
    m_dedicatedPowerShellTerminal->onError = [this](const std::string& error) {
        const HWND target = m_hwndMain;
        auto* update = new PowerShellUiUpdate{
            PowerShellUiUpdate::Kind::Error, error, RGB(255, 100, 100), 0};
        if (!target || !PostMessageA(target, kRawrxdPowerShellUiUpdate, 0,
                                     reinterpret_cast<LPARAM>(update))) {
            delete update;
        }
    };
    
    m_dedicatedPowerShellTerminal->onStarted = [this]() {
        m_powerShellSessionActive = true;
        updatePowerShellStatus();
    };
    
    m_dedicatedPowerShellTerminal->onFinished = [this](int exitCode) {
        m_powerShellSessionActive = false;
        const HWND target = m_hwndMain;
        auto* update = new PowerShellUiUpdate{
            PowerShellUiUpdate::Kind::Finished, {}, RGB(255, 255, 0), exitCode};
        if (!target || !PostMessageA(target, kRawrxdPowerShellUiUpdate, 0,
                                     reinterpret_cast<LPARAM>(update))) {
            delete update;
        }
    };
    
    // Start PowerShell
    startPowerShellSession();
}

// ============================================================================
// POWERSHELL PANEL VISIBILITY & LAYOUT
// ============================================================================

void Win32IDE::showPowerShellPanel() {
    if (!m_hwndPowerShellPanel) {
        return;
    }
    // Four-panel dock owns the single bottom rectangle. Route console show to
    // the TERMINAL tab instead of stacking the peer panel over Output/Build.
    if (m_panelVisible) {
        m_powerShellPanelVisible = false;
        ShowWindow(m_hwndPowerShellPanel, SW_HIDE);
        switchPanelTab(PanelTab::Terminal);
        if (m_hwndMain && IsWindow(m_hwndMain)) {
            RECT rc{};
            if (GetClientRect(m_hwndMain, &rc) && rc.right > 0 && rc.bottom > 0) {
                PostMessageA(m_hwndMain, WM_SIZE, SIZE_RESTORED,
                             MAKELPARAM(rc.right, rc.bottom));
            }
        }
        return;
    }
    m_powerShellPanelVisible = true;
    // Legacy strip PowerShell tab index = channel count (after Debugger).
    constexpr int kPowerShellOutputTab = 12;
    if (m_hwndOutputTabs) {
        TabCtrl_SetCurSel(m_hwndOutputTabs, kPowerShellOutputTab);
        m_selectedOutputTab = kPowerShellOutputTab;
    }
    RECT rc{};
    GetClientRect(m_hwndMain, &rc);
    onSize(rc.right - rc.left, rc.bottom - rc.top);
}

void Win32IDE::hidePowerShellPanel() {
    if (!m_hwndPowerShellPanel) {
        return;
    }
    ShowWindow(m_hwndPowerShellPanel, SW_HIDE);
    m_powerShellPanelVisible = false;
    constexpr int kPowerShellOutputTab = 12;
    if (m_hwndOutputTabs && m_selectedOutputTab == kPowerShellOutputTab) {
        m_selectedOutputTab = 0;
        m_activeOutputTab = "Output";
        TabCtrl_SetCurSel(m_hwndOutputTabs, 0);
    }
    RECT rc{};
    GetClientRect(m_hwndMain, &rc);
    onSize(rc.right - rc.left, rc.bottom - rc.top);
}

void Win32IDE::togglePowerShellPanel() {
    if (m_powerShellPanelVisible) {
        hidePowerShellPanel();
    } else {
        showPowerShellPanel();
    }
}

void Win32IDE::layoutPowerShellPanel() {
    // Geometry is owned by onSize (exclusive peer) or suppressed while the
    // four-panel dock is visible. A free-floating bottom place here would
    // restack over IDC_PANEL_CONTAINER and cover chat/splitter.
    if (!m_hwndPowerShellPanel || !m_powerShellPanelVisible || m_panelVisible) {
        if (m_hwndPowerShellPanel && m_panelVisible) {
            ShowWindow(m_hwndPowerShellPanel, SW_HIDE);
        }
        return;
    }
    RECT mainRect{};
    GetClientRect(m_hwndMain, &mainRect);
    onSize(mainRect.right - mainRect.left, mainRect.bottom - mainRect.top);
}

void Win32IDE::updatePowerShellPanelLayout(int width, int height) {
    if (!m_hwndPowerShellPanel) return;

    width = std::max(0, width);
    height = std::max(160, height);
    
    // Layout internal controls
    if (m_hwndPowerShellOutput) {
        SetWindowPos(m_hwndPowerShellOutput, NULL,
            5, 35,
            std::max(0, width - 10), std::max(0, height - 95),
            SWP_NOZORDER);
    }
    
    if (m_hwndPowerShellInput) {
        SetWindowPos(m_hwndPowerShellInput, NULL,
            5, height - 55,
            std::max(0, width - 110), 25,
            SWP_NOZORDER);
    }
    
    if (m_hwndPSBtnExecute) {
        SetWindowPos(m_hwndPSBtnExecute, NULL,
            width - 100, height - 55,
            90, 25,
            SWP_NOZORDER);
    }
    
    if (m_hwndPowerShellStatusBar) {
        SetWindowPos(m_hwndPowerShellStatusBar, NULL,
            5, height - 25,
            std::max(0, width - 10), 20,
            SWP_NOZORDER);
    }
}

void Win32IDE::resizePowerShellPanel(int width, int height) {
    m_powerShellPanelHeight = height;
    layoutPowerShellPanel();
}

// ============================================================================
// POWERSHELL EXECUTION
// ============================================================================

void Win32IDE::executePowerShellInput() {
    PsTrace("[PS_TRACE] executePowerShellInput() ENTRY thread=%lu\n", GetCurrentThreadId());
    // Prefer live child of the panel container — member can drift if create/layout
    // races; harness SetWindowTextW targets the IDC_PS_INPUT child under panel.
    HWND input = m_hwndPowerShellPanel
        ? GetDlgItem(m_hwndPowerShellPanel, IDC_PS_INPUT)
        : nullptr;
    if (!input) input = m_hwndPowerShellInput;
    if (!input) {
        PsTrace("[PS_TRACE] executePowerShellInput() exit: no input hwnd\n");
        return;
    }
    m_hwndPowerShellInput = input;
    PsTrace("[PS_TRACE] executePowerShellInput() input_hwnd=%p panel=%p\n",
            input, m_hwndPowerShellPanel);

    // Prefer WM_GETTEXT via SendMessageW (same path harness uses). Then
    // GetWindowTextW/A. Cross-process SetWindowText often leaves GetWindowText*
    // empty in-process — WM_SETTEXT cache fills that gap.
    std::string command;
    {
        const LRESULT n = SendMessageW(input, WM_GETTEXTLENGTH, 0, 0);
        if (n > 0) {
            std::wstring wbuf(static_cast<size_t>(n) + 1u, L'\0');
            const LRESULT got = SendMessageW(input, WM_GETTEXT,
                static_cast<WPARAM>(n + 1), reinterpret_cast<LPARAM>(&wbuf[0]));
            if (got > 0) {
                wbuf.resize(static_cast<size_t>(got));
                const int need = WideCharToMultiByte(CP_UTF8, 0, wbuf.c_str(),
                                                    static_cast<int>(wbuf.size()),
                                                    nullptr, 0, nullptr, nullptr);
                if (need > 0) {
                    command.resize(static_cast<size_t>(need));
                    WideCharToMultiByte(CP_UTF8, 0, wbuf.c_str(),
                                        static_cast<int>(wbuf.size()),
                                        &command[0], need, nullptr, nullptr);
                }
            }
        }
    }
    const int wlen = GetWindowTextLengthW(input);
    if (command.empty() && wlen > 0) {
        std::wstring wbuf(static_cast<size_t>(wlen) + 1u, L'\0');
        const int got = GetWindowTextW(input, &wbuf[0], wlen + 1);
        if (got > 0) {
            wbuf.resize(static_cast<size_t>(got));
            const int need = WideCharToMultiByte(CP_UTF8, 0, wbuf.c_str(),
                                                static_cast<int>(wbuf.size()),
                                                nullptr, 0, nullptr, nullptr);
            if (need > 0) {
                command.resize(static_cast<size_t>(need));
                WideCharToMultiByte(CP_UTF8, 0, wbuf.c_str(),
                                    static_cast<int>(wbuf.size()),
                                    &command[0], need, nullptr, nullptr);
            }
        }
    }
    if (command.empty()) {
        char abuf[4096];
        const int alen = GetWindowTextA(input, abuf, sizeof(abuf));
        if (alen > 0) command.assign(abuf, static_cast<size_t>(alen));
    }
    // Prefer the SETTEXT cache when it is longer than what GetWindowText*
    // returned (ANSI SendMessage truncation → 1-char EDIT contents).
    if (!m_powerShellCurrentCommand.empty() &&
        (command.empty() ||
         m_powerShellCurrentCommand.size() > command.size())) {
        command = m_powerShellCurrentCommand;
        PsTrace("[PS_TRACE] executePowerShellInput() using WM_SETTEXT cache\n");
    }
    PsTrace("[PS_TRACE] executePowerShellInput() command_len=%zu cmd='%.100s' wlen=%d\n",
            command.length(), command.c_str(), wlen);
    
    if (command.empty()) {
        PsTrace("[PS_TRACE] executePowerShellInput() exit: empty command\n");
        return;
    }
    m_powerShellCurrentCommand.clear();
    
    // Clear input
    SetWindowTextW(input, L"");
    
    // Add to history
    addPowerShellHistory(command);
    
    // Echo command only — welcome/prior cycle already left a trailing "PS> ".
    // Prepending getPowerShellPrompt() here produced the observed "PS> PS> ..." pane.
    appendPowerShellOutput(command + "\n", RGB(255, 255, 255));
    
    // Execute
    PsTrace("[PS_TRACE] executePowerShellInput() calling executePowerShellPanelCommand() thread=%lu\n", GetCurrentThreadId());
    executePowerShellPanelCommand(command);
    
    PsTrace("[PS_TRACE] executePowerShellInput() EXIT\n");
}

void Win32IDE::executePowerShellPanelCommand(const std::string& command) {
    PsTrace("[PS_TRACE] executePowerShellPanelCommand() ENTRY cmd_len=%zu thread=%lu\n", command.length(), GetCurrentThreadId());
    {
        char dbg[512];
        snprintf(dbg, sizeof(dbg), "[PS_TRACE] executePowerShellPanelCommand() m_dedicatedPowerShellTerminal=%p m_powerShellSessionActive=%d\n", 
                 static_cast<void*>(m_dedicatedPowerShellTerminal.get()), m_powerShellSessionActive ? 1 : 0);
        OutputDebugStringA(dbg);
        FILE* f = fopen("F:\\rawrxd\\ps_trace.log", "a");
        if (f) { fprintf(f, "%s", dbg); fclose(f); }
    }

    // Revive dead pipe hosts (cancel A→B / idle EOF). PRESENT session flag
    // alone is not enough — writeInput no-ops when !isRunning().
    if (!m_dedicatedPowerShellTerminal) {
        initializePowerShellPanel();
    }
    if (m_dedicatedPowerShellTerminal &&
        (!m_powerShellSessionActive || !m_dedicatedPowerShellTerminal->isRunning())) {
        PsTrace("[PS_TRACE] executePowerShellPanelCommand() revive session\n");
        startPowerShellSession();
    }
    
    if (!m_dedicatedPowerShellTerminal || !m_powerShellSessionActive ||
        !m_dedicatedPowerShellTerminal->isRunning()) {
        appendPowerShellOutput("[ERROR] PowerShell session not active\n", RGB(255, 0, 0));
        PsTrace("[PS_TRACE] executePowerShellPanelCommand() exit: session not active\n");
        return;
    }
    
    m_powerShellExecuting = true;
    updatePowerShellStatus();
    // Do NOT mirror panel shell commands into AI chat via agentStepTimeline.onRow.
    // Panel I/O stays in m_hwndPowerShellOutput only (POWERSHELL_PANEL_GATE).
    
    // Send command to PowerShell
    PsTrace("[PS_TRACE] executePowerShellPanelCommand() calling writeInput() cmd_len=%zu thread=%lu\n", command.length(), GetCurrentThreadId());
    m_dedicatedPowerShellTerminal->writeInput(command + "\r\n");
    
    PsTrace("[PS_TRACE] executePowerShellPanelCommand() writeInput() returned\n");
    
    m_powerShellExecuting = false;
    updatePowerShellStatus();
    PsTrace("[PS_TRACE] executePowerShellPanelCommand() EXIT\n");
}

void Win32IDE::stopPowerShellExecution() {
    if (m_dedicatedPowerShellTerminal) {
        // Item7 cancel A→B: interrupt kills the pump host; clear executing
        // flag and stamp a boundary so B does not look like stale A output.
        const bool interrupted = m_dedicatedPowerShellTerminal->interrupt();
        m_powerShellExecuting = false;
        m_powerShellSessionActive = m_dedicatedPowerShellTerminal->isRunning();
        appendPowerShellOutput(
            interrupted ? "\n[Execution stopped — cancel boundary]\n"
                        : "\n[Execution stop requested]\n",
            RGB(255, 255, 0));
        appendPowerShellOutput(getPowerShellPrompt(), RGB(0, 255, 0));
        updatePowerShellStatus();
        // No chat mirror — stop is pane-local status only.
    }
}

void Win32IDE::clearPowerShellConsole() {
    if (m_hwndPowerShellOutput) {
        SetWindowTextW(m_hwndPowerShellOutput, L"");
        appendPowerShellOutput(getPowerShellPrompt(), RGB(0, 255, 0));
    }
}

void Win32IDE::appendPowerShellOutput(const std::string& text, COLORREF color) {
    {
        char dbg[512];
        snprintf(dbg, sizeof(dbg), "[PS_TRACE] appendPowerShellOutput() entry, text_len=%zu, m_hwndPowerShellOutput=%p, thread=%lu\n",
                 text.length(), static_cast<void*>(m_hwndPowerShellOutput), (unsigned long)GetCurrentThreadId());
        OutputDebugStringA(dbg);
    }
    
    if (!m_hwndPowerShellOutput) {
        OutputDebugStringA("[PS_TRACE] appendPowerShellOutput() exit: m_hwndPowerShellOutput is null\n");
        return;
    }

    // B: filter CSI/OSC before RichEdit append (no VT interpreter).
    const std::string cleaned = stripVtForRichEdit(text);
    if (cleaned.empty()) return;

    // Unicode RichEdit: UTF-8 → wide → EM_REPLACESEL(W). Keep VT strip from F.
    const std::wstring wtext = utf8ToWideLocal(cleaned);
    if (wtext.empty() && !cleaned.empty()) {
        OutputDebugStringA("[PS_TRACE] appendPowerShellOutput() exit: UTF-8 convert fail\n");
        return;
    }
    
    const LRESULT len = SendMessageW(m_hwndPowerShellOutput, WM_GETTEXTLENGTH, 0, 0);
    SendMessageW(m_hwndPowerShellOutput, EM_SETSEL,
                 static_cast<WPARAM>(len), static_cast<LPARAM>(len));
    
    CHARFORMAT2W cf = {};
    cf.cbSize = sizeof(CHARFORMAT2W);
    cf.dwMask = CFM_COLOR;
    cf.crTextColor = color;
    SendMessageW(m_hwndPowerShellOutput, EM_SETCHARFORMAT, SCF_SELECTION,
                 reinterpret_cast<LPARAM>(&cf));
    
    SendMessageW(m_hwndPowerShellOutput, EM_REPLACESEL, FALSE,
                 reinterpret_cast<LPARAM>(wtext.c_str()));
    
    {
        char dbg[256];
        snprintf(dbg, sizeof(dbg), "[PS_TRACE] appendPowerShellOutput() exit: EM_REPLACESELW called, output_len_before=%ld\n",
                 static_cast<long>(len));
        OutputDebugStringA(dbg);
    }
    
    // Scroll to bottom
    scrollPowerShellOutputToBottom();
}

// ============================================================================
// POWERSHELL HISTORY
// ============================================================================

void Win32IDE::addPowerShellHistory(const std::string& command) {
    if (command.empty()) return;
    
    // Don't add duplicates
    if (!m_powerShellCommandHistory.empty() && 
        m_powerShellCommandHistory.back() == command) {
        return;
    }
    
    m_powerShellCommandHistory.push_back(command);
    
    // Limit history size
    if (m_powerShellCommandHistory.size() > m_maxPowerShellHistory) {
        m_powerShellCommandHistory.erase(m_powerShellCommandHistory.begin());
    }
    
    // Reset history index
    m_powerShellHistoryIndex = m_powerShellCommandHistory.size();
}

void Win32IDE::navigatePowerShellHistoryUp() {
    if (m_powerShellCommandHistory.empty()) return;
    
    if (m_powerShellHistoryIndex > 0) {
        m_powerShellHistoryIndex--;
        SetWindowTextA(m_hwndPowerShellInput, 
            m_powerShellCommandHistory[m_powerShellHistoryIndex].c_str());
        
        // Select all text
        SendMessage(m_hwndPowerShellInput, EM_SETSEL, 0, -1);
    }
}

void Win32IDE::navigatePowerShellHistoryDown() {
    if (m_powerShellCommandHistory.empty()) return;
    
    if (m_powerShellHistoryIndex < static_cast<int>(m_powerShellCommandHistory.size()) - 1) {
        m_powerShellHistoryIndex++;
        SetWindowTextA(m_hwndPowerShellInput,
            m_powerShellCommandHistory[m_powerShellHistoryIndex].c_str());
        
        // Select all text
        SendMessage(m_hwndPowerShellInput, EM_SETSEL, 0, -1);
    } else if (m_powerShellHistoryIndex == static_cast<int>(m_powerShellCommandHistory.size()) - 1) {
        m_powerShellHistoryIndex++;
        SetWindowTextA(m_hwndPowerShellInput, "");
    }
}

void Win32IDE::showPowerShellHistory() {
    if (m_powerShellCommandHistory.empty()) {
        MessageBoxA(m_hwndMain, "No command history", "PowerShell History", MB_OK | MB_ICONINFORMATION);
        return;
    }
    
    std::string history;
    for (size_t i = 0; i < m_powerShellCommandHistory.size(); i++) {
        history += std::to_string(i + 1) + ": " + m_powerShellCommandHistory[i] + "\n";
    }
    
    MessageBoxA(m_hwndMain, history.c_str(), "PowerShell Command History", MB_OK | MB_ICONINFORMATION);
}

// ============================================================================
// POWERSHELL SESSION MANAGEMENT
// ============================================================================

void Win32IDE::startPowerShellSession() {
    // Active flag can lag a dead pipe (item8 writeInput no-op). Only skip
    // restart when the host is actually running.
    if (m_powerShellSessionActive && m_dedicatedPowerShellTerminal &&
        m_dedicatedPowerShellTerminal->isRunning()) {
        return;
    }
    m_powerShellSessionActive = false;
    
    if (!m_dedicatedPowerShellTerminal) {
        m_dedicatedPowerShellTerminal = std::make_unique<Win32TerminalManager>();
    }
    
    // A: persistent ReadLine/iex pipe pump (not bare -Command - which can
    // exit idle). ConPTY -NoExit emits CSI/OSC RichEdit cannot paint.
    bool started = m_dedicatedPowerShellTerminal->startNonInteractive(
        Win32TerminalManager::PowerShell);
    
    if (started) {
        m_powerShellSessionActive = true;
        appendPowerShellOutput("[PowerShell session started]\n", RGB(0, 255, 0));
    } else {
        appendPowerShellOutput("[ERROR] Failed to start PowerShell session\n", RGB(255, 0, 0));
    }
    
    updatePowerShellStatus();
}

void Win32IDE::restartPowerShellSession() {
    stopPowerShellSession();
    Sleep(500); // Brief delay
    startPowerShellSession();
}

void Win32IDE::stopPowerShellSession() {
    if (m_dedicatedPowerShellTerminal) {
        m_dedicatedPowerShellTerminal->stop();
        m_powerShellSessionActive = false;
        appendPowerShellOutput("[PowerShell session stopped]\n", RGB(255, 255, 0));
    }
    
    updatePowerShellStatus();
}

bool Win32IDE::isPowerShellSessionActive() const {
    return m_powerShellSessionActive;
}

void Win32IDE::updatePowerShellStatus() {
    if (!m_hwndPowerShellStatusBar) return;
    
    std::string status = "PowerShell: ";
    
    if (m_powerShellSessionActive) {
        status += "Active";
        if (m_powerShellExecuting) {
            status += " (Executing...)";
        }
        if (m_powerShellRawrXDLoaded) {
            status += " | RawrXD Module: Loaded";
        }
    } else {
        status += "Not Active";
    }
    
    status += " | " + getPowerShellVersion();
    
    SetWindowTextA(m_hwndPowerShellStatusBar, status.c_str());
}

// ============================================================================
// RAWRXD.PS1 INTEGRATION
// ============================================================================

void Win32IDE::loadRawrXDModule() {
    if (m_powerShellRawrXDLoaded) {
        appendPowerShellOutput("[RawrXD module already loaded]\n", RGB(255, 255, 0));
        return;
    }
    
    appendPowerShellOutput("[Loading RawrXD.ps1 module...]\n", RGB(0, 255, 255));
    
    bool success = loadRawrXDPowerShellModule();
    
    if (success) {
        m_powerShellRawrXDLoaded = true;
        appendPowerShellOutput("[SUCCESS] RawrXD module loaded!\n", RGB(0, 255, 0));
        appendPowerShellOutput("Available functions:\n", RGB(255, 255, 0));
        appendPowerShellOutput("  - Open-GGUFModel\n", RGB(150, 150, 150));
        appendPowerShellOutput("  - Invoke-PoshLLMInference\n", RGB(150, 150, 150));
        appendPowerShellOutput("  - Get-PoshLLMStatus\n", RGB(150, 150, 150));
        appendPowerShellOutput("\n" + getPowerShellPrompt(), RGB(0, 255, 0));
    } else {
        appendPowerShellOutput("[ERROR] Failed to load RawrXD module\n", RGB(255, 0, 0));
        appendPowerShellOutput("Make sure RawrXD.ps1 is in the Powershield directory\n", RGB(255, 100, 100));
    }
    
    updatePowerShellStatus();
}

void Win32IDE::unloadRawrXDModule() {
    if (!m_powerShellRawrXDLoaded) {
        return;
    }
    
    // There's no easy way to unload functions in PowerShell
    // So we just mark it as unloaded
    m_powerShellRawrXDLoaded = false;
    appendPowerShellOutput("[RawrXD module marked as unloaded]\n", RGB(255, 255, 0));
    updatePowerShellStatus();
}

void Win32IDE::executeRawrXDCommand(const std::string& command) {
    if (!m_powerShellRawrXDLoaded) {
        loadRawrXDModule();
    }
    
    executePowerShellPanelCommand(command);
}

void Win32IDE::quickLoadGGUFModel() {
    // Simple dialog to load a GGUF model
    std::string modelPath = getFileDialogPath(false);
    
    if (!modelPath.empty()) {
        std::string command = "Open-GGUFModel -ModelPath '" + modelPath + "' -MaxZoneMB 512";
        executeRawrXDCommand(command);
    }
}

void Win32IDE::quickInference() {
    // Simple dialog for inference
    char prompt[1024] = "";
    
    if (MessageBoxA(m_hwndMain, "Enter your prompt in the PowerShell console using:\nInvoke-PoshLLMInference -Prompt 'your prompt' -MaxTokens 100",
        "Quick Inference", MB_OKCANCEL | MB_ICONINFORMATION) == IDOK) {
        
        // Focus the input
        SetFocus(m_hwndPowerShellInput);
        SetWindowText(m_hwndPowerShellInput, "Invoke-PoshLLMInference -Prompt '' -MaxTokens 100");
        
        // Position cursor before second quote
        SendMessage(m_hwndPowerShellInput, EM_SETSEL, 36, 36);
    }
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

std::string Win32IDE::getPowerShellPrompt() {
    return "PS> ";
}

void Win32IDE::scrollPowerShellOutputToBottom() {
    if (!m_hwndPowerShellOutput) return;
    
    // Scroll to bottom
    SendMessage(m_hwndPowerShellOutput, WM_VSCROLL, SB_BOTTOM, 0);
}

// ============================================================================
// WINDOW PROCEDURES
// ============================================================================

LRESULT CALLBACK Win32IDE::PowerShellPanelProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    // SetPropA ↔ GetPropA (GetPropW under UNICODE misses ANSI props).
    Win32IDE* ide = reinterpret_cast<Win32IDE*>(GetPropA(hwnd, "IDE_PTR"));
    
    switch (uMsg) {
        case WM_COPYDATA: {
            // Cross-process automation: command bytes in COPYDATASTRUCT.
            // Do not depend on GetWindowText of the input EDIT (measured empty
            // after external SetWindowTextW even when WM_GETTEXT from harness
            // returned the string).
            auto* cds = reinterpret_cast<COPYDATASTRUCT*>(lParam);
            if (!ide || !cds || !cds->lpData || cds->cbData <= 0) break;
            if (static_cast<ULONG_PTR>(cds->dwData) != kRawrxdPowerShellCopyDataCmd) break;
            std::string cmd(static_cast<const char*>(cds->lpData),
                            static_cast<size_t>(cds->cbData));
            while (!cmd.empty() &&
                   (cmd.back() == '\0' || cmd.back() == '\r' || cmd.back() == '\n')) {
                cmd.pop_back();
            }
            PsTrace("[PS_TRACE] WM_COPYDATA cmd_len=%zu cmd='%.100s'\n",
                    cmd.size(), cmd.c_str());
            if (cmd.empty()) return TRUE;
            ide->addPowerShellHistory(cmd);
            ide->appendPowerShellOutput(cmd + "\n", RGB(255, 255, 255));
            ide->executePowerShellPanelCommand(cmd);
            return TRUE;
        }
        case WM_COMMAND: {
            int id = LOWORD(wParam);
            
            switch (id) {
                case IDC_PS_BTN_EXECUTE:
                    {
                        PsTrace("[PS_TRACE] EXECUTE_CLICKED IDC_PS_BTN_EXECUTE thread=%lu\n", GetCurrentThreadId());
                        if (ide) ide->executePowerShellInput();
                    }
                    break;
                case IDC_PS_BTN_CLEAR:
                    if (ide) ide->clearPowerShellConsole();
                    break;
                case IDC_PS_BTN_STOP:
                    if (ide) ide->stopPowerShellExecution();
                    break;
                case IDC_PS_BTN_HISTORY:
                    if (ide) ide->showPowerShellHistory();
                    break;
                case IDC_PS_BTN_RESTART:
                    if (ide) ide->restartPowerShellSession();
                    break;
                case IDC_PS_BTN_LOAD_RAWRXD:
                    if (ide) ide->loadRawrXDModule();
                    break;
            }
            break;
        }
    }
    
    WNDPROC oldProc = reinterpret_cast<WNDPROC>(GetPropA(hwnd, "OLDPROC"));
    return oldProc ? CallWindowProcW(oldProc, hwnd, uMsg, wParam, lParam)
                   : DefWindowProcW(hwnd, uMsg, wParam, lParam);
}

LRESULT CALLBACK Win32IDE::PowerShellInputProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    Win32IDE* ide = reinterpret_cast<Win32IDE*>(GetPropA(hwnd, "IDE_PTR"));
    WNDPROC oldProc = reinterpret_cast<WNDPROC>(GetPropA(hwnd, "OLDPROC"));
    
    switch (uMsg) {
        case WM_SETTEXT:
            // Cache UTF-8 command for executePowerShellInput — cross-process
            // SetWindowText can make subsequent GetWindowText* return empty.
            // Harness Add-Type often binds ANSI SendMessage + UTF-16 payload;
            // DefWindowProcA then stores only the first Latin character (item8).
            if (ide && lParam) {
                const auto* bytes = reinterpret_cast<const unsigned char*>(lParam);
                const wchar_t* wide = reinterpret_cast<const wchar_t*>(lParam);
                const bool utf16ViaAnsi =
                    bytes[0] != 0 && bytes[1] == 0 && wide[0] != 0 &&
                    (wide[1] != 0 || wide[0] < 128);
                if (IsWindowUnicode(hwnd) || utf16ViaAnsi) {
                    if (utf16ViaAnsi && !IsWindowUnicode(hwnd)) {
                        SetWindowTextW(hwnd, wide);
                    }
                    const int need = WideCharToMultiByte(CP_UTF8, 0, wide, -1,
                                                         nullptr, 0, nullptr, nullptr);
                    if (need > 1) {
                        ide->m_powerShellCurrentCommand.assign(
                            static_cast<size_t>(need - 1), '\0');
                        WideCharToMultiByte(CP_UTF8, 0, wide, -1,
                                            &ide->m_powerShellCurrentCommand[0],
                                            need, nullptr, nullptr);
                    } else {
                        ide->m_powerShellCurrentCommand.clear();
                    }
                    PsTrace("[PS_TRACE] WM_SETTEXT cache len=%zu utf16Ansi=%d\n",
                            ide->m_powerShellCurrentCommand.size(),
                            utf16ViaAnsi ? 1 : 0);
                    if (utf16ViaAnsi) {
                        return TRUE; // already applied via SetWindowTextW
                    }
                } else {
                    ide->m_powerShellCurrentCommand =
                        reinterpret_cast<const char*>(lParam);
                    PsTrace("[PS_TRACE] WM_SETTEXT cache len=%zu\n",
                            ide->m_powerShellCurrentCommand.size());
                }
            }
            break;
        case WM_GETDLGCODE:
            // EDIT controls normally let the dialog manager consume Enter.
            // Request the key explicitly so the subclass receives it even
            // when the panel is hosted below a tab control.
            return (oldProc ? CallWindowProcW(oldProc, hwnd, uMsg, wParam, lParam)
                            : DefWindowProcW(hwnd, uMsg, wParam, lParam)) |
                   DLGC_WANTALLKEYS;
        case WM_KEYDOWN: {
            switch (wParam) {
                case VK_RETURN:
                    // Arm + execute once on KEYDOWN. WM_CHAR \r must not re-fire.
                    SetPropA(hwnd, "PS_ENTER_ARM", reinterpret_cast<HANDLE>(1));
                    if (ide) ide->executePowerShellInput();
                    return 0;
                    
                case VK_UP:
                    // Navigate history up
                    if (ide) ide->navigatePowerShellHistoryUp();
                    return 0;
                    
                case VK_DOWN:
                    // Navigate history down
                    if (ide) ide->navigatePowerShellHistoryDown();
                    return 0;
                    
                case 'L':
                    // Ctrl+L - Clear console
                    if (GetKeyState(VK_CONTROL) & 0x8000) {
                        if (ide) ide->clearPowerShellConsole();
                        return 0;
                    }
                    break;
            }
            break;
        }
        case WM_CHAR:
            // Consume newline always. Execute only when KEYDOWN did not arm
            // (translated dialog paths that deliver CHAR-only Enter).
            if (wParam == '\r' || wParam == '\n') {
                const bool armed = GetPropA(hwnd, "PS_ENTER_ARM") != nullptr;
                RemovePropA(hwnd, "PS_ENTER_ARM");
                if (!armed && ide) ide->executePowerShellInput();
                return 0;
            }
            break;
    }
    
    return oldProc ? CallWindowProcW(oldProc, hwnd, uMsg, wParam, lParam)
                   : DefWindowProcW(hwnd, uMsg, wParam, lParam);
}

LRESULT CALLBACK Win32IDE::TerminalInputProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    WNDPROC oldProc = reinterpret_cast<WNDPROC>(GetPropA(hwnd, "RAWRXD_TERMINAL_OLDPROC"));
    if (uMsg == WM_KEYDOWN && wParam == VK_RETURN) {
        HWND root = GetAncestor(hwnd, GA_ROOT);
        auto* ide = reinterpret_cast<Win32IDE*>(GetWindowLongPtrA(root, GWLP_USERDATA));
        const auto paneValue = reinterpret_cast<ULONG_PTR>(GetPropA(hwnd, "RAWRXD_TERMINAL_PANE"));
        if (ide && paneValue) {
            TerminalPane* pane = ide->findTerminalPane(static_cast<int>(paneValue));
            char text[8192]{};
            GetWindowTextA(hwnd, text, static_cast<int>(sizeof(text)));
            if (pane && pane->manager && text[0]) {
                ide->onTerminalOutput(pane->id, std::string("> ") + text + "\r\n");
                pane->manager->writeInput(std::string(text) + "\r\n");
                SetWindowTextA(hwnd, "");
            }
            return 0;
        }
    }
    return oldProc ? CallWindowProcA(oldProc, hwnd, uMsg, wParam, lParam)
                    : DefWindowProcA(hwnd, uMsg, wParam, lParam);
}
