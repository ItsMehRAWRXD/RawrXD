// Dedicated PowerShell Panel Implementation
// Always-available PowerShell console for Win32IDE

#include "Win32IDE.h"
#include "Win32Utf8.hpp"
#include "Win32IDE_CommandFlight.hpp"
#include <sstream>
#include <algorithm>
#include <string>
#include <cstdio>
#include <richedit.h>
#include <windows.h>

// RichEdit EM_GETTEXTLENGTHEX / EM_SETTEXTEX: 1200 = UTF-16 (not a Win32 CP_* macro).
static constexpr UINT kRichEditUtf16CodePage = 1200;
static constexpr const char kPsMetaTag[] = "RAWRXD_PS_META|";

namespace {

bool parsePowerShellMetaLine(const std::string& line, std::string& version,
                             std::string& edition, std::string& policy)
{
    const size_t tag = line.find(kPsMetaTag);
    if (tag == std::string::npos)
        return false;
    std::string rest = line.substr(tag + sizeof(kPsMetaTag) - 1);
    while (!rest.empty() && (rest.back() == '\r' || rest.back() == '\n'))
        rest.pop_back();
    std::string parts[3];
    int n = 0;
    size_t begin = 0;
    for (size_t i = 0; i <= rest.size() && n < 3; ++i) {
        if (i == rest.size() || rest[i] == '|') {
            parts[n++] = rest.substr(begin, i - begin);
            begin = i + 1;
        }
    }
    if (n < 1 || parts[0].empty())
        return false;
    version = parts[0];
    edition = n > 1 ? parts[1] : std::string();
    policy = n > 2 ? parts[2] : std::string();
    return true;
}

}  // namespace

// PowerShell Panel Control IDs
#define IDC_PS_PANEL_CONTAINER 5000
#define IDC_PS_OUTPUT 5001
#define IDC_PS_INPUT 5002
#define IDC_PS_TOOLBAR 5003
#define IDC_PS_STATUSBAR 5004
#define IDC_PS_BTN_EXECUTE 5010
#define IDC_PS_BTN_CLEAR 5011
#define IDC_PS_BTN_STOP 5012
#define IDC_PS_BTN_HISTORY 5013
#define IDC_PS_BTN_RESTART 5014
#define IDC_PS_BTN_LOAD_RAWRXD 5015
#define IDC_PS_BTN_TOGGLE 5016

// ============================================================================
// POWERSHELL PANEL CREATION
// ============================================================================

void Win32IDE::createPowerShellPanel() {
    if (m_hwndPowerShellPanel) {
        return; // Already created
    }
    
    // Unicode container — ANSI parent can coerce child text through ACP.
    m_hwndPowerShellPanel = CreateWindowExW(
        WS_EX_CLIENTEDGE,
        L"STATIC", L"PowerShell Console",
        WS_CHILD | WS_VISIBLE | WS_BORDER,
        0, 0, 800, m_powerShellPanelHeight,
        m_hwndMain,
        (HMENU)IDC_PS_PANEL_CONTAINER,
        m_hInstance,
        NULL
    );

    // LOGGING AS REQUESTED
    char logBuf[256];
    sprintf_s(logBuf, "PowerShellPanel HWND created: %p (Parent: %p)", m_hwndPowerShellPanel, m_hwndMain);
    LOG_INFO(std::string(logBuf));
    
    if (!m_hwndPowerShellPanel) {
        return;
    }
    
    // Store IDE pointer for callbacks
    SetPropA(m_hwndPowerShellPanel, "IDE_PTR", this);
    
    // Create toolbar
    createPowerShellToolbar();
    
    // Create output area (Unicode RichEdit — panel text is UTF-8 with box-drawing)
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
        // Fallback for older hosts without msftedit
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
    
    // Set output font (DPI-scaled)
    HFONT hFont = CreateFontW(
        -dpiScale(16), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas"
    );
    SendMessage(m_hwndPowerShellOutput, WM_SETFONT, (WPARAM)hFont, TRUE);
    
    // Set background color
    SendMessage(m_hwndPowerShellOutput, EM_SETBKGNDCOLOR, 0, RGB(1, 36, 86)); // PowerShell blue
    
    // Create input area
    m_hwndPowerShellInput = CreateWindowExA(
        WS_EX_CLIENTEDGE,
        "EDIT", "",
        WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
        5, m_powerShellPanelHeight - 55, 690, 25,
        m_hwndPowerShellPanel,
        (HMENU)IDC_PS_INPUT,
        m_hInstance,
        NULL
    );
    
    SendMessage(m_hwndPowerShellInput, WM_SETFONT, (WPARAM)hFont, TRUE);
    
    // Subclass input for custom handling (Enter key, history navigation)
    SetPropA(m_hwndPowerShellInput, "IDE_PTR", this);
    WNDPROC oldProc = (WNDPROC)SetWindowLongPtr(m_hwndPowerShellInput, GWLP_WNDPROC, (LONG_PTR)PowerShellInputProc);
    SetPropA(m_hwndPowerShellInput, "OLDPROC", (HANDLE)oldProc);
    
    // Create Execute button
    m_hwndPSBtnExecute = CreateWindowExA(
        0, "BUTTON", "Execute",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        700, m_powerShellPanelHeight - 55, 90, 25,
        m_hwndPowerShellPanel,
        (HMENU)IDC_PS_BTN_EXECUTE,
        m_hInstance,
        NULL
    );
    SendMessage(m_hwndPSBtnExecute, WM_SETFONT, (WPARAM)hFont, TRUE);
    
    m_hwndPowerShellStatusBar = CreateWindowExW(
        0, L"STATIC", L"PowerShell: starting...",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        5, m_powerShellPanelHeight - 25, 790, 20,
        m_hwndPowerShellPanel,
        (HMENU)IDC_PS_STATUSBAR,
        m_hInstance,
        NULL
    );
    
    HFONT hSmallFont = CreateFontW(
        -dpiScale(12), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI"
    );
    SendMessage(m_hwndPowerShellStatusBar, WM_SETFONT, (WPARAM)hSmallFont, TRUE);
    
    // Initialize PowerShell UI only. The shell session itself is started lazily
    // on first use so the IDE can finish painting immediately.
    initializePowerShellPanel();

    // LOGGING AS REQUESTED
    // char logBuf[256]; // REUSED
    sprintf_s(logBuf, "PowerShell Panel HWNDs: Main=%p Output=%p Input=%p", 
              m_hwndPowerShellPanel, m_hwndPowerShellOutput, m_hwndPowerShellInput);
    LOG_INFO(std::string(logBuf));
    
    // Show welcome message
    appendPowerShellOutput("===============================================================\n", RGB(0, 255, 255));
    appendPowerShellOutput("  RawrXD Integrated PowerShell Console\n", RGB(255, 255, 0));
    appendPowerShellOutput("===============================================================\n", RGB(0, 255, 255));
    appendPowerShellOutput("\n", RGB(200, 200, 200));
    
    appendPowerShellOutput("PowerShell session: starting after UI is live...\n", RGB(0, 255, 0));
    appendPowerShellOutput("\nType commands below or click 'Load RawrXD' to access RawrXD.ps1 functions\n", RGB(200, 200, 200));
    appendPowerShellOutput("\nCommands:\n", RGB(255, 255, 0));
    appendPowerShellOutput("  - Enter: Execute command\n", RGB(150, 150, 150));
    appendPowerShellOutput("  - Up/Down: Navigate history\n", RGB(150, 150, 150));
    appendPowerShellOutput("  - Ctrl+L: Clear console\n", RGB(150, 150, 150));
    appendPowerShellOutput("  - Ctrl+`: Toggle panel\n", RGB(150, 150, 150));
    appendPowerShellOutput("\n" + getPowerShellPrompt(), RGB(0, 255, 0));

    // P1_UI_ENCODING_001 live probe (no model / no GGUF)
    runUiEncodingProbe();
}

void Win32IDE::createPowerShellToolbar() {
    if (!m_hwndPowerShellPanel) return;
    
    // Create toolbar buttons
    int btnX = 5;
    int btnY = 5;
    int btnWidth = 90;
    int btnHeight = 25;
    int btnSpacing = 5;
    
    m_hwndPSBtnClear = CreateWindowExA(
        0, "BUTTON", "Clear",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        btnX, btnY, btnWidth, btnHeight,
        m_hwndPowerShellPanel,
        (HMENU)IDC_PS_BTN_CLEAR,
        m_hInstance, NULL
    );
    btnX += btnWidth + btnSpacing;
    
    m_hwndPSBtnStop = CreateWindowExA(
        0, "BUTTON", "Stop",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        btnX, btnY, btnWidth, btnHeight,
        m_hwndPowerShellPanel,
        (HMENU)IDC_PS_BTN_STOP,
        m_hInstance, NULL
    );
    btnX += btnWidth + btnSpacing;
    
    m_hwndPSBtnHistory = CreateWindowExA(
        0, "BUTTON", "History",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        btnX, btnY, btnWidth, btnHeight,
        m_hwndPowerShellPanel,
        (HMENU)IDC_PS_BTN_HISTORY,
        m_hInstance, NULL
    );
    btnX += btnWidth + btnSpacing;
    
    m_hwndPSBtnRestart = CreateWindowExA(
        0, "BUTTON", "Restart",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        btnX, btnY, btnWidth, btnHeight,
        m_hwndPowerShellPanel,
        (HMENU)IDC_PS_BTN_RESTART,
        m_hInstance, NULL
    );
    btnX += btnWidth + btnSpacing;
    
    m_hwndPSBtnLoadRawrXD = CreateWindowExA(
        0, "BUTTON", "Load RawrXD",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        btnX, btnY, 120, btnHeight,
        m_hwndPowerShellPanel,
        (HMENU)IDC_PS_BTN_LOAD_RAWRXD,
        m_hInstance, NULL
    );
}

void Win32IDE::initializePowerShellPanel() {
    // No main-status SB_GETTEXT here — panel status bar only via updatePowerShellStatus.
    RawrXD::CommandTelemetry::CmdDiagBreadcrumb(
        -1, "initializePowerShellPanel_ENTER_NO_MAIN_SB_GETTEXT");
    // Start dedicated PowerShell terminal
    m_dedicatedPowerShellTerminal = std::make_unique<Win32TerminalManager>();
    
    // Set up callbacks
    m_dedicatedPowerShellTerminal->onOutput = [this](const std::string& output) {
        if (isShuttingDown()) return;
        static std::string hold;
        hold += output;
        std::string display;
        size_t cursor = 0;
        for (;;) {
            const size_t nl = hold.find_first_of("\r\n", cursor);
            if (nl == std::string::npos)
                break;
            const std::string line = hold.substr(cursor, nl - cursor);
            std::string ver, ed, pol;
            if (parsePowerShellMetaLine(line, ver, ed, pol)) {
                m_psState.version = ver;
                if (!ed.empty())
                    m_psState.edition = ed;
                if (!pol.empty())
                    m_psState.currentExecutionPolicy = pol;
                updatePowerShellStatus();
                appendPowerShellOutput("PowerShell Version: " + ver + "\n", RGB(0, 255, 0));
                if (!ed.empty())
                    appendPowerShellOutput("Edition: " + ed + "\n", RGB(0, 255, 0));
            } else if (!line.empty()) {
                display.append(line);
                display.push_back('\n');
            }
            cursor = nl + 1;
            if (cursor < hold.size() && hold[nl] == '\r' && hold[cursor] == '\n')
                ++cursor;
        }
        hold.erase(0, cursor);
        if (hold.find(kPsMetaTag) == std::string::npos && !hold.empty()) {
            display += hold;
            hold.clear();
        }
        if (!display.empty())
            appendPowerShellOutput(display, RGB(200, 200, 200));
    };
    
    m_dedicatedPowerShellTerminal->onError = [this](const std::string& error) {
        if (isShuttingDown()) return;
        appendPowerShellOutput("[ERROR] " + error, RGB(255, 100, 100));
    };
    
    m_dedicatedPowerShellTerminal->onStarted = [this]() {
        if (isShuttingDown()) return;
        m_powerShellSessionActive = true;
        updatePowerShellStatus();
    };
    
    m_dedicatedPowerShellTerminal->onFinished = [this](int exitCode) {
        if (isShuttingDown()) return;
        m_powerShellSessionActive = false;
        appendPowerShellOutput("\n[PowerShell session ended with code: " + std::to_string(exitCode) + "]\n", RGB(255, 255, 0));
        updatePowerShellStatus();
    };
    
    // Defer launching the shell process until the first command is executed.
    // This avoids a multi-second launch stall during WM_CREATE / startup.
    m_powerShellSessionActive = false;
    m_psState.version = "pending";
    m_psState.edition = "pending";
    m_psState.currentExecutionPolicy = "pending";
    updatePowerShellStatus();
    RawrXD::CommandTelemetry::CmdDiagBreadcrumb(
        -1, "initializePowerShellPanel_EXIT_NO_MAIN_SB_GETTEXT");
}

// ============================================================================
// POWERSHELL PANEL VISIBILITY & LAYOUT
// ============================================================================

void Win32IDE::showPowerShellPanel() {
    if (m_hwndPowerShellPanel) {
        ShowWindow(m_hwndPowerShellPanel, SW_SHOW);
        m_powerShellPanelVisible = true;
        
        // Force layout update
        RECT rc;
        GetClientRect(m_hwndMain, &rc);
        onSize(rc.right - rc.left, rc.bottom - rc.top);
    }
}

void Win32IDE::hidePowerShellPanel() {
    if (m_hwndPowerShellPanel) {
        ShowWindow(m_hwndPowerShellPanel, SW_HIDE);
        m_powerShellPanelVisible = false;
        
        // Force layout update
        RECT rc;
        GetClientRect(m_hwndMain, &rc);
        onSize(rc.right - rc.left, rc.bottom - rc.top);
    }
}

void Win32IDE::togglePowerShellPanel() {
    if (m_powerShellPanelVisible) {
        hidePowerShellPanel();
    } else {
        showPowerShellPanel();
    }
}

void Win32IDE::layoutPowerShellPanel() {
    if (!m_hwndMain || !IsWindow(m_hwndMain))
        return;
    // Spatial authority is onSize — never recompute independent geometry here.
    RECT rc{};
    GetClientRect(m_hwndMain, &rc);
    const int w = rc.right - rc.left;
    const int h = rc.bottom - rc.top;
    if (w > 0 && h > 0)
        onSize(w, h);
}

void Win32IDE::updatePowerShellPanelLayout(int width, int height) {
    if (!m_hwndPowerShellPanel) return;
    
    // Layout internal controls
    if (m_hwndPowerShellOutput) {
        SetWindowPos(m_hwndPowerShellOutput, NULL,
            5, 35,
            width - 10, height - 95,
            SWP_NOZORDER);
    }
    
    if (m_hwndPowerShellInput) {
        SetWindowPos(m_hwndPowerShellInput, NULL,
            5, height - 55,
            width - 110, 25,
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
            width - 10, 20,
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
    if (!m_hwndPowerShellInput) return;
    
    char buffer[4096];
    GetWindowTextA(m_hwndPowerShellInput, buffer, sizeof(buffer));
    
    std::string command(buffer);
    if (command.empty()) {
        return;
    }
    
    // Clear input
    SetWindowTextA(m_hwndPowerShellInput, "");
    
    // Add to history
    addPowerShellHistory(command);
    
    // Echo command
    appendPowerShellOutput(getPowerShellPrompt() + command + "\n", RGB(255, 255, 255));
    
    // Execute
    executePowerShellPanelCommand(command);
}

void Win32IDE::executePowerShellPanelCommand(const std::string& command) {
    if (!m_powerShellSessionActive) {
        startPowerShellSession();
    }

    // Route to active terminal: tabbed terminals (Tier2) or dedicated PowerShell session
    if (!m_terminalTabs.empty() && m_activeTerminalTab >= 0 && m_activeTerminalTab < static_cast<int>(m_terminalTabs.size())) {
        auto& tab = m_terminalTabs[m_activeTerminalTab];
        if (tab.manager && tab.manager->isRunning()) {
            m_powerShellExecuting = true;
            updatePowerShellStatus();
            tab.manager->writeInput(command + "\r\n");
            m_powerShellExecuting = false;
            updatePowerShellStatus();
            return;
        }
    }
    if (!m_dedicatedPowerShellTerminal || !m_powerShellSessionActive) {
        appendPowerShellOutput("[ERROR] Terminal session not active. Start a terminal from the panel or add a tab.\n", RGB(255, 0, 0));
        return;
    }
    m_powerShellExecuting = true;
    updatePowerShellStatus();
    m_dedicatedPowerShellTerminal->writeInput(command + "\r\n");
    m_powerShellExecuting = false;
    updatePowerShellStatus();
}

void Win32IDE::stopPowerShellExecution() {
    if (!m_terminalTabs.empty() && m_activeTerminalTab >= 0 && m_activeTerminalTab < static_cast<int>(m_terminalTabs.size())) {
        auto& tab = m_terminalTabs[m_activeTerminalTab];
        if (tab.manager && tab.manager->isRunning()) {
            tab.manager->writeInput("\x03");
            appendPowerShellOutput("\n[Execution stopped]\n", RGB(255, 255, 0));
            return;
        }
    }
    if (m_dedicatedPowerShellTerminal && m_powerShellSessionActive) {
        m_dedicatedPowerShellTerminal->writeInput("\x03");
        appendPowerShellOutput("\n[Execution stopped]\n", RGB(255, 255, 0));
    }
}

void Win32IDE::clearPowerShellConsole() {
    if (m_hwndPowerShellOutput) {
        SetWindowTextW(m_hwndPowerShellOutput, L"");
        appendPowerShellOutput(getPowerShellPrompt(), RGB(0, 255, 0));
    }
}

void Win32IDE::appendPowerShellOutput(const std::string& text, COLORREF color) {
    if (!m_hwndPowerShellOutput) return;

    // Certified path: UTF-8 → MultiByteToWideChar(CP_UTF8) → UTF-16 →
    // Unicode RichEdit EM_REPLACESEL (W). No EM_SETTEXTEX codepage layer.
    const std::wstring wtext = RawrXD::Utf8ToWide(text);
    if (wtext.empty() && !text.empty())
        return; // invalid UTF-8 — fail closed

    const LRESULT len =
        SendMessageW(m_hwndPowerShellOutput, WM_GETTEXTLENGTH, 0, 0);
    SendMessageW(m_hwndPowerShellOutput, EM_SETSEL,
                 static_cast<WPARAM>(len), static_cast<LPARAM>(len));

    CHARFORMAT2W cf{};
    cf.cbSize = sizeof(cf);
    cf.dwMask = CFM_COLOR;
    cf.crTextColor = color;
    SendMessageW(m_hwndPowerShellOutput, EM_SETCHARFORMAT, SCF_SELECTION,
                 reinterpret_cast<LPARAM>(&cf));

    SendMessageW(m_hwndPowerShellOutput, EM_REPLACESEL, FALSE,
                 reinterpret_cast<LPARAM>(wtext.c_str()));

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
    // MessageBox only — cannot reach main-status SB_GETTEXT.
    RawrXD::CommandTelemetry::CmdDiagBreadcrumb(
        -1, "showPowerShellHistory_ENTER_NO_MAIN_SB_GETTEXT");
    if (m_powerShellCommandHistory.empty()) {
        MessageBoxA(m_hwndMain, "No command history", "PowerShell History", MB_OK | MB_ICONINFORMATION);
        RawrXD::CommandTelemetry::CmdDiagBreadcrumb(
            -1, "showPowerShellHistory_EXIT_EMPTY");
        return;
    }
    
    std::string history;
    for (size_t i = 0; i < m_powerShellCommandHistory.size(); i++) {
        history += std::to_string(i + 1) + ": " + m_powerShellCommandHistory[i] + "\n";
    }
    
    MessageBoxA(m_hwndMain, history.c_str(), "PowerShell Command History", MB_OK | MB_ICONINFORMATION);
    RawrXD::CommandTelemetry::CmdDiagBreadcrumb(
        -1, "showPowerShellHistory_EXIT_SHOWN");
}

// ============================================================================
// POWERSHELL SESSION MANAGEMENT
// ============================================================================

void Win32IDE::startPowerShellSession() {
    if (m_powerShellSessionActive) {
        return;
    }
    
    // stop() nulls callbacks to avoid use-after-free; rebind on a fresh manager.
    if (!m_dedicatedPowerShellTerminal || !m_dedicatedPowerShellTerminal->onOutput)
        initializePowerShellPanel();
    
    bool started = m_dedicatedPowerShellTerminal->start(Win32TerminalManager::PowerShell);
    
    if (started) {
        m_powerShellSessionActive = true;
        appendPowerShellOutput("[PowerShell session started]\n", RGB(0, 255, 0));
        m_dedicatedPowerShellTerminal->writeInput(
            "Write-Output ('RAWRXD_PS_META|' + $PSVersionTable.PSVersion.ToString()"
            " + '|' + [string]$PSVersionTable.PSEdition"
            " + '|' + [string](Get-ExecutionPolicy))\r\n");
    } else {
        m_psState.version = "start failed";
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
    
    status += " | ";
    status += m_psState.version.empty() ? "pending" : m_psState.version;
    
    const std::wstring wstatus = RawrXD::Utf8ToWide(status);
    SetWindowTextW(m_hwndPowerShellStatusBar, wstatus.c_str());
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

// quickLoadGGUFModel() is now implemented in Win32IDE.cpp with full model source
// resolver support (HuggingFace, Ollama blobs, HTTP URLs, local files).

void Win32IDE::quickInference() {
    // Simple dialog for inference
    char prompt[1024] = "";
    
    if (MessageBoxA(m_hwndMain, "Enter your prompt in the PowerShell console using:\nInvoke-PoshLLMInference -Prompt 'your prompt' -MaxTokens 100",
        "Quick Inference", MB_OKCANCEL | MB_ICONINFORMATION) == IDOK) {
        
        // Focus the input
        SetFocus(m_hwndPowerShellInput);
        SetWindowTextA(m_hwndPowerShellInput, "Invoke-PoshLLMInference -Prompt '' -MaxTokens 100");
        
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
    Win32IDE* ide = (Win32IDE*)GetPropA(hwnd, "IDE_PTR");
    
    switch (uMsg) {
        case WM_COMMAND: {
            int id = LOWORD(wParam);
            
            switch (id) {
                case IDC_PS_BTN_EXECUTE:
                    if (ide) ide->executePowerShellInput();
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
    
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

LRESULT CALLBACK Win32IDE::PowerShellInputProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    Win32IDE* ide = (Win32IDE*)GetPropA(hwnd, "IDE_PTR");
    WNDPROC oldProc = (WNDPROC)GetPropA(hwnd, "OLDPROC");
    
    switch (uMsg) {
        case WM_KEYDOWN: {
            switch (wParam) {
                case VK_RETURN:
                    // Execute command on Enter
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
    }
    
    return CallWindowProc(oldProc, hwnd, uMsg, wParam, lParam);
}

void Win32IDE::runUiEncodingProbe()
{
    static constexpr const char* kProbe =
        "ENCODING_PROBE: ASCII abc XYZ 123 | caf\xC3\xA9 | \xCE\xBB | "
        "\xE4\xB8\xAD\xE6\x96\x87 | \xE2\x9C\x93";

    // --- Boundary A: UTF-8 source → UTF-16 ---
    const std::wstring wProbe = RawrXD::Utf8ToWide(std::string(kProbe));
    const bool convLatin = wProbe.find(L'\x00E9') != std::wstring::npos;       // é
    const bool convGreek = wProbe.find(L'\x03BB') != std::wstring::npos;       // λ
    const bool convCjk = wProbe.find(L"\x4E2D\x6587") != std::wstring::npos;  // 中文
    const bool convSym = wProbe.find(L'\x2713') != std::wstring::npos;         // ✓

    appendPowerShellOutput("\n", RGB(200, 200, 200));
    appendPowerShellOutput(std::string(kProbe) + "\n", RGB(0, 255, 255));

    // Ensure status bar exists (panel may be created before enhanced status bar).
    if ((!m_hwndStatusBar || !IsWindow(m_hwndStatusBar)) && m_hwndMain)
        createEnhancedStatusBar(m_hwndMain);

    wchar_t prevStatus[512] = {};
    const bool statusExists =
        m_hwndStatusBar != nullptr && IsWindow(m_hwndStatusBar);
    const bool statusUnicode =
        statusExists && IsWindowUnicode(m_hwndStatusBar) != FALSE;

    if (statusExists) {
        if (statusUnicode) {
            RawrXD::CommandTelemetry::CmdDiagIdeGetTextScope scope(
                "runUiEncodingProbe_SAVE_PREV", m_hwndStatusBar, 0, prevStatus);
            SendMessageW(m_hwndStatusBar, SB_GETTEXTW, 0, (LPARAM)prevStatus);
        }
        RawrXD::StatusBarSetTextUtf8(m_hwndStatusBar, 0, kProbe);
    }

    bool asciiOk = false;
    bool latinOk = false;
    bool cjkOk = false;
    bool symbolOk = false;
    bool statusAsciiOk = false;
    bool statusUtf8Ok = false;
    bool noQuestion = true;
    std::wstring gotRich;

    // --- Boundary B: RichEdit readback (UTF-16) via EM_GETTEXTEX ---
    if (m_hwndPowerShellOutput) {
        GETTEXTLENGTHEX gtl{};
        gtl.flags = GTL_DEFAULT;
        gtl.codepage = kRichEditUtf16CodePage;
        const LONG n = (LONG)SendMessageW(m_hwndPowerShellOutput, EM_GETTEXTLENGTHEX,
                                          (WPARAM)&gtl, 0);
        if (n > 0) {
            gotRich.assign(static_cast<size_t>(n) + 1, L'\0');
            GETTEXTEX gt{};
            gt.cb = static_cast<DWORD>((n + 1) * sizeof(wchar_t));
            gt.flags = GT_DEFAULT;
            gt.codepage = kRichEditUtf16CodePage;
            const LRESULT got = SendMessageW(m_hwndPowerShellOutput, EM_GETTEXTEX,
                                             (WPARAM)&gt, (LPARAM)gotRich.data());
            if (got > 0)
                gotRich.resize(static_cast<size_t>(got));
            else {
                // Fallback only for length; still Unicode API
                GetWindowTextW(m_hwndPowerShellOutput, gotRich.data(), n + 1);
                gotRich.resize(wcslen(gotRich.c_str()));
            }
            asciiOk = gotRich.find(L"ASCII abc XYZ 123") != std::wstring::npos;
            latinOk = gotRich.find(L'\x00E9') != std::wstring::npos;
            cjkOk = gotRich.find(L"\x4E2D\x6587") != std::wstring::npos;
            symbolOk = gotRich.find(L'\x2713') != std::wstring::npos;
            noQuestion = gotRich.find(L'?') == std::wstring::npos ||
                         gotRich.find(L"ASCII abc XYZ 123") != std::wstring::npos;
            // '?' may appear in other UI text; require no '?' in the probe slice
            const size_t probeAt = gotRich.find(L"ENCODING_PROBE:");
            if (probeAt != std::wstring::npos) {
                const size_t sliceEnd = gotRich.find(L'\n', probeAt);
                const std::wstring slice = gotRich.substr(
                    probeAt, sliceEnd == std::wstring::npos ? std::wstring::npos
                                                            : sliceEnd - probeAt);
                noQuestion = slice.find(L'?') == std::wstring::npos;
            }
        }
    }

    if (statusExists) {
        std::wstring got;
        if (statusUnicode) {
            wchar_t buf[512] = {};
            {
                RawrXD::CommandTelemetry::CmdDiagIdeGetTextScope scope(
                    "runUiEncodingProbe", m_hwndStatusBar, 0, buf);
                SendMessageW(m_hwndStatusBar, SB_GETTEXTW, 0, (LPARAM)buf);
            }
            got = buf;
        } else {
            char abuf[512] = {};
            {
                RawrXD::CommandTelemetry::CmdDiagIdeGetTextScope scope(
                    "runUiEncodingProbe_A", m_hwndStatusBar, 0, abuf);
                SendMessageA(m_hwndStatusBar, SB_GETTEXTA, 0, (LPARAM)abuf);
            }
            const int n = MultiByteToWideChar(CP_ACP, 0, abuf, -1, nullptr, 0);
            if (n > 0) {
                got.assign(static_cast<size_t>(n), L'\0');
                MultiByteToWideChar(CP_ACP, 0, abuf, -1, got.data(), n);
                if (!got.empty() && got.back() == L'\0')
                    got.pop_back();
            }
        }
        statusAsciiOk = got.find(L"ASCII abc XYZ 123") != std::wstring::npos;
        statusUtf8Ok = got.find(L'\x00E9') != std::wstring::npos;
        if (prevStatus[0] && statusUnicode)
            SendMessageW(m_hwndStatusBar, SB_SETTEXTW, 0, (LPARAM)prevStatus);
        else if (statusUnicode)
            SendMessageW(m_hwndStatusBar, SB_SETTEXTW, 0, (LPARAM)L"Ready");
        else
            SendMessageA(m_hwndStatusBar, SB_SETTEXTA, 0, (LPARAM)"Ready");
    }

    // Honest 002 gates: LATIN is U+00E9, not aliased CJK.
    // Status bar may be ANSI under /MANIFEST:NO (comctl v5); ACP branch still
    // must carry ASCII + Latin é for STATUSBAR_* on Western code pages.
    const bool utf8ProbeOk = latinOk && cjkOk;
    const bool statusOk = statusExists && statusAsciiOk && statusUtf8Ok;
    const bool all = asciiOk && latinOk && cjkOk && symbolOk && statusOk &&
                     noQuestion && convLatin && convCjk;

    char line[384];
    sprintf_s(line,
              "[P1_UI_ENCODING_002] ASCII=%s LATIN=%s CJK=%s SYM=%s "
              "STATUS_ASCII=%s STATUS_UTF8=%s NO_Q=%s CONV=%s/%s => %s\n",
              asciiOk ? "PASS" : "FAIL",
              latinOk ? "PASS" : "FAIL",
              cjkOk ? "PASS" : "FAIL",
              symbolOk ? "PASS" : "FAIL",
              statusAsciiOk ? "PASS" : "FAIL",
              statusUtf8Ok ? "PASS" : "FAIL",
              noQuestion ? "PASS" : "FAIL",
              convLatin ? "L" : "l",
              convCjk ? "C" : "c",
              all ? "PASS" : "FAIL");
    appendPowerShellOutput(line, all ? RGB(0, 255, 0) : RGB(255, 80, 80));
    appendToOutput(line, "System", all ? OutputSeverity::Info : OutputSeverity::Warning);

    FILE* f = nullptr;
    if (fopen_s(&f, "P1_UI_ENCODING_IDE_PROBE.txt", "wb") == 0 && f) {
        std::fprintf(f, "RAWRXD_P1_UI_ENCODING_IDE=%s\n", all ? "PASS" : "FAIL");
        std::fprintf(f, "ASCII_PROBE_EXACT=%s\n", asciiOk ? "PASS" : "FAIL");
        std::fprintf(f, "UTF8_LATIN_EXACT=%s\n", latinOk ? "PASS" : "FAIL");
        std::fprintf(f, "UTF8_CJK_EXACT=%s\n", cjkOk ? "PASS" : "FAIL");
        std::fprintf(f, "UTF8_SYMBOL_EXACT=%s\n", symbolOk ? "PASS" : "FAIL");
        std::fprintf(f, "UTF8_PROBE_EXACT=%s\n", utf8ProbeOk ? "PASS" : "FAIL");
        std::fprintf(f, "STATUSBAR_EXISTS_AT_PROBE=%s\n",
                     statusExists ? "PASS" : "FAIL");
        std::fprintf(f, "STATUSBAR_IS_UNICODE=%s\n",
                     statusExists ? (statusUnicode ? "YES" : "NO")
                                  : "NOT_TESTED");
        std::fprintf(f, "STATUSBAR_ASCII_EXACT=%s\n",
                     statusExists ? (statusAsciiOk ? "PASS" : "FAIL") : "NOT_TESTED");
        std::fprintf(f, "STATUSBAR_UTF8_EXACT=%s\n",
                     statusExists ? (statusUtf8Ok ? "PASS" : "FAIL") : "NOT_TESTED");
        std::fprintf(f, "STATUSBAR_EXACT=%s\n", statusOk ? "PASS" : "FAIL");
        std::fprintf(f, "NO_REPLACEMENT_QUESTION=%s\n", noQuestion ? "PASS" : "FAIL");
        std::fprintf(f, "STATUSBAR_HWND=%p\n", (void*)m_hwndStatusBar);
        std::fprintf(f, "CONV_LATIN_BEFORE_UI=%s\n", convLatin ? "PASS" : "FAIL");
        std::fprintf(f, "CONV_CJK_BEFORE_UI=%s\n", convCjk ? "PASS" : "FAIL");
        std::fprintf(f, "CONV_GREEK_BEFORE_UI=%s\n", convGreek ? "PASS" : "FAIL");
        std::fprintf(f, "CONV_SYMBOL_BEFORE_UI=%s\n", convSym ? "PASS" : "FAIL");
        std::fclose(f);
    }

    // Transition dump: existence before Unicode/readback classification
    if (fopen_s(&f, "P1_UI_ENCODING_TRANSITION.txt", "wb") == 0 && f) {
        std::fprintf(f, "IN_UTF8_LEN=%zu\n", strlen(kProbe));
        std::fprintf(f, "AFTER_UTF8_TO_WIDE_LEN=%zu\n", wProbe.size());
        std::fprintf(f, "AFTER_UTF8_TO_WIDE_HAS_LATIN_EACUTE=%s\n",
                     convLatin ? "PASS" : "FAIL");
        std::fprintf(f, "AFTER_RICHEDIT_HAS_LATIN_EACUTE=%s\n",
                     latinOk ? "PASS" : "FAIL");
        std::fprintf(f, "STATUSBAR_EXISTS_AT_PROBE=%s\n",
                     statusExists ? "PASS" : "FAIL");
        std::fprintf(f, "STATUSBAR_IS_UNICODE=%s\n",
                     statusExists ? (statusUnicode ? "YES" : "NO")
                                  : "NOT_TESTED");
        std::fprintf(f, "AFTER_STATUSBAR_HAS_LATIN_EACUTE=%s\n",
                     statusExists ? (statusUtf8Ok ? "PASS" : "FAIL")
                                  : "NOT_TESTED");
        const char* first = "none";
        if (!convLatin) first = "UTF8_TO_WIDE";
        else if (!latinOk) first = "RICHEDIT_READBACK";
        else if (!statusExists) first = "STATUSBAR_EXISTS_AT_PROBE";
        else if (!statusUtf8Ok) first = "STATUSBAR_READBACK";
        else if (!statusAsciiOk) first = "STATUSBAR_ASCII";
        std::fprintf(f, "FIRST_FALSE_BYTE_TRANSITION=%s\n", first);
        // Observability only — not a hard fail once ACP branch carries Latin.
        std::fprintf(f, "STATUSBAR_UNICODE_HWND=%s\n",
                     statusExists ? (statusUnicode ? "YES" : "NO") : "NOT_TESTED");
        std::fclose(f);
    }
}

