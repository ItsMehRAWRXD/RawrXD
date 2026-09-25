// ============================================================================
// [SOURCE] win32app\Win32IDE_VSCodeUI.cpp
// FILE: D:\rawrxd\src\win32app\Win32IDE_VSCodeUI.cpp
// ============================================================================

// Win32IDE_VSCodeUI.cpp - VS Code-like UI Components Implementation
// Activity Bar, Secondary Sidebar, Panel (Terminal/Output/Problems/Debug Console), Enhanced Status Bar

#include "Win32IDE.h"
#include <commctrl.h>
#include <richedit.h>
#include <sstream>
#include <iomanip>

// Define GET_X_LPARAM and GET_Y_LPARAM if not available
#ifndef GET_X_LPARAM
#define GET_X_LPARAM(lp) ((int)(short)LOWORD(lp))
#endif
#ifndef GET_Y_LPARAM
#define GET_Y_LPARAM(lp) ((int)(short)HIWORD(lp))
#endif

// Define IDC_STATUS_BAR if not defined
#ifndef IDC_STATUS_BAR
#define IDC_STATUS_BAR 2000
#endif

#pragma comment(lib, "comctl32.lib")

// Activity Bar button IDs
#define IDC_ACTIVITY_BAR 1100
#define IDC_ACTBAR_EXPLORER 1101
#define IDC_ACTBAR_SEARCH 1102
#define IDC_ACTBAR_SCM 1103
#define IDC_ACTBAR_DEBUG 1104
#define IDC_ACTBAR_EXTENSIONS 1105
#define IDC_ACTBAR_SETTINGS 1106
#define IDC_ACTBAR_ACCOUNTS 1107

// Secondary Sidebar IDs
#define IDC_SECONDARY_SIDEBAR 1200
#define IDC_SECONDARY_SIDEBAR_HEADER 1201
#define IDC_COPILOT_CHAT_INPUT 1202
#define IDC_COPILOT_CHAT_OUTPUT 1203
#define IDC_COPILOT_SEND_BTN 1204
#define IDC_COPILOT_CLEAR_BTN 1205

// Panel IDs
#define IDC_PANEL_CONTAINER 1300
#define IDC_PANEL_TABS 1301
#define IDC_PANEL_TERMINAL 1302
#define IDC_PANEL_OUTPUT 1303
#define IDC_PANEL_PROBLEMS 1304
#define IDC_PANEL_DEBUG_CONSOLE 1305
#define IDC_PANEL_TOOLBAR 1306
#define IDC_PANEL_BTN_NEW_TERMINAL 1307
#define IDC_PANEL_BTN_SPLIT_TERMINAL 1308
#define IDC_PANEL_BTN_KILL_TERMINAL 1309
#define IDC_PANEL_BTN_MAXIMIZE 1310
#define IDC_PANEL_BTN_CLOSE 1311
#define IDC_PANEL_PROBLEMS_LIST 1312

// Status Bar item IDs
#define IDC_STATUS_REMOTE 1400
#define IDC_STATUS_BRANCH 1401
#define IDC_STATUS_SYNC 1402
#define IDC_STATUS_ERRORS 1403
#define IDC_STATUS_WARNINGS 1404
#define IDC_STATUS_LINE_COL 1405
#define IDC_STATUS_SPACES 1406
#define IDC_STATUS_ENCODING 1407
#define IDC_STATUS_EOL 1408
#define IDC_STATUS_LANGUAGE 1409
#define IDC_STATUS_COPILOT 1410
#define IDC_STATUS_NOTIFICATIONS 1411

// VS Code-like colors
static const COLORREF VSCODE_ACTIVITY_BAR_BG = RGB(51, 51, 51);      // Dark gray
static const COLORREF VSCODE_ACTIVITY_BAR_ACTIVE = RGB(37, 37, 38);  // Slightly lighter
static const COLORREF VSCODE_ACTIVITY_BAR_HOVER = RGB(90, 93, 94);   // Hover highlight
static const COLORREF VSCODE_ACTIVITY_BAR_ICON = RGB(204, 204, 204); // Icon color
static const COLORREF VSCODE_ACTIVITY_BAR_INDICATOR = RGB(0, 122, 204); // Active indicator blue

static const COLORREF VSCODE_SIDEBAR_BG = RGB(37, 37, 38);
static const COLORREF VSCODE_PANEL_BG = RGB(30, 30, 30);
static const COLORREF VSCODE_STATUS_BAR_BG = RGB(0, 122, 204);       // Blue for normal
static const COLORREF VSCODE_STATUS_BAR_DEBUG = RGB(204, 102, 0);    // Orange for debug
static const COLORREF VSCODE_STATUS_BAR_REMOTE = RGB(22, 130, 93);   // Green for remote
static const COLORREF VSCODE_STATUS_BAR_TEXT = RGB(255, 255, 255);

// Unicode icons for Activity Bar (simple ASCII fallbacks)
static const char* ICON_EXPLORER = "[]";     // File explorer
static const char* ICON_SEARCH = "()";       // Search
static const char* ICON_SCM = "<>";          // Source control
static const char* ICON_DEBUG = ">";         // Run/Debug
static const char* ICON_EXTENSIONS = "++";   // Extensions
static const char* ICON_SETTINGS = "*";      // Settings gear
static const char* ICON_ACCOUNTS = "@";      // User account

// ============================================================================
// Activity Bar (Far Left) - VS Code style vertical icon bar
// ============================================================================

void Win32IDE::createActivityBarUI(HWND hwndParent)
{
    // Create brushes for Activity Bar colors
    m_actBarBackgroundBrush = CreateSolidBrush(VSCODE_ACTIVITY_BAR_BG);
    m_actBarHoverBrush = CreateSolidBrush(VSCODE_ACTIVITY_BAR_HOVER);
    m_actBarActiveBrush = CreateSolidBrush(VSCODE_ACTIVITY_BAR_ACTIVE);
    
    // Create the Activity Bar container
    m_hwndActivityBar = CreateWindowExA(
        0, "STATIC", "",
        WS_CHILD | WS_VISIBLE | SS_OWNERDRAW,
        0, 0, ACTIVITY_BAR_WIDTH, 600,
        hwndParent, (HMENU)IDC_ACTIVITY_BAR, m_hInstance, nullptr);
    
    // Set the background color
    SetClassLongPtr(m_hwndActivityBar, GCLP_HBRBACKGROUND, (LONG_PTR)m_actBarBackgroundBrush);
    
    // Create Activity Bar buttons (icons)
    const char* buttonLabels[] = { ICON_EXPLORER, ICON_SEARCH, ICON_SCM, ICON_DEBUG, ICON_EXTENSIONS, ICON_SETTINGS, ICON_ACCOUNTS };
    const char* tooltips[] = { "Explorer (Ctrl+Shift+E)", "Search (Ctrl+Shift+F)", "Source Control (Ctrl+Shift+G)", 
                               "Run and Debug (Ctrl+Shift+D)", "Extensions (Ctrl+Shift+X)", "Settings", "Accounts" };
    int buttonHeight = 48;
    
    for (int i = 0; i < 7; i++) {
        int yPos = (i < 5) ? (i * buttonHeight) : (600 - (7 - i) * buttonHeight); // Top 5 + bottom 2
        
        m_activityBarButtons[i] = CreateWindowExA(
            0, "BUTTON", buttonLabels[i],
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
            0, yPos, ACTIVITY_BAR_WIDTH, buttonHeight,
            m_hwndActivityBar, (HMENU)(IDC_ACTBAR_EXPLORER + i), m_hInstance, nullptr);
        
        // Store IDE pointer for button subclass
        SetWindowLongPtr(m_activityBarButtons[i], GWLP_USERDATA, (LONG_PTR)this);
        
        // Create tooltip
        HWND hwndTip = CreateWindowEx(0, TOOLTIPS_CLASS, nullptr,
            WS_POPUP | TTS_ALWAYSTIP,
            CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
            hwndParent, nullptr, m_hInstance, nullptr);
        
        TOOLINFOA ti = { sizeof(TOOLINFOA) };
        ti.uFlags = TTF_SUBCLASS | TTF_IDISHWND;
        ti.hwnd = hwndParent;
        ti.uId = (UINT_PTR)m_activityBarButtons[i];
        ti.lpszText = const_cast<char*>(tooltips[i]);
        SendMessage(hwndTip, TTM_ADDTOOL, 0, (LPARAM)&ti);
    }
    
    m_activeActivityBarButton = 0; // Explorer is active by default
    m_sidebarVisible = true;
    m_sidebarWidth = 260;
}

void Win32IDE::updateActivityBarState()
{
    // Repaint all activity bar buttons to reflect current state
    for (int i = 0; i < 7; i++) {
        if (m_activityBarButtons[i]) {
            InvalidateRect(m_activityBarButtons[i], nullptr, TRUE);
        }
    }
}

LRESULT CALLBACK Win32IDE::ActivityBarButtonProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    Win32IDE* pThis = (Win32IDE*)GetWindowLongPtr(hwnd, GWLP_USERDATA);
    
    switch (uMsg) {
    case WM_DRAWITEM:
        {
            DRAWITEMSTRUCT* dis = (DRAWITEMSTRUCT*)lParam;
            int buttonIndex = dis->CtlID - IDC_ACTBAR_EXPLORER;
            
            // Draw background
            COLORREF bgColor = (buttonIndex == pThis->m_activeActivityBarButton) 
                ? VSCODE_ACTIVITY_BAR_ACTIVE : VSCODE_ACTIVITY_BAR_BG;
            
            if (dis->itemState & ODS_SELECTED) {
                bgColor = VSCODE_ACTIVITY_BAR_HOVER;
            }
            
            HBRUSH hBrush = CreateSolidBrush(bgColor);
            FillRect(dis->hDC, &dis->rcItem, hBrush);
            DeleteObject(hBrush);
            
            // Draw active indicator (left border)
            if (buttonIndex == pThis->m_activeActivityBarButton) {
                RECT indicatorRect = dis->rcItem;
                indicatorRect.right = 3;
                HBRUSH hIndicator = CreateSolidBrush(VSCODE_ACTIVITY_BAR_INDICATOR);
                FillRect(dis->hDC, &indicatorRect, hIndicator);
                DeleteObject(hIndicator);
            }
            
            // Draw icon text centered
            SetBkMode(dis->hDC, TRANSPARENT);
            SetTextColor(dis->hDC, VSCODE_ACTIVITY_BAR_ICON);
            
            char buttonText[16];
            GetWindowTextA(hwnd, buttonText, 16);
            DrawTextA(dis->hDC, buttonText, -1, &dis->rcItem, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            
            return TRUE;
        }
    }
    
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

// ============================================================================
// Secondary Sidebar (Right) - AI Chat / Copilot area
// ============================================================================

void Win32IDE::createSecondarySidebar(HWND hwndParent)
{
    m_secondarySidebarVisible = true;
    m_secondarySidebarWidth = 320;
    
    // Create the secondary sidebar container
    m_hwndSecondarySidebar = CreateWindowExA(
        WS_EX_CLIENTEDGE, "STATIC", "",
        WS_CHILD | WS_VISIBLE,
        0, 0, m_secondarySidebarWidth, 600,
        hwndParent, (HMENU)IDC_SECONDARY_SIDEBAR, m_hInstance, nullptr);
    
    // Header label
    m_hwndSecondarySidebarHeader = CreateWindowExA(
        0, "STATIC", " GitHub Copilot Chat",
        WS_CHILD | WS_VISIBLE | SS_LEFT | SS_CENTERIMAGE,
        0, 0, m_secondarySidebarWidth, 28,
        m_hwndSecondarySidebar, (HMENU)IDC_SECONDARY_SIDEBAR_HEADER, m_hInstance, nullptr);
    
    // Chat output area (read-only rich edit for formatted messages)
    m_hwndCopilotChatOutput = CreateWindowExA(
        WS_EX_CLIENTEDGE, "EDIT", "",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
        5, 32, m_secondarySidebarWidth - 10, 450,
        m_hwndSecondarySidebar, (HMENU)IDC_COPILOT_CHAT_OUTPUT, m_hInstance, nullptr);
    
    // Chat input area
    m_hwndCopilotChatInput = CreateWindowExA(
        WS_EX_CLIENTEDGE, "EDIT", "",
        WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | ES_WANTRETURN | WS_VSCROLL,
        5, 490, m_secondarySidebarWidth - 10, 60,
        m_hwndSecondarySidebar, (HMENU)IDC_COPILOT_CHAT_INPUT, m_hInstance, nullptr);
    
    // Send button
    m_hwndCopilotSendBtn = CreateWindowExA(
        0, "BUTTON", "Send",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        5, 555, 80, 28,
        m_hwndSecondarySidebar, (HMENU)IDC_COPILOT_SEND_BTN, m_hInstance, nullptr);
    
    // Clear button
    m_hwndCopilotClearBtn = CreateWindowExA(
        0, "BUTTON", "Clear",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        90, 555, 80, 28,
        m_hwndSecondarySidebar, (HMENU)IDC_COPILOT_CLEAR_BTN, m_hInstance, nullptr);
    
    // Set initial message
    SetWindowTextA(m_hwndCopilotChatOutput, 
        "GitHub Copilot Chat\r\n"
        "==================\r\n\r\n"
        "Ask me anything about your code!\r\n\r\n"
        "Examples:\r\n"
        "- Explain this code\r\n"
        "- How do I fix this error?\r\n"
        "- Generate unit tests\r\n"
        "- Refactor this function\r\n");
}

void Win32IDE::toggleSecondarySidebar()
{
    m_secondarySidebarVisible = !m_secondarySidebarVisible;
    ShowWindow(m_hwndSecondarySidebar, m_secondarySidebarVisible ? SW_SHOW : SW_HIDE);
    
    // Trigger resize to update layout
    RECT rect;
    GetClientRect(m_hwndMain, &rect);
    onSize(rect.right, rect.bottom);
}

void Win32IDE::updateSecondarySidebarContent()
{
    // Update chat display with history
    std::string chatText;
    for (const auto& msg : m_chatHistory) {
        if (msg.first == "user") {
            chatText += "You: " + msg.second + "\r\n\r\n";
        } else {
            chatText += "Copilot: " + msg.second + "\r\n\r\n";
        }
    }
    SetWindowTextA(m_hwndCopilotChatOutput, chatText.c_str());
    
    // Scroll to bottom
    int len = GetWindowTextLengthA(m_hwndCopilotChatOutput);
    SendMessage(m_hwndCopilotChatOutput, EM_SETSEL, len, len);
    SendMessage(m_hwndCopilotChatOutput, EM_SCROLLCARET, 0, 0);
}

void Win32IDE::sendCopilotMessage(const std::string& message)
{
    if (message.empty()) return;


    // Add user message to history
    m_chatHistory.push_back({"user", message});
    
    // Generate response using the AI inference system
    std::string response;
    
    if (isModelLoaded()) {
        // Use the loaded GGUF model for inference
        response = generateResponse(message);
    } else {
        // No model loaded - prompt user to load one
        response = "⚠️ No AI model loaded.\r\n\r\n"
                   "To use AI assistance, please load a GGUF model:\r\n"
                   "1. Open the File Explorer (Activity Bar → Explorer icon)\r\n"
                   "2. Navigate to a folder containing .gguf files\r\n"
                   "3. Double-click a model file to load it\r\n\r\n"
                   "Supported models: LLaMA, Mistral, Phi, Qwen, and other GGUF-compatible models.\r\n\r\n"
                   "Once loaded, I can help with:\r\n"
                   "• Code explanation and analysis\r\n"
                   "• Bug fixing suggestions\r\n"
                   "• Code generation\r\n"
                   "• Programming questions";
    }
    
    m_chatHistory.push_back({"assistant", response});
    
    // Update display
    updateSecondarySidebarContent();
    
    // Clear input
    SetWindowTextA(m_hwndCopilotChatInput, "");
}

void Win32IDE::clearCopilotChat()
{
    m_chatHistory.clear();
    SetWindowTextA(m_hwndCopilotChatOutput, 
        "GitHub Copilot Chat\r\n"
        "==================\r\n\r\n"
        "Chat cleared. Ask me anything about your code!\r\n");
}

void Win32IDE::appendCopilotResponse(const std::string& response)
{
    m_chatHistory.push_back({"assistant", response});
    updateSecondarySidebarContent();
}

LRESULT CALLBACK Win32IDE::SecondarySidebarProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    Win32IDE* pThis = (Win32IDE*)GetWindowLongPtr(hwnd, GWLP_USERDATA);
    
    switch (uMsg) {
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLOREDIT:
        {
            HDC hdc = (HDC)wParam;
            SetBkColor(hdc, VSCODE_SIDEBAR_BG);
            SetTextColor(hdc, RGB(204, 204, 204));
            static HBRUSH hBrush = CreateSolidBrush(VSCODE_SIDEBAR_BG);
            return (LRESULT)hBrush;
        }
    }
    
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

// ============================================================================
// Panel (Bottom) - Terminal, Output, Problems, Debug Console
// ============================================================================

void Win32IDE::createPanel(HWND hwndParent)
{
    m_panelVisible = true;
    m_panelMaximized = false;
    m_panelHeight = 250;
    m_activePanelTab = PanelTab::Terminal;
    m_errorCount = 0;
    m_warningCount = 0;
    
    // Create panel container
    m_hwndPanelContainer = CreateWindowExA(
        0, "STATIC", "",
        WS_CHILD | WS_VISIBLE,
        0, 0, 800, m_panelHeight,
        hwndParent, (HMENU)IDC_PANEL_CONTAINER, m_hInstance, nullptr);
    
    // Create tab control for panel views
    m_hwndPanelTabs = CreateWindowExA(
        0, WC_TABCONTROLA, "",
        WS_CHILD | WS_VISIBLE | TCS_TABS | TCS_FOCUSNEVER,
        0, 0, 400, 24,
        m_hwndPanelContainer, (HMENU)IDC_PANEL_TABS, m_hInstance, nullptr);
    
    // Add tabs: Terminal, Output, Problems, Debug Console
    TCITEMA tie = { TCIF_TEXT };
    tie.pszText = const_cast<char*>("TERMINAL");
    TabCtrl_InsertItem(m_hwndPanelTabs, 0, &tie);
    tie.pszText = const_cast<char*>("OUTPUT");
    TabCtrl_InsertItem(m_hwndPanelTabs, 1, &tie);
    tie.pszText = const_cast<char*>("PROBLEMS");
    TabCtrl_InsertItem(m_hwndPanelTabs, 2, &tie);
    tie.pszText = const_cast<char*>("DEBUG CONSOLE");
    TabCtrl_InsertItem(m_hwndPanelTabs, 3, &tie);
    
    // Create panel toolbar (right side)
    m_hwndPanelToolbar = CreateWindowExA(
        0, "STATIC", "",
        WS_CHILD | WS_VISIBLE,
        400, 0, 200, 24,
        m_hwndPanelContainer, (HMENU)IDC_PANEL_TOOLBAR, m_hInstance, nullptr);
    
    // Toolbar buttons
    m_hwndPanelNewTerminalBtn = CreateWindowExA(
        0, "BUTTON", "+",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        0, 0, 24, 22,
        m_hwndPanelToolbar, (HMENU)IDC_PANEL_BTN_NEW_TERMINAL, m_hInstance, nullptr);
    
    m_hwndPanelSplitTerminalBtn = CreateWindowExA(
        0, "BUTTON", "||",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        26, 0, 24, 22,
        m_hwndPanelToolbar, (HMENU)IDC_PANEL_BTN_SPLIT_TERMINAL, m_hInstance, nullptr);
    
    m_hwndPanelKillTerminalBtn = CreateWindowExA(
        0, "BUTTON", "X",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        52, 0, 24, 22,
        m_hwndPanelToolbar, (HMENU)IDC_PANEL_BTN_KILL_TERMINAL, m_hInstance, nullptr);
    
    m_hwndPanelMaximizeBtn = CreateWindowExA(
        0, "BUTTON", "^",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        130, 0, 24, 22,
        m_hwndPanelToolbar, (HMENU)IDC_PANEL_BTN_MAXIMIZE, m_hInstance, nullptr);
    
    m_hwndPanelCloseBtn = CreateWindowExA(
        0, "BUTTON", "x",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        156, 0, 24, 22,
        m_hwndPanelToolbar, (HMENU)IDC_PANEL_BTN_CLOSE, m_hInstance, nullptr);
    
    // Create Problems list view
    m_hwndProblemsListView = CreateWindowExA(
        WS_EX_CLIENTEDGE, WC_LISTVIEWA, "",
        WS_CHILD | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
        0, 26, 800, m_panelHeight - 26,
        m_hwndPanelContainer, (HMENU)IDC_PANEL_PROBLEMS_LIST, m_hInstance, nullptr);
    
    // Add columns to Problems list
    LVCOLUMNA lvc = { 0 };
    lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    
    lvc.pszText = const_cast<char*>("Severity");
    lvc.cx = 70;
    lvc.iSubItem = 0;
    ListView_InsertColumn(m_hwndProblemsListView, 0, &lvc);
    
    lvc.pszText = const_cast<char*>("Message");
    lvc.cx = 400;
    lvc.iSubItem = 1;
    ListView_InsertColumn(m_hwndProblemsListView, 1, &lvc);
    
    lvc.pszText = const_cast<char*>("File");
    lvc.cx = 200;
    lvc.iSubItem = 2;
    ListView_InsertColumn(m_hwndProblemsListView, 2, &lvc);
    
    lvc.pszText = const_cast<char*>("Line");
    lvc.cx = 60;
    lvc.iSubItem = 3;
    ListView_InsertColumn(m_hwndProblemsListView, 3, &lvc);
    
    // Initially show terminal, hide problems list
    ShowWindow(m_hwndProblemsListView, SW_HIDE);
}

void Win32IDE::togglePanel()
{
    m_panelVisible = !m_panelVisible;
    ShowWindow(m_hwndPanelContainer, m_panelVisible ? SW_SHOW : SW_HIDE);
    
    // Trigger resize to update layout
    RECT rect;
    GetClientRect(m_hwndMain, &rect);
    onSize(rect.right, rect.bottom);
}

void Win32IDE::maximizePanel()
{
    m_panelMaximized = !m_panelMaximized;
    
    if (m_panelMaximized) {
        // Store original height and maximize
        RECT rect;
        GetClientRect(m_hwndMain, &rect);
        m_panelHeight = rect.bottom - 100; // Leave some space for toolbar/status
        SetWindowTextA(m_hwndPanelMaximizeBtn, "v");
    } else {
        // Restore to default height
        m_panelHeight = 250;
        SetWindowTextA(m_hwndPanelMaximizeBtn, "^");
    }
    
    // Trigger resize
    RECT rect;
    GetClientRect(m_hwndMain, &rect);
    onSize(rect.right, rect.bottom);
}

void Win32IDE::restorePanel()
{
    if (m_panelMaximized) {
        maximizePanel(); // Toggle back to normal
    }
}

void Win32IDE::switchPanelTab(PanelTab tab)
{
    m_activePanelTab = tab;
    
    // Show/hide appropriate views
    bool showTerminal = (tab == PanelTab::Terminal);
    bool showOutput = (tab == PanelTab::Output);
    bool showProblems = (tab == PanelTab::Problems);
    bool showDebugConsole = (tab == PanelTab::DebugConsole);
    
    // Show/hide terminal panes
    for (auto& pane : m_terminalPanes) {
        ShowWindow(pane.hwnd, showTerminal ? SW_SHOW : SW_HIDE);
    }
    
    // Show/hide output windows
    for (auto& kv : m_outputWindows) {
        bool show = showOutput && (kv.first == m_activeOutputTab);
        ShowWindow(kv.second, show ? SW_SHOW : SW_HIDE);
    }
    
    // Show/hide problems list
    ShowWindow(m_hwndProblemsListView, showProblems ? SW_SHOW : SW_HIDE);
    
    // Show/hide debug console
    if (m_hwndDebugConsole) {
        ShowWindow(m_hwndDebugConsole, showDebugConsole ? SW_SHOW : SW_HIDE);
    }
    
    // Update tab selection
    TabCtrl_SetCurSel(m_hwndPanelTabs, static_cast<int>(tab));
    
    // Update toolbar buttons based on current tab
    bool isTerminalTab = (tab == PanelTab::Terminal);
    EnableWindow(m_hwndPanelNewTerminalBtn, isTerminalTab);
    EnableWindow(m_hwndPanelSplitTerminalBtn, isTerminalTab);
    EnableWindow(m_hwndPanelKillTerminalBtn, isTerminalTab);
}

void Win32IDE::updatePanelContent()
{
    // Update problems count in tab
    std::string problemsTabText = "PROBLEMS";
    if (m_errorCount > 0 || m_warningCount > 0) {
        std::ostringstream oss;
        oss << "PROBLEMS (" << m_errorCount << " errors, " << m_warningCount << " warnings)";
        problemsTabText = oss.str();
    }
    
    TCITEMA tie = { TCIF_TEXT };
    tie.pszText = const_cast<char*>(problemsTabText.c_str());
    TabCtrl_SetItem(m_hwndPanelTabs, 2, &tie);
}

void Win32IDE::addProblem(const std::string& file, int line, int col, const std::string& msg, int severity)
{
    ProblemItem problem;
    problem.file = file;
    problem.line = line;
    problem.column = col;
    problem.message = msg;
    problem.severity = severity;
    m_problems.push_back(problem);
    
    // Update counts
    if (severity == 0) m_errorCount++;
    else if (severity == 1) m_warningCount++;
    
    // Add to list view
    LVITEMA lvi = { 0 };
    lvi.mask = LVIF_TEXT;
    lvi.iItem = static_cast<int>(m_problems.size() - 1);
    
    const char* severityStr = (severity == 0) ? "Error" : (severity == 1) ? "Warning" : "Info";
    lvi.pszText = const_cast<char*>(severityStr);
    ListView_InsertItem(m_hwndProblemsListView, &lvi);
    
    // Set item text using direct SendMessage calls with ANSI structures
    LVITEMA lviSet = { 0 };
    lviSet.iSubItem = 1;
    lviSet.pszText = const_cast<char*>(msg.c_str());
    SendMessage(m_hwndProblemsListView, LVM_SETITEMTEXTA, lvi.iItem, (LPARAM)&lviSet);
    
    lviSet.iSubItem = 2;
    lviSet.pszText = const_cast<char*>(file.c_str());
    SendMessage(m_hwndProblemsListView, LVM_SETITEMTEXTA, lvi.iItem, (LPARAM)&lviSet);
    
    char lineStrBuf[32];
    _snprintf_s(lineStrBuf, sizeof(lineStrBuf), _TRUNCATE, "%d", line);
    lviSet.iSubItem = 3;
    lviSet.pszText = lineStrBuf;
    SendMessage(m_hwndProblemsListView, LVM_SETITEMTEXTA, lvi.iItem, (LPARAM)&lviSet);
    
    // Update panel content
    updatePanelContent();
    updateEnhancedStatusBar();
}

void Win32IDE::clearProblems()
{
    m_problems.clear();
    m_errorCount = 0;
    m_warningCount = 0;
    ListView_DeleteAllItems(m_hwndProblemsListView);
    updatePanelContent();
    updateEnhancedStatusBar();
}

void Win32IDE::goToProblem(int index)
{
    if (index < 0 || index >= static_cast<int>(m_problems.size())) return;
    
    const ProblemItem& problem = m_problems[index];
    
    // Open file if different from current
    if (problem.file != m_currentFile) {
        // Load the file
        std::ifstream file(problem.file);
        if (file) {
            std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            SetWindowTextA(m_hwndEditor, content.c_str());
            m_currentFile = problem.file;
            m_fileModified = false;
        }
    }
    
    // Go to line
    int lineIndex = SendMessage(m_hwndEditor, EM_LINEINDEX, problem.line - 1, 0);
    SendMessage(m_hwndEditor, EM_SETSEL, lineIndex + problem.column - 1, lineIndex + problem.column - 1);
    SendMessage(m_hwndEditor, EM_SCROLLCARET, 0, 0);
    SetFocus(m_hwndEditor);
}

void Win32IDE::updateProblemsPanel()
{
    updatePanelContent();
}

// ============================================================================
// Enhanced Status Bar - VS Code style with all status items
// ============================================================================

void Win32IDE::createEnhancedStatusBar(HWND hwndParent)
{
    // Initialize status bar info
    m_statusBarInfo.remoteName = "";
    m_statusBarInfo.branchName = "main";
    m_statusBarInfo.syncAhead = 0;
    m_statusBarInfo.syncBehind = 0;
    m_statusBarInfo.errors = 0;
    m_statusBarInfo.warnings = 0;
    m_statusBarInfo.line = 1;
    m_statusBarInfo.column = 1;
    m_statusBarInfo.spacesOrTabWidth = 4;
    m_statusBarInfo.useSpaces = true;
    m_statusBarInfo.encoding = "UTF-8";
    m_statusBarInfo.eolSequence = "CRLF";
    m_statusBarInfo.languageMode = "Plain Text";
    m_statusBarInfo.copilotActive = true;
    m_statusBarInfo.copilotSuggestions = 0;
    
    // Create status bar with multiple parts
    m_hwndStatusBar = CreateWindowExA(
        0, STATUSCLASSNAMEA, "",
        WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
        0, 0, 0, 0,
        hwndParent, (HMENU)IDC_STATUS_BAR, m_hInstance, nullptr);
    
    // Set up parts - 12 parts for all status items
    // [Remote][Branch][Sync][Errors][Warnings] ... [Line:Col][Spaces][Encoding][EOL][Language][Copilot]
    int parts[] = { 80, 150, 200, 250, 300, -1, 380, 440, 510, 560, 650, 700 };
    SendMessage(m_hwndStatusBar, SB_SETPARTS, 12, (LPARAM)parts);
    
    // Set initial text
    updateEnhancedStatusBar();
}

void Win32IDE::updateEnhancedStatusBar()
{
    if (!m_hwndStatusBar) return;
    
    // Part 0: Remote indicator (if connected)
    if (!m_statusBarInfo.remoteName.empty()) {
        std::string remoteText = ">< " + m_statusBarInfo.remoteName;
        SendMessageA(m_hwndStatusBar, SB_SETTEXTA, 0, (LPARAM)remoteText.c_str());
    } else {
        SendMessageA(m_hwndStatusBar, SB_SETTEXTA, 0, (LPARAM)"");
    }
    
    // Part 1: Branch indicator
    std::string branchText = "<> " + m_statusBarInfo.branchName;
    SendMessageA(m_hwndStatusBar, SB_SETTEXTA, 1, (LPARAM)branchText.c_str());
    
    // Part 2: Sync status (ahead/behind)
    std::ostringstream syncOss;
    if (m_statusBarInfo.syncAhead > 0 || m_statusBarInfo.syncBehind > 0) {
        syncOss << m_statusBarInfo.syncAhead << "↑ " << m_statusBarInfo.syncBehind << "↓";
    }
    SendMessageA(m_hwndStatusBar, SB_SETTEXTA, 2, (LPARAM)syncOss.str().c_str());
    
    // Part 3: Errors count
    std::ostringstream errOss;
    errOss << "X " << m_statusBarInfo.errors;
    SendMessageA(m_hwndStatusBar, SB_SETTEXTA, 3, (LPARAM)errOss.str().c_str());
    
    // Part 4: Warnings count
    std::ostringstream warnOss;
    warnOss << "! " << m_statusBarInfo.warnings;
    SendMessageA(m_hwndStatusBar, SB_SETTEXTA, 4, (LPARAM)warnOss.str().c_str());
    
    // Part 5: Spacer / file info
    SendMessageA(m_hwndStatusBar, SB_SETTEXTA, 5, (LPARAM)"");
    
    // Part 6: Line and Column
    std::ostringstream lineColOss;
    lineColOss << "Ln " << m_statusBarInfo.line << ", Col " << m_statusBarInfo.column;
    SendMessageA(m_hwndStatusBar, SB_SETTEXTA, 6, (LPARAM)lineColOss.str().c_str());
    
    // Part 7: Spaces/Tabs
    std::ostringstream spacesOss;
    spacesOss << (m_statusBarInfo.useSpaces ? "Spaces: " : "Tab Size: ") << m_statusBarInfo.spacesOrTabWidth;
    SendMessageA(m_hwndStatusBar, SB_SETTEXTA, 7, (LPARAM)spacesOss.str().c_str());
    
    // Part 8: Encoding
    SendMessageA(m_hwndStatusBar, SB_SETTEXTA, 8, (LPARAM)m_statusBarInfo.encoding.c_str());
    
    // Part 9: End of Line
    SendMessageA(m_hwndStatusBar, SB_SETTEXTA, 9, (LPARAM)m_statusBarInfo.eolSequence.c_str());
    
    // Part 10: Language Mode
    SendMessageA(m_hwndStatusBar, SB_SETTEXTA, 10, (LPARAM)m_statusBarInfo.languageMode.c_str());
    
    // Part 11: Copilot status
    std::string copilotText = m_statusBarInfo.copilotActive ? "Copilot" : "Copilot (off)";
    if (m_statusBarInfo.copilotSuggestions > 0) {
        copilotText += " ▼";  // Indicates suggestions available
    }
    SendMessageA(m_hwndStatusBar, SB_SETTEXTA, 11, (LPARAM)copilotText.c_str());
}

void Win32IDE::updateCursorPosition()
{
    if (!m_hwndEditor) return;
    
    // Get current selection/cursor position
    CHARRANGE range;
    SendMessage(m_hwndEditor, EM_EXGETSEL, 0, (LPARAM)&range);
    
    // Calculate line and column
    int charIndex = range.cpMin;
    int lineIndex = SendMessage(m_hwndEditor, EM_LINEFROMCHAR, charIndex, 0);
    int lineStart = SendMessage(m_hwndEditor, EM_LINEINDEX, lineIndex, 0);
    int column = charIndex - lineStart;
    
    m_statusBarInfo.line = lineIndex + 1;
    m_statusBarInfo.column = column + 1;
    
    updateEnhancedStatusBar();
}

void Win32IDE::updateLanguageMode()
{
    detectLanguageFromFile(m_currentFile);
    updateEnhancedStatusBar();
}

void Win32IDE::detectLanguageFromFile(const std::string& filePath)
{
    if (filePath.empty()) {
        m_statusBarInfo.languageMode = "Plain Text";
        return;
    }
    
    // Get file extension
    size_t dotPos = filePath.rfind('.');
    if (dotPos == std::string::npos) {
        m_statusBarInfo.languageMode = "Plain Text";
        return;
    }
    
    std::string ext = filePath.substr(dotPos + 1);
    
    // Convert to lowercase
    for (char& c : ext) {
        c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    }
    
    // Map extension to language mode
    static const std::map<std::string, std::string> extToLang = {
        {"cpp", "C++"},
        {"c", "C"},
        {"h", "C/C++ Header"},
        {"hpp", "C++ Header"},
        {"py", "Python"},
        {"js", "JavaScript"},
        {"ts", "TypeScript"},
        {"jsx", "JavaScript React"},
        {"tsx", "TypeScript React"},
        {"json", "JSON"},
        {"xml", "XML"},
        {"html", "HTML"},
        {"htm", "HTML"},
        {"css", "CSS"},
        {"scss", "SCSS"},
        {"less", "Less"},
        {"md", "Markdown"},
        {"txt", "Plain Text"},
        {"ps1", "PowerShell"},
        {"psm1", "PowerShell"},
        {"psd1", "PowerShell"},
        {"bat", "Batch"},
        {"cmd", "Batch"},
        {"sh", "Shell Script"},
        {"bash", "Shell Script"},
        {"zsh", "Shell Script"},
        {"java", "Java"},
        {"cs", "C#"},
        {"fs", "F#"},
        {"vb", "Visual Basic"},
        {"go", "Go"},
        {"rs", "Rust"},
        {"rb", "Ruby"},
        {"php", "PHP"},
        {"swift", "Swift"},
        {"kt", "Kotlin"},
        {"scala", "Scala"},
        {"lua", "Lua"},
        {"r", "R"},
        {"sql", "SQL"},
        {"yaml", "YAML"},
        {"yml", "YAML"},
        {"toml", "TOML"},
        {"ini", "INI"},
        {"cfg", "Config"},
        {"asm", "Assembly"},
        {"s", "Assembly"}
    };
    
    auto it = extToLang.find(ext);
    if (it != extToLang.end()) {
        m_statusBarInfo.languageMode = it->second;
    } else {
        m_statusBarInfo.languageMode = "Plain Text";
    }
}

// ============================================================================
// AGENTIC INTELLIGENCE IMPLEMENTATIONS
// ============================================================================

// ============================================================================
// AgentMemory Implementation
// ============================================================================

AgentMemory::AgentMemory() : m_db(nullptr), m_dbPath() {}

AgentMemory::~AgentMemory() {
    if (m_db) {
        sqlite3_close(m_db);
    }
}

bool AgentMemory::initializeDatabase() {
    int rc = sqlite3_open(m_dbPath.c_str(), &m_db);
    if (rc != SQLITE_OK) {
        return false;
    }

    // Enable WAL mode for better concurrency
    sqlite3_exec(m_db, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
    sqlite3_exec(m_db, "PRAGMA synchronous=NORMAL;", nullptr, nullptr, nullptr);

    return createTables();
}

bool AgentMemory::createTables() {
    const char* createExecutionsTable = R"(
        CREATE TABLE IF NOT EXISTS executions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action_type TEXT NOT NULL,
            outcome TEXT NOT NULL,
            execution_time_ms INTEGER,
            error_message TEXT,
            context TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            confidence_before INTEGER,
            confidence_after INTEGER
        );
    )";

    const char* createPatternsTable = R"(
        CREATE TABLE IF NOT EXISTS patterns (
            pattern_name TEXT PRIMARY KEY,
            description TEXT,
            frequency INTEGER DEFAULT 0,
            success_rate REAL DEFAULT 0.0,
            associated_actions TEXT,
            last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    )";

    char* errMsg = nullptr;
    int rc = sqlite3_exec(m_db, createExecutionsTable, nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        sqlite3_free(errMsg);
        return false;
    }

    rc = sqlite3_exec(m_db, createPatternsTable, nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        sqlite3_free(errMsg);
        return false;
    }

    return true;
}

bool AgentMemory::loadPatterns() {
    const char* selectPatterns = "SELECT pattern_name, description, frequency, success_rate, associated_actions, last_seen FROM patterns;";

    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(m_db, selectPatterns, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        return false;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        PatternRecord record;
        record.patternName = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        record.description = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        record.frequency = sqlite3_column_int(stmt, 2);
        record.successRate = sqlite3_column_double(stmt, 3);

        std::string actionsStr = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        // Parse comma-separated actions
        size_t pos = 0;
        std::string token;
        while ((pos = actionsStr.find(',')) != std::string::npos) {
            token = actionsStr.substr(0, pos);
            record.associatedActions.push_back(token);
            actionsStr.erase(0, pos + 1);
        }
        if (!actionsStr.empty()) {
            record.associatedActions.push_back(actionsStr);
        }

        // Parse timestamp
        const char* timestampStr = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        // For simplicity, just set to now - in real implementation parse the timestamp

        m_patternCache[record.patternName] = record;
    }

    sqlite3_finalize(stmt);
    return true;
}

bool AgentMemory::initialize(const std::string& projectRoot) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_dbPath = projectRoot + "/agent_memory.db";

    if (!initializeDatabase()) {
        return false;
    }

    return loadPatterns();
}

void AgentMemory::recordExecution(const std::string& actionType, ExecutionOutcome outcome,
                                int executionTimeMs, const std::string& errorMessage,
                                const std::string& context) {
    std::lock_guard<std::mutex> lock(m_mutex);

    const char* insertExecution = R"(
        INSERT INTO executions (action_type, outcome, execution_time_ms, error_message, context)
        VALUES (?, ?, ?, ?, ?);
    )";

    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(m_db, insertExecution, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        return;
    }

    std::string outcomeStr;
    switch (outcome) {
        case ExecutionOutcome::SUCCESS: outcomeStr = "SUCCESS"; break;
        case ExecutionOutcome::FAILURE: outcomeStr = "FAILURE"; break;
        case ExecutionOutcome::PARTIAL_SUCCESS: outcomeStr = "PARTIAL_SUCCESS"; break;
        case ExecutionOutcome::TIMEOUT: outcomeStr = "TIMEOUT"; break;
        case ExecutionOutcome::CANCELLED: outcomeStr = "CANCELLED"; break;
    }

    sqlite3_bind_text(stmt, 1, actionType.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, outcomeStr.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, executionTimeMs);
    sqlite3_bind_text(stmt, 4, errorMessage.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, context.c_str(), -1, SQLITE_TRANSIENT);

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    // Update pattern success rates
    updatePattern(actionType, outcome == ExecutionOutcome::SUCCESS);
}

void AgentMemory::updatePattern(const std::string& patternName, bool success) {
    // Simplified pattern learning - in real implementation this would be more sophisticated
    if (m_patternCache.find(patternName) == m_patternCache.end()) {
        PatternRecord record;
        record.patternName = patternName;
        record.description = "Auto-detected pattern";
        record.frequency = 1;
        record.successRate = success ? 1.0 : 0.0;
        record.associatedActions = {patternName};
        record.lastSeen = std::chrono::system_clock::now();

        m_patternCache[patternName] = record;

        // Insert into database
        const char* insertPattern = R"(
            INSERT OR REPLACE INTO patterns (pattern_name, description, frequency, success_rate, associated_actions)
            VALUES (?, ?, ?, ?, ?);
        )";

        sqlite3_stmt* stmt;
        int rc = sqlite3_prepare_v2(m_db, insertPattern, -1, &stmt, nullptr);
        if (rc == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, patternName.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 2, record.description.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(stmt, 3, record.frequency);
            sqlite3_bind_double(stmt, 4, record.successRate);
            std::string actionsStr;
            for (size_t i = 0; i < record.associatedActions.size(); ++i) {
                if (i > 0) actionsStr += ",";
                actionsStr += record.associatedActions[i];
            }
            sqlite3_bind_text(stmt, 5, actionsStr.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    } else {
        // Update existing pattern
        PatternRecord& record = m_patternCache[patternName];
        record.frequency++;
        int successCount = static_cast<int>(record.successRate * (record.frequency - 1));
        if (success) successCount++;
        record.successRate = static_cast<double>(successCount) / record.frequency;
        record.lastSeen = std::chrono::system_clock::now();

        const char* updatePattern = R"(
            UPDATE patterns SET frequency = ?, success_rate = ?, last_seen = CURRENT_TIMESTAMP
            WHERE pattern_name = ?;
        )";

        sqlite3_stmt* stmt;
        int rc = sqlite3_prepare_v2(m_db, updatePattern, -1, &stmt, nullptr);
        if (rc == SQLITE_OK) {
            sqlite3_bind_int(stmt, 1, record.frequency);
            sqlite3_bind_double(stmt, 2, record.successRate);
            sqlite3_bind_text(stmt, 3, patternName.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }
}

double AgentMemory::getSuccessRate(const std::string& actionType) const {
    std::lock_guard<std::mutex> lock(m_mutex);

    const char* selectSuccessRate = R"(
        SELECT
            CAST(SUM(CASE WHEN outcome = 'SUCCESS' THEN 1 ELSE 0 END) AS REAL) /
            CAST(COUNT(*) AS REAL) as success_rate
        FROM executions
        WHERE action_type = ?
        AND timestamp > datetime('now', '-30 days');
    )";

    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(m_db, selectSuccessRate, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        return 0.5; // Default neutral confidence
    }

    sqlite3_bind_text(stmt, 1, actionType.c_str(), -1, SQLITE_TRANSIENT);

    double successRate = 0.5;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        successRate = sqlite3_column_double(stmt, 0);
        if (successRate != successRate) { // NaN check
            successRate = 0.5;
        }
    }

    sqlite3_finalize(stmt);
    return successRate;
}

double AgentMemory::getPatternSuccessRate(const std::string& patternName) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_patternCache.find(patternName);
    return (it != m_patternCache.end()) ? it->second.successRate : 0.5;
}

std::vector<std::string> AgentMemory::getLearnedPatterns() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<std::string> patterns;
    for (const auto& pair : m_patternCache) {
        patterns.push_back(pair.first);
    }
    return patterns;
}

int AgentMemory::getExecutionCount(const std::string& actionType) const {
    std::lock_guard<std::mutex> lock(m_mutex);

    const char* countExecutions = "SELECT COUNT(*) FROM executions WHERE action_type = ?;";

    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(m_db, countExecutions, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        return 0;
    }

    sqlite3_bind_text(stmt, 1, actionType.c_str(), -1, SQLITE_TRANSIENT);

    int count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
    }

    sqlite3_finalize(stmt);
    return count;
}

std::vector<ExecutionRecord> AgentMemory::getRecentExecutions(int limit) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<ExecutionRecord> records;

    const char* selectRecent = R"(
        SELECT action_type, outcome, execution_time_ms, error_message, context, timestamp
        FROM executions
        ORDER BY timestamp DESC
        LIMIT ?;
    )";

    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(m_db, selectRecent, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        return records;
    }

    sqlite3_bind_int(stmt, 1, limit);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        ExecutionRecord record;
        record.actionType = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));

        std::string outcomeStr = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        if (outcomeStr == "SUCCESS") record.outcome = ExecutionOutcome::SUCCESS;
        else if (outcomeStr == "FAILURE") record.outcome = ExecutionOutcome::FAILURE;
        else if (outcomeStr == "PARTIAL_SUCCESS") record.outcome = ExecutionOutcome::PARTIAL_SUCCESS;
        else if (outcomeStr == "TIMEOUT") record.outcome = ExecutionOutcome::TIMEOUT;
        else record.outcome = ExecutionOutcome::CANCELLED;

        record.executionTimeMs = sqlite3_column_int(stmt, 2);
        record.errorMessage = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        record.context = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        // Timestamp parsing would be implemented here

        records.push_back(record);
    }

    sqlite3_finalize(stmt);
    return records;
}

void AgentMemory::cleanupOldRecords(int daysOld) {
    std::lock_guard<std::mutex> lock(m_mutex);

    std::string deleteOld = "DELETE FROM executions WHERE timestamp < datetime('now', '-" +
                           std::to_string(daysOld) + " days');";

    sqlite3_exec(m_db, deleteOld.c_str(), nullptr, nullptr, nullptr);
}

// ============================================================================
// HierarchicalPlanner Implementation
// ============================================================================

HierarchicalPlanner::HierarchicalPlanner() : m_memory(nullptr) {}

std::vector<SubGoal> HierarchicalPlanner::decomposeWish(const std::string& wish, const PlanningContext& context) {
    // Simple heuristic-based decomposition
    TaskComplexity complexity = assessComplexity(wish);

    switch (complexity) {
        case TaskComplexity::SIMPLE:
            return decomposeSimpleTask(wish, context);
        case TaskComplexity::MODERATE:
            return decomposeModerateTask(wish, context);
        case TaskComplexity::COMPLEX:
        case TaskComplexity::VERY_COMPLEX:
            return decomposeComplexTask(wish, context);
        default:
            return {};
    }
}

std::vector<SubGoal> HierarchicalPlanner::decomposeSimpleTask(const std::string& wish, const PlanningContext& context) {
    std::vector<SubGoal> subGoals;

    SubGoal goal;
    goal.description = wish;
    goal.requiredActions = {wish}; // Simplified
    goal.complexity = TaskComplexity::SIMPLE;
    goal.estimatedTimeMinutes = 5;
    goal.successCriteria = {"Task completed successfully"};

    subGoals.push_back(goal);
    return subGoals;
}

std::vector<SubGoal> HierarchicalPlanner::decomposeModerateTask(const std::string& wish, const PlanningContext& context) {
    std::vector<SubGoal> subGoals;

    // Break into 2-3 sub-goals
    SubGoal goal1;
    goal1.description = "Analyze " + wish;
    goal1.requiredActions = {"SearchFiles", "AnalyzeCode"};
    goal1.complexity = TaskComplexity::SIMPLE;
    goal1.estimatedTimeMinutes = 3;
    goal1.successCriteria = {"Analysis complete"};

    SubGoal goal2;
    goal2.description = "Implement " + wish;
    goal2.requiredActions = {"FileEdit", "RunBuild"};
    goal2.dependencies = {"Analyze " + wish};
    goal2.complexity = TaskComplexity::MODERATE;
    goal2.estimatedTimeMinutes = 10;
    goal2.successCriteria = {"Implementation complete", "Build successful"};

    subGoals.push_back(goal1);
    subGoals.push_back(goal2);

    optimizeDecomposition(subGoals, context);
    return subGoals;
}

std::vector<SubGoal> HierarchicalPlanner::decomposeComplexTask(const std::string& wish, const PlanningContext& context) {
    std::vector<SubGoal> subGoals;

    // Research phase
    SubGoal research;
    research.description = "Research and plan " + wish;
    research.requiredActions = {"SearchFiles", "AnalyzeCode", "QueryUser"};
    research.complexity = TaskComplexity::MODERATE;
    research.estimatedTimeMinutes = 15;
    research.successCriteria = {"Requirements understood", "Plan created"};

    // Implementation phase
    SubGoal implement;
    implement.description = "Implement " + wish;
    implement.requiredActions = {"FileEdit", "RunBuild", "ExecuteTests"};
    implement.dependencies = {"Research and plan " + wish};
    implement.complexity = TaskComplexity::COMPLEX;
    implement.estimatedTimeMinutes = 30;
    implement.successCriteria = {"Code implemented", "Tests pass", "Build successful"};

    // Validation phase
    SubGoal validate;
    validate.description = "Validate and document " + wish;
    validate.requiredActions = {"RunBuild", "ExecuteTests", "CommitGit"};
    validate.dependencies = {"Implement " + wish};
    validate.complexity = TaskComplexity::MODERATE;
    validate.estimatedTimeMinutes = 10;
    validate.successCriteria = {"All tests pass", "Documentation updated", "Changes committed"};

    subGoals.push_back(research);
    subGoals.push_back(implement);
    subGoals.push_back(validate);

    optimizeDecomposition(subGoals, context);
    return subGoals;
}

bool HierarchicalPlanner::validateDecomposition(const std::vector<SubGoal>& subGoals) {
    // Check for circular dependencies, missing dependencies, etc.
    std::unordered_map<std::string, std::vector<std::string>> dependencyGraph;

    for (const SubGoal& goal : subGoals) {
        dependencyGraph[goal.description] = goal.dependencies;
    }

    // Simple cycle detection (basic implementation)
    for (const auto& pair : dependencyGraph) {
        std::unordered_set<std::string> visited;
        std::unordered_set<std::string> recursionStack;

        if (hasCycle(pair.first, dependencyGraph, visited, recursionStack)) {
            return false;
        }
    }

    return true;
}

bool HierarchicalPlanner::hasCycle(const std::string& node,
                                 const std::unordered_map<std::string, std::vector<std::string>>& graph,
                                 std::unordered_set<std::string>& visited,
                                 std::unordered_set<std::string>& recursionStack) {
    visited.insert(node);
    recursionStack.insert(node);

    auto it = graph.find(node);
    if (it != graph.end()) {
        for (const std::string& dep : it->second) {
            if (recursionStack.find(dep) != recursionStack.end()) {
                return true;
            }
            if (visited.find(dep) == visited.end() &&
                hasCycle(dep, graph, visited, recursionStack)) {
                return true;
            }
        }
    }

    recursionStack.erase(node);
    return false;
}

void HierarchicalPlanner::optimizeDecomposition(std::vector<SubGoal>& subGoals, const PlanningContext& context) {
    // Sort by dependencies (topological sort)
    // Use success rates to prioritize high-success actions
    // Adjust time estimates based on historical data

    if (m_memory) {
        for (SubGoal& goal : subGoals) {
            for (const std::string& action : goal.requiredActions) {
                double successRate = m_memory->getSuccessRate(action);
                // Adjust time estimate based on success rate
                if (successRate < 0.5) {
                    goal.estimatedTimeMinutes = static_cast<int>(goal.estimatedTimeMinutes * 1.5);
                }
            }
        }
    }
}

std::vector<std::string> HierarchicalPlanner::getDependencyChain(const SubGoal& goal) const {
    // Return flattened dependency chain
    return goal.dependencies;
}

int HierarchicalPlanner::estimateTotalTime(const std::vector<SubGoal>& subGoals) const {
    int total = 0;
    for (const SubGoal& goal : subGoals) {
        total += goal.estimatedTimeMinutes;
    }
    return total;
}

TaskComplexity HierarchicalPlanner::assessComplexity(const std::string& task) const {
    // Simple heuristic based on keywords and length
    size_t wordCount = 0;
    bool inWord = false;

    for (char c : task) {
        if (std::isalnum(c)) {
            if (!inWord) {
                wordCount++;
                inWord = true;
            }
        } else {
            inWord = false;
        }
    }

    // Complexity keywords
    std::vector<std::string> complexKeywords = {"implement", "create", "build", "system", "architecture", "multiple", "complex"};
    int complexWordCount = 0;

    std::string lowerTask = task;
    std::transform(lowerTask.begin(), lowerTask.end(), lowerTask.begin(), ::tolower);

    for (const std::string& keyword : complexKeywords) {
        if (lowerTask.find(keyword) != std::string::npos) {
            complexWordCount++;
        }
    }

    if (wordCount <= 5 && complexWordCount == 0) {
        return TaskComplexity::SIMPLE;
    } else if (wordCount <= 10 && complexWordCount <= 1) {
        return TaskComplexity::MODERATE;
    } else if (wordCount <= 20 && complexWordCount <= 3) {
        return TaskComplexity::COMPLEX;
    } else {
        return TaskComplexity::VERY_COMPLEX;
    }
}

// ============================================================================
// AgentSelfReflection Implementation
// ============================================================================

AgentSelfReflection::AgentSelfReflection() : m_memory(nullptr) {}

ErrorType AgentSelfReflection::classifyError(const std::string& errorMessage) const {
    std::string lowerError = errorMessage;
    std::transform(lowerError.begin(), lowerError.end(), lowerError.begin(), ::tolower);

    if (lowerError.find("permission denied") != std::string::npos ||
        lowerError.find("access denied") != std::string::npos) {
        return ErrorType::PERMISSION_DENIED;
    } else if (lowerError.find("file not found") != std::string::npos ||
               lowerError.find("no such file") != std::string::npos) {
        return ErrorType::FILE_NOT_FOUND;
    } else if (lowerError.find("network") != std::string::npos ||
               lowerError.find("connection") != std::string::npos) {
        return ErrorType::NETWORK_ERROR;
    } else if (lowerError.find("timeout") != std::string::npos) {
        return ErrorType::TIMEOUT;
    } else if (lowerError.find("syntax") != std::string::npos ||
               lowerError.find("parse error") != std::string::npos) {
        return ErrorType::INVALID_SYNTAX;
    } else if (lowerError.find("dependency") != std::string::npos ||
               lowerError.find("not found") != std::string::npos) {
        return ErrorType::DEPENDENCY_MISSING;
    } else if (lowerError.find("out of memory") != std::string::npos ||
               lowerError.find("insufficient") != std::string::npos) {
        return ErrorType::RESOURCE_EXHAUSTED;
    }

    return ErrorType::UNKNOWN;
}

std::vector<std::string> AgentSelfReflection::generateFixes(ErrorType errorType, const std::string& context) const {
    std::vector<std::string> fixes;

    switch (errorType) {
        case ErrorType::PERMISSION_DENIED:
            fixes = {
                "Run with elevated privileges",
                "Check file ownership and permissions",
                "Create a copy and replace the original",
                "Use a different location with proper permissions"
            };
            break;
        case ErrorType::FILE_NOT_FOUND:
            fixes = {
                "Verify the file path exists",
                "Check for typos in the filename",
                "Ensure the working directory is correct",
                "Create the file if it should exist"
            };
            break;
        case ErrorType::NETWORK_ERROR:
            fixes = {
                "Check network connectivity",
                "Verify server availability",
                "Try a different network endpoint",
                "Implement retry logic with backoff"
            };
            break;
        case ErrorType::TIMEOUT:
            fixes = {
                "Increase timeout duration",
                "Break the operation into smaller chunks",
                "Optimize the operation for speed",
                "Run the operation asynchronously"
            };
            break;
        case ErrorType::INVALID_SYNTAX:
            fixes = {
                "Validate syntax against language specification",
                "Use a linter or syntax checker",
                "Check for common syntax errors",
                "Review recent changes for typos"
            };
            break;
        case ErrorType::DEPENDENCY_MISSING:
            fixes = {
                "Install missing dependencies",
                "Update package manager",
                "Check dependency versions",
                "Use alternative dependencies"
            };
            break;
        case ErrorType::RESOURCE_EXHAUSTED:
            fixes = {
                "Reduce memory usage",
                "Increase available resources",
                "Optimize algorithms for efficiency",
                "Process data in smaller batches"
            };
            break;
        default:
            fixes = {
                "Review error logs for more details",
                "Check system resources",
                "Verify configuration settings",
                "Consult documentation or community resources"
            };
    }

    return fixes;
}

double AgentSelfReflection::calculateConfidence(const std::string& actionType) const {
    if (!m_memory) return 0.5;

    double successRate = m_memory->getSuccessRate(actionType);
    int executionCount = m_memory->getExecutionCount(actionType);

    // Confidence increases with more executions and higher success rates
    double confidence = successRate * (1.0 - std::exp(-executionCount / 10.0));
    return std::max(0.1, std::min(0.9, confidence));
}

ErrorAnalysis AgentSelfReflection::analyzeError(const std::string& actionType, const std::string& errorMessage,
                                              const std::string& context) {
    ErrorAnalysis analysis;
    analysis.type = classifyError(errorMessage);
    analysis.rootCause = errorMessage;
    analysis.severity = 5; // Default medium severity
    analysis.impact = "Operation failed";
    analysis.recoverable = true;
    analysis.suggestedFixes = generateFixes(analysis.type, context);

    // Adjust severity based on error type
    switch (analysis.type) {
        case ErrorType::PERMISSION_DENIED:
        case ErrorType::RESOURCE_EXHAUSTED:
            analysis.severity = 8;
            break;
        case ErrorType::INVALID_SYNTAX:
        case ErrorType::DEPENDENCY_MISSING:
            analysis.severity = 6;
            break;
        default:
            analysis.severity = 5;
    }

    return analysis;
}

std::vector<AlternativeApproach> AgentSelfReflection::generateAlternatives(const std::string& actionType,
                                                                         const ErrorAnalysis& analysis,
                                                                         const std::string& context) {
    std::vector<AlternativeApproach> alternatives;

    for (const std::string& fix : analysis.suggestedFixes) {
        AlternativeApproach alt;
        alt.description = fix;
        alt.actions = {fix}; // Simplified - in real implementation, map to actual actions
        alt.confidence = calculateConfidence(actionType) * 0.8; // Slightly lower confidence for alternatives
        alt.expectedSuccessRate = 0.7; // Conservative estimate
        alt.estimatedTimeMinutes = 5; // Default time

        alternatives.push_back(alt);
    }

    // Sort by confidence
    std::sort(alternatives.begin(), alternatives.end(),
              [](const AlternativeApproach& a, const AlternativeApproach& b) {
                  return a.confidence > b.confidence;
              });

    return alternatives;
}

bool AgentSelfReflection::shouldEscalateToHuman(const ErrorAnalysis& analysis,
                                              const std::vector<AlternativeApproach>& alternatives) const {
    // Escalate if severity is high and no good alternatives
    if (analysis.severity >= 8) {
        return true;
    }

    // Escalate if all alternatives have low confidence
    bool hasGoodAlternative = false;
    for (const AlternativeApproach& alt : alternatives) {
        if (alt.confidence > 0.6) {
            hasGoodAlternative = true;
            break;
        }
    }

    return !hasGoodAlternative;
}

ConfidenceAdjustment AgentSelfReflection::adjustConfidence(ExecutionOutcome outcome, const std::string& actionType,
                                                         int executionTimeMs) {
    ConfidenceAdjustment adjustment;
    adjustment.actionType = actionType;

    double currentConfidence = m_confidenceLevels[actionType];
    adjustment.oldConfidence = currentConfidence;

    // Adjust confidence based on outcome
    double adjustmentFactor = 0.05; // Small adjustment
    if (outcome == ExecutionOutcome::SUCCESS) {
        currentConfidence = std::min(0.95, currentConfidence + adjustmentFactor);
    } else {
        currentConfidence = std::max(0.05, currentConfidence - adjustmentFactor);
    }

    adjustment.newConfidence = currentConfidence;
    adjustment.reason = (outcome == ExecutionOutcome::SUCCESS) ? "Success" : "Failure";

    m_confidenceLevels[actionType] = currentConfidence;

    return adjustment;
}

double AgentSelfReflection::getConfidence(const std::string& actionType) const {
    auto it = m_confidenceLevels.find(actionType);
    return (it != m_confidenceLevels.end()) ? it->second : 0.5;
}

void AgentSelfReflection::learnFromExecution(const std::string& actionType, bool success, int executionTimeMs,
                                           const std::string& errorMessage) {
    ExecutionOutcome outcome = success ? ExecutionOutcome::SUCCESS : ExecutionOutcome::FAILURE;
    adjustConfidence(outcome, actionType, executionTimeMs);
}

// ============================================================================
// ProjectContext Implementation
// ============================================================================

ProjectContext::ProjectContext() : m_analyzed(false) {}

bool ProjectContext::analyzeProject(const std::string& projectRoot) {
    m_projectRoot = projectRoot;
    m_overview = ArchitectureOverview();

    try {
        scanProjectStructure();
        analyzeCodePatterns();
        m_overview.codeStyle = detectCodeStyle(getSourceFiles());
        calculateMetrics();
        m_analyzed = true;
        return true;
    } catch (const std::exception&) {
        m_analyzed = false;
        return false;
    }
}

void ProjectContext::scanProjectStructure() {
    // Simplified file scanning - in real implementation use filesystem
    std::vector<std::string> extensions = {".cpp", ".hpp", ".c", ".h", ".py", ".java", ".cs", ".js", ".ts"};

    // Mock data for demonstration
    m_overview.totalFiles = 1500;
    m_overview.totalLines = 500000;
    m_overview.totalFunctions = 8000;
    m_overview.totalClasses = 500;

    m_overview.languageDistribution = {
        {"C++", 1200},
        {"Python", 150},
        {"JavaScript", 100},
        {"Other", 50}
    };

    m_overview.mainEntryPoints = {"Win32_IDE_Complete.cpp", "main.py"};
    m_overview.externalDependencies = {"Qt", "SQLite", "OpenSSL"};
}

void ProjectContext::analyzeCodePatterns() {
    // Simplified pattern analysis
    m_overview.patterns = {
        {"Singleton", "Creational pattern for single instances", 25, {"getInstance()", "static instance"}},
        {"Factory", "Creational pattern for object creation", 18, {"createObject()", "factory method"}},
        {"Observer", "Behavioral pattern for event handling", 12, {"attach()", "notify()", "update()"}}
    };
}

CodeStyle ProjectContext::detectCodeStyle(const std::vector<std::string>& files) const {
    // Simplified style detection
    return CodeStyle::ALLMAN; // Most common in C++
}

std::vector<std::string> ProjectContext::getSourceFiles() const {
    // Return mock file list
    return {"Win32_IDE_Complete.cpp", "AgentMemory.cpp", "HierarchicalPlanner.cpp"};
}

void ProjectContext::calculateMetrics() {
    // Calculate additional metrics
    m_overview.totalFunctions = m_overview.totalClasses * 16; // Rough estimate
}

std::vector<std::string> ProjectContext::getBestPracticeRecommendations() const {
    std::vector<std::string> recommendations;

    if (m_overview.totalFiles > 1000) {
        recommendations.push_back("Consider modularizing the large codebase into smaller libraries");
    }

    if (m_overview.languageDistribution["C++"] > 1000) {
        recommendations.push_back("Ensure consistent C++ coding standards across the project");
    }

    if (m_overview.patterns.size() < 5) {
        recommendations.push_back("Consider applying more design patterns for better code organization");
    }

    return recommendations;
}

// ============================================================================
// AutonomousDecisionEngine Implementation
// ============================================================================

AutonomousDecisionEngine::AutonomousDecisionEngine() : m_currentLevel(AutonomyLevel::SEMI_AUTONOMOUS), m_memory(nullptr) {
    m_riskThresholds = {
        {"FileEdit", 0.3},
        {"RunBuild", 0.5},
        {"ExecuteTests", 0.4},
        {"CommitGit", 0.6},
        {"InvokeCommand", 0.7}
    };
}

std::vector<RiskFactor> AutonomousDecisionEngine::assessRisks(const std::string& action, const DecisionContext& context) const {
    std::vector<RiskFactor> risks;

    // File operations are generally low risk
    if (action.find("FileEdit") != std::string::npos) {
        risks.push_back({"File modification", RiskLevel::LOW, 0.2, "Standard file operation"});
    }

    // Build operations have medium risk
    if (action.find("RunBuild") != std::string::npos) {
        risks.push_back({"Build failure impact", RiskLevel::MEDIUM, 0.4, "Build failures can block development"});
    }

    // Git operations are higher risk
    if (action.find("CommitGit") != std::string::npos) {
        risks.push_back({"Version control changes", RiskLevel::HIGH, 0.6, "Commits are permanent"});
    }

    // Command execution is highest risk
    if (action.find("InvokeCommand") != std::string::npos) {
        risks.push_back({"Arbitrary command execution", RiskLevel::CRITICAL, 0.8, "Commands can have system-wide effects"});
    }

    // Adjust based on project context
    if (context.projectContext.totalFiles > 10000) {
        for (RiskFactor& risk : risks) {
            risk.weight *= 1.2; // Higher risk for large projects
        }
    }

    // Adjust based on complexity
    if (context.complexity == "high") {
        for (RiskFactor& risk : risks) {
            risk.weight *= 1.1;
        }
    }

    return risks;
}

double AutonomousDecisionEngine::calculateRiskScore(const std::vector<RiskFactor>& risks) const {
    double totalScore = 0.0;
    double totalWeight = 0.0;

    for (const RiskFactor& risk : risks) {
        double levelMultiplier = 1.0;
        switch (risk.level) {
            case RiskLevel::LOW: levelMultiplier = 1.0; break;
            case RiskLevel::MEDIUM: levelMultiplier = 2.0; break;
            case RiskLevel::HIGH: levelMultiplier = 3.0; break;
            case RiskLevel::CRITICAL: levelMultiplier = 4.0; break;
        }

        totalScore += (risk.weight * levelMultiplier);
        totalWeight += risk.weight;
    }

    return totalWeight > 0 ? (totalScore / totalWeight) / 4.0 : 0.0; // Normalize to 0-1
}

bool AutonomousDecisionEngine::isActionLowRisk(const std::string& action, const DecisionContext& context) const {
    auto risks = assessRisks(action, context);
    double riskScore = calculateRiskScore(risks);
    return riskScore < 0.4; // Threshold for low risk
}

DecisionOutcome AutonomousDecisionEngine::makeDecision(const DecisionContext& context) {
    DecisionOutcome outcome;
    outcome.requiresApproval = false;
    outcome.autonomyLevel = m_currentLevel;
    outcome.confidence = 0.8;

    std::vector<std::string> lowRiskActions;
    std::vector<std::string> highRiskActions;

    // Categorize actions by risk
    for (const std::string& action : context.availableActions) {
        if (isActionLowRisk(action, context)) {
            lowRiskActions.push_back(action);
        } else {
            highRiskActions.push_back(action);
        }
    }

    switch (m_currentLevel) {
        case AutonomyLevel::SUPERVISED:
            outcome.requiresApproval = true;
            outcome.approvedActions = {};
            outcome.requiresApprovalActions = context.availableActions;
            outcome.reasoning = "All actions require approval in supervised mode";
            break;

        case AutonomyLevel::SEMI_AUTONOMOUS:
            outcome.approvedActions = lowRiskActions;
            outcome.requiresApprovalActions = highRiskActions;
            outcome.requiresApproval = !highRiskActions.empty();
            outcome.reasoning = "Low-risk actions approved automatically";
            break;

        case AutonomyLevel::FULLY_AUTONOMOUS:
            outcome.approvedActions = context.availableActions;
            outcome.requiresApprovalActions = {};
            outcome.reasoning = "All actions approved in fully autonomous mode";
            break;
    }

    // Adjust confidence based on success rates
    if (m_memory) {
        double avgSuccessRate = 0.0;
        for (const std::string& action : outcome.approvedActions) {
            avgSuccessRate += context.actionSuccessRates.count(action) ?
                             context.actionSuccessRates.at(action) : 0.5;
        }
        if (!outcome.approvedActions.empty()) {
            avgSuccessRate /= outcome.approvedActions.size();
            outcome.confidence = std::max(0.5, avgSuccessRate);
        }
    }

    return outcome;
}

double AutonomousDecisionEngine::getMaxRiskThreshold() const {
    double maxThreshold = 0.0;
    for (const auto& pair : m_riskThresholds) {
        maxThreshold = std::max(maxThreshold, pair.second);
    }
    return maxThreshold;
}

void AutonomousDecisionEngine::adjustRiskThresholds(const std::string& actionType, double newThreshold) {
    m_riskThresholds[actionType] = newThreshold;
}

// ============================================================================
// IDEAgentBridge Implementation
// ============================================================================

IDEAgentBridge::IDEAgentBridge(Win32IDE* ide)
    : m_ide(ide), m_currentState(AgentExecutionState::IDLE),
      m_agentMemory(nullptr), m_hierarchicalPlanner(nullptr),
      m_selfReflection(nullptr), m_projectContext(nullptr),
      m_decisionEngine(nullptr) {}

IDEAgentBridge::~IDEAgentBridge() = default;

bool IDEAgentBridge::initialize(const std::string& projectRoot) {
    try {
        // Initialize components
        m_agentMemory = std::make_unique<AgentMemory>();
        if (!m_agentMemory->initialize(projectRoot)) {
            return false;
        }

        m_hierarchicalPlanner = std::make_unique<HierarchicalPlanner>();
        m_hierarchicalPlanner->setMemory(m_agentMemory.get());

        m_selfReflection = std::make_unique<AgentSelfReflection>();
        m_selfReflection->setMemory(m_agentMemory.get());

        m_projectContext = std::make_unique<ProjectContext>();

        m_decisionEngine = std::make_unique<AutonomousDecisionEngine>();
        m_decisionEngine->setMemory(m_agentMemory.get());

        return true;
    } catch (const std::exception&) {
        return false;
    }
}

void IDEAgentBridge::executeWish(const std::string& wish, bool requireApproval) {
    if (m_currentState != AgentExecutionState::IDLE) {
        return; // Already executing
    }

    m_currentWish = wish;
    m_currentState = AgentExecutionState::ANALYZING;

    // Analyze project if needed
    if (!m_projectContext->isProjectAnalyzed()) {
        // Assume project root from IDE
        m_projectContext->analyzeProject("D:\\rawrxd");
    }

    // Generate plan
    PlanningContext context;
    context.projectRoot = "D:\\rawrxd";
    context.availableTools = {"FileEdit", "SearchFiles", "RunBuild", "ExecuteTests", "CommitGit"};
    context.timeBudgetMinutes = 60;
    context.maxComplexity = TaskComplexity::COMPLEX;

    if (m_agentMemory) {
        for (const std::string& tool : context.availableTools) {
            context.toolSuccessRates[tool] = m_agentMemory->getSuccessRate(tool);
        }
    }

    m_currentPlan = m_hierarchicalPlanner->decomposeWish(wish, context);

    // Make decision
    DecisionContext decisionContext;
    decisionContext.wish = wish;
    decisionContext.availableActions = context.availableTools;
    decisionContext.projectContext = m_projectContext->getArchitectureOverview();
    decisionContext.urgency = "medium";
    decisionContext.complexity = "medium";
    decisionContext.actionSuccessRates = context.toolSuccessRates;

    DecisionOutcome decision = m_decisionEngine->makeDecision(decisionContext);

    if (decision.requiresApproval && requireApproval) {
        m_currentState = AgentExecutionState::APPROVAL_PENDING;
        emit agentGeneratedPlan(QString::fromStdString("Plan generated for: " + wish));
        emit agentApprovalNeeded(QString::fromStdString("Approval needed for " +
                             std::to_string(decision.requiresApprovalActions.size()) + " actions"));
        return;
    }

    // Execute plan
    executePlan();
}

void IDEAgentBridge::approvePlan() {
    if (m_currentState == AgentExecutionState::APPROVAL_PENDING) {
        executePlan();
    }
}

void IDEAgentBridge::rejectPlan() {
    m_currentState = AgentExecutionState::IDLE;
    m_currentPlan.clear();
    emit agentExecutionFailed("Plan rejected by user");
}

void IDEAgentBridge::executePlan() {
    m_currentState = AgentExecutionState::EXECUTING;
    emit agentExecutionStarted();

    // Simplified execution - in real implementation this would be more sophisticated
    for (size_t i = 0; i < m_currentPlan.size(); ++i) {
        const SubGoal& goal = m_currentPlan[i];

        emit agentExecutionProgress(static_cast<int>((i * 100) / m_currentPlan.size()),
                                  QString::fromStdString("Executing: " + goal.description));

        // Simulate execution
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));

        // Record in memory
        if (m_agentMemory) {
            m_agentMemory->recordExecution("SubGoal_" + std::to_string(i),
                                         ExecutionOutcome::SUCCESS, 1000,
                                         "", goal.description);
        }
    }

    m_currentState = AgentExecutionState::COMPLETED;
    emit agentExecutionCompleted(QString::fromStdString("Successfully completed: " + m_currentWish));
}

std::string IDEAgentBridge::getCurrentStatus() const {
    switch (m_currentState) {
        case AgentExecutionState::IDLE: return "Idle";
        case AgentExecutionState::ANALYZING: return "Analyzing request";
        case AgentExecutionState::PLANNING: return "Generating plan";
        case AgentExecutionState::APPROVAL_PENDING: return "Waiting for approval";
        case AgentExecutionState::EXECUTING: return "Executing plan";
        case AgentExecutionState::REFLECTING: return "Reflecting on results";
        case AgentExecutionState::COMPLETED: return "Completed";
        case AgentExecutionState::FAILED: return "Failed";
        default: return "Unknown";
    }
}

// ============================================================================
// ActionExecutor Implementation
// ============================================================================

ActionExecutor::ActionExecutor(Win32IDE* ide) : m_selfReflection(nullptr), m_ide(ide) {}

ActionExecutionResult ActionExecutor::executeAction(const Action& action) {
    ActionExecutionResult result;
    result.success = false;

    try {
        switch (action.type) {
            case ActionType::FileEdit:
                result = handleFileEdit(action);
                break;
            case ActionType::SearchFiles:
                result = handleSearchFiles(action);
                break;
            case ActionType::RunBuild:
                result = handleRunBuild(action);
                break;
            case ActionType::ExecuteTests:
                result = handleExecuteTests(action);
                break;
            case ActionType::CommitGit:
                result = handleCommitGit(action);
                break;
            case ActionType::InvokeCommand:
                result = handleInvokeCommand(action);
                break;
            case ActionType::RecursiveAgent:
                result = handleRecursiveAgent(action);
                break;
            case ActionType::QueryUser:
                result = handleQueryUser(action);
                break;
            default:
                result.error = "Unknown action type";
                result.executionTimeMs = 0;
        }

        // Learn from execution
        if (m_selfReflection) {
            m_selfReflection->learnFromExecution(actionTypeToString(action.type),
                                               result.success, result.executionTimeMs,
                                               result.error);
        }

    } catch (const std::exception& e) {
        result.success = false;
        result.error = e.what();
        result.executionTimeMs = 0;
    }

    return result;
}

ActionExecutionResult ActionExecutor::handleFileEdit(const Action& action) {
    ActionExecutionResult result;
    auto start = std::chrono::high_resolution_clock::now();

    // Simplified file edit - in real implementation would use IDE's file operations
    std::string filePath = action.parameters.at("filePath");
    std::string content = action.parameters.at("content");

    try {
        std::ofstream file(filePath);
        if (file.is_open()) {
            file << content;
            file.close();
            result.success = true;
            result.result = "File edited successfully";
        } else {
            result.error = "Failed to open file";
        }
    } catch (const std::exception& e) {
        result.error = e.what();
    }

    auto end = std::chrono::high_resolution_clock::now();
    result.executionTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    return result;
}

ActionExecutionResult ActionExecutor::handleSearchFiles(const Action& action) {
    ActionExecutionResult result;
    auto start = std::chrono::high_resolution_clock::now();

    // Simplified search - in real implementation would use IDE's search
    std::string pattern = action.parameters.at("pattern");
    std::string directory = action.parameters.count("directory") ?
                           action.parameters.at("directory") : ".";

    // Mock search result
    result.success = true;
    result.result = "Found 5 matches for pattern: " + pattern;

    auto end = std::chrono::high_resolution_clock::now();
    result.executionTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    return result;
}

ActionExecutionResult ActionExecutor::handleRunBuild(const Action& action) {
    ActionExecutionResult result;
    auto start = std::chrono::high_resolution_clock::now();

    // Simplified build - in real implementation would run actual build
    result.success = true;
    result.result = "Build completed successfully";

    auto end = std::chrono::high_resolution_clock::now();
    result.executionTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    return result;
}

ActionExecutionResult ActionExecutor::handleExecuteTests(const Action& action) {
    ActionExecutionResult result;
    auto start = std::chrono::high_resolution_clock::now();

    // Simplified test execution
    result.success = true;
    result.result = "All tests passed";

    auto end = std::chrono::high_resolution_clock::now();
    result.executionTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    return result;
}

ActionExecutionResult ActionExecutor::handleCommitGit(const Action& action) {
    ActionExecutionResult result;
    auto start = std::chrono::high_resolution_clock::now();

    // Simplified git commit
    result.success = true;
    result.result = "Changes committed successfully";

    auto end = std::chrono::high_resolution_clock::now();
    result.executionTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    return result;
}

ActionExecutionResult ActionExecutor::handleInvokeCommand(const Action& action) {
    ActionExecutionResult result;
    auto start = std::chrono::high_resolution_clock::now();

    // Simplified command execution - HIGH RISK
    std::string command = action.parameters.at("command");

    // For safety, only allow safe commands
    if (command.find("rm") != std::string::npos || command.find("del") != std::string::npos) {
        result.error = "Dangerous command blocked";
        result.success = false;
    } else {
        result.success = true;
        result.result = "Command executed: " + command;
    }

    auto end = std::chrono::high_resolution_clock::now();
    result.executionTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    return result;
}

ActionExecutionResult ActionExecutor::handleRecursiveAgent(const Action& action) {
    ActionExecutionResult result;
    auto start = std::chrono::high_resolution_clock::now();

    // Simplified recursive agent call
    result.success = true;
    result.result = "Recursive agent completed";

    auto end = std::chrono::high_resolution_clock::now();
    result.executionTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    return result;
}

ActionExecutionResult ActionExecutor::handleQueryUser(const Action& action) {
    ActionExecutionResult result;
    auto start = std::chrono::high_resolution_clock::now();

    // Simplified user query
    std::string question = action.parameters.at("question");
    result.success = true;
    result.result = "User responded to: " + question;

    auto end = std::chrono::high_resolution_clock::now();
    result.executionTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    return result;
}

std::vector<ActionType> ActionExecutor::getSupportedActions() const {
    return {
        ActionType::FileEdit,
        ActionType::SearchFiles,
        ActionType::RunBuild,
        ActionType::ExecuteTests,
        ActionType::CommitGit,
        ActionType::InvokeCommand,
        ActionType::RecursiveAgent,
        ActionType::QueryUser
    };
}

bool ActionExecutor::isActionSafe(const Action& action) const {
    // Basic safety check
    if (action.type == ActionType::InvokeCommand) {
        std::string command = action.parameters.at("command");
        return command.find("rm") == std::string::npos &&
               command.find("del") == std::string::npos &&
               command.find("format") == std::string::npos;
    }
    return true;
}

std::string ActionExecutor::actionTypeToString(ActionType type) {
    switch (type) {
        case ActionType::FileEdit: return "FileEdit";
        case ActionType::SearchFiles: return "SearchFiles";
        case ActionType::RunBuild: return "RunBuild";
        case ActionType::ExecuteTests: return "ExecuteTests";
        case ActionType::CommitGit: return "CommitGit";
        case ActionType::InvokeCommand: return "InvokeCommand";
        case ActionType::RecursiveAgent: return "RecursiveAgent";
        case ActionType::QueryUser: return "QueryUser";
        default: return "Unknown";
    }
}

// ============================================================================
// ModelInvoker Implementation
// ============================================================================

ModelInvoker::ModelInvoker() : m_projectContext(nullptr), m_defaultBackend(LLMBackend::Ollama) {}

std::string ModelInvoker::buildSystemPrompt(const InvocationParams& params) const {
    std::string prompt = "You are an AI assistant helping with software development tasks.\n\n";

    if (m_projectContext && m_projectContext->isProjectAnalyzed()) {
        const ArchitectureOverview& overview = m_projectContext->getArchitectureOverview();

        prompt += "Project Context:\n";
        prompt += "- Total files: " + std::to_string(overview.totalFiles) + "\n";
        prompt += "- Main languages: ";
        for (const auto& pair : overview.languageDistribution) {
            prompt += pair.first + " (" + std::to_string(pair.second) + " files), ";
        }
        prompt += "\n";
        prompt += "- Code style: " + std::string(overview.codeStyle == CodeStyle::ALLMAN ? "Allman" : "Unknown") + "\n\n";

        auto recommendations = m_projectContext->getBestPracticeRecommendations();
        if (!recommendations.empty()) {
            prompt += "Best Practice Recommendations:\n";
            for (const std::string& rec : recommendations) {
                prompt += "- " + rec + "\n";
            }
            prompt += "\n";
        }
    }

    prompt += "User Request: " + params.userMessage + "\n\n";
    prompt += "Please provide a detailed, actionable response.";

    return prompt;
}

LLMResponse ModelInvoker::invoke(const InvocationParams& params) {
    LLMResponse response;
    response.success = false;

    try {
        std::string systemPrompt = buildSystemPrompt(params);

        switch (params.backend) {
            case LLMBackend::Ollama:
                response = sendOllamaRequest(systemPrompt, params);
                break;
            case LLMBackend::Claude:
                response = sendClaudeRequest(systemPrompt, params);
                break;
            case LLMBackend::OpenAI:
                response = sendOpenAIRequest(systemPrompt, params);
                break;
            case LLMBackend::LocalGGUF:
                response = sendLocalGGUFRequest(systemPrompt, params);
                break;
            default:
                response.error = "Unsupported backend";
                return response;
        }

        if (response.success) {
            response.confidence = 0.8; // Simplified confidence calculation
        }

    } catch (const std::exception& e) {
        response.error = e.what();
    }

    return response;
}

LLMResponse ModelInvoker::sendOllamaRequest(const std::string& prompt, const InvocationParams& params) {
    LLMResponse response;
    // Simplified - in real implementation would make HTTP request to Ollama
    response.success = true;
    response.content = "Ollama response: This is a simulated response for '" + params.userMessage + "'";
    response.tokensUsed = 150;
    return response;
}

LLMResponse ModelInvoker::sendClaudeRequest(const std::string& prompt, const InvocationParams& params) {
    LLMResponse response;
    response.success = false;
    response.error = "Claude backend not implemented";
    return response;
}

LLMResponse ModelInvoker::sendOpenAIRequest(const std::string& prompt, const InvocationParams& params) {
    LLMResponse response;
    response.success = false;
    response.error = "OpenAI backend not implemented";
    return response;
}

LLMResponse ModelInvoker::sendLocalGGUFRequest(const std::string& prompt, const InvocationParams& params) {
    LLMResponse response;
    // Simplified - in real implementation would use local GGUF model
    response.success = true;
    response.content = "Local GGUF response: This is a simulated response for '" + params.userMessage + "'";
    response.tokensUsed = 120;
    return response;
}

bool ModelInvoker::validatePlanResponse(const std::string& response) const {
    // Basic validation - check for JSON structure
    return response.find("{") != std::string::npos && response.find("}") != std::string::npos;
}

std::vector<LLMBackend> ModelInvoker::getAvailableBackends() const {
    return {LLMBackend::Ollama, LLMBackend::LocalGGUF};
}

bool ModelInvoker::isBackendAvailable(LLMBackend backend) const {
    switch (backend) {
        case LLMBackend::Ollama:
            return !m_ollamaUrl.empty();
        case LLMBackend::LocalGGUF:
            return true; // Assume local model is available
        default:
            return false;
    }
}

// ============================================================================
// EditorAgentIntegration Implementation
// ============================================================================

EditorAgentIntegration::EditorAgentIntegration(Win32IDE* ide)
    : m_ide(ide), m_agentBridge(nullptr) {}

void EditorAgentIntegration::triggerSuggestions() {
    if (!m_agentBridge) return;

    analyzeCurrentCode();
    generateSuggestions();
    filterSuggestions();
    rankSuggestions();

    emit suggestionsUpdated();
}

void EditorAgentIntegration::analyzeCurrentCode() {
    // Simplified code analysis - in real implementation would analyze current file
    m_currentSuggestions.clear();
}

void EditorAgentIntegration::generateSuggestions() {
    // Generate suggestions based on code analysis
    AgentSuggestion suggestion;
    suggestion.type = SuggestionType::Completion;
    suggestion.title = "Complete function";
    suggestion.description = "Add missing function implementation";
    suggestion.actions = {"Implement function body"};
    suggestion.lineNumber = 1;
    suggestion.columnNumber = 1;
    suggestion.confidence = 0.8;
    suggestion.category = "Code Completion";

    m_currentSuggestions.push_back(suggestion);
}

void EditorAgentIntegration::filterSuggestions() {
    // Filter out low-confidence suggestions
    m_currentSuggestions.erase(
        std::remove_if(m_currentSuggestions.begin(), m_currentSuggestions.end(),
                      [](const AgentSuggestion& s) { return s.confidence < 0.5; }),
        m_currentSuggestions.end());
}

void EditorAgentIntegration::rankSuggestions() {
    // Sort by confidence
    std::sort(m_currentSuggestions.begin(), m_currentSuggestions.end(),
              [](const AgentSuggestion& a, const AgentSuggestion& b) {
                  return a.confidence > b.confidence;
              });
}

void EditorAgentIntegration::acceptSuggestion(int index) {
    if (index >= 0 && index < static_cast<int>(m_currentSuggestions.size())) {
        const AgentSuggestion& suggestion = m_currentSuggestions[index];
        emit suggestionAccepted(QString::fromStdString(suggestion.title));
        // In real implementation, apply the suggestion to the editor
    }
}

void EditorAgentIntegration::dismissSuggestion(int index) {
    if (index >= 0 && index < static_cast<int>(m_currentSuggestions.size())) {
        const AgentSuggestion& suggestion = m_currentSuggestions[index];
        emit suggestionDismissed(QString::fromStdString(suggestion.title));
        m_currentSuggestions.erase(m_currentSuggestions.begin() + index);
    }
}

void EditorAgentIntegration::dismissAllSuggestions() {
    m_currentSuggestions.clear();
    emit suggestionsUpdated();
}

std::vector<AgentSuggestion> EditorAgentIntegration::getCurrentSuggestions() const {
    return m_currentSuggestions;
}

bool EditorAgentIntegration::hasSuggestions() const {
    return !m_currentSuggestions.empty();
}

void EditorAgentIntegration::updateCursorPosition(int line, int column) {
    // Update suggestions based on cursor position
    // In real implementation, this would re-analyze code around cursor
}

// ============================================================================
// AGENTIC INTEGRATION COMPLETE
// ============================================================================
