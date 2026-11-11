// Win32IDE_VSCodeUI.cpp - VS Code-like UI Components Implementation
// Activity Bar, Secondary Sidebar, Panel (Terminal/Output/Problems/Debug Console), Enhanced Status Bar

#include "Win32IDE.h"
#include <algorithm>
#include <commctrl.h>
#include <richedit.h>
#include <fstream>
#include <sstream>   
#include <iomanip>   
#include <string>
#include <vector>
#include "QtLogCompat.h"

// Heap-allocated strings retained by ListView/Tab controls (LVIF_TEXT / TCIF_TEXT
// do not copy text; they retain the pointer).  Cleared when the owning items
// are deleted or replaced.
static std::vector<char*> g_panelStringHeap;
static std::vector<char*> g_problemStringHeap;

// ProblemStringHeap bundles file+msg heap allocations for a problems ListView
// item so they can be freed together when the item is deleted/replaced.
struct ProblemStringHeap { char* file; char* msg; };
static std::vector<ProblemStringHeap*> g_problemHeapObjects;

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

// The activity bar is hosted by a STATIC window for lightweight painting, but
// STATIC controls do not forward child button notifications to the IDE.  Keep
// the native button behavior and explicitly forward the completed click to
// the main window so the live sidebar views are reachable.
static LRESULT CALLBACK ActivityBarButtonForwardProc(
    HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam,
    UINT_PTR, DWORD_PTR)
{
    // The original implementation created ordinary pushbuttons while a
    // separate, unused WM_DRAWITEM routine attempted to paint them.  The
    // stock button therefore repainted the icon surface with the system
    // theme, producing blended labels and stale pixels.  Paint the button in
    // the subclass that actually owns it, while leaving native click and
    // keyboard behavior intact.
    if (message == WM_ERASEBKGND) {
        return 1;
    }
    if (message == WM_PAINT) {
        PAINTSTRUCT ps{};
        HDC hdc = BeginPaint(hwnd, &ps);
        RECT rc{};
        GetClientRect(hwnd, &rc);

        const bool active = GetPropA(hwnd, "RawrXD.ActivityActive") != nullptr;
        const bool pressed = (GetKeyState(VK_LBUTTON) & 0x8000) != 0 &&
            (GetCapture() == hwnd);
        const COLORREF bg = pressed ? VSCODE_ACTIVITY_BAR_HOVER
            : (active ? VSCODE_ACTIVITY_BAR_ACTIVE : VSCODE_ACTIVITY_BAR_BG);
        HBRUSH brush = CreateSolidBrush(bg);
        FillRect(hdc, &rc, brush);
        DeleteObject(brush);

        if (active) {
            RECT indicator = rc;
            indicator.right = 3;
            HBRUSH indicatorBrush = CreateSolidBrush(VSCODE_ACTIVITY_BAR_INDICATOR);
            FillRect(hdc, &indicator, indicatorBrush);
            DeleteObject(indicatorBrush);
        }

        char label[32]{};
        GetWindowTextA(hwnd, label, static_cast<int>(sizeof(label)));
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, VSCODE_ACTIVITY_BAR_ICON);
        DrawTextA(hdc, label, -1, &rc,
                  DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        EndPaint(hwnd, &ps);
        return 0;
    }
    if (message == WM_NCDESTROY) {
        RemovePropA(hwnd, "RawrXD.ActivityActive");
    }

    const bool activate = message == WM_LBUTTONUP ||
        (message == WM_KEYUP && (wParam == VK_SPACE || wParam == VK_RETURN));
    const LRESULT result = DefSubclassProc(hwnd, message, wParam, lParam);
    if (activate) {
        HWND activityBar = GetParent(hwnd);
        HWND mainWindow = activityBar ? GetParent(activityBar) : nullptr;
        if (mainWindow) {
            SendMessageA(mainWindow, WM_COMMAND,
                MAKEWPARAM(GetDlgCtrlID(hwnd), BN_CLICKED),
                reinterpret_cast<LPARAM>(hwnd));
        }
    }
    return result;
}

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
        hwndParent, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_ACTIVITY_BAR)), m_hInstance, nullptr);
    
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
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            0, yPos, ACTIVITY_BAR_WIDTH, buttonHeight,
            m_hwndActivityBar, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_ACTBAR_EXPLORER + i)), m_hInstance, nullptr);
        
        // Store IDE pointer for button subclass
        SetWindowLongPtr(m_activityBarButtons[i], GWLP_USERDATA, (LONG_PTR)this);
        SetPropA(m_activityBarButtons[i], "RawrXD.ActivityActive",
                 reinterpret_cast<HANDLE>(static_cast<INT_PTR>(i == 0 ? 1 : 0)));
        SetWindowSubclass(m_activityBarButtons[i], ActivityBarButtonForwardProc, 1, 0);
        
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
            SetPropA(m_activityBarButtons[i], "RawrXD.ActivityActive",
                     reinterpret_cast<HANDLE>(static_cast<INT_PTR>(
                         i == m_activeActivityBarButton ? 1 : 0)));
            InvalidateRect(m_activityBarButtons[i], nullptr, TRUE);
            UpdateWindow(m_activityBarButtons[i]);
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
        hwndParent, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_SECONDARY_SIDEBAR)), m_hInstance, nullptr);
    
    // Header label
    m_hwndSecondarySidebarHeader = CreateWindowExA(
        0, "STATIC", " GitHub Copilot Chat",
        WS_CHILD | WS_VISIBLE | SS_LEFT | SS_CENTERIMAGE,
        0, 0, m_secondarySidebarWidth, 28,
        m_hwndSecondarySidebar, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_SECONDARY_SIDEBAR_HEADER)), m_hInstance, nullptr);

    // Keep parity with createChatPanel: step strip above transcript.
    HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
    m_agentStepTimeline.onRow = [this](const std::string& line) {
        if (line.empty()) return;
        if (auto* session = activeChatSession()) {
            session->stepRows.push_back(line);
        }
        if (m_hwndCopilotChatOutput) {
            appendCopilotChatUtf8("\r\n" + line + "\r\n");
        }
    };
    m_agentStepTimeline.create(m_hwndSecondarySidebar, m_hInstance, hFont,
                               5, 32, m_secondarySidebarWidth - 10, 88);
    
    // Chat output/input must be CreateWindowExW so UTF-16 WM_SETTEXT survives
    // (CreateWindowExA EDIT maps CJK to '?'; measured MULTILINE_UNICODE=FAIL).
    m_hwndCopilotChatOutput = CreateWindowExW(
        WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
        5, 125, m_secondarySidebarWidth - 10, 357,
        m_hwndSecondarySidebar, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_COPILOT_CHAT_OUTPUT)), m_hInstance, nullptr);
    
    m_hwndCopilotChatInput = CreateWindowExW(
        WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | ES_WANTRETURN | WS_VSCROLL,
        5, 490, m_secondarySidebarWidth - 10, 60,
        m_hwndSecondarySidebar, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_COPILOT_CHAT_INPUT)), m_hInstance, nullptr);
    
    // Send button
    m_hwndCopilotSendBtn = CreateWindowExA(
        0, "BUTTON", "Send",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        5, 555, 80, 28,
        m_hwndSecondarySidebar, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_COPILOT_SEND_BTN)), m_hInstance, nullptr);
    
    // Clear button
    m_hwndCopilotClearBtn = CreateWindowExA(
        0, "BUTTON", "Clear",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        90, 555, 80, 28,
        m_hwndSecondarySidebar, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_COPILOT_CLEAR_BTN)), m_hInstance, nullptr);
    
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
    // Rebuild the transcript with explicit Windows line endings.  The old
    // implementation used bare LF and the streaming callback prefixed every
    // fragment with "AI:", making adjacent messages look duplicated.
    std::string chatText;
    if (m_chatHistory.empty()) {
        chatText = "Welcome to RawrXD AI Chat!\r\n\r\n"
                   "Select a model and type a message to begin.\r\n";
    }
    for (const auto& msg : m_chatHistory) {
        if (msg.first == "user") {
            chatText += "> User: " + msg.second + "\r\n\r\n";
        } else {
            chatText += "AI: " + msg.second + "\r\n\r\n";
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
    
    qInfo() << "=== SEND MESSAGE CLICKED ===";
    qInfo() << "[sendCopilotMessage] Message: " << message.c_str();
    
    // Add user message to history
    m_chatHistory.push_back({"user", message});
    
    // Generate response using the AI inference system
    std::string response;
    
    if (isModelLoaded()) {
        qInfo() << "[sendCopilotMessage] Model is loaded, calling generateResponse...";
        // Use the loaded GGUF model for inference
        response = generateResponse(message);
        qInfo() << "[sendCopilotMessage] Inference response: " << response.c_str();
    } else {
        // No model loaded - prompt user to load one
        qWarning() << "[sendCopilotMessage] No model loaded!";
        response = " No AI model loaded.\r\n\r\n"
                   "To use AI assistance, please load a GGUF model:\r\n"
                   "1. Open the File Explorer (Activity Bar  Explorer icon)\r\n"
                   "2. Navigate to a folder containing .gguf files\r\n"
                   "3. Double-click a model file to load it\r\n\r\n"
                   "Supported models: LLaMA, Mistral, Phi, Qwen, and other GGUF-compatible models.\r\n\r\n"
                   "Once loaded, I can help with:\r\n"
                   " Code explanation and analysis\r\n"
                   " Bug fixing suggestions\r\n"
                   " Code generation\r\n"
                   " Programming questions";
    }
    
    m_chatHistory.push_back({"assistant", response});
    qInfo() << "[sendCopilotMessage] Added response to history, updating UI...";
    qInfo() << "=== SEND MESSAGE END ===";
    
    // Update display
    updateSecondarySidebarContent();
    
    // Clear input
    SetWindowTextA(m_hwndCopilotChatInput, "");
}

void Win32IDE::clearCopilotChat()
{
    cancelComputerUse();
    m_chatHistory.clear();
    disarmAgentThoughtTimer();
    m_agentStepTimeline.clear();
    if (auto* session = activeChatSession()) session->stepRows.clear();
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
    Win32IDE* pThis = reinterpret_cast<Win32IDE*>(GetPropA(hwnd, "IDE_PTR"));

    if (uMsg == WM_COPYDATA && pThis) {
        auto* cds = reinterpret_cast<COPYDATASTRUCT*>(lParam);
        if (cds && cds->lpData && cds->cbData > 0 &&
            static_cast<ULONG_PTR>(cds->dwData) == kRawrxdChatInputCopyDataCmd) {
            std::string text(static_cast<const char*>(cds->lpData),
                             static_cast<size_t>(cds->cbData));
            while (!text.empty() &&
                   (text.back() == '\0' || text.back() == '\r' || text.back() == '\n')) {
                text.pop_back();
            }
            const bool ok = pThis->stageCopilotChatInputUtf8(text);
            return ok ? TRUE : FALSE;
        }
    }

    // Route the session-strip action buttons directly from the owning sidebar.
    // These controls are children of the subclassed STATIC container; relying
    // only on a forwarded WM_COMMAND made the close button sensitive to the
    // parent-procedure chain and left the visible X inert in some launches.
    if (uMsg == WM_COMMAND && pThis && HIWORD(wParam) == BN_CLICKED) {
        const int commandId = LOWORD(wParam);
        const HWND source = reinterpret_cast<HWND>(lParam);
        if (commandId == IDC_CLOSE_CHAT || source == pThis->m_hwndCloseChatBtn) {
            pThis->closeActiveChatSession();
            return 0;
        }
        if (commandId == IDC_NEW_CHAT || source == pThis->m_hwndNewChatBtn) {
            pThis->createChatSession();
            return 0;
        }
        if (commandId == IDC_RESTORE_CHAT || source == pThis->m_hwndRestoreChatBtn) {
            pThis->restoreClosedChatSession();
            return 0;
        }
        if (commandId == IDC_ROLLBACK_CHAT || source == pThis->m_hwndRollbackChatBtn) {
            pThis->rollbackActiveChat();
            return 0;
        }
    }

    // Child controls are owned by this sidebar, while the command router lives
    // on the main IDE window. Forward notifications with their original
    // control HWND so routing remains unambiguous (especially New Chat and
    // the model selectors).
    if ((uMsg == WM_COMMAND || uMsg == WM_NOTIFY) && GetParent(hwnd)) {
        return SendMessageA(GetParent(hwnd), uMsg, wParam, lParam);
    }
    
    switch (uMsg) {
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLOREDIT:
        {
            if (pThis) {
                // Route sidebar controls through the live theme instead of
                // the startup-only VSCODE_SIDEBAR_BG brush.  The old static
                // brush made this subtree ignore dark/light theme switches.
                return pThis->handleThemeControlColor(uMsg, wParam, lParam);
            }
            HDC hdc = (HDC)wParam;
            SetBkColor(hdc, VSCODE_SIDEBAR_BG);
            SetTextColor(hdc, RGB(204, 204, 204));
            static HBRUSH hBrush = CreateSolidBrush(VSCODE_SIDEBAR_BG);
            return (LRESULT)hBrush;
        }
    }
    
    WNDPROC oldProc = reinterpret_cast<WNDPROC>(GetPropA(hwnd, "OLDPROC"));
    // Sidebar host is subclassed via SetWindowLongPtrW — keep W path.
    return oldProc ? CallWindowProcW(oldProc, hwnd, uMsg, wParam, lParam)
                   : DefWindowProcW(hwnd, uMsg, wParam, lParam);
}

// ============================================================================
// Panel (Bottom) - Terminal, Output, Problems, Debug Console
// ============================================================================

LRESULT CALLBACK Win32IDE::PanelContainerThemeProc(
    HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam,
    UINT_PTR, DWORD_PTR refData)
{
    // Bottom-dock STATIC paints COLOR_WINDOW gray unless themed here.
    auto* ide = reinterpret_cast<Win32IDE*>(refData);
    if (message == WM_ERASEBKGND && ide) {
        HDC hdc = reinterpret_cast<HDC>(wParam);
        RECT rc{};
        GetClientRect(hwnd, &rc);
        if (HBRUSH brush = ide->panelThemeBackgroundBrush()) {
            FillRect(hdc, &rc, brush);
            return 1;
        }
    }
    if (message == WM_PAINT && ide) {
        PAINTSTRUCT ps{};
        HDC hdc = BeginPaint(hwnd, &ps);
        if (HBRUSH brush = ide->panelThemeBackgroundBrush()) {
            FillRect(hdc, &ps.rcPaint, brush);
        }
        EndPaint(hwnd, &ps);
        return 0;
    }
    if (message == WM_CTLCOLORSTATIC || message == WM_CTLCOLOREDIT ||
        message == WM_CTLCOLORLISTBOX || message == WM_CTLCOLORBTN ||
        message == WM_CTLCOLORDLG) {
        if (ide) {
            return ide->panelThemeControlColor(message, wParam, lParam);
        }
    }
    if ((message == WM_COMMAND || message == WM_NOTIFY) && GetParent(hwnd)) {
        return SendMessageA(GetParent(hwnd), message, wParam, lParam);
    }
    return DefSubclassProc(hwnd, message, wParam, lParam);
}

HBRUSH Win32IDE::panelThemeBackgroundBrush()
{
    if (!m_backgroundBrush) {
        m_backgroundBrush = CreateSolidBrush(m_currentTheme.backgroundColor);
    }
    return m_backgroundBrush;
}

LRESULT Win32IDE::panelThemeControlColor(UINT message, WPARAM wParam, LPARAM lParam)
{
    return handleThemeControlColor(message, wParam, lParam);
}

void Win32IDE::createPanel(HWND hwndParent)
{
    m_panelVisible = true;
    m_panelMaximized = false;
    // Keep a previously restored session height (loadIdeSession may run before
    // a late createPanel); only seed default when unset/collapsed.
    if (m_panelHeight < 160) {
        m_panelHeight = 250;
    }
    m_activePanelTab = PanelTab::Terminal;
    m_errorCount = 0;
    m_warningCount = 0;
    
    // Create panel container. During WM_CREATE avoid WS_VISIBLE (same hang
    // class as doc-tabs); show after ensurePanelVisible/layoutBottomDock.
    const DWORD panelStyle = WS_CHILD | WS_CLIPCHILDREN | WS_CLIPSIBLINGS |
        (IsWindowVisible(hwndParent) ? WS_VISIBLE : 0);
    SetLastError(0);
    m_hwndPanelContainer = CreateWindowExA(
        0, "STATIC", "",
        panelStyle,
        0, 0, 800, m_panelHeight,
        hwndParent, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_PANEL_CONTAINER)), m_hInstance, nullptr);
    if (m_hwndPanelContainer) {
        SetWindowSubclass(m_hwndPanelContainer, &Win32IDE::PanelContainerThemeProc, 1,
                          reinterpret_cast<DWORD_PTR>(this));
    }
    {
        const DWORD createErr = GetLastError();
        std::ofstream trace("F:\\rawrxd\\startup_trace.log", std::ios::app);
        if (trace) {
            // Non-null HWND + leftover err=183 is TLS noise, not create failure.
            // parentVis=0 during WM_CREATE is intentional (WS_VISIBLE deferred).
            trace << "createPanel: hwnd=" << m_hwndPanelContainer
                  << " err=" << (m_hwndPanelContainer ? 0 : createErr)
                  << " parentVis=" << (IsWindowVisible(hwndParent) ? 1 : 0) << '\n';
            trace.flush();
        }
    }
    
    // Create tab control for panel views
    m_hwndPanelTabs = CreateWindowExA(
        0, WC_TABCONTROLA, "",
        WS_CHILD | WS_VISIBLE | TCS_TABS | TCS_FOCUSNEVER,
        0, 0, 400, 24,
        m_hwndPanelContainer, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_PANEL_TABS)), m_hInstance, nullptr);
    
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
        m_hwndPanelContainer, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_PANEL_TOOLBAR)), m_hInstance, nullptr);
    
    // Toolbar buttons
    m_hwndPanelNewTerminalBtn = CreateWindowExA(
        0, "BUTTON", "+",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        0, 0, 24, 22,
        m_hwndPanelToolbar, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_PANEL_BTN_NEW_TERMINAL)), m_hInstance, nullptr);
    
    m_hwndPanelSplitTerminalBtn = CreateWindowExA(
        0, "BUTTON", "||",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        26, 0, 24, 22,
        m_hwndPanelToolbar, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_PANEL_BTN_SPLIT_TERMINAL)), m_hInstance, nullptr);
    
    m_hwndPanelKillTerminalBtn = CreateWindowExA(
        0, "BUTTON", "X",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        52, 0, 24, 22,
        m_hwndPanelToolbar, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_PANEL_BTN_KILL_TERMINAL)), m_hInstance, nullptr);
    
    m_hwndPanelMaximizeBtn = CreateWindowExA(
        0, "BUTTON", "^",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        130, 0, 24, 22,
        m_hwndPanelToolbar, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_PANEL_BTN_MAXIMIZE)), m_hInstance, nullptr);
    
    m_hwndPanelCloseBtn = CreateWindowExA(
        0, "BUTTON", "x",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        156, 0, 24, 22,
        m_hwndPanelToolbar, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_PANEL_BTN_CLOSE)), m_hInstance, nullptr);
    
    // Create all four panel-body HWNDs (1302/1303/1312/1305) so VisId probes
    // never see ABSENT after createPanel. Bodies start hidden; switchPanelTab
    // ShowWindow/create-if-missing owns visibility. Do not call switchPanelTab
    // here — createPanel can run under WM_CREATE / TabCtrl_InsertItem depth.
    ensurePanelTabBodies();
}

void Win32IDE::togglePanel()
{
    m_panelVisible = !m_panelVisible;
    if (m_hwndPanelContainer && IsWindow(m_hwndPanelContainer)) {
        ShowWindow(m_hwndPanelContainer, m_panelVisible ? SW_SHOW : SW_HIDE);
    }
    // Prefer ensurePanelVisible layout when showing (deferred WM_SIZE).
    if (m_panelVisible) {
        ensurePanelVisible();
        return;
    }
    if (m_hwndMain && IsWindow(m_hwndMain)) {
        RECT rect{};
        if (GetClientRect(m_hwndMain, &rect) && rect.right > 0 && rect.bottom > 0) {
            PostMessageA(m_hwndMain, WM_SIZE, SIZE_RESTORED,
                         MAKELPARAM(rect.right, rect.bottom));
        }
    }
}

void Win32IDE::layoutBottomDock()
{
    // Re-entrancy-safe bottom dock for IDC_PANEL_CONTAINER (1300) + list
    // (1312). Assign non-zero height so IsWindowVisible does not stay 0 after
    // ShowWindow on a zero-rect child (G7 FOUR_PANEL / INTEG_007→008).
    // No TabCtrl_InsertItem / onSize — safe from switchPanelTab create path.
    // Hard floor: dockH >= 160 whenever client can hold it (74AA collapse fix).
    static volatile const char kG7DockLayoutMark[] =
        "G7_layoutBottomDock_SetWindowPos_1300";
    if (kG7DockLayoutMark[0] == 0 || !m_hwndMain || !IsWindow(m_hwndMain) ||
        !m_hwndPanelContainer || !IsWindow(m_hwndPanelContainer)) {
        return;
    }
    if (IsIconic(m_hwndMain)) {
        return;
    }
    RECT rc{};
    if (!GetClientRect(m_hwndMain, &rc)) {
        return;
    }
    const int width = rc.right - rc.left;
    const int height = rc.bottom - rc.top;
    if (width <= 0 || height <= 0) {
        return;
    }
    int statusH = 24;
    if (m_hwndStatusBar && IsWindow(m_hwndStatusBar)) {
        RECT sr{};
        if (GetClientRect(m_hwndStatusBar, &sr) && sr.bottom > sr.top) {
            statusH = sr.bottom - sr.top;
        }
    }
    if (m_panelHeight < 160) {
        m_panelHeight = 250;
    }
    const int bottomHeight = (std::min)(420, (std::max)(160, m_panelHeight));
    const int avail = (std::max)(0, height - statusH - 80);
    int dockH = (std::min)(bottomHeight, (std::max)(160, avail));
    if (height - statusH >= 160) {
        dockH = (std::max)(160, dockH);
    }
    const int bottomTop = (std::max)(0, height - statusH - dockH);
    // No SWP_SHOWWINDOW — that re-entered WM_COMMAND/show paths as 0xC000041D
    // on 604D when ensurePanelVisible ran layoutBottomDock synchronously.
    SetWindowPos(m_hwndPanelContainer, nullptr, 0, bottomTop, width, dockH,
                 SWP_NOZORDER | SWP_NOACTIVATE);
    if (m_hwndPanelTabs && IsWindow(m_hwndPanelTabs)) {
        MoveWindow(m_hwndPanelTabs, 0, 0, (std::max)(0, width - 200), 24, TRUE);
    }
    if (m_hwndPanelToolbar && IsWindow(m_hwndPanelToolbar)) {
        MoveWindow(m_hwndPanelToolbar, (std::max)(0, width - 200), 0, 200, 24, TRUE);
    }
    const int bodyH = (std::max)(1, dockH - 26);
    if (m_hwndPanelTerminal && IsWindow(m_hwndPanelTerminal)) {
        MoveWindow(m_hwndPanelTerminal, 0, 26, width, bodyH, TRUE);
    }
    if (m_hwndPanelOutput && IsWindow(m_hwndPanelOutput)) {
        MoveWindow(m_hwndPanelOutput, 0, 26, width, bodyH, TRUE);
    }
    if (m_hwndProblemsListView && IsWindow(m_hwndProblemsListView)) {
        MoveWindow(m_hwndProblemsListView, 0, 26, width, bodyH, TRUE);
    }
    if (m_hwndDebugConsole && IsWindow(m_hwndDebugConsole)) {
        MoveWindow(m_hwndDebugConsole, 0, 26, width, bodyH, TRUE);
    }
    // Single owner: never leave peer PowerShell / legacy strip visible over 1300.
    if (m_hwndPowerShellPanel && IsWindow(m_hwndPowerShellPanel)) {
        ShowWindow(m_hwndPowerShellPanel, SW_HIDE);
    }
    m_powerShellPanelVisible = false;
    if (m_hwndOutputTabs && IsWindow(m_hwndOutputTabs)) {
        ShowWindow(m_hwndOutputTabs, SW_HIDE);
    }
    if (m_hwndSeverityFilter && IsWindow(m_hwndSeverityFilter)) {
        ShowWindow(m_hwndSeverityFilter, SW_HIDE);
    }
    if (m_hwndSplitter && IsWindow(m_hwndSplitter)) {
        const int splitterY = (std::max)(0, bottomTop - 4);
        MoveWindow(m_hwndSplitter, 0, splitterY, width, 4, TRUE);
        ShowWindow(m_hwndSplitter, SW_SHOW);
    }
}

void Win32IDE::ensurePanelVisible()
{
    // Show-only product path for four-panel (Problems/Output/Terminal/Debug).
    // IDM_VIEW_PANEL must not toggle the dock away, and the exclusive
    // PowerShell surface must not suppress IDC_PANEL_CONTAINER after Build.
    // Do NOT call onSize here: switchPanelTab may run from TabCtrl_InsertItem
    // during createPanel/WM_CREATE; nested onSize → stack death (INTEG_007).
    // W3/604D: sync layoutBottomDock from WM_COMMAND → 0xC000041D. Flags +
    // ShowWindow only; geometry via posted WM_SIZE once layout is armed.
    static volatile const char kG7DockMark[] =
        "G7_ensurePanelVisible_ShowWindow_1300";
    if (kG7DockMark[0] == 0) {
        return;
    }
    try {
        m_panelVisible = true;
        m_outputPanelVisible = true;
        if (m_powerShellPanelVisible) {
            if (m_hwndPowerShellPanel && IsWindow(m_hwndPowerShellPanel)) {
                ShowWindow(m_hwndPowerShellPanel, SW_HIDE);
            }
            m_powerShellPanelVisible = false;
        }
        if (m_hwndPanelContainer && IsWindow(m_hwndPanelContainer)) {
            ShowWindow(m_hwndPanelContainer, SW_SHOW);
        }
        if (m_hwndMain && IsWindow(m_hwndMain)) {
            RECT rc{};
            if (GetClientRect(m_hwndMain, &rc) && rc.right > 0 && rc.bottom > 0) {
                PostMessageA(m_hwndMain, WM_SIZE, SIZE_RESTORED,
                             MAKELPARAM(rc.right, rc.bottom));
            }
        }
    } catch (...) {
        // Never let panel show escape as FATAL_USER_CALLBACK from a command.
    }
}

void Win32IDE::maximizePanel()
{
    // File-local: Win32IDE.h was locked by concurrent rebuild; keep P08
    // unmaximize restore without a new member.
    static int s_heightBeforeMaximize = 0;
    m_panelMaximized = !m_panelMaximized;
    
    if (m_panelMaximized) {
        if (s_heightBeforeMaximize < 160) {
            s_heightBeforeMaximize =
                (m_panelHeight >= 160) ? m_panelHeight : 250;
        }
        RECT rect;
        GetClientRect(m_hwndMain, &rect);
        m_panelHeight = rect.bottom - 100; // Leave some space for toolbar/status
        SetWindowTextA(m_hwndPanelMaximizeBtn, "v");
    } else {
        // Never hardcode 250 — that wiped dragged dock height (P08).
        m_panelHeight = (s_heightBeforeMaximize >= 160)
            ? s_heightBeforeMaximize
            : 250;
        s_heightBeforeMaximize = 0;
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

void Win32IDE::ensurePanelTabBodies()
{
    // Create-if-missing stable VisId bodies under IDC_PANEL_CONTAINER.
    // No onSize / TabCtrl_InsertItem — safe during createPanel + switchPanelTab.
    if (!m_hwndPanelContainer || !IsWindow(m_hwndPanelContainer)) {
        return;
    }
    const int bodyH = (std::max)(1, m_panelHeight - 26);
    auto makeEdit = [&](HWND& slot, int ctrlId, const char* seed) {
        if (slot && IsWindow(slot)) {
            return;
        }
        slot = CreateWindowExA(
            WS_EX_CLIENTEDGE, RICHEDIT_CLASSA, "",
            WS_CHILD | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
            0, 26, 800, bodyH, m_hwndPanelContainer,
            reinterpret_cast<HMENU>(static_cast<UINT_PTR>(ctrlId)),
            m_hInstance, nullptr);
        if (!slot) {
            slot = CreateWindowExA(
                WS_EX_CLIENTEDGE, "EDIT", "",
                WS_CHILD | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
                0, 26, 800, bodyH, m_hwndPanelContainer,
                reinterpret_cast<HMENU>(static_cast<UINT_PTR>(ctrlId)),
                m_hInstance, nullptr);
        }
        if (slot) {
            if (seed && seed[0]) {
                appendText(slot, seed);
            }
            ShowWindow(slot, SW_HIDE);
        }
    };

    makeEdit(m_hwndPanelTerminal, IDC_PANEL_TERMINAL,
             "Terminal ready. Select this tab or use Terminal menu to run a shell.\r\n");
    makeEdit(m_hwndPanelOutput, IDC_PANEL_OUTPUT,
             "Output ready. Build and tool messages appear here.\r\n");

    if (!m_hwndProblemsListView || !IsWindow(m_hwndProblemsListView)) {
        m_hwndProblemsListView = CreateWindowExA(
            WS_EX_CLIENTEDGE, WC_LISTVIEWA, "",
            WS_CHILD | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
            0, 26, 800, bodyH, m_hwndPanelContainer,
            reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_PANEL_PROBLEMS_LIST)),
            m_hInstance, nullptr);
        if (m_hwndProblemsListView) {
            ListView_SetExtendedListViewStyle(
                m_hwndProblemsListView, LVS_EX_FULLROWSELECT | LVS_EX_LABELTIP);
            LVCOLUMNA lvc = { 0 };
            lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
            lvc.pszText = const_cast<char*>("Severity");
            lvc.cx = 70; lvc.iSubItem = 0;
            ListView_InsertColumn(m_hwndProblemsListView, 0, &lvc);
            lvc.pszText = const_cast<char*>("Message");
            lvc.cx = 400; lvc.iSubItem = 1;
            ListView_InsertColumn(m_hwndProblemsListView, 1, &lvc);
            lvc.pszText = const_cast<char*>("File");
            lvc.cx = 200; lvc.iSubItem = 2;
            ListView_InsertColumn(m_hwndProblemsListView, 2, &lvc);
            lvc.pszText = const_cast<char*>("Line");
            lvc.cx = 60; lvc.iSubItem = 3;
            ListView_InsertColumn(m_hwndProblemsListView, 3, &lvc);
            ShowWindow(m_hwndProblemsListView, SW_HIDE);
        }
    }

    makeEdit(m_hwndDebugConsole, IDC_PANEL_DEBUG_CONSOLE,
             "Debug Console ready. Start a debug session to see debugger output.\r\n");
}

void Win32IDE::switchPanelTab(PanelTab tab)
{
    // TabCtrl_InsertItem during createPanel can raise TCN_SELCHANGE into this
    // path; never re-enter ensurePanelVisible/createPanel (WM_CREATE stack
    // death). Exclusive ShowWindow MUST still run on re-entry — early-return
    // that only set m_activePanelTab left 1302 WS_VISIBLE stuck True while
    // 1303/1312/1305 stayed hidden (Batch18 P07 HWND_VIS exclusive FAIL).
    static thread_local int s_switchDepth = 0;
    const bool reentered = (s_switchDepth > 0);
    ++s_switchDepth;

    m_activePanelTab = tab;
    if (!reentered) {
        ensurePanelVisible();
        if (m_hwndMain && IsWindow(m_hwndMain) &&
            (!m_hwndPanelContainer || !IsWindow(m_hwndPanelContainer))) {
            createPanel(m_hwndMain);
            ensurePanelVisible();
        }
        ensurePanelTabBodies();
    }

    const bool showTerminal = (tab == PanelTab::Terminal);
    const bool showOutput = (tab == PanelTab::Output);
    const bool showProblems = (tab == PanelTab::Problems);
    const bool showDebugConsole = (tab == PanelTab::DebugConsole);

    // ShowWindow only — no SetWindowLongPtr GWL_STYLE, no SWP_SHOWWINDOW,
    // no SWP_FRAMECHANGED. Those re-enter comctl32 ListView paint/notify and
    // fault as 0xC000041D when selecting PROBLEMS (Batch18 P07 crash on sel=2).
    auto showBody = [](HWND hwnd, bool show) {
        if (!hwnd || !IsWindow(hwnd)) return;
        ShowWindow(hwnd, show ? SW_SHOW : SW_HIDE);
        if (show) {
            BringWindowToTop(hwnd);
        }
    };

    showBody(m_hwndPanelTerminal, showTerminal);
    showBody(m_hwndPanelOutput, showOutput);
    showBody(m_hwndProblemsListView, showProblems);
    showBody(m_hwndDebugConsole, showDebugConsole);

    // Peer legacy panes stay hidden so they cannot cover 1302/1303 VisId bodies.
    for (auto& pane : m_terminalPanes) {
        if (pane.hwnd) ShowWindow(pane.hwnd, SW_HIDE);
        if (pane.input) ShowWindow(pane.input, SW_HIDE);
        if (pane.execute) ShowWindow(pane.execute, SW_HIDE);
        if (pane.stop) ShowWindow(pane.stop, SW_HIDE);
        if (pane.clear) ShowWindow(pane.clear, SW_HIDE);
    }
    for (auto& kv : m_outputWindows) {
        if (kv.second) ShowWindow(kv.second, SW_HIDE);
    }

    if (!reentered) {
        // Geometry via posted WM_SIZE only — sync layoutBottomDock here
        // previously faulted on the WM_COMMAND/show path (0xC000041D).
        if (m_hwndMain && IsWindow(m_hwndMain)) {
            RECT rc{};
            if (GetClientRect(m_hwndMain, &rc) && rc.right > 0 && rc.bottom > 0) {
                PostMessageA(m_hwndMain, WM_SIZE, SIZE_RESTORED,
                             MAKELPARAM(rc.right, rc.bottom));
            }
        }
        if (m_hwndPanelTabs && IsWindow(m_hwndPanelTabs))
            TabCtrl_SetCurSel(m_hwndPanelTabs, static_cast<int>(tab));
        if (m_hwndPanelNewTerminalBtn)
            EnableWindow(m_hwndPanelNewTerminalBtn, showTerminal);
        if (m_hwndPanelSplitTerminalBtn)
            EnableWindow(m_hwndPanelSplitTerminalBtn, showTerminal);
        if (m_hwndPanelKillTerminalBtn)
            EnableWindow(m_hwndPanelKillTerminalBtn, showTerminal);
    }

    --s_switchDepth;
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
    
    // Free previous panel tab text (TabCtrl_SetItem retains pszText).
    for (auto* ptr : g_panelStringHeap) delete[] ptr;
    g_panelStringHeap.clear();
    
    char* tabTextHeap = new char[problemsTabText.length() + 1];
    strcpy_s(tabTextHeap, problemsTabText.length() + 1, problemsTabText.c_str());
    g_panelStringHeap.push_back(tabTextHeap);
    
    TCITEMA tie = { TCIF_TEXT };
    tie.pszText = tabTextHeap;
    TabCtrl_SetItem(m_hwndPanelTabs, 2, &tie);
}

#if 0 // DUP_addProblem BATCH17_DUP_DISABLE
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

    // Model always updates; ListView is optional until the panel HWND exists.
    if (!m_hwndProblemsListView || !IsWindow(m_hwndProblemsListView)) {
        updatePanelContent();
        updateEnhancedStatusBar();
        return;
    }
    
    // Add to list view
    LVITEMA lvi = { 0 };
    lvi.mask = LVIF_TEXT | LVIF_PARAM;
    lvi.iItem = static_cast<int>(m_problems.size() - 1);
    
    const char* severityStr = (severity == 0) ? "Error" : (severity == 1) ? "Warning" : "Info";
    lvi.pszText = const_cast<char*>(severityStr);
    lvi.lParam = reinterpret_cast<LPARAM>(new ProblemStringHeap{});
    auto* problemHeap = reinterpret_cast<ProblemStringHeap*>(lvi.lParam);
    problemHeap->file = new char[file.length() + 1];
    strcpy_s(problemHeap->file, file.length() + 1, file.c_str());
    problemHeap->msg = new char[msg.length() + 1];
    strcpy_s(problemHeap->msg, msg.length() + 1, msg.c_str());
    g_problemHeapObjects.push_back(problemHeap);
    ListView_InsertItem(m_hwndProblemsListView, &lvi);
    
    // Set item text using direct SendMessage calls with ANSI structures
    LVITEMA lviSet = { 0 };
    lviSet.iSubItem = 1;
    lviSet.pszText = problemHeap->msg;
    lviSet.lParam = reinterpret_cast<LPARAM>(problemHeap);
    SendMessage(m_hwndProblemsListView, LVM_SETITEMTEXTA, lvi.iItem, (LPARAM)&lviSet);
    
    lviSet.iSubItem = 2;
    lviSet.pszText = problemHeap->file;
    lviSet.lParam = reinterpret_cast<LPARAM>(problemHeap);
    SendMessage(m_hwndProblemsListView, LVM_SETITEMTEXTA, lvi.iItem, (LPARAM)&lviSet);
    
    char lineStrBuf[32];
    _snprintf_s(lineStrBuf, sizeof(lineStrBuf), _TRUNCATE, "%d", line);
    char* lineHeap = new char[strlen(lineStrBuf) + 1];
    strcpy_s(lineHeap, strlen(lineStrBuf) + 1, lineStrBuf);
    g_problemStringHeap.push_back(lineHeap);
    lviSet.iSubItem = 3;
    lviSet.pszText = lineHeap;
    lviSet.lParam = reinterpret_cast<LPARAM>(lineHeap);
    SendMessage(m_hwndProblemsListView, LVM_SETITEMTEXTA, lvi.iItem, (LPARAM)&lviSet);
    
    // Surface Problems tab when real diagnostics arrive.
    switchPanelTab(PanelTab::Problems);
    updatePanelContent();
    updateEnhancedStatusBar();
}
#endif // DUP_addProblem

#if 0 // DUP_clearProblems BATCH17_DUP_DISABLE
void Win32IDE::clearProblems()
{
    // Free heap-allocated problem strings before deleting items.
    for (auto* heapObj : g_problemHeapObjects) {
        delete[] heapObj->file;
        delete[] heapObj->msg;
        delete heapObj;
    }
    g_problemHeapObjects.clear();
    for (auto* ptr : g_problemStringHeap) {
        delete[] ptr;
    }
    g_problemStringHeap.clear();
    m_problems.clear();
    m_errorCount = 0;
    m_warningCount = 0;
    for (auto& pane : m_terminalPanes) {
        pane.diagCarry.clear();
    }
    if (m_hwndProblemsListView) {
        ListView_DeleteAllItems(m_hwndProblemsListView);
    }
    updatePanelContent();
    updateEnhancedStatusBar();
}
#endif // DUP_clearProblems

void cleanupVSCodeUIStrings()
{
    // Free VSCodeUI panel heap-allocated control strings on window destruction.
    for (auto* ptr : g_panelStringHeap) delete[] ptr;
    g_panelStringHeap.clear();
    for (auto* ptr : g_problemStringHeap) delete[] ptr;
    g_problemStringHeap.clear();
}

void Win32IDE::goToProblem(int index)
{
    // B12: openDocumentPath + RichEdit EM_EXSETSEL caret (not POSTED_NM_DBLCLK alone).
    OutputDebugStringA("B12_NAV_OPENDOC_PATH=1\n");
    auto writeProof = [](const std::string& body) {
        std::ofstream proof("F:\\rawrxd\\evidence\\B12_NAVIGATE_LATEST.log",
                            std::ios::trunc);
        if (proof) proof << body << "\n";
    };
    if (index < 0 || index >= static_cast<int>(m_problems.size())) {
        writeProof("goToProblem=EARLY index_oob index=" + std::to_string(index) +
                   " size=" + std::to_string(m_problems.size()));
        return;
    }
    const ProblemItem& problem = m_problems[index];
    if (problem.file.empty()) {
        writeProof("goToProblem=EARLY empty_file index=" + std::to_string(index));
        return;
    }

    const int line = problem.line > 0 ? problem.line : 1;
    const int col = problem.column > 0 ? problem.column : 1;

    auto samePath = [](const std::string& a, const std::string& b) -> bool {
        return _stricmp(a.c_str(), b.c_str()) == 0;
    };
    if (!samePath(m_currentFile, problem.file)) {
        // Avoid modal save prompt on harness navigate; fall back to raw load.
        const bool wasMod = m_fileModified;
        m_fileModified = false;
        if (!openDocumentPath(problem.file)) {
            m_fileModified = wasMod;
            std::ifstream file(problem.file, std::ios::binary);
            if (!file) {
                writeProof("goToProblem=EARLY open_fail path=" + problem.file);
                return;
            }
            std::string content((std::istreambuf_iterator<char>(file)),
                               std::istreambuf_iterator<char>());
            setEditorText(content);
            m_currentFile = problem.file;
            m_fileModified = false;
            updateTitleBarText();
        }
    }
    // Prefer editor control id 1001 when present (harness measures this HWND).
    HWND editor = m_hwndEditor;
    if (m_hwndMain) {
        HWND byId = GetDlgItem(m_hwndMain, 1001);
        if (byId && IsWindow(byId)) {
            editor = byId;
            m_hwndEditor = byId;
        }
    }
    if (!editor || !IsWindow(editor)) {
        writeProof("goToProblem=EARLY no_editor path=" + problem.file +
                   " line=" + std::to_string(line));
        return;
    }

    // Ensure the editor actually holds file content before navigating to a line.
    // The samePath short-circuit above skips openDocumentPath, so a prior
    // load can leave m_currentFile set with an empty buffer; EM_LINEINDEX on an
    // empty editor returns -1 and goToProblem would no-op (selStart/selEnd stay 0).
    if (GetWindowTextLengthW(editor) == 0) {
        std::ifstream file(problem.file, std::ios::binary);
        if (file) {
            std::string content((std::istreambuf_iterator<char>(file)),
                                std::istreambuf_iterator<char>());
            setEditorText(content);
        }
    }

    const int lineIndex =
        static_cast<int>(SendMessage(editor, EM_LINEINDEX, line - 1, 0));
    if (lineIndex < 0) {
        writeProof("goToProblem=EARLY lineindex_fail path=" + problem.file +
                   " line=" + std::to_string(line));
        return;
    }
    const int caret = lineIndex + (col - 1 < 0 ? 0 : col - 1);
    // Prefer EM_SETSEL (works Edit+RichEdit); also EM_EXSETSEL for RichEdit.
    SendMessage(editor, EM_SETSEL, (WPARAM)caret, (LPARAM)caret);
    CHARRANGE cr = { caret, caret };
    SendMessage(editor, EM_EXSETSEL, 0, (LPARAM)&cr);
    SendMessage(editor, EM_SCROLLCARET, 0, 0);
    SetFocus(editor);
    m_statusBarInfo.line = line;
    m_statusBarInfo.column = col;
    updateEnhancedStatusBar();
    updateTitleBarText();
    {
        std::ostringstream nav;
        nav << "[B12] navigateToFileLine " << problem.file << ":" << line << "\n";
        appendToOutput(nav.str(), "Output", OutputSeverity::Info);
        OutputDebugStringA(nav.str().c_str());
        writeProof(std::string("path=") + problem.file + " line=" +
                   std::to_string(line) + " col=" + std::to_string(col) +
                   " caret=" + std::to_string(caret));
    }
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
        hwndParent, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_STATUS_BAR)), m_hInstance, nullptr);
    
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
        syncOss << m_statusBarInfo.syncAhead << " " << m_statusBarInfo.syncBehind << "";
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
        copilotText += " ";  // Indicates suggestions available
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
// Agent ESP Panel - Live telemetry dashboard
// ============================================================================

void Win32IDE::createESPPanel(HWND hwndParent)
{
    // Create ESP panel container
    m_hwndESPPanel = CreateWindowExA(
        0, "STATIC", "",
        WS_CHILD | WS_VISIBLE,
        0, 0, 400, 300,
        hwndParent, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(1500)), m_hInstance, nullptr);

    // Create toolbar
    HWND hwndESPToolbar = CreateWindowExA(
        0, "STATIC", "",
        WS_CHILD | WS_VISIBLE,
        0, 0, 400, 28,
        m_hwndESPPanel, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(1501)), m_hInstance, nullptr);

    // Toolbar buttons
    HWND btnClear = CreateWindowExA(
        0, "BUTTON", "Clear",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        5, 3, 60, 22,
        hwndESPToolbar, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(1502)), m_hInstance, nullptr);

    HWND btnPause = CreateWindowExA(
        0, "BUTTON", "Pause",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        70, 3, 60, 22,
        hwndESPToolbar, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(1503)), m_hInstance, nullptr);

    HWND btnFilter = CreateWindowExA(
        0, "BUTTON", "Filter",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        135, 3, 60, 22,
        hwndESPToolbar, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(1504)), m_hInstance, nullptr);

    // Create list view for ESP events
    m_hwndESPList = CreateWindowExA(
        WS_EX_CLIENTEDGE, WC_LISTVIEWA, "",
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
        0, 30, 400, 270,
        m_hwndESPPanel, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(1505)), m_hInstance, nullptr);

    // Add columns
    LVCOLUMNA lvc = { 0 };
    lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

    lvc.pszText = const_cast<char*>("#");
    lvc.cx = 40;
    lvc.iSubItem = 0;
    ListView_InsertColumn(m_hwndESPList, 0, &lvc);

    lvc.pszText = const_cast<char*>("Time");
    lvc.cx = 80;
    lvc.iSubItem = 1;
    ListView_InsertColumn(m_hwndESPList, 1, &lvc);

    lvc.pszText = const_cast<char*>("Kind");
    lvc.cx = 100;
    lvc.iSubItem = 2;
    ListView_InsertColumn(m_hwndESPList, 2, &lvc);

    lvc.pszText = const_cast<char*>("Message");
    lvc.cx = 180;
    lvc.iSubItem = 3;
    ListView_InsertColumn(m_hwndESPList, 3, &lvc);

    // Initialize ESP recorder
    std::string espLogPath = m_currentDirectory + "\\agentic_live.jsonl";
    m_espRecorder = std::make_unique<rawrxd::esp::Recorder>(m_espBus, espLogPath,
        [this](const rawrxd::esp::Event& event) {
            // Post to UI thread
            PostMessageA(m_hwndMain, WM_APP + 100, 0, reinterpret_cast<LPARAM>(new rawrxd::esp::Event(event)));
        });
    m_espRecorder->start();
    m_espActive = true;
    m_espRequestId = 1;
}

void Win32IDE::toggleESPPanel()
{
    if (!m_hwndESPPanel) {
        createESPPanel(m_hwndMain);
    }
    bool visible = IsWindowVisible(m_hwndESPPanel);
    ShowWindow(m_hwndESPPanel, visible ? SW_HIDE : SW_SHOW);
}

void Win32IDE::updateESPPanel()
{
    // This is called from the UI thread via WM_APP+100
    // Events are processed in onESPEvent
}

void Win32IDE::onESPEvent(const rawrxd::esp::Event& event)
{
    std::lock_guard<std::mutex> lock(m_espEventsMutex);
    const std::string eventKey =
        std::to_string(event.request_id) + ":" + std::to_string(event.sequence);
    if (!m_espDisplayedKeys.insert(eventKey).second) {
        return;
    }
    m_espEvents.push_back(event);
    if (m_espEvents.size() > MAX_ESP_EVENTS) {
        const auto& evicted = m_espEvents.front();
        m_espDisplayedKeys.erase(
            std::to_string(evicted.request_id) + ":" +
            std::to_string(evicted.sequence));
        m_espEvents.erase(m_espEvents.begin());
    }

    switch (event.kind) {
    case rawrxd::esp::Kind::PrefillStart:
        m_agentStepTimeline.beginThought();
        armAgentThoughtTimer();
        break;
    case rawrxd::esp::Kind::PrefillEnd:
    case rawrxd::esp::Kind::TokenGenerated:
        disarmAgentThoughtTimer();
        m_agentStepTimeline.closeThoughtIfOpen();
        break;
    case rawrxd::esp::Kind::ToolStart: {
        const std::string& m = event.message;
        std::string lower = m;
        for (char& c : lower) {
            if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
        }
        if (lower.find("powershell") != std::string::npos || lower.find("pwsh") != std::string::npos) {
            m_agentStepTimeline.addChip("powershell", m);
        } else if (lower.find("explor") != std::string::npos || lower.find("glob") != std::string::npos ||
                   lower.find("grep") != std::string::npos || lower.find("read") != std::string::npos) {
            m_agentStepTimeline.addExplored(m);
        } else {
            m_agentStepTimeline.addChip("tool", m);
        }
        break;
    }
    case rawrxd::esp::Kind::ToolResult:
        m_agentStepTimeline.addTool("tool", event.message,
                                    static_cast<int>(event.value), event.value == 0);
        break;
    case rawrxd::esp::Kind::AgentStep:
        m_agentStepTimeline.addChip("step", event.message);
        break;
    case rawrxd::esp::Kind::FileChanged:
        m_agentStepTimeline.addExplored(event.message);
        break;
    case rawrxd::esp::Kind::Finished:
        disarmAgentThoughtTimer();
        m_agentStepTimeline.closeThoughtIfOpen();
        m_agentStepTimeline.addChip("done", event.message.empty() ? "finished" : event.message);
        break;
    case rawrxd::esp::Kind::Error:
        disarmAgentThoughtTimer();
        m_agentStepTimeline.addChip("fail", event.message);
        break;
    default:
        break;
    }

    if (!m_hwndESPList) return;

    // Add to list view
    LVITEMA lvi = { 0 };
    lvi.mask = LVIF_TEXT;
    lvi.iItem = ListView_GetItemCount(m_hwndESPList);
    lvi.iSubItem = 0;

    // Sequence number
    char seqBuf[32];
    std::snprintf(seqBuf, sizeof(seqBuf), "%llu", (unsigned long long)event.sequence);
    char* seqHeap = new char[strlen(seqBuf) + 1];
    strcpy_s(seqHeap, strlen(seqBuf) + 1, seqBuf);
    g_panelStringHeap.push_back(seqHeap);
    lvi.pszText = seqHeap;
    ListView_InsertItem(m_hwndESPList, &lvi);

    // Timestamp (relative to start or just HH:MM:SS.mmm)
    auto ns = event.timestamp_ns;
    auto sec = static_cast<std::time_t>(ns / 1000000000ULL);
    auto ms = (ns % 1000000000ULL) / 1000000ULL;
    std::tm tm_buf;
    localtime_s(&tm_buf, &sec);
    char timeBuf[32];
    std::strftime(timeBuf, sizeof(timeBuf), "%H:%M:%S", &tm_buf);
    char fullTimeBuf[48];
    std::snprintf(fullTimeBuf, sizeof(fullTimeBuf), "%s.%03llu", timeBuf, (unsigned long long)ms);
    ListView_SetItemText(m_hwndESPList, lvi.iItem, 1, fullTimeBuf);

    // Kind
    std::string kindStr = rawrxd::esp::kind_name(event.kind);
    ListView_SetItemText(m_hwndESPList, lvi.iItem, 2, const_cast<LPSTR>(kindStr.c_str()));

    // Message (truncated)
    std::string msg = event.message;
    if (msg.size() > 120) msg = msg.substr(0, 117) + "...";
    ListView_SetItemText(m_hwndESPList, lvi.iItem, 3, const_cast<LPSTR>(msg.c_str()));

    // Auto-scroll to bottom
    ListView_EnsureVisible(m_hwndESPList, lvi.iItem, FALSE);
}

// Handle ESP events posted from recorder thread
LRESULT Win32IDE::handleESPEvent(WPARAM wParam, LPARAM lParam)
{
    if (lParam) {
        rawrxd::esp::Event* event = reinterpret_cast<rawrxd::esp::Event*>(lParam);
        onESPEvent(*event);
        delete event;
    }
    return 0;
}
