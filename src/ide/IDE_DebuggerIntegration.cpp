/*===========================================================================
 * IDE_DebuggerIntegration.cpp
 * RawrXD IDE Debugger UI Implementation
 *===========================================================================*/

#include "IDE_DebuggerIntegration.h"
#include <windowsx.h>
#include <commctrl.h>
#include <stdio.h>

#pragma comment(lib, "comctl32.lib")

namespace RawrXD {

/*===========================================================================
 * DEBUG TOOLBAR IMPLEMENTATION
 *===========================================================================*/

DebugToolbar::Button DebugToolbar::s_buttons[] = {
    { ID_DEBUG_START,         0, "Start Debugging (F5)",       true },
    { ID_DEBUG_STOP,          1, "Stop Debugging (Shift+F5)", false },
    { ID_DEBUG_PAUSE,         2, "Break (Ctrl+Break)",      false },
    { ID_DEBUG_CONTINUE,      3, "Continue (F5)",           false },
    { -1, -1, nullptr, false }, // Separator
    { ID_DEBUG_STEP_INTO,     4, "Step Into (F11)",         false },
    { ID_DEBUG_STEP_OVER,     5, "Step Over (F10)",         false },
    { ID_DEBUG_STEP_OUT,      6, "Step Out (Shift+F11)",    false },
    { -1, -1, nullptr, false }, // Separator
    { ID_DEBUG_TOGGLE_BP,     7, "Toggle Breakpoint (F9)",  true },
};

const int DebugToolbar::s_buttonCount = sizeof(s_buttons) / sizeof(s_buttons[0]);

DebugToolbar::DebugToolbar() : m_hwnd(nullptr), m_parent(nullptr), m_imageList(nullptr) {}

DebugToolbar::~DebugToolbar() {
    Destroy();
}

bool DebugToolbar::Create(HWND parentWnd, int x, int y, int width, int height) {
    m_parent = parentWnd;
    
    // Create toolbar
    m_hwnd = CreateWindowEx(0, TOOLBARCLASSNAME, nullptr,
        WS_CHILD | WS_VISIBLE | TBSTYLE_FLAT | TBSTYLE_TOOLTIPS | CCS_TOP,
        x, y, width, height,
        parentWnd, nullptr, GetModuleHandle(nullptr), nullptr);
    
    if (!m_hwnd) {
        return false;
    }
    
    // Create image list (16x16 icons)
    m_imageList = ImageList_Create(16, 16, ILC_COLOR32 | ILC_MASK, 8, 8);
    
    // Add default buttons
    TBBUTTON buttons[s_buttonCount];
    int btnIdx = 0;
    
    for (int i = 0; i < s_buttonCount; i++) {
        if (s_buttons[i].id == -1) {
            // Separator
            buttons[btnIdx].iBitmap = 0;
            buttons[btnIdx].idCommand = 0;
            buttons[btnIdx].fsState = TBSTATE_ENABLED;
            buttons[btnIdx].fsStyle = TBSTYLE_SEP;
            buttons[btnIdx].iString = 0;
        } else {
            buttons[btnIdx].iBitmap = s_buttons[i].imageIndex;
            buttons[btnIdx].idCommand = s_buttons[i].id;
            buttons[btnIdx].fsState = s_buttons[i].enabled ? TBSTATE_ENABLED : 0;
            buttons[btnIdx].fsStyle = TBSTYLE_BUTTON;
            buttons[btnIdx].iString = 0;
        }
        btnIdx++;
    }
    
    SendMessage(m_hwnd, TB_BUTTONSTRUCTSIZE, sizeof(TBBUTTON), 0);
    SendMessage(m_hwnd, TB_SETIMAGELIST, 0, (LPARAM)m_imageList);
    SendMessage(m_hwnd, TB_ADDBUTTONS, btnIdx, (LPARAM)buttons);
    SendMessage(m_hwnd, TB_AUTOSIZE, 0, 0);
    
    return true;
}

void DebugToolbar::Destroy() {
    if (m_imageList) {
        ImageList_Destroy(m_imageList);
        m_imageList = nullptr;
    }
    if (m_hwnd) {
        DestroyWindow(m_hwnd);
        m_hwnd = nullptr;
    }
}

void DebugToolbar::UpdateState(DebugState state) {
    // Enable/disable buttons based on state
    bool isRunning = (state == DebugState::Running);
    bool isPaused = (state == DebugState::Paused || state == DebugState::Stepping);
    bool isIdle = (state == DebugState::Idle);
    
    EnableButton(ID_DEBUG_START, isIdle);
    EnableButton(ID_DEBUG_STOP, !isIdle);
    EnableButton(ID_DEBUG_PAUSE, isRunning);
    EnableButton(ID_DEBUG_CONTINUE, isPaused);
    EnableButton(ID_DEBUG_STEP_INTO, isPaused);
    EnableButton(ID_DEBUG_STEP_OVER, isPaused);
    EnableButton(ID_DEBUG_STEP_OUT, isPaused);
}

void DebugToolbar::EnableButton(int cmdId, bool enable) {
    SendMessage(m_hwnd, TB_ENABLEBUTTON, cmdId, enable ? TRUE : FALSE);
}

void DebugToolbar::OnStart() {
    auto& svc = DebuggerService::GetInstance();
    if (svc.GetState() == DebugState::Idle) {
        // TODO: Get executable path from project settings
        // svc.LaunchProcess("target.exe");
    }
}

void DebugToolbar::OnStop() {
    DebuggerService::GetInstance().Terminate();
}

void DebugToolbar::OnPause() {
    DebuggerService::GetInstance().Pause();
}

void DebugToolbar::OnContinue() {
    DebuggerService::GetInstance().Continue();
}

void DebugToolbar::OnStepInto() {
    DebuggerService::GetInstance().StepInto();
}

void DebugToolbar::OnStepOver() {
    DebuggerService::GetInstance().StepOver();
}

void DebugToolbar::OnStepOut() {
    DebuggerService::GetInstance().StepOut();
}

void DebugToolbar::OnToggleBreakpoint() {
    // TODO: Get current file/line from editor
    // DebuggerService::GetInstance().ToggleBreakpoint(file, line);
}

/*===========================================================================
 * REGISTER VIEWER PANEL IMPLEMENTATION
 *===========================================================================*/

const char* RegisterViewerPanel::s_regNames[] = {
    "RAX", "RBX", "RCX", "RDX",
    "RSI", "RDI", "RBP", "RSP",
    "R8",  "R9",  "R10", "R11",
    "R12", "R13", "R14", "R15",
    "RIP"
};

RegisterViewerPanel::RegisterViewerPanel() 
    : m_hwnd(nullptr), m_parent(nullptr), m_font(nullptr), m_fontBold(nullptr) {
}

RegisterViewerPanel::~RegisterViewerPanel() {
    Destroy();
}

bool RegisterViewerPanel::Create(HWND parentWnd, int x, int y, int width, int height) {
    m_parent = parentWnd;
    
    WNDCLASS wc = {};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.lpszClassName = "RawrXD_RegisterViewer";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    RegisterClass(&wc);
    
    m_hwnd = CreateWindowEx(
        WS_EX_CLIENTEDGE,
        "RawrXD_RegisterViewer",
        "Registers",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL,
        x, y, width, height,
        parentWnd, nullptr, GetModuleHandle(nullptr), this
    );
    
    if (!m_hwnd) {
        return false;
    }
    
    // Create fonts
    m_font = CreateFont(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                       DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                       DEFAULT_QUALITY, FIXED_PITCH | FF_MODERN, "Consolas");
    m_fontBold = CreateFont(14, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                            DEFAULT_QUALITY, FIXED_PITCH | FF_MODERN, "Consolas");
    
    return true;
}

void RegisterViewerPanel::Destroy() {
    if (m_font) {
        DeleteObject(m_font);
        m_font = nullptr;
    }
    if (m_fontBold) {
        DeleteObject(m_fontBold);
        m_fontBold = nullptr;
    }
    if (m_hwnd) {
        DestroyWindow(m_hwnd);
        m_hwnd = nullptr;
    }
}

void RegisterViewerPanel::UpdateRegisters(const RegisterSet& regs) {
    m_previousRegs = m_currentRegs;
    m_currentRegs = regs;
    InvalidateRect(m_hwnd, nullptr, TRUE);
}

void RegisterViewerPanel::Clear() {
    m_currentRegs = RegisterSet();
    m_previousRegs = RegisterSet();
    InvalidateRect(m_hwnd, nullptr, TRUE);
}

void RegisterViewerPanel::Show(bool show) {
    ShowWindow(m_hwnd, show ? SW_SHOW : SW_HIDE);
}

bool RegisterViewerPanel::IsVisible() const {
    return IsWindowVisible(m_hwnd) == TRUE;
}

LRESULT CALLBACK RegisterViewerPanel::WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    RegisterViewerPanel* panel = nullptr;
    
    if (msg == WM_CREATE) {
        CREATESTRUCT* cs = reinterpret_cast<CREATESTRUCT*>(lParam);
        panel = reinterpret_cast<RegisterViewerPanel*>(cs->lpCreateParams);
        SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(panel));
    } else {
        panel = reinterpret_cast<RegisterViewerPanel*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
    }
    
    if (panel) {
        return panel->HandleMessage(msg, wParam, lParam);
    }
    
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

LRESULT RegisterViewerPanel::HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(m_hwnd, &ps);
            Paint(hdc);
            EndPaint(m_hwnd, &ps);
            return 0;
        }
        
        case WM_ERASEBKGND:
            return 1;
            
        default:
            return DefWindowProc(m_hwnd, msg, wParam, lParam);
    }
}

void RegisterViewerPanel::Paint(HDC hdc) {
    RECT rect;
    GetClientRect(m_hwnd, &rect);
    
    // Fill background
    FillRect(hdc, &rect, (HBRUSH)(COLOR_WINDOW + 1));
    
    // Draw header
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, GetSysColor(COLOR_WINDOWTEXT));
    HFONT oldFont = (HFONT)SelectObject(hdc, m_fontBold);
    
    RECT headerRect = { 10, 5, rect.right - 10, 25 };
    DrawText(hdc, "x64 Registers", -1, &headerRect, DT_LEFT | DT_VCENTER);
    
    SelectObject(hdc, m_font);
    
    // Draw registers in two columns
    int y = 30;
    int colWidth = (rect.right - 30) / 2;
    
    uint64_t* regValues = reinterpret_cast<uint64_t*>(&m_currentRegs);
    uint64_t* prevValues = reinterpret_cast<uint64_t*>(&m_previousRegs);
    
    for (int i = 0; i < s_regCount; i++) {
        int col = i / ((s_regCount + 1) / 2);
        int row = i % ((s_regCount + 1) / 2);
        int x = 10 + col * colWidth;
        int lineY = y + row * 20;
        
        bool modified = (regValues[i] != prevValues[i]);
        DrawRegister(hdc, x, lineY, s_regNames[i], regValues[i], modified);
    }
    
    SelectObject(hdc, oldFont);
}

void RegisterViewerPanel::DrawRegister(HDC hdc, int x, int& y, const char* name, uint64_t value, bool modified) {
    // Register name
    SetTextColor(hdc, GetSysColor(COLOR_WINDOWTEXT));
    HFONT oldFont = (HFONT)SelectObject(hdc, modified ? m_fontBold : m_font);
    
    RECT nameRect = { x, y, x + 40, y + 18 };
    DrawText(hdc, name, -1, &nameRect, DT_LEFT | DT_VCENTER);
    
    // Value
    char valueStr[32];
    snprintf(valueStr, sizeof(valueStr), "%016llX", value);
    
    if (modified) {
        SetTextColor(hdc, RGB(200, 0, 0)); // Red for modified
    } else {
        SetTextColor(hdc, RGB(0, 128, 0)); // Green for unchanged
    }
    
    RECT valueRect = { x + 45, y, x + 165, y + 18 };
    DrawText(hdc, valueStr, -1, &valueRect, DT_LEFT | DT_VCENTER | DT_MONO);
    
    SelectObject(hdc, oldFont);
}

/*===========================================================================
 * MEMORY VIEWER PANEL IMPLEMENTATION
 *===========================================================================*/

MemoryViewerPanel::MemoryViewerPanel()
    : m_hwnd(nullptr), m_parent(nullptr), m_editAddress(nullptr), m_scrollbar(nullptr)
    , m_baseAddress(0), m_lineCount(0), m_visibleLines(0)
    , m_font(nullptr), m_fontFixed(nullptr) {
}

MemoryViewerPanel::~MemoryViewerPanel() {
    Destroy();
}

bool MemoryViewerPanel::Create(HWND parentWnd, int x, int y, int width, int height) {
    m_parent = parentWnd;
    
    WNDCLASS wc = {};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.lpszClassName = "RawrXD_MemoryViewer";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    RegisterClass(&wc);
    
    m_hwnd = CreateWindowEx(
        WS_EX_CLIENTEDGE,
        "RawrXD_MemoryViewer",
        "Memory",
        WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
        x, y, width, height,
        parentWnd, nullptr, GetModuleHandle(nullptr), this
    );
    
    if (!m_hwnd) {
        return false;
    }
    
    // Create address edit box
    m_editAddress = CreateWindowEx(WS_EX_CLIENTEDGE, "EDIT", "",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        5, 5, 150, 22, m_hwnd, nullptr, GetModuleHandle(nullptr), nullptr);
    SendMessage(m_editAddress, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);
    
    // Create scrollbar
    m_scrollbar = CreateWindow("SCROLLBAR", "",
        WS_CHILD | WS_VISIBLE | SBS_VERT,
        width - 20, 30, 16, height - 35,
        m_hwnd, nullptr, GetModuleHandle(nullptr), nullptr);
    
    // Set scrollbar range
    SCROLLINFO si = {};
    si.cbSize = sizeof(si);
    si.fMask = SIF_RANGE | SIF_PAGE;
    si.nMin = 0;
    si.nMax = s_maxLines;
    si.nPage = 20;
    SetScrollInfo(m_scrollbar, SB_CTL, &si, TRUE);
    
    // Create fonts
    m_font = CreateFont(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                       DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                       DEFAULT_QUALITY, FIXED_PITCH | FF_MODERN, "Consolas");
    
    return true;
}

void MemoryViewerPanel::Destroy() {
    if (m_font) {
        DeleteObject(m_font);
        m_font = nullptr;
    }
    if (m_hwnd) {
        DestroyWindow(m_hwnd);
        m_hwnd = nullptr;
    }
}

void MemoryViewerPanel::SetAddress(uint64_t address) {
    m_baseAddress = address;
    Refresh();
    
    // Update edit box
    char addrStr[32];
    snprintf(addrStr, sizeof(addrStr), "%016llX", address);
    SetWindowTextA(m_editAddress, addrStr);
}

void MemoryViewerPanel::Refresh() {
    // Read memory from debugger service
    auto& svc = DebuggerService::GetInstance();
    size_t size = s_bytesPerLine * m_visibleLines;
    auto mem = svc.ReadMemory(m_baseAddress, size);
    
    if (mem.valid) {
        m_memoryData = std::move(mem.data);
    } else {
        m_memoryData.clear();
    }
    
    InvalidateRect(m_hwnd, nullptr, TRUE);
}

void MemoryViewerPanel::Clear() {
    m_memoryData.clear();
    m_baseAddress = 0;
    SetWindowTextA(m_editAddress, "");
    InvalidateRect(m_hwnd, nullptr, TRUE);
}

void MemoryViewerPanel::Show(bool show) {
    ShowWindow(m_hwnd, show ? SW_SHOW : SW_HIDE);
}

bool MemoryViewerPanel::IsVisible() const {
    return IsWindowVisible(m_hwnd) == TRUE;
}

LRESULT CALLBACK MemoryViewerPanel::WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    MemoryViewerPanel* panel = nullptr;
    
    if (msg == WM_CREATE) {
        CREATESTRUCT* cs = reinterpret_cast<CREATESTRUCT*>(lParam);
        panel = reinterpret_cast<MemoryViewerPanel*>(cs->lpCreateParams);
        SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(panel));
    } else {
        panel = reinterpret_cast<MemoryViewerPanel*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
    }
    
    if (panel) {
        return panel->HandleMessage(msg, wParam, lParam);
    }
    
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

LRESULT MemoryViewerPanel::HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(m_hwnd, &ps);
            Paint(hdc);
            EndPaint(m_hwnd, &ps);
            return 0;
        }
        
        case WM_SIZE: {
            int width = LOWORD(lParam);
            int height = HIWORD(lParam);
            
            // Resize scrollbar
            SetWindowPos(m_scrollbar, nullptr, width - 20, 30, 16, height - 35,
                        SWP_NOZORDER);
            
            // Calculate visible lines
            m_visibleLines = (height - 35) / 16;
            
            return 0;
        }
        
        case WM_VSCROLL:
            OnScroll(LOWORD(wParam), HIWORD(wParam));
            return 0;
            
        case WM_ERASEBKGND:
            return 1;
            
        default:
            return DefWindowProc(m_hwnd, msg, wParam, lParam);
    }
}

void MemoryViewerPanel::Paint(HDC hdc) {
    RECT rect;
    GetClientRect(m_hwnd, &rect);
    
    // Fill background
    FillRect(hdc, &rect, (HBRUSH)(COLOR_WINDOW + 1));
    
    // Draw memory content
    HFONT oldFont = (HFONT)SelectObject(hdc, m_font);
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, GetSysColor(COLOR_WINDOWTEXT));
    
    int y = 35;
    
    for (int line = 0; line < m_visibleLines && line * s_bytesPerLine < m_memoryData.size(); line++) {
        uint64_t addr = m_baseAddress + line * s_bytesPerLine;
        size_t offset = line * s_bytesPerLine;
        size_t remaining = m_memoryData.size() - offset;
        size_t bytes = (remaining < s_bytesPerLine) ? remaining : s_bytesPerLine;
        
        std::string lineStr = DebuggerUtils::FormatMemoryLine(
            addr, m_memoryData.data() + offset, bytes);
        
        TextOutA(hdc, 10, y, lineStr.c_str(), (int)lineStr.length());
        y += 16;
    }
    
    SelectObject(hdc, oldFont);
}

void MemoryViewerPanel::OnScroll(int scrollCode, int pos) {
    SCROLLINFO si = {};
    si.cbSize = sizeof(si);
    si.fMask = SIF_ALL;
    GetScrollInfo(m_scrollbar, SB_CTL, &si);
    
    int oldPos = si.nPos;
    
    switch (scrollCode) {
        case SB_LINEUP: si.nPos--; break;
        case SB_LINEDOWN: si.nPos++; break;
        case SB_PAGEUP: si.nPos -= si.nPage; break;
        case SB_PAGEDOWN: si.nPos += si.nPage; break;
        case SB_THUMBPOSITION:
        case SB_THUMBTRACK: si.nPos = pos; break;
    }
    
    si.nPos = max(si.nMin, min(si.nPos, (int)(si.nMax - si.nPage)));
    
    if (si.nPos != oldPos) {
        SetScrollInfo(m_scrollbar, SB_CTL, &si, TRUE);
        m_baseAddress += (si.nPos - oldPos) * s_bytesPerLine;
        Refresh();
    }
}

/*===========================================================================
 * CALL STACK PANEL IMPLEMENTATION
 *===========================================================================*/

CallStackPanel::CallStackPanel() 
    : m_hwnd(nullptr), m_parent(nullptr), m_listView(nullptr), m_font(nullptr) {
}

CallStackPanel::~CallStackPanel() {
    Destroy();
}

bool CallStackPanel::Create(HWND parentWnd, int x, int y, int width, int height) {
    m_parent = parentWnd;
    
    // Initialize common controls
    INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(icex);
    icex.dwICC = ICC_LISTVIEW_CLASSES;
    InitCommonControlsEx(&icex);
    
    // Create list view
    m_hwnd = CreateWindowEx(WS_EX_CLIENTEDGE, WC_LISTVIEW, "Call Stack",
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL,
        x, y, width, height,
        parentWnd, nullptr, GetModuleHandle(nullptr), this);
    
    if (!m_hwnd) {
        return false;
    }
    
    // Set extended styles
    ListView_SetExtendedListViewStyle(m_hwnd, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
    
    // Add columns
    LVCOLUMN lvc = {};
    lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    
    lvc.iSubItem = 0;
    lvc.pszText = (LPSTR)"Frame";
    lvc.cx = 50;
    ListView_InsertColumn(m_hwnd, 0, &lvc);
    
    lvc.iSubItem = 1;
    lvc.pszText = (LPSTR)"Address";
    lvc.cx = 120;
    ListView_InsertColumn(m_hwnd, 1, &lvc);
    
    lvc.iSubItem = 2;
    lvc.pszText = (LPSTR)"Function";
    lvc.cx = 200;
    ListView_InsertColumn(m_hwnd, 2, &lvc);
    
    lvc.iSubItem = 3;
    lvc.pszText = (LPSTR)"File";
    lvc.cx = 250;
    ListView_InsertColumn(m_hwnd, 3, &lvc);
    
    return true;
}

void CallStackPanel::Destroy() {
    if (m_hwnd) {
        DestroyWindow(m_hwnd);
        m_hwnd = nullptr;
    }
}

void CallStackPanel::UpdateStack(const std::vector<StackFrame>& frames) {
    m_frames = frames;
    
    // Clear and repopulate
    ListView_DeleteAllItems(m_hwnd);
    
    for (size_t i = 0; i < frames.size(); i++) {
        LVITEM lvi = {};
        lvi.mask = LVIF_TEXT;
        lvi.iItem = (int)i;
        
        // Frame number
        char frameNum[16];
        snprintf(frameNum, sizeof(frameNum), "%zu", i);
        lvi.pszText = frameNum;
        ListView_InsertItem(m_hwnd, &lvi);
        
        // Address
        char addrStr[32];
        snprintf(addrStr, sizeof(addrStr), "%016llX", frames[i].returnAddress);
        ListView_SetItemText(m_hwnd, (int)i, 1, addrStr);
        
        // Function name
        ListView_SetItemText(m_hwnd, (int)i, 2, 
            (LPSTR)(frames[i].symbolName.empty() ? "???" : frames[i].symbolName.c_str()));
        
        // File
        char fileStr[512];
        if (!frames[i].fileName.empty() && frames[i].lineNumber > 0) {
            snprintf(fileStr, sizeof(fileStr), "%s:%d",
                frames[i].fileName.c_str(), frames[i].lineNumber);
        } else {
            strcpy(fileStr, "");
        }
        ListView_SetItemText(m_hwnd, (int)i, 3, fileStr);
    }
}

void CallStackPanel::Clear() {
    m_frames.clear();
    ListView_DeleteAllItems(m_hwnd);
}

void CallStackPanel::Show(bool show) {
    ShowWindow(m_hwnd, show ? SW_SHOW : SW_HIDE);
}

bool CallStackPanel::IsVisible() const {
    return IsWindowVisible(m_hwnd) == TRUE;
}

int CallStackPanel::GetSelectedFrame() const {
    return ListView_GetNextItem(m_hwnd, -1, LVNI_SELECTED);
}

LRESULT CALLBACK CallStackPanel::WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    CallStackPanel* panel = nullptr;
    
    if (msg == WM_NCCREATE) {
        CREATESTRUCT* cs = reinterpret_cast<CREATESTRUCT*>(lParam);
        panel = reinterpret_cast<CallStackPanel*>(cs->lpCreateParams);
        SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(panel));
    } else {
        panel = reinterpret_cast<CallStackPanel*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
    }
    
    if (panel) {
        return panel->HandleMessage(msg, wParam, lParam);
    }
    
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

LRESULT CallStackPanel::HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_NOTIFY: {
            LPNMHDR pnmh = reinterpret_cast<LPNMHDR>(lParam);
            if (pnmh->code == NM_DBLCLK) {
                int selected = GetSelectedFrame();
                if (selected >= 0) {
                    OnDoubleClick(selected);
                }
            }
            break;
        }
    }
    
    return DefWindowProc(m_hwnd, msg, wParam, lParam);
}

void CallStackPanel::OnDoubleClick(int index) {
    if (index >= 0 && index < (int)m_frames.size()) {
        // TODO: Navigate to source location
        // IDE_NavigateToSource(m_frames[index].fileName, m_frames[index].lineNumber);
    }
}

/*===========================================================================
 * DEBUGGER UI MANAGER IMPLEMENTATION
 *===========================================================================*/

DebuggerUIManager::DebuggerUIManager() 
    : m_mainWnd(nullptr), m_initialized(false) {
}

DebuggerUIManager::~DebuggerUIManager() {
    Shutdown();
}

DebuggerUIManager& DebuggerUIManager::GetInstance() {
    static DebuggerUIManager instance;
    return instance;
}

bool DebuggerUIManager::Initialize(HWND mainWnd) {
    if (m_initialized) {
        return true;
    }
    
    m_mainWnd = mainWnd;
    
    // Initialize debugger service
    auto& svc = DebuggerService::GetInstance();
    if (!svc.Initialize()) {
        return false;
    }
    
    // Set callbacks
    svc.SetEventCallback(OnDebugEventCallback);
    svc.SetStateChangeCallback(OnStateChangeCallback);
    
    // Create toolbar
    RECT rc;
    GetClientRect(mainWnd, &rc);
    m_toolbar.Create(mainWnd, 0, 0, rc.right, 28);
    
    // Create panels (initially hidden)
    m_regPanel.Create(mainWnd, rc.right - 300, 60, 280, 400);
    m_regPanel.Show(false);
    
    m_memPanel.Create(mainWnd, rc.right - 600, 60, 280, 400);
    m_memPanel.Show(false);
    
    m_stackPanel.Create(mainWnd, 10, rc.bottom - 200, rc.right - 20, 180);
    m_stackPanel.Show(false);
    
    m_initialized = true;
    return true;
}

void DebuggerUIManager::Shutdown() {
    if (!m_initialized) {
        return;
    }
    
    m_toolbar.Destroy();
    m_regPanel.Destroy();
    m_memPanel.Destroy();
    m_stackPanel.Destroy();
    
    DebuggerService::GetInstance().Shutdown();
    
    m_initialized = false;
}

bool DebuggerUIManager::OnCommand(int cmdId) {
    switch (cmdId) {
        case ID_DEBUG_START: m_toolbar.OnStart(); return true;
        case ID_DEBUG_STOP: m_toolbar.OnStop(); return true;
        case ID_DEBUG_PAUSE: m_toolbar.OnPause(); return true;
        case ID_DEBUG_CONTINUE: m_toolbar.OnContinue(); return true;
        case ID_DEBUG_STEP_INTO: m_toolbar.OnStepInto(); return true;
        case ID_DEBUG_STEP_OVER: m_toolbar.OnStepOver(); return true;
        case ID_DEBUG_STEP_OUT: m_toolbar.OnStepOut(); return true;
        case ID_DEBUG_TOGGLE_BP: m_toolbar.OnToggleBreakpoint(); return true;
        case ID_DEBUG_SHOW_REGISTERS: ShowRegisterPanel(!m_regPanel.IsVisible()); return true;
        case ID_DEBUG_SHOW_MEMORY: ShowMemoryPanel(!m_memPanel.IsVisible()); return true;
        case ID_DEBUG_SHOW_CALLSTACK: ShowCallStackPanel(!m_stackPanel.IsVisible()); return true;
    }
    return false;
}

bool DebuggerUIManager::OnDebugEvent(WPARAM wParam, LPARAM lParam) {
    (void)wParam;
    (void)lParam;
    
    // Poll for events
    DebuggerService::GetInstance().PollEvents();
    return true;
}

void DebuggerUIManager::OnDebugUpdate() {
    auto& svc = DebuggerService::GetInstance();
    
    if (svc.IsPaused()) {
        UpdateRegisterView();
        UpdateMemoryView();
        UpdateCallStack();
    }
}

bool DebuggerUIManager::OnKeyDown(int vkCode, bool ctrl, bool shift) {
    // F5 - Start/Continue
    if (vkCode == VK_F5 && !ctrl && !shift) {
        auto& svc = DebuggerService::GetInstance();
        if (svc.IsPaused()) {
            svc.Continue();
        } else if (svc.GetState() == DebugState::Idle) {
            m_toolbar.OnStart();
        }
        return true;
    }
    
    // Shift+F5 - Stop
    if (vkCode == VK_F5 && shift && !ctrl) {
        m_toolbar.OnStop();
        return true;
    }
    
    // F9 - Toggle Breakpoint
    if (vkCode == VK_F9 && !ctrl && !shift) {
        m_toolbar.OnToggleBreakpoint();
        return true;
    }
    
    // F10 - Step Over
    if (vkCode == VK_F10 && !ctrl && !shift) {
        m_toolbar.OnStepOver();
        return true;
    }
    
    // F11 - Step Into
    if (vkCode == VK_F11 && !ctrl && !shift) {
        m_toolbar.OnStepInto();
        return true;
    }
    
    // Shift+F11 - Step Out
    if (vkCode == VK_F11 && shift && !ctrl) {
        m_toolbar.OnStepOut();
        return true;
    }
    
    return false;
}

void DebuggerUIManager::UpdateDebugState(DebugState state) {
    m_toolbar.UpdateState(state);
}

void DebuggerUIManager::UpdateRegisterView() {
    auto& svc = DebuggerService::GetInstance();
    auto regs = svc.GetRegisters();
    m_regPanel.UpdateRegisters(regs);
}

void DebuggerUIManager::UpdateMemoryView() {
    // Memory view updates on its own when scrolled
    m_memPanel.Refresh();
}

void DebuggerUIManager::UpdateCallStack() {
    auto& svc = DebuggerService::GetInstance();
    auto frames = svc.GetCallStack();
    m_stackPanel.UpdateStack(frames);
}

void DebuggerUIManager::ShowRegisterPanel(bool show) {
    m_regPanel.Show(show);
}

void DebuggerUIManager::ShowMemoryPanel(bool show) {
    m_memPanel.Show(show);
}

void DebuggerUIManager::ShowCallStackPanel(bool show) {
    m_stackPanel.Show(show);
}

void DebuggerUIManager::TogglePanels() {
    bool anyVisible = m_regPanel.IsVisible() || m_memPanel.IsVisible() || m_stackPanel.IsVisible();
    ShowRegisterPanel(!anyVisible);
    ShowMemoryPanel(!anyVisible);
    ShowCallStackPanel(!anyVisible);
}

void DebuggerUIManager::OnDebugEventCallback(const DebugEvent& event) {
    auto& ui = GetInstance();
    
    switch (event.type) {
        case DebugEventType::BreakpointHit:
            // Update UI
            PostMessage(ui.m_mainWnd, WM_DEBUG_UPDATE, 0, 0);
            break;
            
        case DebugEventType::ExceptionRaised:
            // Show exception info
            MessageBoxA(ui.m_mainWnd, event.description.c_str(), "Exception", MB_OK | MB_ICONERROR);
            break;
            
        case DebugEventType::ProcessExited:
            ui.UpdateDebugState(DebugState::Terminated);
            break;
            
        default:
            break;
    }
}

void DebuggerUIManager::OnStateChangeCallback(DebugState oldState, DebugState newState) {
    (void)oldState;
    auto& ui = GetInstance();
    ui.UpdateDebugState(newState);
}

/*===========================================================================
 * GLOBAL INTEGRATION FUNCTIONS
 *===========================================================================*/

static DebuggerUIManager* g_debuggerUI = nullptr;

bool IDE_InitDebugger(HWND mainWnd) {
    if (!g_debuggerUI) {
        g_debuggerUI = &DebuggerUIManager::GetInstance();
    }
    return g_debuggerUI->Initialize(mainWnd);
}

void IDE_ShutdownDebugger() {
    if (g_debuggerUI) {
        g_debuggerUI->Shutdown();
        g_debuggerUI = nullptr;
    }
}

bool IDE_HandleDebugCommand(int cmdId) {
    if (!g_debuggerUI) return false;
    return g_debuggerUI->OnCommand(cmdId);
}

bool IDE_HandleDebugEvent(WPARAM wParam, LPARAM lParam) {
    if (!g_debuggerUI) return false;
    return g_debuggerUI->OnDebugEvent(wParam, lParam);
}

bool IDE_HandleDebugKeys(int vkCode, bool ctrl, bool shift) {
    if (!g_debuggerUI) return false;
    return g_debuggerUI->OnKeyDown(vkCode, ctrl, shift);
}

void IDE_UpdateDebugUI() {
    if (g_debuggerUI) {
        g_debuggerUI->OnDebugUpdate();
    }
}

void IDE_ShowDebugPanels(bool show) {
    if (!g_debuggerUI) return;
    
    if (show) {
        g_debuggerUI->ShowRegisterPanel(true);
        g_debuggerUI->ShowMemoryPanel(true);
        g_debuggerUI->ShowCallStackPanel(true);
    } else {
        g_debuggerUI->ShowRegisterPanel(false);
        g_debuggerUI->ShowMemoryPanel(false);
        g_debuggerUI->ShowCallStackPanel(false);
    }
}

} // namespace RawrXD
