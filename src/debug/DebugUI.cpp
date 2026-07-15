//=============================================================================
// RawrXD Debug UI Integration — Phase 24 Implementation
// Pure Win32, Zero External Dependencies
//=============================================================================
#include "DebugUI.hpp"
#include "DebugBackend.h"
#include <windowsx.h>
#include <commctrl.h>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")

namespace RawrXD {
namespace DebugUI {

//=============================================================================
// String Helpers (Zero CRT string functions)
//=============================================================================

static int StrLen(const char* s) {
    int n = 0;
    while (s[n]) ++n;
    return n;
}

static void StrCpy(char* dst, const char* src) {
    while ((*dst++ = *src++));
}

static void StrCat(char* dst, const char* src) {
    while (*dst) ++dst;
    while ((*dst++ = *src++));
}

static void Hex64(char* buf, uint64_t val) {
    const char* hex = "0123456789ABCDEF";
    buf[0] = '0'; buf[1] = 'x';
    for (int i = 0; i < 16; ++i) {
        buf[2 + i] = hex[(val >> (60 - i * 4)) & 0xF];
    }
    buf[18] = 0;
}

static void Hex8(char* buf, uint8_t val) {
    const char* hex = "0123456789ABCDEF";
    buf[0] = hex[val >> 4];
    buf[1] = hex[val & 0xF];
    buf[2] = 0;
}

static void Dec(char* buf, int64_t val) {
    if (val == 0) { buf[0] = '0'; buf[1] = 0; return; }
    bool neg = val < 0;
    if (neg) val = -val;
    char tmp[32];
    int i = 0;
    while (val > 0) {
        tmp[i++] = '0' + (val % 10);
        val /= 10;
    }
    int j = 0;
    if (neg) buf[j++] = '-';
    while (i > 0) buf[j++] = tmp[--i];
    buf[j] = 0;
}

static int WStrToStr(char* dst, const wchar_t* src, int maxLen) {
    int i = 0;
    while (src[i] && i < maxLen - 1) {
        dst[i] = (char)src[i];
        ++i;
    }
    dst[i] = 0;
    return i;
}

//=============================================================================
// BreakpointGutter Implementation
//=============================================================================

void BreakpointGutter::Initialize(HWND hEditor) {
    m_hEditor = hEditor;
    m_bpCapacity = 32;
    m_breakLines = (int*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, m_bpCapacity * sizeof(int));
    m_bpCount = 0;
}

void BreakpointGutter::Shutdown() {
    if (m_breakLines) {
        HeapFree(GetProcessHeap(), 0, m_breakLines);
        m_breakLines = nullptr;
    }
    m_bpCapacity = 0;
    m_bpCount = 0;
}

void BreakpointGutter::GrowBreakpointArray() {
    int newCap = m_bpCapacity * 2;
    int* newArr = (int*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, newCap * sizeof(int));
    for (int i = 0; i < m_bpCount; ++i) newArr[i] = m_breakLines[i];
    HeapFree(GetProcessHeap(), 0, m_breakLines);
    m_breakLines = newArr;
    m_bpCapacity = newCap;
}

int BreakpointGutter::FindBreakpointIndex(int line) const {
    for (int i = 0; i < m_bpCount; ++i) {
        if (m_breakLines[i] == line) return i;
    }
    return -1;
}

bool BreakpointGutter::HasBreakpoint(int line) const {
    return FindBreakpointIndex(line) >= 0;
}

void BreakpointGutter::ToggleBreakpoint(int line) {
    int idx = FindBreakpointIndex(line);
    if (idx >= 0) {
        // Remove
        for (int i = idx; i < m_bpCount - 1; ++i) {
            m_breakLines[i] = m_breakLines[i + 1];
        }
        --m_bpCount;
    } else {
        // Add
        if (m_bpCount >= m_bpCapacity) GrowBreakpointArray();
        m_breakLines[m_bpCount++] = line;
    }
    InvalidateRect(m_hEditor, nullptr, FALSE);
}

void BreakpointGutter::ClearBreakpoint(int line) {
    int idx = FindBreakpointIndex(line);
    if (idx >= 0) {
        for (int i = idx; i < m_bpCount - 1; ++i) {
            m_breakLines[i] = m_breakLines[i + 1];
        }
        --m_bpCount;
        InvalidateRect(m_hEditor, nullptr, FALSE);
    }
}

void BreakpointGutter::OnPaint(HDC hdc, const RECT& rcGutter, int firstLine, int lineCount) {
    // Fill gutter background
    HBRUSH hBrush = CreateSolidBrush(RGB(45, 45, 48));
    FillRect(hdc, &rcGutter, hBrush);
    DeleteObject(hBrush);
    
    // Draw line numbers and breakpoints
    HFONT hFont = (HFONT)GetCurrentObject(hdc, OBJ_FONT);
    TEXTMETRIC tm;
    GetTextMetrics(hdc, &tm);
    int lineHeight = tm.tmHeight + tm.tmExternalLeading;
    
    for (int i = 0; i < lineCount; ++i) {
        int line = firstLine + i;
        int y = rcGutter.top + i * lineHeight;
        
        // Draw breakpoint circle
        if (HasBreakpoint(line)) {
            HBRUSH hRed = CreateSolidBrush(RGB(255, 90, 90));
            HPEN hPen = CreatePen(PS_SOLID, 1, RGB(200, 50, 50));
            HGDIOBJ oldBrush = SelectObject(hdc, hRed);
            HGDIOBJ oldPen = SelectObject(hdc, hPen);
            Ellipse(hdc, 3, y + 3, 13, y + 13);
            SelectObject(hdc, oldBrush);
            SelectObject(hdc, oldPen);
            DeleteObject(hRed);
            DeleteObject(hPen);
        }
        
        // Draw line number
        char num[16];
        Dec(num, line + 1);
        SetTextColor(hdc, RGB(120, 120, 120));
        SetBkMode(hdc, TRANSPARENT);
        RECT rcNum = { 16, y, rcGutter.right, y + lineHeight };
        DrawTextA(hdc, num, StrLen(num), &rcNum, DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
    }
}

int BreakpointGutter::HitTest(int x, int y) const {
    if (x < 0 || x >= GUTTER_WIDTH) return -1;
    // Need line height calculation - simplified
    return -1;  // Caller should convert y to line
}

void BreakpointGutter::SyncWithBackend(DebugSession* session) {
    if (!session) return;
    // Query backend for active breakpoints and sync visual state
    auto bps = session->GetBreakpoints();
    // Clear and repopulate
    m_bpCount = 0;
    for (const auto& bp : bps) {
        // Convert address to line (requires symbol info)
        // For now, just store the address as a pseudo-line
        if (m_bpCount >= m_bpCapacity) GrowBreakpointArray();
        m_breakLines[m_bpCount++] = (int)(bp.address & 0xFFFFFFFF);
    }
    InvalidateRect(m_hEditor, nullptr, FALSE);
}

//=============================================================================
// CallStackPanel Implementation
//=============================================================================

#define IDC_CALLSTACK_TREE 1001

LRESULT CALLBACK CallStackPanel::WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    CallStackPanel* pThis = (CallStackPanel*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
    switch (msg) {
        case WM_CREATE:
            pThis = (CallStackPanel*)((CREATESTRUCT*)lParam)->lpCreateParams;
            SetWindowLongPtr(hWnd, GWLP_USERDATA, (LONG_PTR)pThis);
            pThis->m_hWnd = hWnd;
            pThis->OnCreate();
            return 0;
        case WM_SIZE:
            if (pThis) pThis->OnSize(LOWORD(lParam), HIWORD(lParam));
            return 0;
        case WM_NOTIFY:
            if (pThis) pThis->OnNotify((NMHDR*)lParam);
            return 0;
        case WM_DESTROY:
            return 0;
    }
    return DefWindowProc(hWnd, msg, wParam, lParam);
}

void CallStackPanel::Initialize(HWND hParent, int x, int y, int w, int h) {
    WNDCLASSEX wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.lpszClassName = "RawrXD_CallStackPanel";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    RegisterClassEx(&wc);
    
    m_hWnd = CreateWindowEx(WS_EX_CLIENTEDGE, "RawrXD_CallStackPanel", "Call Stack",
        WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
        x, y, w, h, hParent, nullptr, GetModuleHandle(nullptr), this);
}

void CallStackPanel::Shutdown() {
    if (m_hWnd) DestroyWindow(m_hWnd);
}

void CallStackPanel::OnCreate() {
    m_hTree = CreateWindowEx(0, WC_TREEVIEW, "",
        WS_CHILD | WS_VISIBLE | TVS_HASBUTTONS | TVS_LINESATROOT | TVS_SHOWSELALWAYS,
        0, 0, 100, 100, m_hWnd, (HMENU)IDC_CALLSTACK_TREE, GetModuleHandle(nullptr), nullptr);
}

void CallStackPanel::OnSize(int w, int h) {
    SetWindowPos(m_hTree, nullptr, 0, 0, w, h, SWP_NOZORDER);
}

void CallStackPanel::OnNotify(NMHDR* pnmh) {
    if (pnmh->idFrom != IDC_CALLSTACK_TREE) return;
    if (pnmh->code == TVN_SELCHANGED) {
        NMTREEVIEW* pnm = (NMTREEVIEW*)pnmh;
        int idx = (int)pnm->itemNew.lParam;
        if (m_onSelect) m_onSelect(idx, m_user);
    }
}

void CallStackPanel::Update(const StackFrame* frames, int count) {
    TreeView_DeleteAllItems(m_hTree);
    if (!frames || count <= 0) return;
    
    for (int i = 0; i < count; ++i) {
        char buf[512];
        const StackFrame& f = frames[i];
        
        // Format: Module!Function+0xoffset
        char addr[32];
        Hex64(addr, f.instructionPointer);
        
        buf[0] = 0;
        if (!f.functionName.empty()) {
            StrCat(buf, f.functionName.c_str());
        } else {
            StrCat(buf, "<unknown>");
        }
        StrCat(buf, "() at ");
        StrCat(buf, addr);
        
        TVINSERTSTRUCT tvis = {};
        tvis.hParent = TVI_ROOT;
        tvis.hInsertAfter = TVI_LAST;
        tvis.item.mask = TVIF_TEXT | TVIF_PARAM;
        tvis.item.pszText = buf;
        tvis.item.lParam = i;
        TreeView_InsertItem(m_hTree, &tvis);
    }
}

void CallStackPanel::Clear() {
    TreeView_DeleteAllItems(m_hTree);
}

void CallStackPanel::SetSelectionCallback(void (*callback)(int, void*), void* user) {
    m_onSelect = callback;
    m_user = user;
}

//=============================================================================
// RegisterPanel Implementation
//=============================================================================

#define IDC_REGISTER_LIST 1002
#define IDM_TOGGLE_FORMAT 2001

LRESULT CALLBACK RegisterPanel::WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    RegisterPanel* pThis = (RegisterPanel*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
    switch (msg) {
        case WM_CREATE:
            pThis = (RegisterPanel*)((CREATESTRUCT*)lParam)->lpCreateParams;
            SetWindowLongPtr(hWnd, GWLP_USERDATA, (LONG_PTR)pThis);
            pThis->m_hWnd = hWnd;
            pThis->OnCreate();
            return 0;
        case WM_SIZE:
            if (pThis) pThis->OnSize(LOWORD(lParam), HIWORD(lParam));
            return 0;
        case WM_CONTEXTMENU:
            if (pThis) {
                HMENU hMenu = CreatePopupMenu();
                AppendMenu(hMenu, MF_STRING, IDM_TOGGLE_FORMAT, pThis->m_hexMode ? "Decimal" : "Hexadecimal");
                TrackPopupMenu(hMenu, TPM_RIGHTBUTTON, LOWORD(lParam), HIWORD(lParam), 0, hWnd, nullptr);
                DestroyMenu(hMenu);
            }
            return 0;
        case WM_COMMAND:
            if (pThis && LOWORD(wParam) == IDM_TOGGLE_FORMAT) {
                pThis->ToggleFormat();
            }
            return 0;
        case WM_DESTROY:
            return 0;
    }
    return DefWindowProc(hWnd, msg, wParam, lParam);
}

void RegisterPanel::Initialize(HWND hParent, int x, int y, int w, int h) {
    WNDCLASSEX wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.lpszClassName = "RawrXD_RegisterPanel";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    RegisterClassEx(&wc);
    
    m_hWnd = CreateWindowEx(WS_EX_CLIENTEDGE, "RawrXD_RegisterPanel", "Registers",
        WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
        x, y, w, h, hParent, nullptr, GetModuleHandle(nullptr), this);
}

void RegisterPanel::Shutdown() {
    if (m_hWnd) DestroyWindow(m_hWnd);
}

void RegisterPanel::OnCreate() {
    m_hList = CreateWindowEx(0, WC_LISTVIEW, "",
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_NOCOLUMNHEADER,
        0, 0, 100, 100, m_hWnd, (HMENU)IDC_REGISTER_LIST, GetModuleHandle(nullptr), nullptr);
    
    // Add columns: Register Name, Value
    LVCOLUMN col = {};
    col.mask = LVCF_TEXT | LVCF_WIDTH;
    col.cx = 80;
    col.pszText = "Reg";
    ListView_InsertColumn(m_hList, 0, &col);
    col.cx = 120;
    col.pszText = "Value";
    ListView_InsertColumn(m_hList, 1, &col);
    
    // Set dark theme colors
    ListView_SetBkColor(m_hList, RGB(30, 30, 30));
    ListView_SetTextColor(m_hList, RGB(220, 220, 220));
    ListView_SetTextBkColor(m_hList, RGB(30, 30, 30));
}

void RegisterPanel::OnSize(int w, int h) {
    SetWindowPos(m_hList, nullptr, 0, 0, w, h, SWP_NOZORDER);
}

void RegisterPanel::PopulateList(const RegisterContext* ctx) {
    ListView_DeleteAllItems(m_hList);
    if (!ctx) return;
    
    struct RegEntry { const char* name; uint64_t value; };
    RegEntry regs[] = {
        { "RAX", ctx->rax }, { "RCX", ctx->rcx }, { "RDX", ctx->rdz }, { "RBX", ctx->rbx },
        { "RSP", ctx->rsp }, { "RBP", ctx->rbp }, { "RSI", ctx->rsi }, { "RDI", ctx->rdi },
        { "R8",  ctx->r8 },  { "R9",  ctx->r9 },  { "R10", ctx->r10 }, { "R11", ctx->r11 },
        { "R12", ctx->r12 }, { "R13", ctx->r13 }, { "R14", ctx->r14 }, { "R15", ctx->r15 },
        { "RIP", ctx->rip }, { "EFLAGS", ctx->eflags }
    };
    
    for (int i = 0; i < 18; ++i) {
        char valBuf[32];
        if (m_hexMode) {
            Hex64(valBuf, regs[i].value);
        } else {
            Dec(valBuf, (int64_t)regs[i].value);
        }
        
        LVITEM item = {};
        item.mask = LVIF_TEXT;
        item.iItem = i;
        item.pszText = (char*)regs[i].name;
        ListView_InsertItem(m_hList, &item);
        ListView_SetItemText(m_hList, i, 1, valBuf);
    }
}

void RegisterPanel::Update(const RegisterContext* ctx) {
    PopulateList(ctx);
}

void RegisterPanel::Clear() {
    ListView_DeleteAllItems(m_hList);
}

void RegisterPanel::ToggleFormat() {
    m_hexMode = !m_hexMode;
    // Trigger refresh - need to store last context or request from backend
    InvalidateRect(m_hList, nullptr, TRUE);
}

//=============================================================================
// MemoryPanel Implementation
//=============================================================================

#define IDC_MEMORY_EDIT 1003
#define IDC_MEMORY_HEX  1004

LRESULT CALLBACK MemoryPanel::WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    MemoryPanel* pThis = (MemoryPanel*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
    switch (msg) {
        case WM_CREATE:
            pThis = (MemoryPanel*)((CREATESTRUCT*)lParam)->lpCreateParams;
            SetWindowLongPtr(hWnd, GWLP_USERDATA, (LONG_PTR)pThis);
            pThis->m_hWnd = hWnd;
            pThis->OnCreate();
            return 0;
        case WM_SIZE:
            if (pThis) pThis->OnSize(LOWORD(lParam), HIWORD(lParam));
            return 0;
        case WM_PAINT:
            if (pThis) {
                PAINTSTRUCT ps;
                HDC hdc = BeginPaint(hWnd, &ps);
                pThis->OnPaint(hdc);
                EndPaint(hWnd, &ps);
            }
            return 0;
        case WM_LBUTTONDOWN:
            if (pThis) pThis->OnLButtonDown(GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam));
            return 0;
        case WM_CHAR:
            if (pThis) pThis->OnChar(wParam);
            return 0;
        case WM_DESTROY:
            return 0;
    }
    return DefWindowProc(hWnd, msg, wParam, lParam);
}

void MemoryPanel::Initialize(HWND hParent, int x, int y, int w, int h) {
    WNDCLASSEX wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.lpszClassName = "RawrXD_MemoryPanel";
    wc.hbrBackground = (HBRUSH)CreateSolidBrush(RGB(30, 30, 30));
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    RegisterClassEx(&wc);
    
    m_hWnd = CreateWindowEx(WS_EX_CLIENTEDGE, "RawrXD_MemoryPanel", "Memory",
        WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
        x, y, w, h, hParent, nullptr, GetModuleHandle(nullptr), this);
}

void MemoryPanel::Shutdown() {
    if (m_hWnd) DestroyWindow(m_hWnd);
}

void MemoryPanel::OnCreate() {
    // Address input at top
    m_hEdit = CreateWindowEx(0, "EDIT", "0x0000000000000000",
        WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
        5, 5, 200, 20, m_hWnd, (HMENU)IDC_MEMORY_EDIT, GetModuleHandle(nullptr), nullptr);
    
    // Set dark theme
    SendMessage(m_hEdit, WM_SETFONT,
        (WPARAM)CreateFont(12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            DEFAULT_QUALITY, FIXED_PITCH | FF_MODERN, "Consolas"),
        TRUE);
}

void MemoryPanel::OnSize(int w, int h) {
    // Edit at top, rest for hex view
    SetWindowPos(m_hEdit, nullptr, 5, 5, w - 10, 20, SWP_NOZORDER);
    InvalidateRect(m_hWnd, nullptr, TRUE);
}

void MemoryPanel::SetAddress(uint64_t addr) {
    m_address = addr;
    char buf[32];
    Hex64(buf, addr);
    SetWindowTextA(m_hEdit, buf);
    InvalidateRect(m_hWnd, nullptr, TRUE);
}

void MemoryPanel::Refresh(DebugSession* session) {
    if (session) {
        session->ReadMemory(m_address, m_buffer, sizeof(m_buffer));
    }
    InvalidateRect(m_hWnd, nullptr, TRUE);
}

void MemoryPanel::SetEditMode(bool edit) {
    m_editMode = edit;
    InvalidateRect(m_hWnd, nullptr, TRUE);
}

void MemoryPanel::OnPaint(HDC hdc) {
    RECT rc;
    GetClientRect(m_hWnd, &rc);
    
    // Fill background
    HBRUSH hBrush = CreateSolidBrush(RGB(30, 30, 30));
    FillRect(hdc, &rc, hBrush);
    DeleteObject(hBrush);
    
    // Create font
    HFONT hFont = CreateFont(12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        DEFAULT_QUALITY, FIXED_PITCH | FF_MODERN, "Consolas");
    HFONT hOldFont = (HFONT)SelectObject(hdc, hFont);
    
    SetTextColor(hdc, RGB(220, 220, 220));
    SetBkMode(hdc, TRANSPARENT);
    
    // Draw hex dump
    int y = 30;
    int lineHeight = 16;
    
    for (int row = 0; row < 16; ++row) {
        uint64_t rowAddr = m_address + row * m_bytesPerRow;
        
        // Address
        char addrBuf[32];
        Hex64(addrBuf, rowAddr);
        TextOutA(hdc, 5, y, addrBuf, StrLen(addrBuf));
        
        // Hex bytes
        int xHex = 130;
        for (int col = 0; col < m_bytesPerRow; ++col) {
            char byteBuf[4];
            Hex8(byteBuf, m_buffer[row * m_bytesPerRow + col]);
            TextOutA(hdc, xHex + col * 25, y, byteBuf, 2);
        }
        
        // ASCII
        int xAscii = 130 + m_bytesPerRow * 25 + 10;
        char asciiBuf[17];
        for (int col = 0; col < m_bytesPerRow; ++col) {
            uint8_t b = m_buffer[row * m_bytesPerRow + col];
            asciiBuf[col] = (b >= 32 && b < 127) ? b : '.';
        }
        asciiBuf[m_bytesPerRow] = 0;
        TextOutA(hdc, xAscii, y, asciiBuf, StrLen(asciiBuf));
        
        y += lineHeight;
    }
    
    SelectObject(hdc, hOldFont);
    DeleteObject(hFont);
}

void MemoryPanel::OnLButtonDown(int x, int y) {
    // Calculate which byte was clicked
    if (y < 30) return;
    
    int row = (y - 30) / 16;
    if (row < 0 || row >= 16) return;
    
    // Simple hit test for hex area
    if (x >= 130 && x < 130 + m_bytesPerRow * 25) {
        int col = (x - 130) / 25;
        if (col >= 0 && col < m_bytesPerRow) {
            // Byte selected - could highlight or enter edit mode
            m_editMode = true;
        }
    }
}

void MemoryPanel::OnChar(WPARAM ch) {
    if (m_editMode) {
        // Handle hex input
        if ((ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F') || (ch >= 'a' && ch <= 'f')) {
            // Accumulate hex digits and write to memory
        }
    }
}

//=============================================================================
// DebugToolbar Implementation
//=============================================================================

#define ID_BTN_GO       2001
#define ID_BTN_STEP     2002
#define ID_BTN_STEPOVER 2003
#define ID_BTN_STOP     2004

LRESULT CALLBACK DebugToolbar::WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    DebugToolbar* pThis = (DebugToolbar*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
    switch (msg) {
        case WM_CREATE:
            pThis = (DebugToolbar*)((CREATESTRUCT*)lParam)->lpCreateParams;
            SetWindowLongPtr(hWnd, GWLP_USERDATA, (LONG_PTR)pThis);
            pThis->m_hWnd = hWnd;
            return 0;
        case WM_COMMAND:
            if (pThis) pThis->OnCommand(LOWORD(wParam));
            return 0;
        case WM_DESTROY:
            return 0;
    }
    return DefWindowProc(hWnd, msg, wParam, lParam);
}

void DebugToolbar::Initialize(HWND hParent, int x, int y, int w, int h) {
    WNDCLASSEX wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.lpszClassName = "RawrXD_DebugToolbar";
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    RegisterClassEx(&wc);
    
    m_hWnd = CreateWindowEx(0, "RawrXD_DebugToolbar", "",
        WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
        x, y, w, h, hParent, nullptr, GetModuleHandle(nullptr), this);
    
    int btnW = 60, btnH = 24, pad = 4;
    int bx = pad;
    
    m_hBtnGo = CreateWindow("BUTTON", "Go (F5)",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED,
        bx, pad, btnW, btnH, m_hWnd, (HMENU)ID_BTN_GO, GetModuleHandle(nullptr), nullptr);
    bx += btnW + pad;
    
    m_hBtnStep = CreateWindow("BUTTON", "Step (F11)",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED,
        bx, pad, btnW + 10, btnH, m_hWnd, (HMENU)ID_BTN_STEP, GetModuleHandle(nullptr), nullptr);
    bx += btnW + 14;
    
    m_hBtnStepOver = CreateWindow("BUTTON", "Over (F10)",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED,
        bx, pad, btnW + 10, btnH, m_hWnd, (HMENU)ID_BTN_STEPOVER, GetModuleHandle(nullptr), nullptr);
    bx += btnW + 14;
    
    m_hBtnStop = CreateWindow("BUTTON", "Stop (Shift+F5)",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED,
        bx, pad, btnW + 30, btnH, m_hWnd, (HMENU)ID_BTN_STOP, GetModuleHandle(nullptr), nullptr);
}

void DebugToolbar::Shutdown() {
    if (m_hWnd) DestroyWindow(m_hWnd);
}

void DebugToolbar::SetRunning(bool running) {
    EnableWindow(m_hBtnGo, running ? FALSE : TRUE);
    EnableWindow(m_hBtnStep, running ? FALSE : TRUE);
    EnableWindow(m_hBtnStepOver, running ? FALSE : TRUE);
    EnableWindow(m_hBtnStop, running ? TRUE : FALSE);
}

void DebugToolbar::SetAttached(bool attached) {
    if (!attached) {
        EnableWindow(m_hBtnGo, FALSE);
        EnableWindow(m_hBtnStep, FALSE);
        EnableWindow(m_hBtnStepOver, FALSE);
        EnableWindow(m_hBtnStop, FALSE);
    }
}

void DebugToolbar::SetCallbacks(
    void (*onGo)(void*),
    void (*onStep)(void*),
    void (*onStepOver)(void*),
    void (*onStop)(void*),
    void* user
) {
    m_onGo = onGo;
    m_onStep = onStep;
    m_onStepOver = onStepOver;
    m_onStop = onStop;
    m_user = user;
}

void DebugToolbar::OnCommand(int id) {
    switch (id) {
        case ID_BTN_GO:       if (m_onGo) m_onGo(m_user); break;
        case ID_BTN_STEP:     if (m_onStep) m_onStep(m_user); break;
        case ID_BTN_STEPOVER: if (m_onStepOver) m_onStepOver(m_user); break;
        case ID_BTN_STOP:     if (m_onStop) m_onStop(m_user); break;
    }
}

//=============================================================================
// DebugEventLog Implementation
//=============================================================================

#define IDC_EVENT_EDIT 1005

void DebugEventLog::Initialize(HWND hParent, int x, int y, int w, int h) {
    m_hWnd = CreateWindowEx(WS_EX_CLIENTEDGE, "EDIT", "",
        WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL,
        x, y, w, h, hParent, (HMENU)IDC_EVENT_EDIT, GetModuleHandle(nullptr), nullptr);
    
    SendMessage(m_hWnd, WM_SETFONT,
        (WPARAM)CreateFont(12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            DEFAULT_QUALITY, FIXED_PITCH | FF_MODERN, "Consolas"),
        TRUE);
    
    // Dark theme
    SendMessage(m_hWnd, EM_SETBKGNDCOLOR, 0, RGB(30, 30, 30));
}

void DebugEventLog::Shutdown() {
    if (m_hWnd) DestroyWindow(m_hWnd);
}

void DebugEventLog::AppendText(const char* text) {
    int len = GetWindowTextLengthA(m_hWnd);
    SendMessageA(m_hWnd, EM_SETSEL, len, len);
    SendMessageA(m_hWnd, EM_REPLACESEL, FALSE, (LPARAM)text);
}

void DebugEventLog::Log(const char* message) {
    AppendText(message);
    AppendText("\r\n");
    ++m_lineCount;
    TrimOldLines();
}

void DebugEventLog::LogException(uint32_t code, uint64_t addr) {
    char buf[256];
    char hex[32];
    Hex64(hex, addr);
    
    const char* name = "Unknown";
    switch (code) {
        case 0xC0000005: name = "ACCESS_VIOLATION"; break;
        case 0x80000003: name = "BREAKPOINT"; break;
        case 0x80000004: name = "SINGLE_STEP"; break;
        case 0xC0000094: name = "INT_DIVIDE_BY_ZERO"; break;
        case 0xC0000095: name = "INT_OVERFLOW"; break;
        case 0xC00000FD: name = "STACK_OVERFLOW"; break;
        case 0xC0000135: name = "DLL_NOT_FOUND"; break;
        case 0xC0000138: name = "ORDINAL_NOT_FOUND"; break;
        case 0xC0000139: name = "ENTRYPOINT_NOT_FOUND"; break;
        case 0xC0000142: name = "DLL_INIT_FAILED"; break;
    }
    
    buf[0] = 0;
    StrCat(buf, "[!] Exception: ");
    StrCat(buf, name);
    StrCat(buf, " at ");
    StrCat(buf, hex);
    Log(buf);
}

void DebugEventLog::LogBreakpoint(uint64_t addr) {
    char buf[128];
    char hex[32];
    Hex64(hex, addr);
    buf[0] = 0;
    StrCat(buf, "[*] Breakpoint hit at ");
    StrCat(buf, hex);
    Log(buf);
}

void DebugEventLog::LogDllLoad(const wchar_t* path, uint64_t base) {
    char buf[512];
    char hex[32];
    Hex64(hex, base);
    char pathA[256];
    WStrToStr(pathA, path, 256);
    buf[0] = 0;
    StrCat(buf, "[*] DLL loaded: ");
    StrCat(buf, pathA);
    StrCat(buf, " at ");
    StrCat(buf, hex);
    Log(buf);
}

void DebugEventLog::Clear() {
    SetWindowTextA(m_hWnd, "");
    m_lineCount = 0;
}

void DebugEventLog::TrimOldLines() {
    if (m_lineCount <= MAX_LINES) return;
    // Remove oldest lines by selecting and deleting
    int linesToRemove = m_lineCount - MAX_LINES + 100;
    SendMessage(m_hWnd, EM_LINESCROLL, 0, linesToRemove);
    SendMessage(m_hWnd, EM_SETSEL, 0, (LPARAM)SendMessage(m_hWnd, EM_LINEINDEX, linesToRemove, 0));
    SendMessage(m_hWnd, EM_REPLACESEL, TRUE, (LPARAM)"");
    m_lineCount -= linesToRemove;
}

//=============================================================================
// DebugUIManager Implementation
//=============================================================================

DebugUIManager& DebugUIManager::Instance() {
    static DebugUIManager inst;
    return inst;
}

bool DebugUIManager::Initialize(HWND hMainWindow) {
    m_hMain = hMainWindow;
    
    // Init common controls
    INITCOMMONCONTROLSEX icc = {};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_TREEVIEW_CLASSES;
    InitCommonControlsEx(&icc);
    
    CreatePanelWindows();
    return true;
}

void DebugUIManager::Shutdown() {
    DestroyPanelWindows();
}

void DebugUIManager::CreatePanelWindows() {
    RECT rc;
    GetClientRect(m_hMain, &rc);
    CalculateLayout(rc.right, rc.bottom);
    
    m_toolbar.Initialize(m_hMain, m_rcToolbar.left, m_rcToolbar.top,
        m_rcToolbar.right - m_rcToolbar.left, m_rcToolbar.bottom - m_rcToolbar.top);
    
    m_callstack.Initialize(m_hMain, m_rcCallStack.left, m_rcCallStack.top,
        m_rcCallStack.right - m_rcCallStack.left, m_rcCallStack.bottom - m_rcCallStack.top);
    
    m_registers.Initialize(m_hMain, m_rcRegisters.left, m_rcRegisters.top,
        m_rcRegisters.right - m_rcRegisters.left, m_rcRegisters.bottom - m_rcRegisters.top);
    
    m_memory.Initialize(m_hMain, m_rcMemory.left, m_rcMemory.top,
        m_rcMemory.right - m_rcMemory.left, m_rcMemory.bottom - m_rcMemory.top);
    
    m_eventLog.Initialize(m_hMain, m_rcEventLog.left, m_rcEventLog.top,
        m_rcEventLog.right - m_rcEventLog.left, m_rcEventLog.bottom - m_rcEventLog.top);
    
    // Wire toolbar callbacks
    m_toolbar.SetCallbacks(
        [](void* user) { /* Go */ },
        [](void* user) { /* Step */ },
        [](void* user) { /* Step Over */ },
        [](void* user) { /* Stop */ },
        this
    );
}

void DebugUIManager::DestroyPanelWindows() {
    m_toolbar.Shutdown();
    m_callstack.Shutdown();
    m_registers.Shutdown();
    m_memory.Shutdown();
    m_eventLog.Shutdown();
}

void DebugUIManager::CalculateLayout(int width, int height) {
    int toolbarH = 32;
    int panelW = 300;
    int bottomH = 150;
    int rightX = width - panelW;
    
    // Toolbar at top
    m_rcToolbar = { 0, 0, width, toolbarH };
    
    // Call stack: top-right
    m_rcCallStack = { rightX, toolbarH, width, toolbarH + (height - toolbarH - bottomH) / 2 };
    
    // Registers: middle-right
    m_rcRegisters = { rightX, m_rcCallStack.bottom, width, m_rcCallStack.bottom + (height - toolbarH - bottomH) / 2 };
    
    // Memory: below registers (or tabbed - simplified)
    m_rcMemory = { rightX, m_rcRegisters.bottom, width, height - bottomH };
    
    // Event log: bottom
    m_rcEventLog = { 0, height - bottomH, width, height };
}

void DebugUIManager::OnMainResize(int width, int height) {
    CalculateLayout(width, height);
    
    SetWindowPos(m_toolbar.GetHwnd(), nullptr,
        m_rcToolbar.left, m_rcToolbar.top,
        m_rcToolbar.right - m_rcToolbar.left, m_rcToolbar.bottom - m_rcToolbar.top,
        SWP_NOZORDER);
    
    SetWindowPos(m_callstack.GetHwnd(), nullptr,
        m_rcCallStack.left, m_rcCallStack.top,
        m_rcCallStack.right - m_rcCallStack.left, m_rcCallStack.bottom - m_rcCallStack.top,
        SWP_NOZORDER);
    
    SetWindowPos(m_registers.GetHwnd(), nullptr,
        m_rcRegisters.left, m_rcRegisters.top,
        m_rcRegisters.right - m_rcRegisters.left, m_rcRegisters.bottom - m_rcRegisters.top,
        SWP_NOZORDER);
    
    SetWindowPos(m_memory.GetHwnd(), nullptr,
        m_rcMemory.left, m_rcMemory.top,
        m_rcMemory.right - m_rcMemory.left, m_rcMemory.bottom - m_rcMemory.top,
        SWP_NOZORDER);
    
    SetWindowPos(m_eventLog.GetHwnd(), nullptr,
        m_rcEventLog.left, m_rcEventLog.top,
        m_rcEventLog.right - m_rcEventLog.left, m_rcEventLog.bottom - m_rcEventLog.top,
        SWP_NOZORDER);
}

void DebugUIManager::ShowPanels(bool show) {
    m_visible = show;
    int cmd = show ? SW_SHOW : SW_HIDE;
    ShowWindow(m_toolbar.GetHwnd(), cmd);
    ShowWindow(m_callstack.GetHwnd(), cmd);
    ShowWindow(m_registers.GetHwnd(), cmd);
    ShowWindow(m_memory.GetHwnd(), cmd);
    ShowWindow(m_eventLog.GetHwnd(), cmd);
    
    if (show) {
        RECT rc;
        GetClientRect(m_hMain, &rc);
        OnMainResize(rc.right, rc.bottom);
    }
}

bool DebugUIManager::ArePanelsVisible() const {
    return m_visible;
}

void DebugUIManager::AttachSession(DebugSession* session) {
    m_session = session;
    m_toolbar.SetAttached(true);
    m_toolbar.SetRunning(false);  // Stopped at breakpoint or start
    m_eventLog.Log("[*] Debug session attached");
}

void DebugUIManager::DetachSession() {
    m_session = nullptr;
    m_toolbar.SetAttached(false);
    m_eventLog.Log("[*] Debug session detached");
}

void DebugUIManager::OnBreakpointHit(uint64_t addr) {
    m_toolbar.SetRunning(false);
    m_eventLog.LogBreakpoint(addr);
    
    // Update call stack
    if (m_session) {
        auto stack = m_session->GetCallStack();
        m_callstack.Update(stack.data(), (int)stack.size());
    }
    
    // Update registers
    if (m_session) {
        RegisterContext ctx;
        m_session->GetRegisters(ctx);
        m_registers.Update(&ctx);
    }
    
    // Update memory at RIP
    m_memory.SetAddress(addr);
    m_memory.Refresh(m_session);
    
    // Bring window to front
    SetForegroundWindow(m_hMain);
}

void DebugUIManager::OnException(uint32_t code, uint64_t addr) {
    m_toolbar.SetRunning(false);
    m_eventLog.LogException(code, addr);
    SetForegroundWindow(m_hMain);
}

void DebugUIManager::OnStepComplete() {
    m_toolbar.SetRunning(false);
    m_eventLog.Log("[*] Step complete");
    
    // Update registers and memory
    if (m_session) {
        RegisterContext ctx;
        m_session->GetRegisters(ctx);
        m_registers.Update(&ctx);
        m_memory.Refresh(m_session);
    }
}

void DebugUIManager::OnProcessExit(uint32_t code) {
    m_toolbar.SetRunning(false);
    m_toolbar.SetAttached(false);
    char buf[64];
    buf[0] = 0;
    StrCat(buf, "[*] Process exited with code ");
    char num[32];
    Dec(num, code);
    StrCat(buf, num);
    m_eventLog.Log(buf);
}

void DebugUIManager::OnDllLoad(const wchar_t* path, uint64_t base) {
    m_eventLog.LogDllLoad(path, base);
}

} // namespace DebugUI
} // namespace RawrXD
