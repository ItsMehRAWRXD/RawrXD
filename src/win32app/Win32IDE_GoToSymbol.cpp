// ============================================================================
// Win32IDE_GoToSymbol.cpp — Go To Symbol Picker (Ctrl+Shift+O)
// ============================================================================
// VS Code-style "@" symbol picker — a popup at the top-center of the editor
// that lists all document symbols from the outline cache, supports fuzzy
// filtering by name, and jumps to the selected symbol's line via gotoLine().
//
// Architecture:
//   - WS_POPUP overlay with EDIT filter + ListView showing symbols
//   - Populated from m_outlineSymbols (refreshed from LSP or local parse)
//   - Fuzzy substring match on typing
//   - Enter/Click → gotoLine(), Esc → dismiss
//   - Kind icons via Unicode glyphs (same style as OutlinePanel)
//
// Rule: NO SOURCE FILE IS TO BE SIMPLIFIED.
// ============================================================================

#include "Win32IDE.h"
#include <richedit.h>
#include <commctrl.h>
#include <algorithm>
#include <cctype>
#include <cwctype>
#include <string>

// ── File-static state ───────────────────────────────────────────────────────
struct FlatSymbol {
    std::wstring name;
    std::wstring detail;
    std::wstring kindLabel;
    int line = 0;
    int kindValue = 0;
};

static struct GoToSymbolState {
    HWND hwndOverlay    = nullptr;
    HWND hwndEdit       = nullptr;
    HWND hwndList       = nullptr;
    WNDPROC oldEditProc = nullptr;
    Win32IDE* pIDE      = nullptr;
    bool active         = false;
    std::vector<FlatSymbol> allSymbols;
    std::vector<FlatSymbol> filtered;
} s_gts;

#define IDC_GTS_EDIT  9911
#define IDC_GTS_LIST  9912

// ── Forward declarations ────────────────────────────────────────────────────
static LRESULT CALLBACK GoToSymbolOverlayProc(HWND, UINT, WPARAM, LPARAM);
static LRESULT CALLBACK GoToSymbolEditProc(HWND, UINT, WPARAM, LPARAM);
static void populateList();
static void filterSymbols();
static void commitSymbolSelection();

// ============================================================================
// Symbol kind → display label (matches LSP SymbolKind enum)
// ============================================================================
static const wchar_t* symbolKindLabel(int kind)
{
    switch (kind) {
    case 1:  return L"File";
    case 2:  return L"Module";
    case 3:  return L"Namespace";
    case 4:  return L"Package";
    case 5:  return L"Class";
    case 6:  return L"Method";
    case 7:  return L"Property";
    case 8:  return L"Field";
    case 9:  return L"Constructor";
    case 10: return L"Enum";
    case 11: return L"Interface";
    case 12: return L"Function";
    case 13: return L"Variable";
    case 14: return L"Constant";
    case 15: return L"String";
    case 16: return L"Number";
    case 17: return L"Boolean";
    case 18: return L"Array";
    case 19: return L"Object";
    case 20: return L"Key";
    case 21: return L"Null";
    case 22: return L"EnumMember";
    case 23: return L"Struct";
    case 24: return L"Event";
    case 25: return L"Operator";
    case 26: return L"TypeParameter";
    default: return L"Symbol";
    }
}

// ============================================================================
// Symbol kind → icon glyph
// ============================================================================
static const wchar_t* symbolKindIcon(int kind)
{
    switch (kind) {
    case 5:  return L"\x25A0 ";   // ■ Class
    case 6:  return L"\x25B6 ";   // ▶ Method
    case 9:  return L"\x25B6 ";   // ▶ Constructor
    case 12: return L"\x0192 ";   // ƒ Function
    case 13: return L"\x03B1 ";   // α Variable
    case 14: return L"\x03C0 ";   // π Constant
    case 10: return L"\x2261 ";   // ≡ Enum
    case 22: return L"\x2022 ";   // • EnumMember
    case 23: return L"\x25A1 ";   // □ Struct
    case 11: return L"\x25CB ";   // ○ Interface
    case 7:  return L"\x25C6 ";   // ◆ Property
    case 8:  return L"\x25C6 ";   // ◆ Field
    case 3:  return L"\x2302 ";   // ⌂ Namespace
    default: return L"\x00B7 ";   // · default
    }
}

// ============================================================================
// Flatten outline symbols into a searchable list (member function — accesses
// private m_outlineSymbols and refreshOutlineFromLSP)
// ============================================================================
void Win32IDE::populateSymbolPickerData()
{
    s_gts.allSymbols.clear();

    // Refresh from LSP (accesses private members)
    refreshOutlineFromLSP();

    // Recursively flatten OutlineSymbol tree → FlatSymbol list
    auto addSymbol = [](const OutlineSymbol& sym, auto& self) -> void {
        FlatSymbol fs;
        fs.name = std::wstring(sym.name.begin(), sym.name.end());
        fs.detail = std::wstring(sym.detail.begin(), sym.detail.end());
        fs.kindLabel = symbolKindLabel(sym.kind);
        fs.kindValue = sym.kind;
        fs.line = sym.line;
        s_gts.allSymbols.push_back(fs);

        for (const auto& child : sym.children) {
            self(child, self);
        }
    };

    for (const auto& sym : m_outlineSymbols) {
        addSymbol(sym, addSymbol);
    }

    // Sort by line number
    std::sort(s_gts.allSymbols.begin(), s_gts.allSymbols.end(),
              [](const FlatSymbol& a, const FlatSymbol& b) { return a.line < b.line; });
}

// ============================================================================
// Case-insensitive wide substring match
// ============================================================================
static bool wideSubstringMatch(const std::wstring& haystack, const std::wstring& needle)
{
    if (needle.empty()) return true;
    size_t hLen = haystack.size();
    size_t nLen = needle.size();
    if (nLen > hLen) return false;
    for (size_t i = 0; i <= hLen - nLen; ++i) {
        bool match = true;
        for (size_t j = 0; j < nLen; ++j) {
            if (towlower(haystack[i + j]) != towlower(needle[j])) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

// ============================================================================
// filterSymbols — apply the edit text as a filter
// ============================================================================
static void filterSymbols()
{
    if (!s_gts.hwndEdit || !s_gts.hwndList) return;

    wchar_t buf[256] = {};
    GetWindowTextW(s_gts.hwndEdit, buf, _countof(buf));
    std::wstring query(buf);

    // Strip leading @ (VS Code convention)
    if (!query.empty() && query[0] == L'@')
        query = query.substr(1);

    s_gts.filtered.clear();
    for (const auto& sym : s_gts.allSymbols) {
        if (wideSubstringMatch(sym.name, query)) {
            s_gts.filtered.push_back(sym);
        }
    }

    populateList();
}

// ============================================================================
// populateList — fill ListView from s_gts.filtered
// ============================================================================
static void populateList()
{
    if (!s_gts.hwndList) return;

    SendMessage(s_gts.hwndList, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(s_gts.hwndList);

    LVITEMW lvi = {};
    lvi.mask = LVIF_TEXT;

    for (int i = 0; i < (int)s_gts.filtered.size(); ++i) {
        const auto& sym = s_gts.filtered[i];

        // Column 0: icon + name
        std::wstring nameLabel = symbolKindIcon(sym.kindValue) + sym.name;
        lvi.iItem = i;
        lvi.iSubItem = 0;
        lvi.pszText = const_cast<LPWSTR>(nameLabel.c_str());
        ListView_InsertItem(s_gts.hwndList, &lvi);

        // Column 1: kind
        {
            LVITEMW lvi2 = {};
            lvi2.iSubItem = 1;
            lvi2.pszText = const_cast<LPWSTR>(sym.kindLabel.c_str());
            SendMessageW(s_gts.hwndList, LVM_SETITEMTEXTW, i, (LPARAM)&lvi2);
        }

        // Column 2: line number
        {
            wchar_t lineBuf[16];
            _snwprintf_s(lineBuf, _countof(lineBuf), _TRUNCATE, L"%d", sym.line);
            LVITEMW lvi3 = {};
            lvi3.iSubItem = 2;
            lvi3.pszText = lineBuf;
            SendMessageW(s_gts.hwndList, LVM_SETITEMTEXTW, i, (LPARAM)&lvi3);
        }
    }

    SendMessage(s_gts.hwndList, WM_SETREDRAW, TRUE, 0);

    // Auto-select first item
    if (!s_gts.filtered.empty()) {
        ListView_SetItemState(s_gts.hwndList, 0, LVIS_SELECTED | LVIS_FOCUSED,
                              LVIS_SELECTED | LVIS_FOCUSED);
    }
}

// ============================================================================
// commitSymbolSelection — jump to the selected symbol
// ============================================================================
static void commitSymbolSelection()
{
    if (!s_gts.hwndList || !s_gts.pIDE) return;

    int sel = ListView_GetNextItem(s_gts.hwndList, -1, LVNI_SELECTED);
    if (sel < 0 || sel >= (int)s_gts.filtered.size()) return;

    int line = s_gts.filtered[sel].line;
    s_gts.pIDE->navigateToLine(line);
    s_gts.pIDE->hideGoToSymbolPicker();
}

// ============================================================================
// showGoToSymbolPicker
// ============================================================================
void Win32IDE::showGoToSymbolPicker()
{
    if (s_gts.active) {
        SetFocus(s_gts.hwndEdit);
        SendMessage(s_gts.hwndEdit, EM_SETSEL, 0, -1);
        return;
    }

    s_gts.pIDE = this;

    // ── Register class once ─────────────────────────────────────────────────
    static bool classRegistered = false;
    if (!classRegistered) {
        WNDCLASSEXW wc = {};
        wc.cbSize        = sizeof(wc);
        wc.lpfnWndProc   = GoToSymbolOverlayProc;
        wc.hInstance      = m_hInstance;
        wc.hCursor        = LoadCursor(nullptr, IDC_ARROW);
        wc.hbrBackground  = CreateSolidBrush(RGB(37, 37, 38));
        wc.lpszClassName  = L"RawrXD_GoToSymbol";
        RegisterClassExW(&wc);
        classRegistered = true;
    }

    // ── Flatten symbol data ─────────────────────────────────────────────────
    populateSymbolPickerData();

    // ── Calculate position: top-center of main window ───────────────────────
    RECT rcMain = {};
    GetWindowRect(m_hwndMain, &rcMain);
    const int popW = 500;
    const int popH = 340;
    const int popX = rcMain.left + (rcMain.right - rcMain.left - popW) / 2;
    const int popY = rcMain.top + 50;

    s_gts.hwndOverlay = CreateWindowExW(
        WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
        L"RawrXD_GoToSymbol", L"",
        WS_POPUP | WS_BORDER,
        popX, popY, popW, popH,
        m_hwndMain, nullptr, m_hInstance, nullptr);

    // ── EDIT ────────────────────────────────────────────────────────────────
    s_gts.hwndEdit = CreateWindowExW(
        0, L"EDIT", L"@",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | WS_BORDER,
        8, 8, popW - 16, 24,
        s_gts.hwndOverlay, (HMENU)(UINT_PTR)IDC_GTS_EDIT,
        m_hInstance, nullptr);

    // Subclass edit for key handling
    s_gts.oldEditProc = (WNDPROC)SetWindowLongPtrW(s_gts.hwndEdit, GWLP_WNDPROC,
                                                     (LONG_PTR)GoToSymbolEditProc);

    // ── ListView ────────────────────────────────────────────────────────────
    s_gts.hwndList = CreateWindowExW(
        0, WC_LISTVIEWW, L"",
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS | LVS_NOCOLUMNHEADER,
        8, 38, popW - 16, popH - 46,
        s_gts.hwndOverlay, (HMENU)(UINT_PTR)IDC_GTS_LIST,
        m_hInstance, nullptr);

    // Dark theme for list
    ListView_SetBkColor(s_gts.hwndList, RGB(37, 37, 38));
    ListView_SetTextBkColor(s_gts.hwndList, RGB(37, 37, 38));
    ListView_SetTextColor(s_gts.hwndList, RGB(204, 204, 204));
    ListView_SetExtendedListViewStyle(s_gts.hwndList, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);

    // Add columns
    LVCOLUMNW lvc = {};
    lvc.mask = LVCF_WIDTH | LVCF_TEXT;
    lvc.cx = popW - 16 - 80 - 50;
    lvc.pszText = (LPWSTR)L"Symbol";
    ListView_InsertColumn(s_gts.hwndList, 0, &lvc);
    lvc.cx = 80;
    lvc.pszText = (LPWSTR)L"Kind";
    ListView_InsertColumn(s_gts.hwndList, 1, &lvc);
    lvc.cx = 50;
    lvc.pszText = (LPWSTR)L"Line";
    ListView_InsertColumn(s_gts.hwndList, 2, &lvc);

    // ── Font ────────────────────────────────────────────────────────────────
    HFONT hFont = CreateFontW(
        -14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    SendMessage(s_gts.hwndEdit, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(s_gts.hwndList, WM_SETFONT, (WPARAM)hFont, TRUE);

    // ── Populate ────────────────────────────────────────────────────────────
    s_gts.filtered = s_gts.allSymbols;
    populateList();

    ShowWindow(s_gts.hwndOverlay, SW_SHOWNA);
    SetForegroundWindow(s_gts.hwndOverlay);
    SetFocus(s_gts.hwndEdit);
    SendMessage(s_gts.hwndEdit, EM_SETSEL, 1, -1); // select after @

    s_gts.active = true;
}

// ============================================================================
// hideGoToSymbolPicker
// ============================================================================
void Win32IDE::hideGoToSymbolPicker()
{
    if (!s_gts.active) return;

    if (s_gts.hwndOverlay) {
        DestroyWindow(s_gts.hwndOverlay);
        s_gts.hwndOverlay = nullptr;
        s_gts.hwndEdit    = nullptr;
        s_gts.hwndList    = nullptr;
    }
    s_gts.allSymbols.clear();
    s_gts.filtered.clear();
    s_gts.active = false;

    if (m_hwndEditor && IsWindow(m_hwndEditor))
        SetFocus(m_hwndEditor);
}

bool Win32IDE::isGoToSymbolPickerVisible() const
{
    return s_gts.active;
}

// ============================================================================
// GoToSymbol overlay WndProc
// ============================================================================
static LRESULT CALLBACK GoToSymbolOverlayProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLOREDIT:
    {
        HDC hdc = (HDC)wParam;
        SetTextColor(hdc, RGB(204, 204, 204));
        SetBkColor(hdc, RGB(37, 37, 38));
        static HBRUSH s_brush = CreateSolidBrush(RGB(37, 37, 38));
        return (LRESULT)s_brush;
    }

    case WM_NOTIFY:
    {
        NMHDR* pNM = reinterpret_cast<NMHDR*>(lParam);
        if (pNM && pNM->hwndFrom == s_gts.hwndList) {
            if (pNM->code == NM_DBLCLK || pNM->code == NM_RETURN) {
                commitSymbolSelection();
                return 0;
            }
        }
        break;
    }

    case WM_ACTIVATE:
        if (LOWORD(wParam) == WA_INACTIVE) {
            if (s_gts.pIDE)
                s_gts.pIDE->hideGoToSymbolPicker();
        }
        return 0;

    case WM_CLOSE:
        if (s_gts.pIDE)
            s_gts.pIDE->hideGoToSymbolPicker();
        return 0;

    case WM_DESTROY:
        s_gts.hwndOverlay = nullptr;
        s_gts.active = false;
        return 0;
    }

    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

// ============================================================================
// GoToSymbol EDIT subclass — intercept Enter/Esc/Up/Down + live filter
// ============================================================================
static LRESULT CALLBACK GoToSymbolEditProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_KEYDOWN:
        if (wParam == VK_RETURN) {
            commitSymbolSelection();
            return 0;
        }
        if (wParam == VK_ESCAPE) {
            if (s_gts.pIDE)
                s_gts.pIDE->hideGoToSymbolPicker();
            return 0;
        }
        if (wParam == VK_DOWN) {
            int sel = ListView_GetNextItem(s_gts.hwndList, -1, LVNI_SELECTED);
            int count = ListView_GetItemCount(s_gts.hwndList);
            if (sel + 1 < count) {
                ListView_SetItemState(s_gts.hwndList, sel, 0, LVIS_SELECTED | LVIS_FOCUSED);
                ListView_SetItemState(s_gts.hwndList, sel + 1, LVIS_SELECTED | LVIS_FOCUSED,
                                      LVIS_SELECTED | LVIS_FOCUSED);
                ListView_EnsureVisible(s_gts.hwndList, sel + 1, FALSE);
            }
            return 0;
        }
        if (wParam == VK_UP) {
            int sel = ListView_GetNextItem(s_gts.hwndList, -1, LVNI_SELECTED);
            if (sel > 0) {
                ListView_SetItemState(s_gts.hwndList, sel, 0, LVIS_SELECTED | LVIS_FOCUSED);
                ListView_SetItemState(s_gts.hwndList, sel - 1, LVIS_SELECTED | LVIS_FOCUSED,
                                      LVIS_SELECTED | LVIS_FOCUSED);
                ListView_EnsureVisible(s_gts.hwndList, sel - 1, FALSE);
            }
            return 0;
        }
        break;

    case WM_CHAR:
        if (wParam == '\r' || wParam == '\n')
            return 0;
        // Fall through — let the edit handle the character, then filter
        {
            LRESULT result = CallWindowProcW(s_gts.oldEditProc, hwnd, msg, wParam, lParam);
            filterSymbols();
            return result;
        }
    }

    return CallWindowProcW(s_gts.oldEditProc, hwnd, msg, wParam, lParam);
}
