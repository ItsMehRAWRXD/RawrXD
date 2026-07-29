/**
 * @file FindReplaceDialog.cpp
 * @brief Find and Replace Dialog Implementation
 */

#include "FindReplaceDialog.hpp"
#include <commctrl.h>
#include <regex>

#pragma comment(lib, "comctl32.lib")

namespace RawrXD::IDE {

// Dialog template IDs
#define IDC_FIND_TEXT       1001
#define IDC_REPLACE_TEXT    1002
#define IDC_CASE_SENSITIVE  1003
#define IDC_WHOLE_WORD      1004
#define IDC_USE_REGEX       1005
#define IDC_WRAP_AROUND     1006
#define IDC_DIRECTION_UP    1007
#define IDC_DIRECTION_DOWN  1008
#define IDC_FIND_NEXT       1009
#define IDC_REPLACE         1010
#define IDC_REPLACE_ALL     1011
#define IDC_RESULT_LABEL    1012

FindReplaceDialog::FindReplaceDialog()
    : m_hwnd(nullptr)
    , m_hwndParent(nullptr)
    , m_replaceMode(false)
    , m_hwndFindEdit(nullptr)
    , m_hwndReplaceEdit(nullptr)
    , m_hwndCaseCheck(nullptr)
    , m_hwndWholeWordCheck(nullptr)
    , m_hwndRegexCheck(nullptr)
    , m_hwndWrapCheck(nullptr)
    , m_hwndUpRadio(nullptr)
    , m_hwndDownRadio(nullptr)
{
}

FindReplaceDialog::~FindReplaceDialog() {
    Destroy();
}

bool FindReplaceDialog::Create(HWND hwndParent, bool replaceMode) {
    if (m_hwnd) return true;
    
    m_hwndParent = hwndParent;
    m_replaceMode = replaceMode;
    
    // Create as modeless dialog
    m_hwnd = CreateDialogParam(
        GetModuleHandle(nullptr),
        replaceMode ? MAKEINTRESOURCE(IDD_REPLACE_DIALOG) : MAKEINTRESOURCE(IDD_FIND_DIALOG),
        hwndParent,
        DialogProc,
        reinterpret_cast<LPARAM>(this)
    );
    
    if (!m_hwnd) {
        // Fallback: Create simple dialog manually
        m_hwnd = CreateWindowExW(
            WS_EX_DLGMODALFRAME,
            L"#32770",  // Dialog class
            replaceMode ? L"Replace" : L"Find",
            WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_THICKFRAME,
            CW_USEDEFAULT, CW_USEDEFAULT,
            replaceMode ? 400 : 350,
            replaceMode ? 250 : 200,
            hwndParent,
            nullptr,
            GetModuleHandle(nullptr),
            this
        );
        
        if (m_hwnd) {
            CreateControls();
        }
    }
    
    if (m_hwnd) {
        SetWindowLongPtr(m_hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(this));
        CenterOnParent();
        ShowWindow(m_hwnd, SW_SHOW);
        SetFocus(m_hwndFindEdit);
    }
    
    return m_hwnd != nullptr;
}

void FindReplaceDialog::CreateControls() {
    HINSTANCE hInst = GetModuleHandle(nullptr);
    
    // Find what label and edit
    CreateWindowW(L"STATIC", L"Find what:",
        WS_VISIBLE | WS_CHILD | SS_LEFT,
        10, 15, 70, 20, m_hwnd, nullptr, hInst, nullptr);
    
    m_hwndFindEdit = CreateWindowW(L"EDIT", L"",
        WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL,
        90, 12, 240, 24, m_hwnd, (HMENU)IDC_FIND_TEXT, hInst, nullptr);
    
    if (m_replaceMode) {
        // Replace with label and edit
        CreateWindowW(L"STATIC", L"Replace with:",
            WS_VISIBLE | WS_CHILD | SS_LEFT,
            10, 45, 80, 20, m_hwnd, nullptr, hInst, nullptr);
        
        m_hwndReplaceEdit = CreateWindowW(L"EDIT", L"",
            WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL,
            90, 42, 240, 24, m_hwnd, (HMENU)IDC_REPLACE_TEXT, hInst, nullptr);
    }
    
    // Options group
    CreateWindowW(L"BUTTON", L"Options",
        WS_VISIBLE | WS_CHILD | BS_GROUPBOX,
        10, m_replaceMode ? 75 : 45, 200, 100, m_hwnd, nullptr, hInst, nullptr);
    
    m_hwndCaseCheck = CreateWindowW(L"BUTTON", L"Match &case",
        WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX,
        20, m_replaceMode ? 95 : 65, 100, 20, m_hwnd, (HMENU)IDC_CASE_SENSITIVE, hInst, nullptr);
    
    m_hwndWholeWordCheck = CreateWindowW(L"BUTTON", L"Match &whole word",
        WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX,
        20, m_replaceMode ? 115 : 85, 130, 20, m_hwnd, (HMENU)IDC_WHOLE_WORD, hInst, nullptr);
    
    m_hwndRegexCheck = CreateWindowW(L"BUTTON", L"Use regular e&xpressions",
        WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX,
        20, m_replaceMode ? 135 : 105, 160, 20, m_hwnd, (HMENU)IDC_USE_REGEX, hInst, nullptr);
    
    m_hwndWrapCheck = CreateWindowW(L"BUTTON", L"Wrap ar&ound",
        WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX,
        20, m_replaceMode ? 155 : 125, 100, 20, m_hwnd, (HMENU)IDC_WRAP_AROUND, hInst, nullptr);
    CheckDlgButton(m_hwnd, IDC_WRAP_AROUND, BST_CHECKED);
    
    // Direction group
    CreateWindowW(L"BUTTON", L"Direction",
        WS_VISIBLE | WS_CHILD | BS_GROUPBOX,
        220, m_replaceMode ? 75 : 45, 110, 70, m_hwnd, nullptr, hInst, nullptr);
    
    m_hwndUpRadio = CreateWindowW(L"BUTTON", L"&Up",
        WS_VISIBLE | WS_CHILD | BS_AUTORADIOBUTTON,
        230, m_replaceMode ? 95 : 65, 80, 20, m_hwnd, (HMENU)IDC_DIRECTION_UP, hInst, nullptr);
    
    m_hwndDownRadio = CreateWindowW(L"BUTTON", L"&Down",
        WS_VISIBLE | WS_CHILD | BS_AUTORADIOBUTTON | WS_GROUP,
        230, m_replaceMode ? 115 : 85, 80, 20, m_hwnd, (HMENU)IDC_DIRECTION_DOWN, hInst, nullptr);
    CheckDlgButton(m_hwnd, IDC_DIRECTION_DOWN, BST_CHECKED);
    
    // Buttons
    int btnY = m_replaceMode ? 190 : 155;
    CreateWindowW(L"BUTTON", L"&Find Next",
        WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
        90, btnY, 80, 26, m_hwnd, (HMENU)IDC_FIND_NEXT, hInst, nullptr);
    
    if (m_replaceMode) {
        CreateWindowW(L"BUTTON", L"&Replace",
            WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
            180, btnY, 80, 26, m_hwnd, (HMENU)IDC_REPLACE, hInst, nullptr);
        
        CreateWindowW(L"BUTTON", L"Replace &All",
            WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
            270, btnY, 80, 26, m_hwnd, (HMENU)IDC_REPLACE_ALL, hInst, nullptr);
    }
    
    CreateWindowW(L"BUTTON", L"Cancel",
        WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
        m_replaceMode ? 360 : 180, btnY, 70, 26, m_hwnd, (HMENU)IDCANCEL, hInst, nullptr);
}

void FindReplaceDialog::Destroy() {
    if (m_hwnd) {
        DestroyWindow(m_hwnd);
        m_hwnd = nullptr;
    }
}

bool FindReplaceDialog::IsVisible() const {
    return m_hwnd && IsWindowVisible(m_hwnd);
}

void FindReplaceDialog::SetFindText(const std::string& text) {
    m_findText = text;
    if (m_hwndFindEdit) {
        SetWindowTextA(m_hwndFindEdit, text.c_str());
    }
}

void FindReplaceDialog::SetReplaceText(const std::string& text) {
    m_replaceText = text;
    if (m_hwndReplaceEdit) {
        SetWindowTextA(m_hwndReplaceEdit, text.c_str());
    }
}

void FindReplaceDialog::SetFindCallback(std::function<bool(const std::string&, const FindOptions&)> callback) {
    m_findCallback = callback;
}

void FindReplaceDialog::SetReplaceCallback(std::function<bool(const std::string&, const std::string&, const FindOptions&)> callback) {
    m_replaceCallback = callback;
}

void FindReplaceDialog::SetReplaceAllCallback(std::function<int(const std::string&, const std::string&, const FindOptions&)> callback) {
    m_replaceAllCallback = callback;
}

void FindReplaceDialog::UpdateOptionsFromUI() {
    m_options.caseSensitive = IsDlgButtonChecked(m_hwnd, IDC_CASE_SENSITIVE) == BST_CHECKED;
    m_options.wholeWord = IsDlgButtonChecked(m_hwnd, IDC_WHOLE_WORD) == BST_CHECKED;
    m_options.useRegex = IsDlgButtonChecked(m_hwnd, IDC_USE_REGEX) == BST_CHECKED;
    m_options.wrapAround = IsDlgButtonChecked(m_hwnd, IDC_WRAP_AROUND) == BST_CHECKED;
    m_options.direction = IsDlgButtonChecked(m_hwnd, IDC_DIRECTION_UP) == BST_CHECKED 
        ? FindDirection::Backward : FindDirection::Forward;
    
    // Get text
    char buffer[1024];
    if (GetWindowTextA(m_hwndFindEdit, buffer, sizeof(buffer))) {
        m_findText = buffer;
    }
    if (m_replaceMode && GetWindowTextA(m_hwndReplaceEdit, buffer, sizeof(buffer))) {
        m_replaceText = buffer;
    }
}

void FindReplaceDialog::DoFind() {
    UpdateOptionsFromUI();
    if (m_findCallback && !m_findText.empty()) {
        bool found = m_findCallback(m_findText, m_options);
        // Could show "Not found" message here
    }
}

void FindReplaceDialog::DoReplace() {
    UpdateOptionsFromUI();
    if (m_replaceCallback && !m_findText.empty()) {
        m_replaceCallback(m_findText, m_replaceText, m_options);
    }
}

void FindReplaceDialog::DoReplaceAll() {
    UpdateOptionsFromUI();
    if (m_replaceAllCallback && !m_findText.empty()) {
        int count = m_replaceAllCallback(m_findText, m_replaceText, m_options);
        // Show result
        char msg[256];
        snprintf(msg, sizeof(msg), "Replaced %d occurrence(s).", count);
        MessageBoxA(m_hwnd, msg, "Replace All", MB_OK | MB_ICONINFORMATION);
    }
}

void FindReplaceDialog::CenterOnParent() {
    if (!m_hwnd || !m_hwndParent) return;
    
    RECT rcParent, rcDialog;
    GetWindowRect(m_hwndParent, &rcParent);
    GetWindowRect(m_hwnd, &rcDialog);
    
    int width = rcDialog.right - rcDialog.left;
    int height = rcDialog.bottom - rcDialog.top;
    int parentWidth = rcParent.right - rcParent.left;
    int parentHeight = rcParent.bottom - rcParent.top;
    
    int x = rcParent.left + (parentWidth - width) / 2;
    int y = rcParent.top + (parentHeight - height) / 2;
    
    SetWindowPos(m_hwnd, nullptr, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
}

INT_PTR CALLBACK FindReplaceDialog::DialogProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    FindReplaceDialog* dlg = reinterpret_cast<FindReplaceDialog*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
    
    if (!dlg && msg == WM_INITDIALOG) {
        dlg = reinterpret_cast<FindReplaceDialog*>(lParam);
        SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(dlg));
    }
    
    if (dlg) {
        return dlg->HandleMessage(msg, wParam, lParam);
    }
    
    return FALSE;
}

INT_PTR FindReplaceDialog::HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_INITDIALOG:
            return TRUE;
            
        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case IDC_FIND_NEXT:
                    DoFind();
                    return TRUE;
                    
                case IDC_REPLACE:
                    DoReplace();
                    return TRUE;
                    
                case IDC_REPLACE_ALL:
                    DoReplaceAll();
                    return TRUE;
                    
                case IDCANCEL:
                case IDCLOSE:
                    Destroy();
                    return TRUE;
            }
            break;
            
        case WM_CLOSE:
            Destroy();
            return TRUE;
    }
    
    return FALSE;
}

// ============================================================================
// QuickFindBar Implementation
// ============================================================================

QuickFindBar::QuickFindBar()
    : m_hwnd(nullptr)
    , m_hwndParent(nullptr)
    , m_hwndEdit(nullptr)
    , m_hwndResultLabel(nullptr)
{
}

QuickFindBar::~QuickFindBar() {
    if (m_hwnd) {
        DestroyWindow(m_hwnd);
    }
}

bool QuickFindBar::Create(HWND hwndParent) {
    if (m_hwnd) return true;
    
    m_hwndParent = hwndParent;
    
    WNDCLASSEXW wcx = {};
    wcx.cbSize = sizeof(wcx);
    wcx.lpfnWndProc = WndProc;
    wcx.hInstance = GetModuleHandle(nullptr);
    wcx.lpszClassName = L"RawrXD_QuickFindBar";
    wcx.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    RegisterClassExW(&wcx);
    
    m_hwnd = CreateWindowExW(
        WS_EX_TOOLWINDOW,
        L"RawrXD_QuickFindBar",
        nullptr,
        WS_CHILD | WS_BORDER,
        0, 0, 400, 30,
        hwndParent,
        nullptr,
        GetModuleHandle(nullptr),
        this
    );
    
    if (m_hwnd) {
        SetWindowLongPtr(m_hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(this));
        
        // Create edit control
        m_hwndEdit = CreateWindowW(L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
            5, 3, 200, 22, m_hwnd, nullptr, GetModuleHandle(nullptr), nullptr);
        
        // Create result label
        m_hwndResultLabel = CreateWindowW(L"STATIC", L"",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            210, 5, 100, 20, m_hwnd, nullptr, GetModuleHandle(nullptr), nullptr);
        
        // Create buttons
        CreateWindowW(L"BUTTON", L"◀",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            315, 3, 25, 22, m_hwnd, (HMENU)1001, GetModuleHandle(nullptr), nullptr);
        
        CreateWindowW(L"BUTTON", L"▶",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            342, 3, 25, 22, m_hwnd, (HMENU)1002, GetModuleHandle(nullptr), nullptr);
        
        CreateWindowW(L"BUTTON", L"✕",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            369, 3, 25, 22, m_hwnd, (HMENU)IDCANCEL, GetModuleHandle(nullptr), nullptr);
    }
    
    return m_hwnd != nullptr;
}

void QuickFindBar::Show() {
    if (m_hwnd) {
        ShowWindow(m_hwnd, SW_SHOW);
        SetFocus(m_hwndEdit);
    }
}

void QuickFindBar::Hide() {
    if (m_hwnd) {
        ShowWindow(m_hwnd, SW_HIDE);
    }
    if (m_closeCallback) {
        m_closeCallback();
    }
}

bool QuickFindBar::IsVisible() const {
    return m_hwnd && IsWindowVisible(m_hwnd);
}

void QuickFindBar::SetFindText(const std::string& text) {
    if (m_hwndEdit) {
        SetWindowTextA(m_hwndEdit, text.c_str());
    }
}

void QuickFindBar::SetResultCount(int current, int total) {
    if (m_hwndResultLabel) {
        if (total > 0) {
            char buf[64];
            snprintf(buf, sizeof(buf), "%d/%d", current, total);
            SetWindowTextA(m_hwndResultLabel, buf);
        } else {
            SetWindowTextA(m_hwndResultLabel, "No results");
        }
    }
}

void QuickFindBar::SetFindCallback(std::function<void(const std::string&, bool forward)> callback) {
    m_findCallback = callback;
}

void QuickFindBar::SetCloseCallback(std::function<void()> callback) {
    m_closeCallback = callback;
}

LRESULT CALLBACK QuickFindBar::WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    QuickFindBar* bar = reinterpret_cast<QuickFindBar*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
    
    if (bar) {
        return bar->HandleMessage(msg, wParam, lParam);
    }
    
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

LRESULT QuickFindBar::HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case 1001: // Previous
                    if (m_findCallback) {
                        char text[256];
                        GetWindowTextA(m_hwndEdit, text, sizeof(text));
                        m_findCallback(text, false);
                    }
                    return 0;
                    
                case 1002: // Next
                    if (m_findCallback) {
                        char text[256];
                        GetWindowTextA(m_hwndEdit, text, sizeof(text));
                        m_findCallback(text, true);
                    }
                    return 0;
                    
                case IDCANCEL:
                    Hide();
                    return 0;
            }
            
            if (HIWORD(wParam) == EN_CHANGE && m_findCallback) {
                char text[256];
                GetWindowTextA(m_hwndEdit, text, sizeof(text));
                m_findCallback(text, true);
            }
            break;
            
        case WM_KEYDOWN:
            if (wParam == VK_ESCAPE) {
                Hide();
                return 0;
            }
            break;
    }
    
    return DefWindowProc(m_hwnd, msg, wParam, lParam);
}

} // namespace RawrXD::IDE
