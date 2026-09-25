// Win32IDE_SettingsGUI.cpp — full settings dialog with property pages (General, LSP, MCP, Editor, Theme)
#include <windows.h>
#include <commctrl.h>
#include <string>
#include <vector>
#include <functional>
#include <cstdio>

#pragma comment(lib, "comctl32.lib")

namespace RawrXD::IDE {

void Settings_Load(const std::string& path);
void Settings_Save();
std::string Settings_Get(const std::string& key, const std::string& def);
void Settings_Set(const std::string& key, const std::string& value);
int Settings_GetInt(const std::string& key, int def);
void Settings_SetInt(const std::string& key, int v);
bool Settings_GetBool(const std::string& key, bool def);
void Settings_SetBool(const std::string& key, bool v);

// ── Dialog constants ─────────────────────────────────────────────────────────
#define IDD_SETTINGS    9000
#define IDC_TAB         9001
#define IDOK_SET        9002
#define IDCANCEL_SET    9003
#define ID_APPLY        9004

// General page controls
#define IDC_FONT_SIZE   9101
#define IDC_TAB_SIZE    9102
#define IDC_WORD_WRAP   9103
#define IDC_LINE_NUMS   9104
#define IDC_AUTO_SAVE   9105

// LSP page controls
#define IDC_LSP_PATH    9201
#define IDC_LSP_LANG    9202
#define IDC_LSP_ENABLE  9203

// MCP page controls
#define IDC_MCP_CMD     9301
#define IDC_MCP_ENABLE  9302

// Editor page controls
#define IDC_EDITOR_THEME 9401
#define IDC_EDITOR_MINIMAP 9402

// ── Helper: create child dialog pages ────────────────────────────────────────
static HWND g_hDlg = nullptr;
static HWND g_hTab = nullptr;
static std::vector<HWND> g_pages;
static int g_curPage = 0;

static HWND CreateLabel(HWND parent, const char* text, int x, int y, int w, int h)
{
    return CreateWindowExA(0, "STATIC", text, WS_CHILD | WS_VISIBLE | SS_LEFT,
                           x, y, w, h, parent, nullptr, nullptr, nullptr);
}

static HWND CreateEdit(HWND parent, const char* text, int x, int y, int w, int h, int id)
{
    HWND h = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", text,
                             WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                             x, y, w, h, parent, (HMENU)(intptr_t)id, nullptr, nullptr);
    SendMessageA(h, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);
    return h;
}

static HWND CreateCheck(HWND parent, const char* text, int x, int y, int w, int h, int id, bool checked)
{
    HWND h = CreateWindowExA(0, "BUTTON", text,
                             WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
                             x, y, w, h, parent, (HMENU)(intptr_t)id, nullptr, nullptr);
    SendMessageA(h, BM_SETCHECK, checked ? BST_CHECKED : BST_UNCHECKED, 0);
    SendMessageA(h, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);
    return h;
}

static HWND CreateCombo(HWND parent, int x, int y, int w, int h, int id)
{
    HWND h = CreateWindowExA(0, "COMBOBOX", "",
                             WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | CBS_HASSTRINGS,
                             x, y, w, h, parent, (HMENU)(intptr_t)id, nullptr, nullptr);
    SendMessageA(h, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);
    return h;
}

static void CreateGeneralPage(HWND parent)
{
    int y = 16;
    CreateLabel(parent, "Font Size:", 16, y, 80, 20);
    CreateEdit(parent, std::to_string(Settings_GetInt("editor.fontSize", 14)).c_str(), 100, y, 60, 20, IDC_FONT_SIZE);
    y += 32;
    CreateLabel(parent, "Tab Size:", 16, y, 80, 20);
    CreateEdit(parent, std::to_string(Settings_GetInt("editor.tabSize", 4)).c_str(), 100, y, 60, 20, IDC_TAB_SIZE);
    y += 32;
    CreateCheck(parent, "Word Wrap", 16, y, 120, 20, IDC_WORD_WRAP, Settings_GetBool("editor.wordWrap", true));
    y += 24;
    CreateCheck(parent, "Show Line Numbers", 16, y, 140, 20, IDC_LINE_NUMS, Settings_GetBool("editor.lineNumbers", true));
    y += 24;
    CreateCheck(parent, "Auto Save", 16, y, 120, 20, IDC_AUTO_SAVE, Settings_GetBool("editor.autoSave", false));
}

static void CreateLSPPage(HWND parent)
{
    int y = 16;
    CreateCheck(parent, "Enable LSP", 16, y, 120, 20, IDC_LSP_ENABLE, Settings_GetBool("lsp.enabled", false));
    y += 28;
    CreateLabel(parent, "Server Path:", 16, y, 80, 20);
    CreateEdit(parent, Settings_Get("lsp.serverPath", "clangd").c_str(), 100, y, 300, 20, IDC_LSP_PATH);
    y += 28;
    CreateLabel(parent, "Language:", 16, y, 80, 20);
    HWND hLang = CreateCombo(parent, 100, y, 120, 120, IDC_LSP_LANG);
    SendMessageA(hLang, CB_ADDSTRING, 0, (LPARAM)"c");
    SendMessageA(hLang, CB_ADDSTRING, 0, (LPARAM)"cpp");
    SendMessageA(hLang, CB_ADDSTRING, 0, (LPARAM)"python");
    SendMessageA(hLang, CB_ADDSTRING, 0, (LPARAM)"typescript");
    SendMessageA(hLang, CB_ADDSTRING, 0, (LPARAM)"rust");
    std::string cur = Settings_Get("lsp.language", "cpp");
    int sel = (int)SendMessageA(hLang, CB_FINDSTRINGEXACT, -1, (LPARAM)cur.c_str());
    if (sel >= 0) SendMessageA(hLang, CB_SETCURSEL, sel, 0);
}

static void CreateMCPPage(HWND parent)
{
    int y = 16;
    CreateCheck(parent, "Enable MCP", 16, y, 120, 20, IDC_MCP_ENABLE, Settings_GetBool("mcp.enabled", false));
    y += 28;
    CreateLabel(parent, "Server Command:", 16, y, 100, 20);
    CreateEdit(parent, Settings_Get("mcp.serverCmd", "npx -y @modelcontextprotocol/server-filesystem .").c_str(),
               120, y, 360, 20, IDC_MCP_CMD);
    y += 28;
    CreateLabel(parent, "MCP provides tools that the IDE can call for file operations, search, and more.",
                16, y, 460, 40);
}

static void CreateEditorPage(HWND parent)
{
    int y = 16;
    CreateLabel(parent, "Theme:", 16, y, 60, 20);
    HWND hTheme = CreateCombo(parent, 80, y, 150, 120, IDC_EDITOR_THEME);
    SendMessageA(hTheme, CB_ADDSTRING, 0, (LPARAM)"Dark");
    SendMessageA(hTheme, CB_ADDSTRING, 0, (LPARAM)"Light");
    SendMessageA(hTheme, CB_ADDSTRING, 0, (LPARAM)"High Contrast");
    std::string cur = Settings_Get("editor.theme", "Dark");
    int sel = (int)SendMessageA(hTheme, CB_FINDSTRINGEXACT, -1, (LPARAM)cur.c_str());
    if (sel >= 0) SendMessageA(hTheme, CB_SETCURSEL, sel, 0);
    y += 32;
    CreateCheck(parent, "Show Minimap", 16, y, 120, 20, IDC_EDITOR_MINIMAP, Settings_GetBool("editor.minimap", false));
}

static void ShowPage(int idx)
{
    for (size_t i = 0; i < g_pages.size(); ++i) {
        ShowWindow(g_pages[i], (int)i == idx ? SW_SHOW : SW_HIDE);
    }
    g_curPage = idx;
}

static void SaveSettingsFromDialog()
{
    // General
    char buf[512] = {};
    GetWindowTextA(GetDlgItem(g_pages[0], IDC_FONT_SIZE), buf, sizeof(buf));
    Settings_SetInt("editor.fontSize", atoi(buf));
    GetWindowTextA(GetDlgItem(g_pages[0], IDC_TAB_SIZE), buf, sizeof(buf));
    Settings_SetInt("editor.tabSize", atoi(buf));
    Settings_SetBool("editor.wordWrap", SendMessageA(GetDlgItem(g_pages[0], IDC_WORD_WRAP), BM_GETCHECK, 0, 0) == BST_CHECKED);
    Settings_SetBool("editor.lineNumbers", SendMessageA(GetDlgItem(g_pages[0], IDC_LINE_NUMS), BM_GETCHECK, 0, 0) == BST_CHECKED);
    Settings_SetBool("editor.autoSave", SendMessageA(GetDlgItem(g_pages[0], IDC_AUTO_SAVE), BM_GETCHECK, 0, 0) == BST_CHECKED);

    // LSP
    Settings_SetBool("lsp.enabled", SendMessageA(GetDlgItem(g_pages[1], IDC_LSP_ENABLE), BM_GETCHECK, 0, 0) == BST_CHECKED);
    GetWindowTextA(GetDlgItem(g_pages[1], IDC_LSP_PATH), buf, sizeof(buf));
    Settings_Set("lsp.serverPath", buf);
    HWND hLang = GetDlgItem(g_pages[1], IDC_LSP_LANG);
    int langIdx = (int)SendMessageA(hLang, CB_GETCURSEL, 0, 0);
    if (langIdx >= 0) {
        SendMessageA(hLang, CB_GETLBTEXT, langIdx, (LPARAM)buf);
        Settings_Set("lsp.language", buf);
    }

    // MCP
    Settings_SetBool("mcp.enabled", SendMessageA(GetDlgItem(g_pages[2], IDC_MCP_ENABLE), BM_GETCHECK, 0, 0) == BST_CHECKED);
    GetWindowTextA(GetDlgItem(g_pages[2], IDC_MCP_CMD), buf, sizeof(buf));
    Settings_Set("mcp.serverCmd", buf);

    // Editor
    HWND hTheme = GetDlgItem(g_pages[3], IDC_EDITOR_THEME);
    int themeIdx = (int)SendMessageA(hTheme, CB_GETCURSEL, 0, 0);
    if (themeIdx >= 0) {
        SendMessageA(hTheme, CB_GETLBTEXT, themeIdx, (LPARAM)buf);
        Settings_Set("editor.theme", buf);
    }
    Settings_SetBool("editor.minimap", SendMessageA(GetDlgItem(g_pages[3], IDC_EDITOR_MINIMAP), BM_GETCHECK, 0, 0) == BST_CHECKED);

    Settings_Save();
}

static INT_PTR CALLBACK SettingsDlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_INITDIALOG: {
        g_hDlg = hwnd;
        g_hTab = GetDlgItem(hwnd, IDC_TAB);
        if (!g_hTab) {
            // If not using dialog template, create tab here
            RECT rc; GetClientRect(hwnd, &rc);
            g_hTab = CreateWindowExA(0, WC_TABCONTROLA, "",
                                      WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS,
                                      8, 8, rc.right - 16, rc.bottom - 48, hwnd,
                                      (HMENU)(intptr_t)IDC_TAB, nullptr, nullptr);
            SendMessageA(g_hTab, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);
        }

        // Add tabs
        TCITEM tie = {};
        tie.mask = TCIF_TEXT;
        tie.pszText = (LPSTR)"General";
        TabCtrl_InsertItem(g_hTab, 0, &tie);
        tie.pszText = (LPSTR)"LSP";
        TabCtrl_InsertItem(g_hTab, 1, &tie);
        tie.pszText = (LPSTR)"MCP";
        TabCtrl_InsertItem(g_hTab, 2, &tie);
        tie.pszText = (LPSTR)"Editor";
        TabCtrl_InsertItem(g_hTab, 3, &tie);

        RECT tr; GetClientRect(g_hTab, &tr);
        TabCtrl_AdjustRect(g_hTab, FALSE, &tr);

        // Create pages
        HWND hPage0 = CreateWindowExA(0, "STATIC", "", WS_CHILD | WS_VISIBLE | SS_LEFT,
                                       tr.left, tr.top, tr.right - tr.left, tr.bottom - tr.top,
                                       g_hTab, nullptr, nullptr, nullptr);
        HWND hPage1 = CreateWindowExA(0, "STATIC", "", WS_CHILD | SS_LEFT,
                                       tr.left, tr.top, tr.right - tr.left, tr.bottom - tr.top,
                                       g_hTab, nullptr, nullptr, nullptr);
        HWND hPage2 = CreateWindowExA(0, "STATIC", "", WS_CHILD | SS_LEFT,
                                       tr.left, tr.top, tr.right - tr.left, tr.bottom - tr.top,
                                       g_hTab, nullptr, nullptr, nullptr);
        HWND hPage3 = CreateWindowExA(0, "STATIC", "", WS_CHILD | SS_LEFT,
                                       tr.left, tr.top, tr.right - tr.left, tr.bottom - tr.top,
                                       g_hTab, nullptr, nullptr, nullptr);
        g_pages = {hPage0, hPage1, hPage2, hPage3};

        CreateGeneralPage(hPage0);
        CreateLSPPage(hPage1);
        CreateMCPPage(hPage2);
        CreateEditorPage(hPage3);

        // Buttons
        int bw = 80, bh = 24;
        RECT rc; GetClientRect(hwnd, &rc);
        CreateWindowExA(0, "BUTTON", "OK", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON | WS_TABSTOP,
                        rc.right - bw * 3 - 24, rc.bottom - bh - 12, bw, bh, hwnd,
                        (HMENU)(intptr_t)IDOK_SET, nullptr, nullptr);
        CreateWindowExA(0, "BUTTON", "Cancel", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP,
                        rc.right - bw * 2 - 16, rc.bottom - bh - 12, bw, bh, hwnd,
                        (HMENU)(intptr_t)IDCANCEL_SET, nullptr, nullptr);
        CreateWindowExA(0, "BUTTON", "Apply", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP,
                        rc.right - bw - 8, rc.bottom - bh - 12, bw, bh, hwnd,
                        (HMENU)(intptr_t)ID_APPLY, nullptr, nullptr);

        ShowPage(0);
        return TRUE;
    }

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDOK_SET:
            SaveSettingsFromDialog();
            EndDialog(hwnd, IDOK);
            return TRUE;
        case IDCANCEL_SET:
            EndDialog(hwnd, IDCANCEL);
            return TRUE;
        case ID_APPLY:
            SaveSettingsFromDialog();
            return TRUE;
        }
        break;

    case WM_NOTIFY: {
        LPNMHDR pnmh = (LPNMHDR)lParam;
        if (pnmh->idFrom == IDC_TAB && pnmh->code == TCN_SELCHANGE) {
            ShowPage((int)TabCtrl_GetCurSel(g_hTab));
        }
        break;
    }

    case WM_CLOSE:
        EndDialog(hwnd, IDCANCEL);
        return TRUE;
    }
    return FALSE;
}

// ── Public API ────────────────────────────────────────────────────────────────
void SettingsGUI_Show(HWND parent)
{
    // Ensure common controls are initialized
    INITCOMMONCONTROLSEX icc = {};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_TAB_CLASSES;
    InitCommonControlsEx(&icc);

    DialogBoxParamA(GetModuleHandle(nullptr), nullptr, parent, SettingsDlgProc, 0);
}

} // namespace RawrXD::IDE
