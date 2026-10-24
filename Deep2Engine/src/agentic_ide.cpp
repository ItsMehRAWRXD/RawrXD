// ============================================================================
// agentic_ide.cpp - RawrXD Agentic IDE (native Win32/C++20, no Qt)
//
// A native Windows IDE shell that wires together the RawrXD subsystems:
//   - Multi-tab code editor with syntax highlighting
//   - File browser (TreeView)
//   - Integrated terminal (process piping)
//   - AI chat panel
//   - Agentic engine (file tools, shell, build/test/verify)
//   - Model router (chat + ghost text model selection)
//   - Plan orchestrator + LSP client
//   - File operations with Keep/Undo
//
// Zero Qt dependency. Pure Win32 API + C++20.
// ============================================================================

#include "agentic_ide.h"

#include <windowsx.h>
#include <commctrl.h>
#include <shlobj.h>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <thread>
#include <atomic>
#include <filesystem>

// Subsystem headers (non-Qt C++ core)
#include "settings.h"
#include "agentic_file_operations.h"
#include "telemetry.h"
#include "rawrxd_agentcore.h"

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "advapi32.lib")

// ---------------------------------------------------------------------------
// Window class name
// ---------------------------------------------------------------------------
static constexpr wchar_t kWindowClassName[] = L"RawrXD_AgenticIDE_Class";

// ---------------------------------------------------------------------------
// Control IDs
// ---------------------------------------------------------------------------
namespace CtrlId {
    static constexpr int kFileBrowserTree = 4001;
    static constexpr int kTabCtrl = 4002;
    static constexpr int kChatOutput = 4004;
    static constexpr int kChatInput = 4005;
    static constexpr int kChatSend = 4006;
    static constexpr int kTerminalOutput = 4007;
}

// ---------------------------------------------------------------------------
// AgenticIDE implementation
// ---------------------------------------------------------------------------
AgenticIDE::AgenticIDE(HINSTANCE hInstance, int nCmdShow)
    : m_hInstance(hInstance) {
    InitCommonControls();

    // Create main window
    if (!initWindow()) return;

    // Create menu bar
    if (!initMenu()) return;

    // Create child panes
    if (!initLayout()) return;

    ShowWindow(m_hwnd, nCmdShow);
    UpdateWindow(m_hwnd);

    // Initialize subsystems
    static Settings settings;
    settings.initialize();

    static AgenticFileOperations fileOps;

    // Initialize customizable hook system (IDE_HOOKS.md)
    initHooks();
    m_hooks.fire(RawrXD::IdeHooks::HookEvent::Startup);
}

AgenticIDE::~AgenticIDE() {
    m_editorTabs.clear();
    if (m_hwnd) DestroyWindow(m_hwnd);
}

int AgenticIDE::run() {
    MSG msg = {};
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return static_cast<int>(msg.wParam);
}

bool AgenticIDE::initWindow() {
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = &AgenticIDE::s_wndProc;
    wc.hInstance = m_hInstance;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = kWindowClassName;
    wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);

    if (!RegisterClassExW(&wc)) return false;

    m_hwnd = CreateWindowExW(
        0,
        kWindowClassName,
        L"RawrXD Agentic IDE - Native Win32/C++20",
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
        CW_USEDEFAULT, CW_USEDEFAULT, 1400, 900,
        nullptr, nullptr, m_hInstance, this);

    return m_hwnd != nullptr;
}

bool AgenticIDE::initMenu() {
    m_hMenu = CreateMenu();

    // File menu
    HMENU hFile = CreateMenu();
    AppendMenuW(hFile, MF_STRING, kCmdFileNew, L"&New\tCtrl+N");
    AppendMenuW(hFile, MF_STRING, kCmdFileOpen, L"&Open...\tCtrl+O");
    AppendMenuW(hFile, MF_STRING, kCmdFileSave, L"&Save\tCtrl+S");
    AppendMenuW(hFile, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hFile, MF_STRING, kCmdFileExit, L"E&xit\tAlt+F4");
    AppendMenuW(m_hMenu, MF_POPUP, (UINT_PTR)hFile, L"&File");

    // View menu (dock toggles)
    HMENU hView = CreateMenu();
    AppendMenuW(hView, MF_STRING | MF_CHECKED, kCmdViewFileBrowser, L"&File Browser");
    AppendMenuW(hView, MF_STRING | MF_CHECKED, kCmdViewChat, L"&AI Chat");
    AppendMenuW(hView, MF_STRING | MF_CHECKED, kCmdViewTerminal, L"&Terminal");
    AppendMenuW(m_hMenu, MF_POPUP, (UINT_PTR)hView, L"&View");

    // Agent menu
    HMENU hAgent = CreateMenu();
    AppendMenuW(hAgent, MF_STRING, kCmdAgentRun, L"&Run Agent Mission");
    AppendMenuW(m_hMenu, MF_POPUP, (UINT_PTR)hAgent, L"&Agent");

    // Help menu
    HMENU hHelp = CreateMenu();
    AppendMenuW(hHelp, MF_STRING, kCmdHelpAbout, L"&About");
    AppendMenuW(m_hMenu, MF_POPUP, (UINT_PTR)hHelp, L"&Help");

    SetMenu(m_hwnd, m_hMenu);
    return true;
}

bool AgenticIDE::initLayout() {
    RECT rc;
    GetClientRect(m_hwnd, &rc);
    int cx = rc.right - rc.left;
    int cy = rc.bottom - rc.top;

    int statusHeight = 24;
    int paneHeight = cy - statusHeight - 4;
    int leftW = m_leftPaneWidth;
    int rightW = m_rightPaneWidth;
    int editorW = cx - leftW - rightW - 12;

    // File browser pane (left)
    m_hFileBrowser = CreateWindowExW(
        WS_EX_CLIENTEDGE,
        L"SysTreeView32",
        L"",
        WS_CHILD | WS_VISIBLE | TVS_HASLINES | TVS_LINESATROOT | TVS_SHOWSELALWAYS |
        WS_VSCROLL | WS_BORDER,
        4, 4, leftW, paneHeight,
        m_hwnd, (HMENU)(INT_PTR)CtrlId::kFileBrowserTree, m_hInstance, nullptr);

    // Tab control for editor tabs (center top)
    m_hTabCtrl = CreateWindowExW(
        WS_EX_CLIENTEDGE,
        L"SysTabControl32",
        L"",
        WS_CHILD | WS_VISIBLE | TCS_TABS | TCS_FOCUSNEVER,
        leftW + 6, 4, editorW, 24,
        m_hwnd, (HMENU)(INT_PTR)CtrlId::kTabCtrl, m_hInstance, nullptr);

    // Chat pane (right)
    m_hChat = CreateWindowExW(
        WS_EX_CLIENTEDGE,
        L"edit",
        L"",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | WS_BORDER,
        cx - rightW - 4, paneHeight - 30, rightW - 70, 24,
        m_hwnd, (HMENU)(INT_PTR)CtrlId::kChatInput, m_hInstance, nullptr);

    // Chat send button
    m_hChatSend = CreateWindowExW(
        0, L"button", L"Send",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        cx - rightW - 4 + rightW - 70, paneHeight - 30, 60, 24,
        m_hwnd, (HMENU)(INT_PTR)CtrlId::kChatSend, m_hInstance, nullptr);

    // Terminal pane (bottom center)
    m_hTerminal = CreateWindowExW(
        WS_EX_CLIENTEDGE,
        L"edit",
        L"",
        WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL |
        WS_VSCROLL | WS_HSCROLL | WS_BORDER,
        leftW + 6, paneHeight - 130, editorW, 130,
        m_hwnd, (HMENU)(INT_PTR)CtrlId::kTerminalOutput, m_hInstance, nullptr);

    // Status bar
    m_hStatusBar = CreateWindowExW(
        0, L"msctls_statusbar32", L"Ready",
        WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
        0, cy - statusHeight, cx, statusHeight,
        m_hwnd, (HMENU)5000, m_hInstance, nullptr);

    // Populate file browser with drives
    populateTreeDrives();

    // Create the first editor tab
    addEditorTab(L"Untitled");

    return true;
}

bool AgenticIDE::initHooks() {
    // Look for hook configuration in multiple locations so users can customize
    // IDE behavior via AGENTS.md (project conventions) or IDE_HOOKS.md (IDE-local).
    int loaded = m_hooks.loadFromFile("IDE_HOOKS.md");
    if (loaded == 0) {
        loaded = m_hooks.loadFromFile("AGENTS.md");
    }
    (void)loaded;
    return true;
}

LRESULT CALLBACK AgenticIDE::s_wndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_NCCREATE) {
        CREATESTRUCTW* cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
        AgenticIDE* self = static_cast<AgenticIDE*>(cs->lpCreateParams);
        SetWindowLongPtrW(hWnd, GWLP_USERDATA, (LONG_PTR)self);
        self->m_hwnd = hWnd;
        return DefWindowProcW(hWnd, msg, wParam, lParam);
    }

    AgenticIDE* self = reinterpret_cast<AgenticIDE*>(GetWindowLongPtrW(hWnd, GWLP_USERDATA));
    if (self) {
        return self->wndProc(hWnd, msg, wParam, lParam);
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

LRESULT CALLBACK AgenticIDE::wndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_SIZE:
            onSize(LOWORD(wParam), LOWORD(lParam), HIWORD(lParam));
            break;
        case WM_COMMAND:
            onCommand(LOWORD(wParam), HIWORD(wParam), (HWND)lParam);
            break;
        case WM_DESTROY:
            onDestroy();
            PostQuitMessage(0);
            break;
        case WM_NOTIFY: {
            LPNMHDR hdr = (LPNMHDR)lParam;
            if (hdr->hwndFrom == m_hFileBrowser) {
                if (hdr->code == TVN_SELCHANGEDW) {
                    HTREEITEM hItem = TreeView_GetSelection(m_hFileBrowser);
                    if (hItem) {
                        TVITEMW tvi = {};
                        tvi.mask = TVIF_TEXT;
                        tvi.hItem = hItem;
                        wchar_t buf[MAX_PATH] = {};
                        tvi.pszText = buf;
                        tvi.cchTextMax = MAX_PATH;
                        TreeView_GetItem(m_hFileBrowser, &tvi);
                        SetWindowTextW(m_hStatusBar, buf);
                    }
                } else if (hdr->code == NM_DBLCLK) {
                    HTREEITEM hItem = TreeView_GetSelection(m_hFileBrowser);
                    if (hItem) {
                        onTreeDoubleClick(hItem);
                    }
                } else if (hdr->code == TVN_ITEMEXPANDINGW) {
                    LPNMTREEVIEWW lpnmTreeView = (LPNMTREEVIEWW)lParam;
                    HTREEITEM hItem = lpnmTreeView->itemNew.hItem;
                    // Get the stored path
                    TVITEMW tvi = {};
                    tvi.mask = TVIF_PARAM | TVIF_TEXT;
                    tvi.hItem = hItem;
                    TreeView_GetItem(m_hFileBrowser, &tvi);
                    std::wstring path = getTreeItemPath(hItem);
                    if (!path.empty()) {
                        // Clear dummy children
                        HTREEITEM hChild = TreeView_GetChild(m_hFileBrowser, hItem);
                        while (hChild) {
                            HTREEITEM hNext = TreeView_GetNextSibling(m_hFileBrowser, hChild);
                            TreeView_DeleteItem(m_hFileBrowser, hChild);
                            hChild = hNext;
                        }
                        // Populate with real children
                        populateTreeChildren(hItem, path);
                    }
                }
            } else if (hdr->hwndFrom == m_hTabCtrl && hdr->code == TCN_SELCHANGE) {
                int sel = TabCtrl_GetCurSel(m_hTabCtrl);
                setActiveTab(sel);
            }
            break;
        }
        default:
            return DefWindowProcW(hWnd, msg, wParam, lParam);
    }
    return 0;
}

void AgenticIDE::onSize(UINT type, int cx, int cy) {
    if (m_hStatusBar) {
        SendMessageW(m_hStatusBar, WM_SIZE, 0, 0);
        RECT sr;
        GetWindowRect(m_hStatusBar, &sr);
        int statusHeight = sr.bottom - sr.top;
        int paneHeight = cy - statusHeight - 8;
        int leftW = m_leftPaneWidth;
        int rightW = m_rightPaneWidth;
        int editorW = cx - leftW - rightW - 12;

        MoveWindow(m_hFileBrowser, 4, 4, leftW, paneHeight, TRUE);
        MoveWindow(m_hTabCtrl, leftW + 6, 4, editorW, 24, TRUE);
        MoveWindow(m_hTerminal, leftW + 6, paneHeight - 130, editorW, 130, TRUE);
        MoveWindow(m_hChat, cx - rightW - 4, 4, rightW, paneHeight, TRUE);
        MoveWindow(m_hChatInput, cx - rightW - 4, paneHeight - 30, rightW - 70, 24, TRUE);
        MoveWindow(m_hChatSend, cx - rightW - 4 + rightW - 70, paneHeight - 30, 60, 24, TRUE);

        // Resize active editor tab
        if (m_activeTab >= 0 && m_activeTab < (int)m_editorTabs.size()) {
            HWND editorHwnd = m_editorTabs[m_activeTab]->hwnd();
            MoveWindow(editorHwnd, leftW + 6, 28, editorW, paneHeight - 162, TRUE);
        }

        // Hide inactive editors
        for (size_t i = 0; i < m_editorTabs.size(); i++) {
            ShowWindow(m_editorTabs[i]->hwnd(), (int)i == m_activeTab ? SW_SHOW : SW_HIDE);
        }
    }
}

void AgenticIDE::onCommand(WORD id, WORD cmd, HWND hwndCtl) {
    (void)cmd; (void)hwndCtl;
    switch (id) {
        case kCmdFileNew: {
            addEditorTab(L"Untitled");
            break;
        }
        case kCmdFileOpen: {
            OPENFILENAMEW ofn = {};
            wchar_t szFile[MAX_PATH] = L"";
            ofn.lStructSize = sizeof(ofn);
            ofn.hwndOwner = m_hwnd;
            ofn.lpstrFile = szFile;
            ofn.nMaxFile = MAX_PATH;
            ofn.lpstrFilter = L"All Files\0*.*\0Source Files\0*.cpp;*.c;*.h;*.hpp\0Text Files\0*.txt\0";
            ofn.nFilterIndex = 1;
            ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
            if (GetOpenFileNameW(&ofn)) {
                SetWindowTextW(m_hStatusBar, szFile);
                loadFileIntoEditor(szFile);
                // Fire file_open hook
                std::string path(szFile, szFile + wcslen(szFile));
                m_hooks.fire(RawrXD::IdeHooks::HookEvent::FileOpen, path);
            }
            break;
        }
        case kCmdFileSave: {
            if (auto* editor = activeEditor()) {
                OPENFILENAMEW ofn = {};
                wchar_t szFile[MAX_PATH] = L"";
                if (!editor->filePath().empty()) {
                    wcscpy_s(szFile, editor->filePath().c_str());
                }
                ofn.lStructSize = sizeof(ofn);
                ofn.hwndOwner = m_hwnd;
                ofn.lpstrFile = szFile;
                ofn.nMaxFile = MAX_PATH;
                ofn.lpstrFilter = L"All Files\0*.*\0Source Files\0*.cpp;*.c;*.h;*.hpp\0";
                ofn.nFilterIndex = 1;
                ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT;
                if (GetSaveFileNameW(&ofn)) {
                    if (editor->saveFile(szFile)) {
                        editor->setFilePath(szFile);
                        editor->setModified(false);
                        // Update tab title
                        wchar_t name[MAX_PATH] = {};
                        wcsncpy_s(name, szFile, MAX_PATH - 1);
                        wchar_t* slash = wcsrchr(name, L'\\');
                        const wchar_t* tabTitle = (slash) ? slash + 1 : name;
                        TCITEMW tie = {};
                        tie.mask = TCIF_TEXT;
                        tie.pszText = const_cast<wchar_t*>(tabTitle);
                        TabCtrl_SetItem(m_hTabCtrl, m_activeTab, &tie);
                        SetWindowTextW(m_hStatusBar, szFile);
                        // Fire file_save hook
                        std::string path(szFile, szFile + wcslen(szFile));
                        m_hooks.fire(RawrXD::IdeHooks::HookEvent::FileSave, path);
                    }
                }
            }
            break;
        }
        case kCmdFileExit:
            PostMessageW(m_hwnd, WM_CLOSE, 0, 0);
            break;
        case kCmdViewFileBrowser: {
            bool visible = IsWindowVisible(m_hFileBrowser);
            ShowWindow(m_hFileBrowser, visible ? SW_HIDE : SW_SHOW);
            CheckMenuItem(m_hMenu, kCmdViewFileBrowser, visible ? MF_UNCHECKED : MF_CHECKED);
            onSize(0, 0, 0);
            break;
        }
        case kCmdViewChat: {
            bool visible = IsWindowVisible(m_hChat);
            ShowWindow(m_hChat, visible ? SW_HIDE : SW_SHOW);
            ShowWindow(m_hChatInput, visible ? SW_HIDE : SW_SHOW);
            ShowWindow(m_hChatSend, visible ? SW_HIDE : SW_SHOW);
            CheckMenuItem(m_hMenu, kCmdViewChat, visible ? MF_UNCHECKED : MF_CHECKED);
            onSize(0, 0, 0);
            break;
        }
        case kCmdViewTerminal: {
            bool visible = IsWindowVisible(m_hTerminal);
            ShowWindow(m_hTerminal, visible ? SW_HIDE : SW_SHOW);
            CheckMenuItem(m_hMenu, kCmdViewTerminal, visible ? MF_UNCHECKED : MF_CHECKED);
            onSize(0, 0, 0);
            break;
        }
        case kCmdAgentRun: {
            // Fire build_start hook before running agent mission
            m_hooks.fire(RawrXD::IdeHooks::HookEvent::BuildStart);
            if (m_hChat) {
                std::wstring msg = L"> Running agent mission...\n";
                int len = GetWindowTextLengthW(m_hChat);
                std::wstring existing;
                existing.resize(len);
                GetWindowTextW(m_hChat, &existing[0], len + 1);
                SetWindowTextW(m_hChat, (existing + msg).c_str());
            }
            // Fire build_end hook after agent mission completes
            m_hooks.fire(RawrXD::IdeHooks::HookEvent::BuildEnd);
            break;
        }
        case kCmdHelpAbout:
            MessageBoxW(m_hwnd,
                L"RawrXD Agentic IDE\nNative Win32/C++20, no Qt\n\nFeatures:\n- Local AI inference (Deep2/GGUF/Ollama/OpenAI-compatible)\n- Agentic file tools + shell + build/test/verify\n- Independent Chat and GhostText model selectors\n- Multi-tab editor + file browser + integrated terminal\n- Snapshot/Keep/Undo file operations\n- Vulkan GPU inference (AMD dual-GPU)",
                L"About RawrXD IDE", MB_OK | MB_ICONINFORMATION);
            break;
        case CtrlId::kChatSend: {
            int len = GetWindowTextLengthW(m_hChatInput);
            if (len > 0) {
                std::wstring input;
                input.resize(len);
                GetWindowTextW(m_hChatInput, &input[0], len + 1);
                std::wstring chat;
                int chatLen = GetWindowTextLengthW(m_hChat);
                chat.resize(chatLen);
                GetWindowTextW(m_hChat, &chat[0], chatLen + 1);
                SetWindowTextW(m_hChat, (chat + L"> " + input + L"\n").c_str());
                SetWindowTextW(m_hChatInput, L"");
            }
            break;
        }
        default:
            break;
    }
}

void AgenticIDE::onDestroy() {
    m_hooks.fire(RawrXD::IdeHooks::HookEvent::Shutdown);
    m_hwnd = nullptr;
}

int AgenticIDE::addEditorTab(const std::wstring& title) {
    auto editor = std::make_unique<CodeEditor>(m_hwnd, 5000 + (int)m_editorTabs.size());
    HWND editorHwnd = editor->hwnd();

    RECT rc;
    GetClientRect(m_hwnd, &rc);
    int statusHeight = 24;
    int paneHeight = rc.bottom - rc.top - statusHeight - 8;
    int leftW = m_leftPaneWidth;
    int rightW = m_rightPaneWidth;
    int editorW = rc.right - rc.left - leftW - rightW - 12;

    MoveWindow(editorHwnd, leftW + 6, 28, editorW, paneHeight - 162, TRUE);
    ShowWindow(editorHwnd, SW_SHOW);

    int index = (int)m_editorTabs.size();
    m_editorTabs.push_back(std::move(editor));

    // Add tab item
    TCITEMW tie = {};
    tie.mask = TCIF_TEXT;
    wchar_t tabTitle[256] = {};
    wcsncpy_s(tabTitle, title.c_str(), 255);
    tie.pszText = tabTitle;
    TabCtrl_InsertItem(m_hTabCtrl, index, &tie);

    // Set active if first tab
    if (m_activeTab < 0) {
        setActiveTab(0);
    }

    return index;
}

void AgenticIDE::closeEditorTab(int index) {
    if (index < 0 || index >= (int)m_editorTabs.size()) return;
    m_editorTabs.erase(m_editorTabs.begin() + index);
    TabCtrl_DeleteItem(m_hTabCtrl, index);
    if (m_activeTab >= (int)m_editorTabs.size()) {
        m_activeTab = (int)m_editorTabs.size() - 1;
    }
    if (m_activeTab >= 0) {
        setActiveTab(m_activeTab);
    }
}

void AgenticIDE::setActiveTab(int index) {
    if (index < 0 || index >= (int)m_editorTabs.size()) return;
    m_activeTab = index;
    TabCtrl_SetCurSel(m_hTabCtrl, index);
    onSize(0, 0, 0);
}

void AgenticIDE::loadFileIntoEditor(const std::wstring& path) {
    // Check if already open
    for (size_t i = 0; i < m_editorTabs.size(); i++) {
        if (m_editorTabs[i]->filePath() == path) {
            setActiveTab((int)i);
            return;
        }
    }

    // Create new tab
    int index = addEditorTab(path);
    CodeEditor* editor = m_editorTabs[index].get();
    if (editor->loadFile(path)) {
        // Update tab title with file name
        wchar_t name[MAX_PATH] = {};
        wcsncpy_s(name, path.c_str(), MAX_PATH - 1);
        wchar_t* slash = wcsrchr(name, L'\\');
        const wchar_t* tabTitle = (slash) ? slash + 1 : name;
        TCITEMW tie = {};
        tie.mask = TCIF_TEXT;
        tie.pszText = const_cast<wchar_t*>(tabTitle);
        TabCtrl_SetItem(m_hTabCtrl, index, &tie);
        SetWindowTextW(m_hStatusBar, path.c_str());
    }
}

void AgenticIDE::populateTreeDrives() {
    TVINSERTSTRUCTW tis = {};
    tis.hInsertAfter = TVI_LAST;
    tis.item.mask = TVIF_TEXT | TVIF_PARAM | TVIF_STATE;
    tis.item.state = 0;
    tis.item.stateMask = 0;
    for (wchar_t drive = L'A'; drive <= L'Z'; ++drive) {
        std::wstring drivePath = std::wstring(1, drive) + L":\\";
        DWORD attrs = GetFileAttributesW(drivePath.c_str());
        if (attrs != INVALID_FILE_ATTRIBUTES) {
            // Allocate path storage for lParam
            wchar_t* pathCopy = new wchar_t[drivePath.size() + 1];
            wcscpy_s(pathCopy, drivePath.size() + 1, drivePath.c_str());
            tis.item.pszText = const_cast<wchar_t*>(drivePath.c_str());
            tis.item.lParam = (LPARAM)pathCopy;
            // Add a dummy child so the item shows as expandable
            tis.hInsertAfter = TVI_LAST;
            HTREEITEM hItem = TreeView_InsertItem(m_hFileBrowser, &tis);
            if (hItem) {
                TVINSERTSTRUCTW dummy = {};
                dummy.hParent = hItem;
                dummy.hInsertAfter = TVI_LAST;
                dummy.item.mask = TVIF_TEXT;
                dummy.item.pszText = const_cast<wchar_t*>(L"");
                TreeView_InsertItem(m_hFileBrowser, &dummy);
            }
        }
    }
}

void AgenticIDE::populateTreeChildren(HTREEITEM hParent, const std::wstring& path) {
    std::error_code ec;
    for (auto& entry : std::filesystem::directory_iterator(path, ec)) {
        if (ec) break;
        std::wstring entryPath = entry.path().wstring();
        std::wstring entryName = entry.path().filename().wstring();

        // Allocate path storage for lParam
        wchar_t* pathCopy = new wchar_t[entryPath.size() + 1];
        wcscpy_s(pathCopy, entryPath.size() + 1, entryPath.c_str());

        TVINSERTSTRUCTW tis = {};
        tis.hParent = hParent;
        tis.hInsertAfter = TVI_LAST;
        tis.item.mask = TVIF_TEXT | TVIF_PARAM | TVIF_STATE;
        tis.item.state = 0;
        tis.item.stateMask = 0;
        tis.item.pszText = const_cast<wchar_t*>(entryName.c_str());
        tis.item.lParam = (LPARAM)pathCopy;

        if (entry.is_directory()) {
            // Add dummy child for expandable
            tis.hInsertAfter = TVI_LAST;
            HTREEITEM hItem = TreeView_InsertItem(m_hFileBrowser, &tis);
            if (hItem) {
                TVINSERTSTRUCTW dummy = {};
                dummy.hParent = hItem;
                dummy.hInsertAfter = TVI_LAST;
                dummy.item.mask = TVIF_TEXT;
                dummy.item.pszText = const_cast<wchar_t*>(L"");
                TreeView_InsertItem(m_hFileBrowser, &dummy);
            }
        } else {
            // File - no dummy child
            TreeView_InsertItem(m_hFileBrowser, &tis);
        }
    }
}

std::wstring AgenticIDE::getTreeItemPath(HTREEITEM hItem) const {
    TVITEMW tvi = {};
    tvi.mask = TVIF_PARAM;
    tvi.hItem = hItem;
    if (TreeView_GetItem(m_hFileBrowser, &tvi)) {
        wchar_t* path = (wchar_t*)tvi.lParam;
        if (path) return std::wstring(path);
    }
    return L"";
}

void AgenticIDE::onTreeDoubleClick(HTREEITEM hItem) {
    std::wstring path = getTreeItemPath(hItem);
    if (path.empty()) return;

    DWORD attrs = GetFileAttributesW(path.c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        // Toggle expand/collapse
        BOOL expanded = (TreeView_GetItemState(m_hFileBrowser, hItem, TVIS_EXPANDED) != 0);
        if (expanded) {
            TreeView_Expand(m_hFileBrowser, hItem, TVE_COLLAPSE);
        } else {
            TreeView_Expand(m_hFileBrowser, hItem, TVE_EXPAND);
        }
    } else {
        // File - open in editor
        loadFileIntoEditor(path);
    }
}

// Entry point for the native Win32 IDE.
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
    (void)hPrevInstance; (void)pCmdLine;
    AgenticIDE ide(hInstance, nCmdShow);
    return ide.run();
}
