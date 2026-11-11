/*
 * Win32IDE_lifecycle.cpp - core window lifecycle for the RawrXD Win32 IDE
 *
 * Implements the declared-but-unimplemented public/private lifecycle surface
 * (createWindow / showWindow / runMessageLoop / onSize / editor surface /
 * Ollama bridge) plus the static WindowProc dispatch chain. Kept in its own
 * translation unit so the rest of the IDE sources remain untouched.
 */
#include "Win32IDE.h"
#include "IDELogger.h"
#include "Win32IDE_CommandIDs.h"

#include <windows.h>
#include <richedit.h>
#include <string>

namespace {
constexpr const char* kWindowClass = "RawrXD_IDE_Window";
constexpr const char* kWindowTitle = "RawrXD IDE";

Win32IDE* g_ideInstance = nullptr;
}  // namespace

// ---------------------------------------------------------------------------
// Static window procedure: routes to the per-instance handler.
// ---------------------------------------------------------------------------
LRESULT CALLBACK Win32IDE::WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    // The instance pointer is stored in GWLP_USERDATA by WM_NCCREATE, which is
    // the first message sent during CreateWindowExA(). The previous code only
    // assigned g_ideInstance AFTER CreateWindowExA() returned, so WM_CREATE
    // arrived while g_ideInstance was still null, WindowProc fell through to
    // DefWindowProcA, and onCreate() never ran -- the window had a title bar but
    // an entirely blank client area (no menu/toolbar/sidebar/editor).
    Win32IDE* ide = reinterpret_cast<Win32IDE*>(GetWindowLongPtrA(hwnd, GWLP_USERDATA));
    if (!ide) {
        ide = g_ideInstance;
    }

    switch (uMsg) {
        case WM_NCCREATE: {
            auto* cs = reinterpret_cast<CREATESTRUCTA*>(lParam);
            auto* created = static_cast<Win32IDE*>(cs->lpCreateParams);
            if (created) {
                SetWindowLongPtrA(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(created));
                g_ideInstance = created;
                if (created->m_hwndMain == nullptr) {
                    created->m_hwndMain = hwnd;
                }
            }
            return TRUE;
        }
        case WM_CREATE:
            if (ide) {
                ide->onCreate(hwnd);
            }
            return 0;
        case WM_DESTROY:
            if (ide) {
                ide->onDestroy();
            }
            // Detach so a recreated window never dispatches to a dead instance.
            SetWindowLongPtrA(hwnd, GWLP_USERDATA, 0);
            if (ide == g_ideInstance) {
                g_ideInstance = nullptr;
            }
            PostQuitMessage(0);
            return 0;
        case WM_CLOSE:
            if (ide && (!ide->m_fileModified || ide->promptSaveChanges())) DestroyWindow(hwnd);
            return 0;
        case WM_SIZE:
            if (ide) {
                ide->onSize(static_cast<int>(LOWORD(lParam)), static_cast<int>(HIWORD(lParam)));
            }
            return 0;
        case WM_COMMAND:
            if (ide) {
                ide->onCommand(hwnd, static_cast<int>(LOWORD(wParam)),
                               reinterpret_cast<HWND>(lParam), HIWORD(wParam));
            }
            return 0;
        case WM_NOTIFY: {
            // Document tabs report selection changes here.
            auto* nmhdr = reinterpret_cast<NMHDR*>(lParam);
            if (nmhdr && ide && nmhdr->idFrom == IDC_DOC_TABS &&
                nmhdr->code == TCN_SELCHANGE) {
                ide->switchDocumentTab(TabCtrl_GetCurSel(nmhdr->hwndFrom));
            }
            return 0;
        }
        case WM_PAINT: {
            // Fill the client area with the window colour so an unpainted region
            // is never left as an undefined/garbage background.
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            FillRect(hdc, &ps.rcPaint,
                     reinterpret_cast<HBRUSH>(static_cast<intptr_t>(COLOR_WINDOW) + 1));
            EndPaint(hwnd, &ps);
            return 0;
        }
        case WM_APP + 100: {
            // Agent ESP event from recorder thread
            if (ide) {
                return ide->handleESPEvent(wParam, lParam);
            }
            return 0;
        }
        case WM_APP + 101: {
            // Deep2Bridge token stream (if needed)
            return 0;
        }
        case WM_APP + 102: {
            // Deep2Bridge generation complete
            return 0;
        }
        case WM_APP + 103: {
            // Agentic loop progress
            if (ide) {
                return ide->handleAgenticLoopProgress(wParam, lParam);
            }
            return 0;
        }
        case WM_APP + 104: {
            // Agentic loop tool result
            if (ide) {
                return ide->handleAgenticLoopToolResult(wParam, lParam);
            }
            return 0;
        }
        case WM_APP + 105: {
            // Agentic loop complete
            if (ide) {
                return ide->handleAgenticLoopComplete(wParam, lParam);
            }
            return 0;
        }
        default:
            return DefWindowProcA(hwnd, uMsg, wParam, lParam);
    }
}

LRESULT Win32IDE::handleMessage(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    return WindowProc(hwnd, uMsg, wParam, lParam);
}

void Win32IDE::onCreate(HWND hwnd)
{
    m_hwndMain = hwnd;
    try {
        IDELogger::getInstance().info("Win32IDE", "onCreate: main window ready");
    } catch (...) {
    }
    createMenuBar(hwnd);
    createToolbar(hwnd);
    // Title-bar buttons are toolbar children; their commands arrive there first.
    if (m_hwndToolbar) {
        SetWindowSubclass(m_hwndToolbar,
            [](HWND control, UINT message, WPARAM wp, LPARAM lp,
               UINT_PTR, DWORD_PTR) -> LRESULT {
                if (message == WM_COMMAND) return SendMessageA(GetParent(control), message, wp, lp);
                return DefSubclassProc(control, message, wp, lp);
            }, 1, 0);
    }
    createDocumentTabs();
    createSidebar(hwnd);
    createStatusBar(hwnd);
    initializeEditorSurface();
}

void Win32IDE::onDestroy()
{
    m_hwndMain = nullptr;
}

void Win32IDE::onCommand(HWND hwnd, int id, HWND hwndCtl, UINT codeNotify)
{
    if (hwndCtl) {
        if (hwndCtl == m_hwndEditor) {
            if (codeNotify == EN_CHANGE) {
                m_fileModified = true;
                updateTitleBarText();
            }
            return;
        }
        if (codeNotify != BN_CLICKED) return;
        switch (id) {
        case IDC_BTN_MINIMIZE: ShowWindow(hwnd, SW_MINIMIZE); return;
        case IDC_BTN_MAXIMIZE: ShowWindow(hwnd, IsZoomed(hwnd) ? SW_RESTORE : SW_MAXIMIZE); return;
        case IDC_BTN_CLOSE: SendMessageA(hwnd, WM_CLOSE, 0, 0); return;
        case IDC_BTN_SETTINGS: routeCommand(IDM_VIEW_THEME_EDITOR); return;
        case IDC_BTN_GITHUB:
        case IDC_BTN_MICROSOFT:
            SendMessageA(m_hwndStatusBar, SB_SETTEXTA, 0,
                reinterpret_cast<LPARAM>("Unsupported: account integration is unavailable in this build."));
            return;
        default: return;
        }
    }
    if (!routeCommand(id)) {
        const std::string message = "Unsupported command: " + std::to_string(id);
        SendMessageA(m_hwndStatusBar, SB_SETTEXTA, 0, reinterpret_cast<LPARAM>(message.c_str()));
        LOG_WARNING(message);
    }
}

// ---------------------------------------------------------------------------
// Public lifecycle
// ---------------------------------------------------------------------------
bool Win32IDE::createWindow()
{
    INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_WIN95_CLASSES | ICC_TAB_CLASSES};
    if (!InitCommonControlsEx(&controls)) return false;
    // RichEdit's module must remain loaded for the lifetime of its controls.
    static HMODULE richEdit = LoadLibraryA("Riched20.dll");
    if (!richEdit) return false;
    WNDCLASSEXA wc = {};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = m_hInstance;
    wc.hIcon = LoadIconA(nullptr, IDI_APPLICATION);
    wc.hCursor = LoadCursorA(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(static_cast<intptr_t>(COLOR_WINDOW) + 1);
    wc.lpszClassName = kWindowClass;
    wc.hIconSm = LoadIconA(nullptr, IDI_APPLICATION);

    if (!RegisterClassExA(&wc)) {
        const DWORD err = GetLastError();
        if (err != ERROR_CLASS_ALREADY_EXISTS) {
            try {
                IDELogger::getInstance().error("Win32IDE",
                                               "RegisterClassExA failed: " + std::to_string(err));
            } catch (...) {
            }
            return false;
        }
    }

    // Pass `this` through lpParam: WM_NCCREATE is delivered during this call,
    // which is the only point at which the window handle and the instance are
    // both available. With nullptr, WindowProc cannot bind the instance to the
    // window until after CreateWindowExA returns -- but WM_CREATE is sent
    // BEFORE that, so onCreate() never runs and the window stays blank.
    m_hwndMain = CreateWindowExA(
        WS_EX_CLIENTEDGE, kWindowClass, kWindowTitle,
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 1280, 800,
        nullptr, nullptr, m_hInstance, this);
    if (!m_hwndMain) {
        return false;
    }
    g_ideInstance = this;
    return true;
}

void Win32IDE::showWindow()
{
    if (!m_hwndMain) {
        return;
    }
    ShowWindow(m_hwndMain, SW_SHOW);
    UpdateWindow(m_hwndMain);
}

int Win32IDE::runMessageLoop()
{
    MSG msg;
    while (GetMessageA(&msg, nullptr, 0, 0) > 0) {
        if (!IsDialogMessageA(m_hwndMain, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }
    }
    return static_cast<int>(msg.wParam);
}

// ---------------------------------------------------------------------------
// Editor surface
// ---------------------------------------------------------------------------
void Win32IDE::onSize(int width, int height)
{
    if (width <= 0 || height <= 0) {
        return;
    }
    if (m_hwndStatusBar) {
        SendMessageA(m_hwndStatusBar, WM_SIZE, 0, 0);
    }
    if (m_hwndDocTabs) {
        // Tab strip sits directly under the toolbar and spans the client width.
        const int tabTop = m_hwndToolbar ? 40 : 0;
        MoveWindow(m_hwndDocTabs, 0, tabTop, width, DOC_TAB_HEIGHT, TRUE);
    }
    if (m_hwndEditor) {
        const int editorTop = (m_hwndToolbar ? 40 : 0) + DOC_TAB_HEIGHT;
        const int editorHeight = height - editorTop - m_terminalHeight;
        MoveWindow(m_hwndEditor, 0, editorTop, width, editorHeight > 0 ? editorHeight : 0, TRUE);
    }
}

void Win32IDE::initializeEditorSurface()
{
    if (!m_hwndMain) {
        return;
    }
    m_hwndEditor = CreateWindowExA(
        WS_EX_CLIENTEDGE, RICHEDIT_CLASSA, "",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL |
            ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_WANTRETURN,
        0, 0, 400, 300, m_hwndMain, reinterpret_cast<HMENU>(IDC_EDITOR), m_hInstance, nullptr);
    if (m_hwndEditor) {
        SendMessageA(m_hwndEditor, EM_EXLIMITTEXT, 0, 64 * 1024 * 1024);
        SendMessageA(m_hwndEditor, EM_SETEVENTMASK, 0, ENM_CHANGE);
        applyTheme();
    }
}

void Win32IDE::syncEditorToGpuSurface()
{
    // The editor surface is a plain Win32 EDIT control; the GPU path renders
    // through the Vulkan surface when ENABLE_VULKAN is set. Nothing to copy
    // when that surface is absent.
    if (!m_hwndEditor) {
        return;
    }
}

// ---------------------------------------------------------------------------
// Ollama/local-model bridge
// ---------------------------------------------------------------------------
bool Win32IDE::trySendToOllama(const std::string& prompt, std::string& outResponse)
{
    outResponse.clear();
    if (prompt.empty()) {
        outResponse = "empty prompt";
        return false;
    }
    try {
        if (!isModelLoaded()) {
            outResponse = "model not loaded";
            return false;
        }
        outResponse = generateResponse(prompt);
        return !outResponse.empty();
    } catch (const std::exception& e) {
        outResponse = std::string("inference error: ") + e.what();
        return false;
    } catch (...) {
        outResponse = "inference error";
        return false;
    }
}

// ---------------------------------------------------------------------------
// Document tabs (VS Code style)
// ---------------------------------------------------------------------------
void Win32IDE::createDocumentTabs()
{
    if (m_hwndDocTabs) return;

    RECT client{};
    GetClientRect(m_hwndMain, &client);
    const int tabTop = m_hwndToolbar ? 40 : 0;

    m_hwndDocTabs = CreateWindowExA(0, WC_TABCONTROLA, "",
        WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | TCS_TABS,
        0, tabTop, client.right, DOC_TAB_HEIGHT,
        m_hwndMain, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_DOC_TABS)),
        m_hInstance, nullptr);
    if (!m_hwndDocTabs) return;

    // Start with the scratch buffer that already exists in the UI.
    m_openDocuments.clear();
    m_activeDocument = -1;
    addDocumentTab(std::string());
}

int Win32IDE::findDocumentTab(const std::string& path) const
{
    for (size_t i = 0; i < m_openDocuments.size(); ++i) {
        if (m_openDocuments[i] == path) return static_cast<int>(i);
    }
    return -1;
}

void Win32IDE::addDocumentTab(const std::string& path)
{
    if (!m_hwndDocTabs) return;

    // An already-open file becomes the active tab instead of duplicating.
    const int existing = findDocumentTab(path);
    if (existing >= 0) {
        switchDocumentTab(existing);
        return;
    }

    const std::string label = path.empty() ? std::string("Untitled")
                                           : extractLeafName(path);

    TCITEMA tie{};
    tie.mask = TCIF_TEXT;
    tie.pszText = const_cast<char*>(label.c_str());
    const int index = static_cast<int>(m_openDocuments.size());
    TabCtrl_InsertItem(m_hwndDocTabs, index, &tie);

    m_openDocuments.push_back(path);
    TabCtrl_SetCurSel(m_hwndDocTabs, index);
    m_activeDocument = index;
    updateTitleBarText();
}

void Win32IDE::removeDocumentTab(int index)
{
    if (!m_hwndDocTabs || index < 0 ||
        index >= static_cast<int>(m_openDocuments.size())) {
        return;
    }

    TabCtrl_DeleteItem(m_hwndDocTabs, index);
    m_openDocuments.erase(m_openDocuments.begin() + index);

    if (m_openDocuments.empty()) {
        // Keep the editor usable: an untitled buffer always remains.
        addDocumentTab(std::string());
        return;
    }

    if (m_activeDocument >= static_cast<int>(m_openDocuments.size())) {
        m_activeDocument = static_cast<int>(m_openDocuments.size()) - 1;
    }
    if (m_activeDocument < 0) m_activeDocument = 0;
    TabCtrl_SetCurSel(m_hwndDocTabs, m_activeDocument);
}

void Win32IDE::switchDocumentTab(int index)
{
    if (!m_hwndDocTabs || index < 0 ||
        index >= static_cast<int>(m_openDocuments.size())) {
        return;
    }
    m_activeDocument = index;
    TabCtrl_SetCurSel(m_hwndDocTabs, index);

    const std::string& path = m_openDocuments[static_cast<size_t>(index)];
    if (!path.empty()) {
        loadFileIntoEditor(path);
    } else {
        m_currentFile.clear();
        newFile();
    }
}

void Win32IDE::updateDocumentTabs()
{
    if (!m_hwndDocTabs) return;
    TabCtrl_DeleteAllItems(m_hwndDocTabs);
    for (size_t i = 0; i < m_openDocuments.size(); ++i) {
        const std::string label = m_openDocuments[i].empty()
            ? std::string("Untitled") : extractLeafName(m_openDocuments[i]);
        TCITEMA tie{};
        tie.mask = TCIF_TEXT;
        tie.pszText = const_cast<char*>(label.c_str());
        TabCtrl_InsertItem(m_hwndDocTabs, static_cast<int>(i), &tie);
    }
    if (m_activeDocument >= 0 &&
        m_activeDocument < static_cast<int>(m_openDocuments.size())) {
        TabCtrl_SetCurSel(m_hwndDocTabs, m_activeDocument);
    }
}
