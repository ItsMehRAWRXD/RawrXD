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
#include <algorithm>
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
                const int command = static_cast<int>(LOWORD(wParam));
                const int paneId = (command >= 7100) ? (command - 7100) / 10 : -1;
                TerminalPane* pane = (paneId > 0) ? ide->findTerminalPane(paneId) : nullptr;
                const int action = (command >= 7100) ? (command - 7100) % 10 : 0;
                // The terminal EDIT sends focus/change notifications using
                // its control ID. They are not menu commands and must not be
                // forwarded through the global command dispatcher.
                if (pane && action == 1) return 0;
                if (pane && action >= 2 && action <= 4) {
                    if (action == 2 && pane->input) {
                        char text[8192]{};
                        GetWindowTextA(pane->input, text, static_cast<int>(sizeof(text)));
                        if (text[0] && pane->manager) {
                            // Reuse the established command path so chat-mode,
                            // terminal routing and output-thread ownership remain
                            // identical to the legacy command box.
                            if (ide->m_hwndCommandInput) {
                                SetWindowTextA(ide->m_hwndCommandInput, text);
                                ide->executeCommand();
                            }
                            SetWindowTextA(pane->input, "");
                        }
                    } else if (action == 3 && pane->manager) {
                        pane->manager->writeInput("\x03");
                    } else if (action == 4 && pane->hwnd) {
                        SetWindowTextA(pane->hwnd, "");
                    }
                    return 0;
                }
                ide->onCommand(hwnd, command, reinterpret_cast<HWND>(lParam), HIWORD(wParam));
            }
            return 0;
        case WM_NOTIFY: {
            auto* nmhdr = reinterpret_cast<NMHDR*>(lParam);
            if (!nmhdr || !ide) return 0;
            if (nmhdr->idFrom == IDC_DOC_TABS && nmhdr->code == TCN_SELCHANGE) {
                ide->switchDocumentTab(TabCtrl_GetCurSel(nmhdr->hwndFrom));
            } else if (nmhdr->idFrom == IDC_OUTPUT_TABS && nmhdr->code == TCN_SELCHANGE) {
                static const char* outputKeys[] = {"Output", "Errors", "Debug", "Find Results"};
                const int selected = TabCtrl_GetCurSel(nmhdr->hwndFrom);
                if (selected >= 0 && selected < 4) {
                    ide->m_selectedOutputTab = selected;
                    ide->m_activeOutputTab = outputKeys[selected];
                    for (const auto& output : ide->m_outputWindows) {
                        ShowWindow(output.second,
                            ide->m_outputPanelVisible && output.first == ide->m_activeOutputTab
                                ? SW_SHOW : SW_HIDE);
                    }
                }
            } else if (nmhdr->idFrom == IDC_FILE_EXPLORER &&
                       nmhdr->code == TVN_ITEMEXPANDINGA) {
                auto* treeChange = reinterpret_cast<NMTREEVIEWA*>(lParam);
                if (treeChange->action & TVE_EXPAND) {
                    ide->expandTreeNode(treeChange->itemNew.hItem);
                }
            } else if (nmhdr->idFrom == IDC_FILE_EXPLORER && nmhdr->code == NM_DBLCLK) {
                ide->onFileExplorerDoubleClick();
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
        case WM_APP + 106: {
            if (ide) {
                ide->onModelDiscoveryComplete(
                    reinterpret_cast<std::vector<ChatModelEntry>*>(lParam));
            } else {
                delete reinterpret_cast<std::vector<ChatModelEntry>*>(lParam);
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
    const SUBCLASSPROC forwardPaneNotifications =
        [](HWND pane, UINT message, WPARAM wp, LPARAM lp, UINT_PTR, DWORD_PTR) -> LRESULT {
            if (message == WM_COMMAND || message == WM_NOTIFY) {
                return SendMessageA(GetParent(pane), message, wp, lp);
            }
            return DefSubclassProc(pane, message, wp, lp);
        };
    createDocumentTabs();
    createSidebar(hwnd);
    if (m_hwndSidebar) SetWindowSubclass(m_hwndSidebar, forwardPaneNotifications, 2, 0);
    createFileExplorer();
    createStatusBar(hwnd);
    createOutputTabs();
    createChatPanel();
    if (m_hwndSecondarySidebar) {
        SetWindowSubclass(m_hwndSecondarySidebar, forwardPaneNotifications, 3, 0);
    }
    initializeEditorSurface();

    RECT client{};
    if (GetClientRect(hwnd, &client)) {
        onSize(client.right, client.bottom);
    }
}

void Win32IDE::onDestroy()
{
    if (m_modelDiscoveryCancel) m_modelDiscoveryCancel->store(true);
    m_hwndMain = nullptr;
}

void Win32IDE::onCommand(HWND hwnd, int id, HWND hwndCtl, UINT codeNotify)
{
    if (hwndCtl == m_hwndCopilotSendBtn && codeNotify == BN_CLICKED) {
        HandleCopilotSend();
        return;
    }
    if (hwndCtl == m_hwndCopilotClearBtn && codeNotify == BN_CLICKED) {
        HandleCopilotClear();
        return;
    }
    if (hwndCtl == m_hwndModelSelector && codeNotify == CBN_SELCHANGE) {
        onModelSelectionChanged();
        return;
    }
    if (hwndCtl) {
        if (hwndCtl == m_hwndEditor) {
            if (codeNotify == EN_CHANGE) {
                if (!m_suppressEditorDirty) {
                    m_fileModified = true;
                    updateTitleBarText();
                }
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
    int statusHeight = 0;
    if (m_hwndStatusBar) {
        SendMessageA(m_hwndStatusBar, WM_SIZE, 0, 0);
        RECT statusRect{};
        if (GetClientRect(m_hwndStatusBar, &statusRect)) {
            statusHeight = statusRect.bottom - statusRect.top;
        }
    }
    if (m_hwndToolbar) {
        MoveWindow(m_hwndToolbar, 0, 0, width, 40, TRUE);
        layoutTitleBar(width);
    }
    const int toolbarHeight = m_hwndToolbar ? 40 : 0;
    const int contentTop = toolbarHeight + DOC_TAB_HEIGHT;
    if (m_hwndDocTabs) MoveWindow(m_hwndDocTabs, 0, toolbarHeight, width, DOC_TAB_HEIGHT, TRUE);

    const int activityWidth = (m_sidebarVisible && m_hwndActivityBar) ? 48 : 0;
    const int desiredLeft = m_sidebarVisible && m_hwndSidebar ? activityWidth + m_sidebarWidth : 0;
    const int leftWidth = std::min(desiredLeft, std::max(0, (width - 200) / 2));
    const int sidebarWidth = std::max(0, leftWidth - activityWidth);
    const int desiredRight = (m_secondarySidebarVisible && m_hwndSecondarySidebar)
        ? m_secondarySidebarWidth : 0;
    const int rightWidth = std::min(desiredRight, std::max(0, width - leftWidth - 200));

    const int availableHeight = std::max(0, height - contentTop - statusHeight);
    const bool terminalVisible = m_outputPanelVisible && !m_terminalPanes.empty();
    const int desiredBottom = m_outputPanelVisible
        ? (terminalVisible ? m_terminalHeight : m_outputTabHeight) : 0;
    const int bottomHeight = std::min(desiredBottom, std::max(0, availableHeight - 100));
    const int workHeight = std::max(0, availableHeight - bottomHeight);
    const int bottomTop = contentTop + workHeight;

    if (m_hwndActivityBar) {
        MoveWindow(m_hwndActivityBar, 0, contentTop, activityWidth, workHeight, TRUE);
        ShowWindow(m_hwndActivityBar, activityWidth ? SW_SHOW : SW_HIDE);
    }
    if (m_hwndSidebar) {
        MoveWindow(m_hwndSidebar, activityWidth, contentTop, sidebarWidth, workHeight, TRUE);
        ShowWindow(m_hwndSidebar, sidebarWidth > 0 ? SW_SHOW : SW_HIDE);
    }
    if (m_hwndFileExplorer) {
        MoveWindow(m_hwndFileExplorer, 5, 30, std::max(0, sidebarWidth - 10),
                   std::max(0, workHeight - 35), TRUE);
        ShowWindow(m_hwndFileExplorer, sidebarWidth > 0 ? SW_SHOW : SW_HIDE);
    }

    const int editorWidth = std::max(0, width - leftWidth - rightWidth);
    if (m_hwndEditor) MoveWindow(m_hwndEditor, leftWidth, contentTop, editorWidth, workHeight, TRUE);

    if (m_hwndSecondarySidebar) {
        MoveWindow(m_hwndSecondarySidebar, width - rightWidth, contentTop, rightWidth, workHeight, TRUE);
        ShowWindow(m_hwndSecondarySidebar, rightWidth > 0 ? SW_SHOW : SW_HIDE);
        const int buttonY = std::max(110, workHeight - 35);
        const int inputHeight = std::min(80, std::max(45, buttonY - 115));
        const int inputY = std::max(110, buttonY - inputHeight - 5);
        const int outputHeight = std::max(0, inputY - 115);
        if (m_hwndSecondarySidebarHeader) MoveWindow(m_hwndSecondarySidebarHeader, 5, 5, std::max(0, rightWidth - 10), 25, TRUE);
        if (m_hwndModelSelector) MoveWindow(m_hwndModelSelector, 60, 35, std::max(0, rightWidth - 65), 24, TRUE);
        if (m_hwndMaxTokensSlider) MoveWindow(m_hwndMaxTokensSlider, 5, 80, std::max(0, rightWidth - 10), 25, TRUE);
        if (m_hwndMaxTokensLabel) MoveWindow(m_hwndMaxTokensLabel, std::max(5, rightWidth - 55), 60, 50, 18, TRUE);
        if (m_hwndCopilotChatOutput) MoveWindow(m_hwndCopilotChatOutput, 5, 110, std::max(0, rightWidth - 10), outputHeight, TRUE);
        if (m_hwndCopilotChatInput) MoveWindow(m_hwndCopilotChatInput, 5, inputY, std::max(0, rightWidth - 10), inputHeight, TRUE);
        const int buttonWidth = std::max(0, (rightWidth - 15) / 2);
        if (m_hwndCopilotSendBtn) MoveWindow(m_hwndCopilotSendBtn, 5, buttonY, buttonWidth, 30, TRUE);
        if (m_hwndCopilotClearBtn) MoveWindow(m_hwndCopilotClearBtn, 10 + buttonWidth, buttonY, buttonWidth, 30, TRUE);
    }

    const bool showOutput = m_outputPanelVisible && !terminalVisible && bottomHeight > 0;
    if (m_hwndOutputTabs) {
        MoveWindow(m_hwndOutputTabs, 0, bottomTop, std::max(0, width - 150), 24, TRUE);
        ShowWindow(m_hwndOutputTabs, showOutput ? SW_SHOW : SW_HIDE);
    }
    if (m_hwndSeverityFilter) {
        MoveWindow(m_hwndSeverityFilter, std::max(0, width - 145), bottomTop + 2, 140, 100, TRUE);
        ShowWindow(m_hwndSeverityFilter, showOutput ? SW_SHOW : SW_HIDE);
    }
    for (const auto& output : m_outputWindows) {
        MoveWindow(output.second, 0, bottomTop + 24, width, std::max(0, bottomHeight - 24), TRUE);
        ShowWindow(output.second,
            showOutput && output.first == m_activeOutputTab ? SW_SHOW : SW_HIDE);
    }
    if (terminalVisible) {
        layoutTerminalPanes(width, bottomTop, bottomHeight);
        for (auto& pane : m_terminalPanes) {
            if (pane.hwnd) ShowWindow(pane.hwnd, SW_SHOW);
        }
    } else {
        for (auto& pane : m_terminalPanes) {
            if (pane.hwnd) ShowWindow(pane.hwnd, SW_HIDE);
            if (pane.input) ShowWindow(pane.input, SW_HIDE);
            if (pane.execute) ShowWindow(pane.execute, SW_HIDE);
            if (pane.stop) ShowWindow(pane.stop, SW_HIDE);
            if (pane.clear) ShowWindow(pane.clear, SW_HIDE);
        }
    }
    m_editorHeight = workHeight;
}

void Win32IDE::initializeEditorSurface()
{
    if (!m_hwndMain) {
        return;
    }
    m_suppressEditorDirty = true;
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
    // Initial control creation and theme application are not user edits.
    m_fileModified = false;
    m_suppressEditorDirty = false;
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
