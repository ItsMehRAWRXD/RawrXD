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

void configureModelSelectorCombo(HWND combo, int minimumVisibleRows)
{
    if (!combo) return;
    SendMessageA(combo, CB_SETDROPPEDWIDTH, 560, 0);
    SendMessageA(combo, CB_SETMINVISIBLE, minimumVisibleRows, 0);
    SendMessageA(combo, CB_SETITEMHEIGHT, static_cast<WPARAM>(-1), 20);
}

}  // namespace

LRESULT CALLBACK Win32IDE::ModelSelectorSubclassProc(HWND hwnd, UINT uMsg,
                                                       WPARAM wParam, LPARAM lParam,
                                                       UINT_PTR subclassId,
                                                       DWORD_PTR refData)
{
    if (uMsg == WM_LBUTTONDOWN || uMsg == WM_LBUTTONUP) {
        const bool wasDropped =
            SendMessageA(hwnd, CB_GETDROPPEDSTATE, 0, 0) != 0;
        const LRESULT result = DefSubclassProc(hwnd, uMsg, wParam, lParam);
        // Forward the click through the stock control first.  Some native
        // Common Controls builds close the popup again if CB_SHOWDROPDOWN is
        // sent from WM_LBUTTONDOWN, so defer only the fallback open until the
        // button-up dispatch has returned.
        if (uMsg == WM_LBUTTONUP && !wasDropped && IsWindow(hwnd)) {
            // The stock control normally opens on the button-down path. Only
            // post a fallback request when it demonstrably stayed closed;
            // blindly posting TRUE after a successful native open causes the
            // popup to oscillate on Common Controls builds that re-notify the
            // parent while the list is being shown.
            const bool opened =
                SendMessageA(hwnd, CB_GETDROPPEDSTATE, 0, 0) != 0;
            if (!opened) {
                PostMessageA(hwnd, CB_SHOWDROPDOWN, TRUE, 0);
            }
        }
        return result;
    }
    const LRESULT result = DefSubclassProc(hwnd, uMsg, wParam, lParam);
    if (uMsg == WM_NCDESTROY) {
        RemoveWindowSubclass(hwnd, &Win32IDE::ModelSelectorSubclassProc,
                             subclassId);
    }
    (void)refData;
    return result;
}

void Win32IDE::installModelSelectorProc(HWND combo)
{
    if (!combo) return;
    // SetWindowSubclass keeps the native ComboBox procedure and owns the
    // lifetime of the fallback hook. Do not replace GWLP_WNDPROC here: the
    // popup list and asynchronous model discovery can outlive a raw child
    // procedure replacement during teardown.
    SetWindowSubclass(combo, &Win32IDE::ModelSelectorSubclassProc, 1, 0);
    configureModelSelectorCombo(combo, 14);
}

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
        case WM_HSCROLL:
            if (ide && reinterpret_cast<HWND>(lParam) == ide->m_hwndMaxTokensSlider) {
                ide->onMaxTokensChanged(static_cast<int>(SendMessage(
                    ide->m_hwndMaxTokensSlider, TBM_GETPOS, 0, 0)));
                return 0;
            }
            if (ide && reinterpret_cast<HWND>(lParam) == ide->m_hwndContextSlider) {
                ide->m_currentContextTokens = static_cast<int>(SendMessage(
                    ide->m_hwndContextSlider, TBM_GETPOS, 0, 0));
                ide->updateContextControls();
                return 0;
            }
            return DefWindowProcA(hwnd, uMsg, wParam, lParam);
        case WM_COMMAND:
            if (ide) {
                // The dedicated PowerShell edit control emits EN_CHANGE and
                // EN_UPDATE notifications through the main window.  They are
                // input notifications, never menu/command IDs; consuming them
                // here prevents the global dispatcher from reporting bogus
                // "Unsupported command" messages while typing.
                if (reinterpret_cast<HWND>(lParam) == ide->m_hwndPowerShellInput) {
                    if (HIWORD(wParam) == EN_CHANGE) {
                        ide->notifyGhostTextInputChanged(
                            reinterpret_cast<HWND>(lParam));
                    }
                    return 0;
                }
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
            } else if (nmhdr->idFrom == IDC_CHAT_SESSIONS && nmhdr->code == TCN_SELCHANGE) {
                ide->switchChatSession(TabCtrl_GetCurSel(nmhdr->hwndFrom));
            } else if (nmhdr->idFrom == IDC_OUTPUT_TABS && nmhdr->code == TCN_SELCHANGE) {
                const int selected = TabCtrl_GetCurSel(nmhdr->hwndFrom);
                if (selected == 4) {
                    ide->showPowerShellPanel();
                } else if (selected >= 0 && selected < 4) {
                    static const char* outputKeys[] = {"Output", "Errors", "Debug", "Find Results"};
                    ide->hidePowerShellPanel();
                    ide->m_selectedOutputTab = selected;
                    ide->m_activeOutputTab = outputKeys[selected];
                    for (const auto& output : ide->m_outputWindows) {
                        ShowWindow(output.second,
                            ide->m_outputPanelVisible && output.first == ide->m_activeOutputTab
                                ? SW_SHOW : SW_HIDE);
                    }
                }
            } else if (nmhdr->idFrom == IDC_FILE_EXPLORER &&
                       nmhdr->code == TVN_DELETEITEMA) {
                // addTreeItem owns a heap-allocated path for every tree row.
                // TreeView_DeleteAllItems does not free item lParam values;
                // release them at the native delete notification so repeated
                // drive refreshes cannot leak or retain stale paths.
                auto* treeChange = reinterpret_cast<NMTREEVIEWA*>(lParam);
                delete[] reinterpret_cast<char*>(treeChange->itemOld.lParam);
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
        case WM_APP + 73:
            if (ide) return ide->handleNativeGhostTextMessage(uMsg, wParam, lParam) ? 0 : 1;
            return 0;
        case kRawrxdCopilotUiUpdate: {
            auto* update = reinterpret_cast<CopilotChatUiUpdate*>(lParam);
            if (ide && update) {
                ide->handleCopilotUiUpdate(update->sessionId,
                                           update->response,
                                           update->complete);
            }
            delete update;
            return 0;
        }
        case kRawrxdPowerShellUiUpdate: {
            auto* update = reinterpret_cast<PowerShellUiUpdate*>(lParam);
            if (ide && update) {
                if (update->kind == PowerShellUiUpdate::Kind::Output) {
                    ide->appendPowerShellOutput(update->text, update->color);
                } else if (update->kind == PowerShellUiUpdate::Kind::Error) {
                    ide->appendPowerShellOutput("[ERROR] " + update->text,
                                                 update->color);
                } else {
                    ide->appendPowerShellOutput(
                        "\n[PowerShell session ended with code: " +
                        std::to_string(update->exitCode) + "]\n", update->color);
                    ide->updatePowerShellStatus();
                }
            }
            delete update;
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
    // The dedicated PowerShell panel owns the real input, Execute/Stop/Clear
    // controls and its persistent shell session.  It must be created on the
    // canonical startup path; the legacy terminal panes remain available for
    // split-terminal commands but are not the primary bottom surface.
    createPowerShellPanel();
    if (m_hwndSecondarySidebar) {
        SetWindowSubclass(m_hwndSecondarySidebar, forwardPaneNotifications, 3, 0);
    }
    initializeEditorSurface();
    initializeNativeGhostText();

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
    if (hwndCtl == m_hwndCopilotStopBtn && codeNotify == BN_CLICKED) {
        HandleCopilotStop();
        return;
    }
    if (hwndCtl == m_hwndNewChatBtn && codeNotify == BN_CLICKED) {
        createChatSession();
        return;
    }
    if (hwndCtl == m_hwndCloseChatBtn && codeNotify == BN_CLICKED) {
        closeActiveChatSession();
        return;
    }
    if (hwndCtl == m_hwndRestoreChatBtn && codeNotify == BN_CLICKED) {
        restoreClosedChatSession();
        return;
    }
    if (hwndCtl == m_hwndRollbackChatBtn && codeNotify == BN_CLICKED) {
        rollbackActiveChat();
        return;
    }
    if (hwndCtl == m_hwndModelSelector && codeNotify == CBN_SELCHANGE) {
        onModelSelectionChanged();
        return;
    }
    if (hwndCtl == m_hwndGhostModelSelector && codeNotify == CBN_SELCHANGE) {
        onGhostTextSelectionChanged();
        return;
    }
    if (hwndCtl == m_hwndAllowCloudGhostText && codeNotify == BN_CLICKED) {
        onGhostTextCloudConsentChanged();
        return;
    }
    if ((hwndCtl == m_hwndModelSelector || hwndCtl == m_hwndGhostModelSelector) &&
        codeNotify == CBN_DROPDOWN) {
        // The native ComboBox procedure (and the supported child subclass)
        // owns popup visibility. Do not issue another CB_SHOWDROPDOWN here:
        // doing so races the native notification and makes the list visibly
        // open/close repeatedly on some Common Controls builds.
        RECT dropped{};
        const LRESULT count = SendMessage(hwndCtl, CB_GETCOUNT, 0, 0);
        const LRESULT open = SendMessage(hwndCtl, CB_GETDROPPEDSTATE, 0, 0);
        const LRESULT rectOk = SendMessage(hwndCtl, CB_GETDROPPEDCONTROLRECT, 0,
                                           reinterpret_cast<LPARAM>(&dropped));
        const char* selectorName = hwndCtl == m_hwndGhostModelSelector
            ? "GhostTextSelector" : "ModelSelector";
        const std::string diagnostic = std::string("[") + selectorName +
            "] dropdown count=" + std::to_string(count) +
            " open=" + std::to_string(open ? 1 : 0) +
            " rect=" + std::to_string(rectOk ? 1 : 0) +
            " width=" + std::to_string(rectOk ? dropped.right - dropped.left : 0) +
            " height=" + std::to_string(rectOk ? dropped.bottom - dropped.top : 0);
        logInfo(diagnostic);
        appendToOutput(diagnostic + "\n", "Debug", OutputSeverity::Info);
        return;
    }
    if (hwndCtl) {
        if (codeNotify == EN_CHANGE) {
            notifyGhostTextInputChanged(hwndCtl);
        }
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
    const bool powerShellVisible = m_outputPanelVisible && m_powerShellPanelVisible &&
        m_hwndPowerShellPanel != nullptr;
    const bool terminalVisible = !powerShellVisible && m_outputPanelVisible && !m_terminalPanes.empty();
    const int requestedPowerShellHeight = std::clamp(m_powerShellPanelHeight, 160, 420);
    // The active bottom surface owns the complete dock rectangle. PowerShell
    // is not a child of the legacy output-tab strip, so reserving a second
    // strip here would allow two surfaces to occupy the same dock.
    const int desiredBottom = m_outputPanelVisible
        ? (powerShellVisible ? requestedPowerShellHeight
           : (terminalVisible ? m_terminalHeight : m_outputTabHeight)) : 0;
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
    constexpr int breadcrumbHeight = 24;
    if (m_hwndEditorBreadcrumb) {
        MoveWindow(m_hwndEditorBreadcrumb, leftWidth, contentTop,
                   editorWidth, breadcrumbHeight, TRUE);
        ShowWindow(m_hwndEditorBreadcrumb, editorWidth > 0 ? SW_SHOW : SW_HIDE);
    }
    if (m_hwndEditor) {
        MoveWindow(m_hwndEditor, leftWidth, contentTop + breadcrumbHeight,
                   editorWidth, std::max(0, workHeight - breadcrumbHeight), TRUE);
    }

    if (m_hwndSecondarySidebar) {
        MoveWindow(m_hwndSecondarySidebar, width - rightWidth, contentTop, rightWidth, workHeight, TRUE);
        ShowWindow(m_hwndSecondarySidebar, rightWidth > 0 ? SW_SHOW : SW_HIDE);
        constexpr int chatContentTop = 193;
        const int buttonY = std::max(chatContentTop + 5, workHeight - 35);
        const int inputHeight = std::min(80, std::max(45, buttonY - chatContentTop - 5));
        const int inputY = std::max(chatContentTop, buttonY - inputHeight - 5);
        const int outputHeight = std::max(0, inputY - chatContentTop);
        const int tabWidth = std::max(80, rightWidth - 226);
        if (m_hwndChatSessionTabs) MoveWindow(m_hwndChatSessionTabs, 5, 3, tabWidth, 27, TRUE);
        const int actionsX = 5 + tabWidth + 4;
        if (m_hwndNewChatBtn) MoveWindow(m_hwndNewChatBtn, actionsX, 3, 58, 27, TRUE);
        if (m_hwndCloseChatBtn) MoveWindow(m_hwndCloseChatBtn, actionsX + 62, 3, 24, 27, TRUE);
        if (m_hwndRestoreChatBtn) MoveWindow(m_hwndRestoreChatBtn, actionsX + 90, 3, 58, 27, TRUE);
        if (m_hwndRollbackChatBtn) MoveWindow(m_hwndRollbackChatBtn, actionsX + 152, 3, 64, 27, TRUE);
        if (m_hwndSecondarySidebarHeader) MoveWindow(m_hwndSecondarySidebarHeader, 5, 34, std::max(0, rightWidth - 10), 22, TRUE);
        if (m_hwndModelLabel) MoveWindow(m_hwndModelLabel, 5, 35, 85, 18, TRUE);
        if (m_hwndModelSelector) {
            MoveWindow(m_hwndModelSelector, 95, 35, std::max(0, rightWidth - 100), 24, TRUE);
            configureModelSelectorCombo(m_hwndModelSelector, 14);
        }
        if (m_hwndGhostTextModelLabel) MoveWindow(m_hwndGhostTextModelLabel, 5, 62, 85, 18, TRUE);
        if (m_hwndGhostModelSelector) {
            MoveWindow(m_hwndGhostModelSelector, 95, 62, std::max(0, rightWidth - 100), 24, TRUE);
            configureModelSelectorCombo(m_hwndGhostModelSelector, 14);
        }
        if (m_hwndAllowCloudGhostText) MoveWindow(m_hwndAllowCloudGhostText, 5, 89, std::max(0, rightWidth - 10), 18, TRUE);
        if (m_hwndMaxTokensCaption) MoveWindow(m_hwndMaxTokensCaption, 5, 110, 85, 18, TRUE);
        if (m_hwndMaxTokensSlider) MoveWindow(m_hwndMaxTokensSlider, 5, 128, std::max(0, rightWidth - 10), 25, TRUE);
        if (m_hwndMaxTokensLabel) MoveWindow(m_hwndMaxTokensLabel, std::max(5, rightWidth - 55), 108, 50, 18, TRUE);
        if (m_hwndContextCaption) MoveWindow(m_hwndContextCaption, 5, 145, 85, 18, TRUE);
        if (m_hwndContextLabel) MoveWindow(m_hwndContextLabel, std::max(5, rightWidth - 120), 143, 115, 18, TRUE);
        if (m_hwndContextSlider) MoveWindow(m_hwndContextSlider, 5, 163, std::max(0, rightWidth - 10), 25, TRUE);
        if (m_hwndCopilotChatOutput) MoveWindow(m_hwndCopilotChatOutput, 5, 193, std::max(0, rightWidth - 10), outputHeight, TRUE);
        if (m_hwndCopilotChatInput) MoveWindow(m_hwndCopilotChatInput, 5, inputY, std::max(0, rightWidth - 10), inputHeight, TRUE);
        const int buttonWidth = std::max(0, (rightWidth - 20) / 3);
        if (m_hwndCopilotSendBtn) MoveWindow(m_hwndCopilotSendBtn, 5, buttonY, buttonWidth, 30, TRUE);
        if (m_hwndCopilotClearBtn) MoveWindow(m_hwndCopilotClearBtn, 10 + buttonWidth, buttonY, buttonWidth, 30, TRUE);
        if (m_hwndCopilotStopBtn) MoveWindow(m_hwndCopilotStopBtn, 15 + buttonWidth * 2, buttonY, buttonWidth, 30, TRUE);
    }

    // The shared strip remains visible while PowerShell is selected.  The
    // exclusive body below it prevents Output/Errors/Debug/Find Results from
    // sharing pixels or input focus with the shell.
    const bool showOutputTabs = m_outputPanelVisible && !terminalVisible && bottomHeight > 0;
    const bool showOutput = showOutputTabs && !powerShellVisible;
    if (m_hwndOutputTabs) {
        MoveWindow(m_hwndOutputTabs, 0, bottomTop, std::max(0, width - 150), 24, TRUE);
        ShowWindow(m_hwndOutputTabs, showOutputTabs ? SW_SHOW : SW_HIDE);
    }
    if (m_hwndSeverityFilter) {
        MoveWindow(m_hwndSeverityFilter, std::max(0, width - 145), bottomTop + 2, 140, 100, TRUE);
        ShowWindow(m_hwndSeverityFilter, showOutputTabs ? SW_SHOW : SW_HIDE);
    }
    for (const auto& output : m_outputWindows) {
        MoveWindow(output.second, 0, bottomTop + 24, width, std::max(0, bottomHeight - 24), TRUE);
        ShowWindow(output.second,
            showOutput && output.first == m_activeOutputTab ? SW_SHOW : SW_HIDE);
    }
    if (powerShellVisible) {
        // PowerShell owns the body below the shared strip. Output, Errors,
        // Debug, and Find Results remain selectable peers, never overlays.
        for (const auto& output : m_outputWindows) {
            if (output.second) ShowWindow(output.second, SW_HIDE);
        }
        if (m_hwndCommandInput) ShowWindow(m_hwndCommandInput, SW_HIDE);
        if (m_hwndPanelContainer) ShowWindow(m_hwndPanelContainer, SW_HIDE);
        if (m_hwndDebuggerContainer) ShowWindow(m_hwndDebuggerContainer, SW_HIDE);

        const int panelHeight = std::max(0, bottomHeight);
        // The editor ends at bottomTop; the shared strip occupies 24px; the
        // shell body starts below it.  Keeping the panel below the strip is
        // what prevents the shell toolbar from covering Output/Debug tabs.
        SetWindowPos(m_hwndPowerShellPanel, nullptr, 0, bottomTop,
            std::max(0, width), panelHeight,
            SWP_NOZORDER | SWP_NOACTIVATE | SWP_SHOWWINDOW);
        updatePowerShellPanelLayout(std::max(0, width), panelHeight);
        for (auto& pane : m_terminalPanes) {
            if (pane.hwnd) ShowWindow(pane.hwnd, SW_HIDE);
            if (pane.input) ShowWindow(pane.input, SW_HIDE);
            if (pane.execute) ShowWindow(pane.execute, SW_HIDE);
            if (pane.stop) ShowWindow(pane.stop, SW_HIDE);
            if (pane.clear) ShowWindow(pane.clear, SW_HIDE);
        }
    } else if (terminalVisible) {
        if (m_hwndCommandInput) ShowWindow(m_hwndCommandInput, SW_HIDE);
        if (m_hwndPanelContainer) ShowWindow(m_hwndPanelContainer,
            m_panelVisible ? SW_SHOW : SW_HIDE);
        if (m_hwndDebuggerContainer) ShowWindow(m_hwndDebuggerContainer, SW_HIDE);
        layoutTerminalPanes(width, bottomTop, bottomHeight);
        for (auto& pane : m_terminalPanes) {
            if (pane.hwnd) ShowWindow(pane.hwnd, SW_SHOW);
        }
    } else {
        if (m_hwndCommandInput) ShowWindow(m_hwndCommandInput, SW_HIDE);
        if (m_hwndPowerShellPanel) ShowWindow(m_hwndPowerShellPanel, SW_HIDE);
        if (m_hwndPanelContainer) ShowWindow(m_hwndPanelContainer,
            m_panelVisible ? SW_SHOW : SW_HIDE);
        if (m_hwndDebuggerContainer) ShowWindow(m_hwndDebuggerContainer, SW_HIDE);
        for (auto& pane : m_terminalPanes) {
            if (pane.hwnd) ShowWindow(pane.hwnd, SW_HIDE);
            if (pane.input) ShowWindow(pane.input, SW_HIDE);
            if (pane.execute) ShowWindow(pane.execute, SW_HIDE);
            if (pane.stop) ShowWindow(pane.stop, SW_HIDE);
            if (pane.clear) ShowWindow(pane.clear, SW_HIDE);
        }
    }
    m_editorHeight = std::max(0, workHeight - breadcrumbHeight);
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
        SendMessageA(m_hwndEditor, EM_SETBKGNDCOLOR, 0, RGB(30, 30, 30));
        CHARFORMAT2A initialFormat{};
        initialFormat.cbSize = sizeof(initialFormat);
        initialFormat.dwMask = CFM_COLOR | CFM_FACE | CFM_SIZE;
        initialFormat.crTextColor = RGB(220, 220, 220);
        initialFormat.yHeight = 200;
        strncpy_s(initialFormat.szFaceName, LF_FACESIZE, "Consolas", _TRUNCATE);
        SendMessageA(m_hwndEditor, EM_SETCHARFORMAT, SCF_ALL,
                     reinterpret_cast<LPARAM>(&initialFormat));
        applyTheme();
    }
    // Keep the complete active file path visible above the editor. This
    // read-only breadcrumb never owns editor focus.
    m_hwndEditorBreadcrumb = CreateWindowExA(
        WS_EX_CLIENTEDGE, "STATIC", "  Untitled  >  (workspace)",
        WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX,
        0, 0, 400, 24, m_hwndMain, nullptr, m_hInstance, nullptr);
    if (m_hwndEditorBreadcrumb) {
        SendMessageA(m_hwndEditorBreadcrumb, WM_SETFONT,
                     reinterpret_cast<WPARAM>(GetStockObject(DEFAULT_GUI_FONT)), TRUE);
        updateEditorBreadcrumb();
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
