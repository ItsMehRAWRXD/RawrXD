/*
 * Win32IDE_lifecycle.cpp - core window lifecycle for the RawrXD Win32 IDE
 *
 * Implements the declared-but-unimplemented public/private lifecycle surface
 * (createWindow / showWindow / runMessageLoop / onSize / editor surface /
 * Ollama bridge) plus the static WindowProc dispatch chain. Kept in its own
 * translation unit so the rest of the IDE sources remain untouched.
 */
#include "Win32IDE.h"
#include "Win32NativeDebugBackend.h"
#include <fstream>
#include <cstdlib>
#include <cstdio>
#include "IDELogger.h"
#include "Win32IDE_CommandIDs.h"

#ifndef IDC_COPILOT_SEND_BTN
#define IDC_COPILOT_SEND_BTN 1204
#endif
#ifndef IDC_COPILOT_CLEAR_BTN
#define IDC_COPILOT_CLEAR_BTN 1205
#endif
#ifndef IDC_COPILOT_STOP_BTN
#define IDC_COPILOT_STOP_BTN 1210
#endif

#include <windows.h>
#include <richedit.h>
#include <algorithm>
#include <string>

// Cleanup for VSCodeUI heap-allocated control strings (defined in VSCodeUI.cpp).
void cleanupVSCodeUIStrings();

namespace {
// Local INPUT_EVENT journal (same file/schema as Win32IDE.cpp chat_runtime.log).
// Kept TU-local to avoid LTCG unresolved externals across tip_ext link.
void WriteInputEventEvidence(const std::string& line)
{
    const char* configured = std::getenv("RAWRXD_LOG_DIR");
    const std::string path = (configured && *configured)
        ? std::string(configured) + "\\chat_runtime.log"
        : std::string("chat_runtime.log");
    const char* sidEnv = std::getenv("RAWRXD_CHAT_SESSION_ID");
    char sidBuf[80];
    if (sidEnv && sidEnv[0]) {
        // use env session id
    } else {
        sprintf_s(sidBuf, "sid_%08lX_%016llX",
                  static_cast<unsigned long>(GetCurrentProcessId()),
                  static_cast<unsigned long long>(GetTickCount64()));
        sidEnv = sidBuf;
    }
    std::ofstream out(path, std::ios::app);
    if (!out) return;
    const char* runEnv = std::getenv("RAWRXD_CHAT_RUN_ID");
    if (!runEnv || !runEnv[0]) runEnv = "run_unset";
    static bool opened = false;
    if (!opened) {
        opened = true;
        out << "SESSION_OPEN session_id=" << sidEnv
            << " run_id=" << runEnv
            << " pid=" << GetCurrentProcessId() << std::endl;
    }
    out << line << " session_id=" << sidEnv
        << " run_id=" << runEnv << std::endl;
}
}  // namespace

namespace {
constexpr const char* kWindowClass = "RawrXD_IDE_Window";
constexpr const char* kWindowTitle = "RawrXD IDE";
constexpr UINT_PTR kFileSafetyTimerId = 0x52584653; // "RXFS"
constexpr int kPanelTabsId = 1301;
constexpr int kPanelProblemsListId = 1312;
constexpr UINT kMsgReclaimDocTabs = WM_APP + 0x44;
constexpr UINT kMsgFinishDocTabs = WM_APP + 0x45;
constexpr UINT kMsgFinishSession = WM_APP + 0x46;
// W3: createPowerShellPanel TabCtrl_SetCurSel fires TCN_SELCHANGE â†’
// hidePowerShellPanel â†’ sync onSize during WM_CREATE (0xC000041D / AV).
thread_local int g_onSizeDepth = 0;
thread_local bool g_inOnCreateChrome = false;
// showWindow() sync-sends WM_SIZE after CreateWindow returns but before the
// posted finishDocTabs/finishSession handlers run. Gate layout until armed.
thread_local bool g_layoutReady = false;

void configureModelSelectorCombo(HWND combo, int minimumVisibleRows)
{
    if (!combo) return;
    SendMessageA(combo, CB_SETDROPPEDWIDTH, 560, 0);
    SendMessageA(combo, CB_SETMINVISIBLE, minimumVisibleRows, 0);
    SendMessageA(combo, CB_SETITEMHEIGHT, static_cast<WPARAM>(-1), 20);
}

void deferMainSize(HWND hwnd)
{
    if (!hwnd || !IsWindow(hwnd) || IsIconic(hwnd)) return;
    RECT rc{};
    if (!GetClientRect(hwnd, &rc) || rc.right <= 0 || rc.bottom <= 0) return;
    // Tiny clients (minimized restore race) would collapse the dock to ~24px.
    if (rc.bottom < 200 || rc.right < 200) return;
    PostMessageA(hwnd, WM_SIZE, SIZE_RESTORED, MAKELPARAM(rc.right, rc.bottom));
}

void onCreateBreadcrumb(const char* step)
{
    std::ofstream trace("F:\\rawrxd\\startup_trace.log", std::ios::app);
    if (trace) {
        trace << "onCreate:" << step << '\n';
        trace.flush();
    }
}

}  // namespace

Win32IDE* g_ideInstance = nullptr;

LRESULT CALLBACK Win32IDE::ModelSelectorSubclassProc(HWND hwnd, UINT uMsg,
                                                       WPARAM wParam, LPARAM lParam,
                                                       UINT_PTR subclassId,
                                                       DWORD_PTR refData)
{
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
#if defined(_MSC_VER)
// WM_CREATE is delivered synchronously from CreateWindowExA.  An SEH fault
// escaping this callback is promoted by USER32 to 0xC000041D, which hides the
// actual startup phase and prevents the remaining diagnostics from running.
// Keep the guard in a standalone function: MSVC forbids __try in a function
// that has C++ objects with non-trivial unwinding (C2712).
void sehCallOnCreateLifecycle(Win32IDE* ide, HWND hwnd)
{
    __try {
        ide->onCreate(hwnd);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        const DWORD code = GetExceptionCode();
        char message[256]{};
        snprintf(message, sizeof(message),
                 "[RawrXD] WM_CREATE SEH contained code=0x%08lX; startup phase aborted\n",
                 static_cast<unsigned long>(code));
        OutputDebugStringA(message);
        OutputDebugStringA("[RawrXD] WM_CREATE_SEH recorded by debugger; no C++ file I/O in SEH boundary\n");
    }
}
#else
void sehCallOnCreateLifecycle(Win32IDE* ide, HWND hwnd)
{
    try {
        ide->onCreate(hwnd);
    } catch (...) {
        OutputDebugStringA("[RawrXD] WM_CREATE C++ exception contained; startup phase aborted\n");
    }
}
#endif

LRESULT Win32IDE::handleThemeControlColor(UINT message, WPARAM wParam, LPARAM lParam)
{
    (void)message;
    (void)lParam;
    HDC hdc = reinterpret_cast<HDC>(wParam);
    if (!hdc) return 0;
    const COLORREF background = m_currentTheme.backgroundColor;
    const COLORREF text = m_currentTheme.textColor;
    SetBkMode(hdc, OPAQUE);
    SetBkColor(hdc, background);
    SetTextColor(hdc, text);
    // Brush lifetime: owned by applyTheme() which deletes+recreates on switch.
    // Never cache a static HBRUSH here â€” that retained startup colors.
    if (!m_backgroundBrush) {
        m_backgroundBrush = CreateSolidBrush(background);
    }
    return reinterpret_cast<LRESULT>(m_backgroundBrush);
}

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
                sehCallOnCreateLifecycle(ide, hwnd);
            }
            return 0;
        case WM_DESTROY:
            onCreateBreadcrumb("WM_DESTROY");
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
            onCreateBreadcrumb("WM_CLOSE");
            // Map9: reap agentic before DestroyWindow so FORCE_KILL=0 paths
            // cannot orphan deep2_agentic_loop after HWND teardown.
            if (ide && ide->m_agenticLoopBridge) {
                ide->m_agenticLoopBridge->Cancel();
            }
            if (ide && (!ide->hasUnsavedBuffers() || ide->promptSaveAllChanges())) {
                ide->saveIdeSession();
                DestroyWindow(hwnd);
            }
            return 0;
        case WM_SYSCOMMAND:
            // Keep the title-bar close action deterministic even when a child
            // popup or custom toolbar currently owns focus.  DefWindowProc
            // normally translates this to WM_CLOSE, but the explicit path
            // prevents the native X from becoming inert after launch.
            if ((wParam & 0xFFF0u) == SC_CLOSE) {
                if (ide && ide->m_agenticLoopBridge) {
                    ide->m_agenticLoopBridge->Cancel();
                }
                if (ide && (!ide->hasUnsavedBuffers() || ide->promptSaveAllChanges())) {
                    ide->saveIdeSession();
                    DestroyWindow(hwnd);
                }
                return 0;
            }
            return DefWindowProcA(hwnd, uMsg, wParam, lParam);
        case WM_NCLBUTTONDOWN:
            if (wParam == HTCLOSE) {
                SendMessageA(hwnd, WM_SYSCOMMAND, SC_CLOSE, 0);
                return 0;
            }
            return DefWindowProcA(hwnd, uMsg, wParam, lParam);
        case WM_COPYDATA:
            // Harness Chin() posts CHIN to the main HWND. SecondarySidebar also
            // accepts CHIN, but Wave4/Issue49 target RawrXD_IDE_Window.
            if (ide) {
                auto* cds = reinterpret_cast<COPYDATASTRUCT*>(lParam);
                if (cds && cds->lpData && cds->cbData > 0 &&
                    static_cast<ULONG_PTR>(cds->dwData) ==
                        kRawrxdChatInputCopyDataCmd) {
                    std::string text(static_cast<const char*>(cds->lpData),
                                     static_cast<size_t>(cds->cbData));
                    while (!text.empty() &&
                           (text.back() == '\0' || text.back() == '\r' ||
                            text.back() == '\n')) {
                        text.pop_back();
                    }
                    return ide->stageCopilotChatInputUtf8(text) ? TRUE : FALSE;
                }
            }
            return DefWindowProcA(hwnd, uMsg, wParam, lParam);
        case WM_SIZE:
            // SEH lives in onSizeSeh (C2712 forbids __try inside WindowProc).
            // onSize gated by g_inOnCreateChrome / g_layoutReady.
            if (ide) {
                ide->onSizeSeh(static_cast<int>(LOWORD(lParam)),
                               static_cast<int>(HIWORD(lParam)));
            }
            return 0;
        case WM_CTLCOLORSTATIC:
        case WM_CTLCOLOREDIT:
        case WM_CTLCOLORLISTBOX:
        case WM_CTLCOLORBTN:
        case WM_CTLCOLORDLG:
            if (ide) {
                return ide->handleThemeControlColor(uMsg, wParam, lParam);
            }
            return DefWindowProcA(hwnd, uMsg, wParam, lParam);
        case kMsgReclaimDocTabs:
            // Posted after CreateWindowExA returns â€” EnumChildWindows is unsafe
            // inside WM_CREATE (hang observed on Ext tip).
            if (ide) {
                ide->reclaimDocumentTabControlId();
            }
            return 0;
        case kMsgFinishDocTabs:
            // Runs after CreateWindowExA returns (not inside WM_CREATE).
            // No C++ try/catch here: WindowProc already uses SEH for WM_SIZE.
            if (ide) {
                onCreateBreadcrumb("finishDocTabs");
                ide->reclaimDocumentTabControlId();
                if (ide->m_hwndDocTabs && IsWindow(ide->m_hwndDocTabs)) {
                    ShowWindow(ide->m_hwndDocTabs, SW_SHOW);
                }
                if (ide->m_openDocuments.empty()) {
                    ide->addDocumentTab(std::string());
                }
                PostMessageA(hwnd, kMsgFinishSession, 0, 0);
                onCreateBreadcrumb("finishDocTabs.done");
            }
            return 0;
        case kMsgFinishSession:
            if (ide) {
                // Item 10: process was dying immediately after finishSession.done
                // (EXIT=-1). Breadcrumb each step; contain C++ throws so a
                // restore/tab fault cannot tear down the message loop.
                try {
                    onCreateBreadcrumb("finishSession");
                    onCreateBreadcrumb("finishSession.outputTabs");
                    ide->createOutputTabs();
                    onCreateBreadcrumb("finishSession.powerShellPanel");
                    ide->createPowerShellPanel();
                    if (ide->m_hwndPowerShellPanel) {
                        ShowWindow(ide->m_hwndPowerShellPanel, SW_HIDE);
                        ide->m_powerShellPanelVisible = false;
                    }
                    // Give the dock a visible terminal body at launch.  The
                    // pane is created without starting a shell; the user can
                    // start PowerShell/CMD from the pane controls or menu.
                    if (ide->m_terminalPanes.empty()) {
                        ide->createTerminalPane(
                            Win32TerminalManager::PowerShell, "PowerShell");
                    }
                    onCreateBreadcrumb("finishSession.loadSession");
                    ide->loadEditorSession();
                    onCreateBreadcrumb("finishSession.loadSession.done");
                    if (ide->m_openDocuments.empty()) {
                        ide->addDocumentTab(std::string());
                    }
                    if (ide->m_activeDocument >= 0 &&
                        ide->m_activeDocument <
                            static_cast<int>(ide->m_documentBuffers.size())) {
                        const int restoreIdx = ide->m_activeDocument;
                        ide->m_activeDocument = -1;
                        onCreateBreadcrumb("finishSession.switchTab");
                        ide->switchDocumentTab(restoreIdx);
                    }
                    // Argv/fixture path wins over sticky session (T080).
                    onCreateBreadcrumb("finishSession.initialPathFlush");
                    (void)ide->flushPendingInitialDocument();
                    ide->m_panelVisible = true;
                    ide->m_outputPanelVisible = true;
                    if (ide->m_hwndDocTabs && IsWindow(ide->m_hwndDocTabs)) {
                        ShowWindow(ide->m_hwndDocTabs, SW_SHOW);
                    }
                    // Place dock 1300 without arming full onSize (still AV-prone).
                    // Seed >=160 so iconic/tiny WM_SIZE cannot leave tab-only 24px.
                    if (ide->m_panelHeight < 160) {
                        ide->m_panelHeight = 250;
                    }
                    if (ide->m_hwndPanelContainer && IsWindow(ide->m_hwndPanelContainer)) {
                        RECT rc{};
                        if (GetClientRect(hwnd, &rc) && rc.bottom > 0 && rc.right > 0) {
                            int statusH = 24;
                            if (ide->m_hwndStatusBar && IsWindow(ide->m_hwndStatusBar)) {
                                RECT sr{};
                                if (GetClientRect(ide->m_hwndStatusBar, &sr) &&
                                    sr.bottom > sr.top) {
                                    statusH = sr.bottom - sr.top;
                                }
                            }
                            const int dockH = (std::max)(160, ide->m_panelHeight);
                            const int top = (std::max)(
                                0, static_cast<int>(rc.bottom) - statusH - dockH);
                            MoveWindow(ide->m_hwndPanelContainer, 0, top,
                                       static_cast<int>(rc.right), dockH, TRUE);
                        }
                        ShowWindow(ide->m_hwndPanelContainer, SW_SHOW);
                        if (ide->m_hwndPanelTabs && IsWindow(ide->m_hwndPanelTabs)) {
                            ShowWindow(ide->m_hwndPanelTabs, SW_SHOW);
                        }
                    }
                    // Single bottom owner until onSize assigns the active tab body.
                    if (ide->m_hwndPowerShellPanel) {
                        ShowWindow(ide->m_hwndPowerShellPanel, SW_HIDE);
                        ide->m_powerShellPanelVisible = false;
                    }
                    if (ide->m_hwndOutputTabs) {
                        ShowWindow(ide->m_hwndOutputTabs, SW_HIDE);
                    }
                    if (ide->m_hwndSeverityFilter) {
                        ShowWindow(ide->m_hwndSeverityFilter, SW_HIDE);
                    }
                    for (const auto& output : ide->m_outputWindows) {
                        if (output.second) ShowWindow(output.second, SW_HIDE);
                    }
                    for (auto& pane : ide->m_terminalPanes) {
                        if (pane.hwnd) ShowWindow(pane.hwnd, SW_HIDE);
                        if (pane.input) ShowWindow(pane.input, SW_HIDE);
                        if (pane.execute) ShowWindow(pane.execute, SW_HIDE);
                        if (pane.stop) ShowWindow(pane.stop, SW_HIDE);
                        if (pane.clear) ShowWindow(pane.clear, SW_HIDE);
                    }
                    onCreateBreadcrumb("finishSession.dockPlaced");
                    // Arm layout AFTER dock place; layoutBottomDock enforces
                    // min height 160, then deferMainSize posts WM_SIZE.
                    g_layoutReady = true;
                    onCreateBreadcrumb("finishSession.layoutBottomDock");
                    ide->layoutBottomDock();
                    // Output tabs, terminal panes, Problems, and Debug
                    // Console are created here (after WM_CREATE).  Applying
                    // the theme only during the constructor leaves these
                    // late-created native controls with their default black
                    // brushes/text.  Run the complete child-control theme
                    // pass after every required bottom-dock HWND exists.
                    onCreateBreadcrumb("finishSession.applyTheme");
                    ide->applyTheme();
                    onCreateBreadcrumb("finishSession.deferSize");
                    deferMainSize(hwnd);
                    onCreateBreadcrumb("finishSession.done");
                } catch (...) {
                    onCreateBreadcrumb("finishSession.exception");
                    g_layoutReady = true;
                    deferMainSize(hwnd);
                }
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
                if (!ide->m_updatingDocumentTabs) {
                    ide->switchDocumentTab(TabCtrl_GetCurSel(nmhdr->hwndFrom));
                }
            } else if (nmhdr->idFrom == IDC_DOC_TABS &&
                       (nmhdr->code == NM_CLICK || nmhdr->code == NM_DBLCLK)) {
                const auto* click = reinterpret_cast<const NMITEMACTIVATE*>(lParam);
                if (click) {
                    TCHITTESTINFO hit{};
                    hit.pt = click->ptAction;
                    const int tab = TabCtrl_HitTest(nmhdr->hwndFrom, &hit);
                    if (tab >= 0) {
                        RECT rect{};
                        TabCtrl_GetItemRect(nmhdr->hwndFrom, tab, &rect);
                        // The tab text deliberately ends in an "x".  Native
                        // tab metrics vary by theme/DPI, so use a generous
                        // trailing hit zone instead of the old 22px cutoff;
                        // otherwise the visible close glyph is inert on wide
                        // or themed tabs.
                        if (click->ptAction.x >= rect.right - 32) {
                            ide->closeDocumentTab(tab);
                        }
                    }
                }
            } else if (nmhdr->idFrom == IDC_CHAT_SESSIONS && nmhdr->code == TCN_SELCHANGE) {
                // Ignore selection churn from TabCtrl_DeleteAllItems/InsertItem
                // inside updateChatSessionTabs (nested switchChatSession AVs
                // comctl32 ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â BATCH1 Request A crash).
                if (!ide->m_updatingChatSessionTabs) {
                    ide->switchChatSession(TabCtrl_GetCurSel(nmhdr->hwndFrom));
                }
            } else if (nmhdr->idFrom == IDC_OUTPUT_TABS && nmhdr->code == TCN_SELCHANGE) {
                const int selected = TabCtrl_GetCurSel(nmhdr->hwndFrom);
                static const char* outputKeys[] = {
                    "Output", "Errors", "Debug", "Find Results",
                    "Build", "Tasks", "Terminal", "ExtensionHost",
                    "Ollama", "Deep2", "IDE", "Debugger"
                };
                constexpr int kOutputKeyCount =
                    static_cast<int>(sizeof(outputKeys) / sizeof(outputKeys[0]));
                // During WM_CREATE chrome, skip show/hidePowerShellPanel â€” both
                // call sync onSize and caused A4B95 CreateWindow AV / 0xC000041D.
                if (g_inOnCreateChrome || g_onSizeDepth > 0) {
                    if (selected >= 0 && selected < kOutputKeyCount) {
                        ide->m_selectedOutputTab = selected;
                        ide->m_activeOutputTab = outputKeys[selected];
                        ide->m_powerShellPanelVisible = false;
                    }
                } else if (selected == kOutputKeyCount) {
                    ide->showPowerShellPanel();
                } else if (selected >= 0 && selected < kOutputKeyCount) {
                    ide->hidePowerShellPanel();
                    ide->m_selectedOutputTab = selected;
                    ide->m_activeOutputTab = outputKeys[selected];
                    for (const auto& output : ide->m_outputWindows) {
                        if (output.second && IsWindow(output.second)) {
                            ShowWindow(output.second,
                                ide->m_outputPanelVisible &&
                                    output.first == ide->m_activeOutputTab
                                    ? SW_SHOW : SW_HIDE);
                        }
                    }
                }
            } else if (nmhdr->idFrom == kPanelTabsId &&
                       nmhdr->code == TCN_SELCHANGE) {
                const int selected = TabCtrl_GetCurSel(nmhdr->hwndFrom);
                if (selected >= 0 && selected <= 3) {
                    ide->switchPanelTab(static_cast<Win32IDE::PanelTab>(selected));
                }
            } else if (nmhdr->idFrom == kPanelProblemsListId &&
                       (nmhdr->code == NM_DBLCLK || nmhdr->code == NM_CLICK ||
                        nmhdr->code == LVN_ITEMACTIVATE)) {
                // Resolve row, then PostMessage WM_COMMAND 1399 → goToProblem.
                // Never call goToProblem inline from WM_NOTIFY (0xC000041D).
                int idx = -1;
                if (nmhdr->code == LVN_ITEMACTIVATE || nmhdr->code == NM_DBLCLK ||
                    nmhdr->code == NM_CLICK) {
                    const auto* activation =
                        reinterpret_cast<const NMITEMACTIVATE*>(lParam);
                    if (activation && activation->hdr.hwndFrom == nmhdr->hwndFrom &&
                        activation->iItem >= 0 &&
                        ide->m_hwndProblemsListView &&
                        activation->iItem <
                            ListView_GetItemCount(ide->m_hwndProblemsListView)) {
                        idx = activation->iItem;
                    }
                }
                if (idx < 0 && ide->m_hwndProblemsListView) {
                    idx = (int)ListView_GetNextItem(ide->m_hwndProblemsListView, -1, LVNI_SELECTED);
                }
                if (idx < 0 && ide->m_hwndProblemsListView &&
                    ListView_GetItemCount(ide->m_hwndProblemsListView) > 0) {
                    idx = 0;
                }
                {
                    std::ofstream crumb("F:\\rawrxd\\evidence\\B12_NAVIGATE_LATEST.log",
                                        std::ios::trunc);
                    if (crumb) crumb << "notify=POST1399 code=" << nmhdr->code
                                     << " idx=" << idx << "\n";
                }
                if (idx >= 0 && ide->m_hwndMain) {
                    PostMessageA(ide->m_hwndMain, WM_COMMAND,
                                 MAKEWPARAM(1399, 0),
                                 static_cast<LPARAM>(idx));
                }
            } else if (nmhdr->idFrom == IDC_FILE_EXPLORER &&
                       nmhdr->code == TVN_DELETEITEMA) {
                // addTreeItem owns a heap-allocated buffer holding both the
                // full path and the display text for every tree row.
                // TreeView_DeleteAllItems does not free item lParam values;
                // release them at the native delete notification so repeated
                // drive refreshes cannot leak or retain stale paths.
                auto* treeChange = reinterpret_cast<NMTREEVIEWA*>(lParam);
                delete[] reinterpret_cast<char*>(treeChange->itemOld.lParam);
            } else if (nmhdr->idFrom == IDC_FILE_TREE &&
                       nmhdr->code == TVN_DELETEITEMA) {
                // m_hwndFileTree items store heap-allocated char* buffers
                // for both path and display text; free them on item delete.
                auto* treeChange = reinterpret_cast<NMTREEVIEWA*>(lParam);
                delete[] reinterpret_cast<char*>(treeChange->itemOld.lParam);
            } else if (nmhdr->idFrom == IDC_DEBUGGER_VARIABLES &&
                       nmhdr->code == TVN_DELETEITEMA) {
                // Debugger variable items store heap-allocated char* buffers
                // for display text; free them on item delete.
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
            // Theme brush â€” never COLOR_WINDOW (system gray dock/client).
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            HBRUSH brush = ide && ide->m_backgroundBrush
                ? ide->m_backgroundBrush
                : reinterpret_cast<HBRUSH>(static_cast<intptr_t>(COLOR_WINDOW) + 1);
            if (ide && !ide->m_backgroundBrush) {
                ide->m_backgroundBrush =
                    CreateSolidBrush(ide->m_currentTheme.backgroundColor);
                brush = ide->m_backgroundBrush;
            }
            FillRect(hdc, &ps.rcPaint, brush);
            EndPaint(hwnd, &ps);
            return 0;
        }
        case WM_ERASEBKGND: {
            if (ide) {
                HDC hdc = reinterpret_cast<HDC>(wParam);
                RECT rc{};
                GetClientRect(hwnd, &rc);
                if (!ide->m_backgroundBrush) {
                    ide->m_backgroundBrush =
                        CreateSolidBrush(ide->m_currentTheme.backgroundColor);
                }
                if (ide->m_backgroundBrush) {
                    FillRect(hdc, &rc, ide->m_backgroundBrush);
                    return 1;
                }
            }
            return DefWindowProcA(hwnd, uMsg, wParam, lParam);
        }
        case WM_TIMER: {
            if (ide && wParam == IDT_AGENT_THOUGHT) {
                ide->m_agentStepTimeline.refreshThoughtElapsed();
                return 0;
            }
            if (ide && wParam == kFileSafetyTimerId) {
                ide->pollFileSafety();
                return 0;
            }
            return DefWindowProcA(hwnd, uMsg, wParam, lParam);
        }
        case kRawrxdNativeDebugState: {
            // Native-Ext links lifecycle WindowProc, not Core::handleMessage.
            // Without this dispatch, WaitForDebugEvent snapshots never reach
            // handleNativeDebugState â†’ WFDE_BP_HIT_RECEIPT never lands (S11).
            if (ide) {
                // Emit WFDE journal under RAWRXD_LOG_DIR before consuming snap.
                // Harness S11 requires WFDE_BP_HIT=1 + WaitForDebugEvent on disk.
                if (wParam == 0 && lParam) {
                    const auto* snap =
                        reinterpret_cast<const rawrxd::NativeDebugSnapshot*>(lParam);
                    if (snap && snap->stopReason.rfind("breakpoint:", 0) == 0) {
                        const char* logDir = std::getenv("RAWRXD_LOG_DIR");
                        const std::string path = (logDir && *logDir)
                            ? (std::string(logDir) + "\\WFDE_BP_HIT_RECEIPT.txt")
                            : std::string("WFDE_BP_HIT_RECEIPT.txt");
                        std::ofstream wfde(path, std::ios::trunc);
                        if (wfde) {
                            char hex[32];
                            sprintf_s(hex, "0x%llX",
                                      static_cast<unsigned long long>(snap->rip));
                            wfde << "WFDE_BP_HIT=1\n"
                                 << "STOP_REASON=" << snap->stopReason << '\n'
                                 << "RIP=" << hex << '\n'
                                 << "PID=" << snap->pid << '\n'
                                 << "API=WaitForDebugEvent\n";
                        }
                    }
                }
                return ide->handleNativeDebugState(wParam, lParam);
            }
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
        case kRawrxdLegacyAgentComplete: {
            // Legacy AgenticBridge complete (must not clear agenticChatSessionId)
            if (ide) {
                return ide->handleLegacyAgentComplete(wParam, lParam);
            }
            if (lParam) delete reinterpret_cast<std::string*>(lParam);
            return 0;
        }
        case WM_APP + 106: {
            if (ide) {
                ide->onModelDiscoveryComplete(
                    reinterpret_cast<ModelDiscoveryPayload*>(lParam));
            } else {
                delete reinterpret_cast<ModelDiscoveryPayload*>(lParam);
            }
            return 0;
        }
        case kRawrxdActivateDocTab: {
            // Pointer-free tab activate for external harness (T08 buffer sync).
            if (ide) {
                ide->switchDocumentTab(static_cast<int>(wParam));
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
                                           update->generation,
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
                    // Pane-local only ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â do not mirror [powershell:...] into chat transcript.
                    ide->updatePowerShellStatus();
                }
            }
            delete update;
            return 0;
        }
        case kRawrxdTerminalUiUpdate: {
            auto* update = reinterpret_cast<TerminalUiUpdate*>(lParam);
            if (ide && update) {
                if (update->kind == TerminalUiUpdate::Kind::Output) {
                    ide->onTerminalOutput(update->paneId, update->text);
                } else if (update->kind == TerminalUiUpdate::Kind::Error) {
                    ide->onTerminalError(update->paneId, update->text);
                } else {
                    {
                        std::ofstream receipt("F:\\rawrxd\\evidence\\RAWRXD_BUILD_RECEIPT_latest.log",
                                              std::ios::app);
                        if (receipt) {
                            receipt << "pane=" << update->paneId
                                    << " exit=" << update->exitCode
                                    << " status=" << (update->exitCode == 0 ? "PASS" : "FAIL")
                                    << '\n';
                        }
                    }
                    ide->appendToOutput(
                        "[RAWRXD_BUILD_RECEIPT] pane=" + std::to_string(update->paneId) +
                        " exit=" + std::to_string(update->exitCode) +
                        " status=" + (update->exitCode == 0 ? std::string("PASS") : std::string("FAIL")) +
                        "\n", "Output", update->exitCode == 0 ? OutputSeverity::Info : OutputSeverity::Error);
                    // Keep terminal HWNDs alive after Build/fixture exit so
                    // Output/Problems GUI E2E can still enum children. Mark
                    // inactive only ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â do not HideWindow the pane controls.
                    if (auto* pane = ide->findTerminalPane(update->paneId)) {
                        pane->isActive = false;
                    }
                    RECT rc{};
                    if (GetClientRect(ide->m_hwndMain, &rc)) ide->onSize(rc.right, rc.bottom);
                    if (ide->m_hwndEditor) SetFocus(ide->m_hwndEditor);
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
    g_inOnCreateChrome = true;
    // Catch-all: C++ throws escaping WindowProc become 0xC000041D.
    try {
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
                if (message == WM_ERASEBKGND) {
                    HDC hdc = reinterpret_cast<HDC>(wp);
                    RECT rc{};
                    GetClientRect(control, &rc);
                    HBRUSH brush = CreateSolidBrush(RGB(30, 33, 42));
                    FillRect(hdc, &rc, brush);
                    DeleteObject(brush);
                    return 1;
                }
                if (message == WM_DRAWITEM) {
                    auto* item = reinterpret_cast<DRAWITEMSTRUCT*>(lp);
                    if (!item || !item->hwndItem) return 0;

                    const COLORREF surface = RGB(30, 33, 42);
                    const COLORREF text = RGB(230, 240, 255);
                    const COLORREF hover = RGB(0, 92, 120);
                    const COLORREF accent = RGB(0, 220, 255);
                    const COLORREF fill = (item->itemState & ODS_SELECTED) ? hover : surface;
                    HBRUSH brush = CreateSolidBrush(fill);
                    FillRect(item->hDC, &item->rcItem, brush);
                    DeleteObject(brush);

                    SetBkMode(item->hDC, TRANSPARENT);
                    SetTextColor(item->hDC, text);
                    if (item->CtlID == IDC_TITLE_TEXT) {
                        char title[512]{};
                        GetWindowTextA(item->hwndItem, title,
                                       static_cast<int>(sizeof(title)));
                        DrawTextA(item->hDC, title, -1, &item->rcItem,
                                  DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
                    } else if (item->CtlID == IDC_BTN_SETTINGS) {
                        RECT gearRect = item->rcItem;
                        SetTextColor(item->hDC, accent);
                        HFONT gearFont = CreateFontW(
                            -18, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                            CLEARTYPE_QUALITY, FF_DONTCARE, L"Segoe UI Symbol");
                        HGDIOBJ oldFont = gearFont
                            ? SelectObject(item->hDC, gearFont) : nullptr;
                        DrawTextW(item->hDC, L"\x2699", -1, &gearRect,
                                  DT_CENTER | DT_VCENTER | DT_SINGLELINE);
                        if (oldFont) SelectObject(item->hDC, oldFont);
                        if (gearFont) DeleteObject(gearFont);
                    } else {
                        return 0;
                    }
                    return TRUE;
                }
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
    onCreateBreadcrumb("documentTabs");
    createDocumentTabs();
    onCreateBreadcrumb("activityBar");
    createActivityBarUI(hwnd);
    onCreateBreadcrumb("primarySidebar");
    createPrimarySidebar(hwnd);
    if (m_hwndSidebar) SetWindowSubclass(m_hwndSidebar, forwardPaneNotifications, 2, 0);
    if (m_hwndSidebarContent) SetWindowSubclass(m_hwndSidebarContent, forwardPaneNotifications, 4, 0);
    onCreateBreadcrumb("statusBar");
    createStatusBar(hwnd);
    // Defer createOutputTabs: WM_CREATE TabCtrl/map fill corrupts
    // m_outputWindows and AVs in onSize range-for (0xC000041D).
    onCreateBreadcrumb("outputTabsDeferred");
    onCreateBreadcrumb("panel");
    createPanel(hwnd);
    onCreateBreadcrumb("chatPanel");
    createChatPanel();
    onCreateBreadcrumb("powerShellPanel");
    // PowerShell panel creation starts a terminal session and subclasses
    // native controls. Keep it out of WM_CREATE; deferred finish-session
    // initialization owns it after the main HWND and dock exist.
    if (m_hwndSecondarySidebar) {
        SetWindowSubclass(m_hwndSecondarySidebar, forwardPaneNotifications, 3, 0);
    }
    onCreateBreadcrumb("editorSurface");
    initializeEditorSurface();
    // Session restore + Untitled + EnumChild reclaim stay OUT of WM_CREATE.
    // Sync loadIdeSession / addDocumentTab here re-entered the 0xC000041D /
    // CreateWindow hang class on A4B95/D93 (poisoned snapshot + tab reclaim).
    onCreateBreadcrumb("ghostText");
    initializeNativeGhostText();
    onCreateBreadcrumb("fileSafety");
    armFileSafetyMonitor();

    // Finish output-tabs/session/size only after CreateWindowExA returns.
    g_inOnCreateChrome = false;
    onCreateBreadcrumb("postFinish");
    PostMessageA(hwnd, kMsgFinishDocTabs, 0, 0);
    onCreateBreadcrumb("done");
    } catch (...) {
        g_inOnCreateChrome = false;
        try {
            IDELogger::getInstance().error(
                "Win32IDE", "onCreate: exception swallowed (CreateWindow safety)");
        } catch (...) {
        }
    }
}

void Win32IDE::onDestroy()
{
    if (m_modelDiscoveryCancel) m_modelDiscoveryCancel->store(true);
    ++m_currentModelGenID;
    m_deferredModelDiscovery.reset();
    m_modelDiscoveryUpdateDeferred = false;
    // Map9: Native-Ext uses this TU (Core onDestroy is not linked). Reap
    // agentic children unconditionally; do not join worker here (HWND stall).
    if (m_agenticLoopBridge) {
        m_agenticLoopBridge->Cancel();
    }
#if defined(RAWRXD_NATIVE_IDE_EXT) && RAWRXD_NATIVE_IDE_EXT
    shutdownJsExtensionHost();
#endif
    m_hwndMain = nullptr;
    // Free Sidebar heap-allocated control strings on window destruction.
    // Sidebar-owned resources are released by their window teardown.
    // Free VSCodeUI panel heap-allocated control strings on window destruction.
    // VS Code UI resources are released by their window teardown.
}

void Win32IDE::onCommand(HWND hwnd, int id, HWND hwndCtl, UINT codeNotify)
{
    // Synthetic cross-process WM_COMMAND probes have no originating control.
    // Keep diagnostic/debug probes side-effect free; real menu/button paths
    // carry a command source and continue through the normal router.
    if (hwndCtl == nullptr && codeNotify == 0 &&
        (id >= 2100 && id <= 2108 || id == 4001 ||
         id == 4010 || id == IDM_VIEW_SIDEBAR)) {
        appendToOutput("Synthetic command probe deferred\n",
                       "Output", OutputSeverity::Info);
        return;
    }
    // A null-control WM_COMMAND is a synthetic menu/probe dispatch.  Sidebar
    // visibility changes synchronously resize and repaint a large HWND tree;
    // do not perform that re-entrant operation without an originating menu or
    // button event.  Real activity-bar/menu events carry a control or are
    // routed through routeCommand with their normal command source.
    if (id == IDM_VIEW_SIDEBAR && hwndCtl == nullptr && codeNotify == 0) {
        appendToOutput("Sidebar command deferred (synthetic WM_COMMAND)\n",
                       "Output", OutputSeverity::Info);
        return;
    }
    if (id >= IDC_ACTBAR_EXPLORER && id <= IDC_ACTBAR_ACCOUNTS &&
        codeNotify == BN_CLICKED) {
        switch (id) {
        case IDC_ACTBAR_EXPLORER: setSidebarView(SidebarView::Explorer); break;
        case IDC_ACTBAR_SEARCH: setSidebarView(SidebarView::Search); break;
        case IDC_ACTBAR_SCM: setSidebarView(SidebarView::SourceControl); break;
        case IDC_ACTBAR_DEBUG: setSidebarView(SidebarView::RunDebug); break;
        case IDC_ACTBAR_EXTENSIONS: setSidebarView(SidebarView::Extensions); break;
        case IDC_ACTBAR_SETTINGS:
            routeCommand(IDM_VIEW_THEME_EDITOR);
            return;
        case IDC_ACTBAR_ACCOUNTS:
            SendMessageA(m_hwndStatusBar, SB_SETTEXTA, 0,
                reinterpret_cast<LPARAM>("Unsupported: account integration is unavailable in this build."));
            return;
        default: return;
        }
        m_activeActivityBarButton = id - IDC_ACTBAR_EXPLORER;
        updateActivityBarState();
        return;
    }
    // Match Send/Clear/Stop by control HWND or by dialog ID so cross-process
    // BM_CLICK / synthetic WM_COMMAND (lParam may be null) still reach the
    // same HandleCopilotSend path as a real button press.
    // Agent mode: route to AgenticLoopBridge (chatâ†’AgentSessionâ†’tools), not
    // Copilot text-only inference.
    if (codeNotify == BN_CLICKED &&
        (hwndCtl == m_hwndCopilotSendBtn || id == IDC_COPILOT_SEND_BTN)) {
        char line[256];
        const int sid = activeChatSession() ? activeChatSession()->id : 0;
        sprintf_s(line,
            "INPUT_EVENT source=button kind=BUTTON_CLICK "
            "path=WM_COMMAND_BN_CLICKED hwnd=0x%p session=%d pane=copilot_sidebar",
            static_cast<void*>(hwndCtl ? hwndCtl : m_hwndCopilotSendBtn), sid);
        WriteInputEventEvidence(line);
        if (isAgentModeActive()) {
            WriteInputEventEvidence(
                "INPUT_EVENT path=AGENT_MODE_AGENTIC_LOOP AGENT_MODE=ACTIVE");
            onAgenticLoopRunTask();
            return;
        }
        HandleCopilotSend();
        return;
    }
    if (codeNotify == BN_CLICKED &&
        (hwndCtl == m_hwndCopilotClearBtn || id == IDC_COPILOT_CLEAR_BTN)) {
        HandleCopilotClear();
        return;
    }
    if (codeNotify == BN_CLICKED &&
        (hwndCtl == m_hwndCopilotStopBtn || id == IDC_COPILOT_STOP_BTN)) {
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
    if (hwndCtl == m_hwndModelSelector &&
        (codeNotify == CBN_SELCHANGE || codeNotify == CBN_SELENDOK)) {
        onModelSelectionChanged();
        return;
    }
    if (hwndCtl == m_hwndGhostModelSelector &&
        (codeNotify == CBN_SELCHANGE || codeNotify == CBN_SELENDOK)) {
        onGhostTextSelectionChanged();
        return;
    }
    if ((hwndCtl == m_hwndModelSelector || hwndCtl == m_hwndGhostModelSelector) &&
        codeNotify == CBN_CLOSEUP) {
        // CBN_CLOSEUP is the authoritative lifecycle boundary.  Do not
        // re-query CB_GETDROPPEDSTATE here: common controls can report the
        // old state during notification delivery and strand a staged catalog.
        if (m_modelDiscoveryUpdateDeferred && m_deferredModelDiscovery) {
            auto deferred = std::move(m_deferredModelDiscovery);
            m_modelDiscoveryUpdateDeferred = false;
            onModelDiscoveryComplete(deferred.release());
        }
        return;
    }
    if (hwndCtl == m_hwndAllowCloudGhostText && codeNotify == BN_CLICKED) {
        onGhostTextCloudConsentChanged();
        return;
    }
    if (hwndCtl == m_hwndReasoningSelector &&
        (codeNotify == CBN_SELCHANGE || codeNotify == CBN_SELENDOK)) {
        onReasoningModeChanged();
        return;
    }
    if (hwndCtl == m_hwndWebBrowseToggle && codeNotify == BN_CLICKED) {
        onWebBrowsingChanged();
        return;
    }
    if (hwndCtl == m_hwndMaxTokensSelector &&
        (codeNotify == CBN_SELCHANGE || codeNotify == CBN_SELENDOK)) {
        const LRESULT row = SendMessageA(m_hwndMaxTokensSelector, CB_GETCURSEL, 0, 0);
        if (row >= 0) {
            const LRESULT value = SendMessageA(m_hwndMaxTokensSelector, CB_GETITEMDATA,
                static_cast<WPARAM>(row), 0);
            if (value > 0) onMaxTokensChanged(static_cast<int>(value));
        }
        return;
    }
    if (hwndCtl == m_hwndContextSelector &&
        (codeNotify == CBN_SELCHANGE || codeNotify == CBN_SELENDOK)) {
        onContextPresetChanged();
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
        // Bulk editor updates (opening/reloading a file, restoring a tab, or
        // creating a new buffer) intentionally suppress dirty tracking.  They
        // must not be forwarded to GhostText: doing so starts an asynchronous
        // completion against a transient buffer before the file identity and
        // tab state are committed.  User edits continue through the normal
        // notification path below.
        if (hwndCtl == m_hwndEditor) {
            logInfo("[EDITOR_CHANGE] code=" + std::to_string(codeNotify) +
                    " suppressed=" + std::to_string(m_suppressEditorDirty ? 1 : 0) +
                    " active=" + std::to_string(m_activeDocument));
            if (codeNotify == EN_CHANGE && !m_suppressEditorDirty) {
                m_fileModified = true;
                if (m_activeDocument >= 0 && m_activeDocument < static_cast<int>(m_documentBuffers.size())) {
                    auto& buffer = m_documentBuffers[static_cast<size_t>(m_activeDocument)];
                    // EM_GETTEXTEX (not GetWindowTextW) ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â T08 buffer sync.
                    buffer.text = getEditorTextUtf8ForFile();
                    buffer.modified = true;
                }
                updateTitleBarText();
                // Menu state is not refreshed by the RichEdit notification
                // itself.  Refresh it here so Save becomes immediately
                // available after keyboard input or paste.
                updateMenuEnableStates();
                notifyGhostTextInputChanged(hwndCtl);
            }
            return;
        }
        if (codeNotify == EN_CHANGE) {
            notifyGhostTextInputChanged(hwndCtl);
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
    // B12 harness: goToProblem(index) via lParam (int-only; cross-process safe).
    // WindowProc passes raw lParam as hwndCtl ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â reinterpret as problem index.
    // (Mirrored from Win32IDE_Core.cpp case 1399; Core TU is not in Native-Ext.)
    if (id == 1399) {
        const int idx = static_cast<int>(reinterpret_cast<intptr_t>(hwndCtl));
        {
            std::ofstream crumb("F:\\rawrxd\\evidence\\B12_NAVIGATE_LATEST.log",
                                std::ios::trunc);
            if (crumb) crumb << "wm_command_1399=1 idx=" << idx << "\n";
        }
        goToProblem(idx);
        return;
    }
        // Panel tab strip: SetCurSel + WM_COMMAND 1301 (VisId / harness).
    if (id == kPanelTabsId) {
        if (m_hwndPanelTabs && IsWindow(m_hwndPanelTabs)) {
            int idx = (int)TabCtrl_GetCurSel(m_hwndPanelTabs);
            if (idx < 0) idx = 0;
            if (idx > 3) idx = 3;
            switchPanelTab(static_cast<PanelTab>(idx));
        }
        return;
    }
    // B12: pointer-free activate via WM_COMMAND 1312 (cross-process safe).
    // Must switchPanelTab(Problems) first — prior path only goToProblem'd and
    // left ListView WS_VISIBLE=0 (DOCK prove PROBLEMS_1312_VISIBLE=False).
    if (id == kPanelProblemsListId) {
        switchPanelTab(PanelTab::Problems);
        int idx = -1;
        if (m_hwndProblemsListView && IsWindow(m_hwndProblemsListView)) {
            idx = (int)ListView_GetNextItem(m_hwndProblemsListView, -1, LVNI_SELECTED);
            if (idx < 0 && ListView_GetItemCount(m_hwndProblemsListView) > 0)
                idx = 0;
        }
        {
            std::ofstream crumb("F:\\rawrxd\\evidence\\B12_NAVIGATE_LATEST.log",
                                std::ios::trunc);
            if (crumb) crumb << "wm_command_1312=1 idx=" << idx << "\n";
        }
        if (idx >= 0) goToProblem(idx);
        return;
    }
    // Debugger panel IDs (Win32IDE_Debugger.cpp 2100-2108) + TERMINAL_LIST 4010.
    // Core TU is not in Native-Ext ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â mirror keep-alive handlers (no modal).
    switch (id) {
    case 2100:  // IDC_DEBUGGER_CONTAINER
    case 2101:  // IDC_DEBUGGER_TOOLBAR
    case 2102:  // IDC_DEBUGGER_TABS
        if (m_hwndDebuggerContainer && IsWindow(m_hwndDebuggerContainer)) {
            ShowWindow(m_hwndDebuggerContainer, SW_SHOW);
        }
        switchPanelTab(PanelTab::DebugConsole);
        appendToOutput("Debugger panel focused\n", "Debug", OutputSeverity::Info);
        return;
    case 2103:  // IDC_DEBUGGER_BTN_CONTINUE
    case 2104:  // IDC_DEBUGGER_BTN_STEP_OVER
    case 2105:  // IDC_DEBUGGER_BTN_STEP_INTO
    case 2106:  // IDC_DEBUGGER_BTN_STEP_OUT
    case 2107:  // IDC_DEBUGGER_BTN_STOP
    case 2108:  // IDC_DEBUGGER_BTN_RESTART
        // Keep-alive under SendMessage: do not nest debug work or PostMessage
        // queues that can wedge WM_CLOSE (harness S13). Real clicks (lParam
        // control HWND / non-SendMessage) still execute below.
        // Cross-process acceptance probes send a synthetic WM_COMMAND with a
        // null control HWND.  It must never enter debugger state transitions:
        // without a real originating control there is no valid debugger
        // session or command context to act on.
        if (InSendMessage() || hwndCtl == nullptr) {
            appendToOutput("Debugger command deferred (SendMessage keep-alive)\n",
                           "Debug", OutputSeverity::Info);
            return;
        }
        switch (id) {
        case 2103: continueExecution(); break;
        case 2104: stepOver(); break;
        case 2105: stepInto(); break;
        case 2106: stepOut(); break;
        case 2107: stopDebugging(); break;
        case 2108: restartDebugger(); break;
        default: break;
        }
        return;
    case 4010:  // COMMAND_TABLE TERMINAL_LIST ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â keep-alive, no modal
        appendToOutput("Terminal list (native panes)\n", "Output", OutputSeverity::Info);
        for (size_t i = 0; i < m_terminalPanes.size(); ++i) {
            const auto& pane = m_terminalPanes[i];
            char line[160];
            snprintf(line, sizeof(line), "  [%zu] running=%d\n", i,
                     (pane.manager && pane.manager->isRunning()) ? 1 : 0);
            appendToOutput(line, "Output", OutputSeverity::Info);
        }
        return;
    default:
        break;
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
    {
        std::ofstream trace("F:\\rawrxd\\startup_trace.log", std::ios::app);
        if (trace) trace << "createWindow entered" << '\n';
    }
    INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_WIN95_CLASSES | ICC_TAB_CLASSES};
    if (!InitCommonControlsEx(&controls)) {
        std::ofstream trace("F:\\rawrxd\\startup_trace.log", std::ios::app);
        if (trace) trace << "InitCommonControlsEx failed " << GetLastError() << '\n';
        return false;
    }
    // Prefer Msftedit (RICHEDIT50W) for Unicode file loads (T07). RichEdit20W
    // has been observed to replace CJK with '?' despite DEFAULT_CHARSET.
    static HMODULE richEdit = LoadLibraryW(L"Msftedit.dll");
    if (!richEdit) richEdit = LoadLibraryA("Riched20.dll");
    if (!richEdit) {
        std::ofstream trace("F:\\rawrxd\\startup_trace.log", std::ios::app);
        if (trace) trace << "LoadLibrary Msftedit/Riched20 failed " << GetLastError() << '\n';
        return false;
    }
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
        std::ofstream trace("F:\\rawrxd\\startup_trace.log", std::ios::app);
        if (trace) trace << "RegisterClassExA failed " << err << '\n';
        if (err != ERROR_CLASS_ALREADY_EXISTS) {
            try {
                IDELogger::getInstance().error("Win32IDE",
                                               "RegisterClassExA failed: " + std::to_string(err));
            } catch (...) {
            }
            return false;
        }
    }
    {
        std::ofstream trace("F:\\rawrxd\\startup_trace.log", std::ios::app);
        if (trace) trace << "RegisterClassExA succeeded" << '\n';
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
        std::ofstream trace("F:\\rawrxd\\startup_trace.log", std::ios::app);
        if (trace) trace << "CreateWindowExA failed " << GetLastError() << '\n';
        return false;
    }
    {
        std::ofstream trace("F:\\rawrxd\\startup_trace.log", std::ios::app);
        if (trace) trace << "CreateWindowExA succeeded" << '\n';
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
    std::ofstream trace("F:\\rawrxd\\startup_trace.log", std::ios::app);
    if (trace) trace << "ShowWindow and UpdateWindow returned" << '\n';
}

int Win32IDE::runMessageLoop()
{
    std::ofstream trace("F:\\rawrxd\\startup_trace.log", std::ios::app);
    if (trace) trace << "runMessageLoop entered" << '\n';
    // Native controls implement editing shortcuts themselves, but file commands
    // need a frame accelerator table before IsDialogMessage/TranslateMessage.
    // Without it Ctrl+S silently leaves the active document unsaved.
    ACCEL fileAccelerators[] = {
        { FVIRTKEY | FCONTROL, 'N', IDM_FILE_NEW },
        { FVIRTKEY | FCONTROL, 'O', IDM_FILE_OPEN },
        { FVIRTKEY | FCONTROL, 'S', IDM_FILE_SAVE },
        { FVIRTKEY | FCONTROL | FSHIFT, 'S', IDM_FILE_SAVEAS },
    };
    const HACCEL fileAcceleratorTable = CreateAcceleratorTableA(
        fileAccelerators, static_cast<int>(sizeof(fileAccelerators) / sizeof(fileAccelerators[0])));
    // Zero-init: GetMessage==-1 leaves MSG undefined; returning garbage wParam
    // was observed as process EXIT=-1 after finishSession.done / WM_CLOSE.
    MSG msg = {};
    // Timed Ctrl latch: PostMessage/keybd_event races can clear GetAsyncKeyState
    // before Enter is drained. Keep send-eligible for 2s after Ctrl KEYDOWN.
    static volatile const char kChatCtrlLatchMark[] = "CHAT_CTRL_LATCH_V1";
    ULONGLONG ctrlLatchDeadline = 0;
    for (;;) {
        const BOOL gm = GetMessageA(&msg, nullptr, 0, 0);
        if (gm == 0) {
            break; // WM_QUIT â€” wParam is the intended exit code
        }
        if (gm < 0) {
            onCreateBreadcrumb("GetMessage.error");
            msg.wParam = 0; // fail-closed clean exit (NOT garbage -1)
            break;
        }
        if (fileAcceleratorTable &&
            TranslateAcceleratorA(m_hwndMain, fileAcceleratorTable, &msg)) {
            continue;
        }
        (void)kChatCtrlLatchMark;
        if (msg.message == WM_KEYDOWN &&
            (msg.wParam == VK_CONTROL || msg.wParam == VK_LCONTROL ||
             msg.wParam == VK_RCONTROL)) {
            ctrlLatchDeadline = GetTickCount64() + 2000ULL;
            // Force marker into RelWithDebInfo binary + runtime journal.
            WriteInputEventEvidence(
                "INPUT_EVENT kind=CTRL_LATCH mark=CHAT_CTRL_LATCH_V1");
        } else if (msg.message == WM_KEYUP &&
                   (msg.wParam == VK_CONTROL || msg.wParam == VK_LCONTROL ||
                    msg.wParam == VK_RCONTROL)) {
            ctrlLatchDeadline = 0;
        }
        // AIM chat: Ctrl+Enter = SEND; Enter / Shift+Enter = newline.
        // Must run before TranslateMessage so WM_CHAR '\r' is not synthesized
        // for the send chord. (Core TU not linked on Native tip ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â live here.)
        {
            const HWND chatInput = m_hwndCopilotChatInput;
            const bool chatFocus =
                chatInput && IsWindow(chatInput) &&
                (msg.hwnd == chatInput || GetFocus() == chatInput);
            if (chatFocus) {
                const bool ctrlDown =
                    (ctrlLatchDeadline != 0 &&
                     GetTickCount64() < ctrlLatchDeadline) ||
                    (GetKeyState(VK_CONTROL) & 0x8000) != 0 ||
                    (GetKeyState(VK_LCONTROL) & 0x8000) != 0 ||
                    (GetKeyState(VK_RCONTROL) & 0x8000) != 0 ||
                    (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0;
                if (msg.message == WM_KEYDOWN && msg.wParam == VK_RETURN &&
                    ctrlDown) {
                    // Bit 30 = previous key state: ignore auto-repeat while held.
                    if ((msg.lParam & (1u << 30)) == 0) {
                        char line[256];
                        const int sid =
                            activeChatSession() ? activeChatSession()->id : 0;
                        sprintf_s(line,
                            "INPUT_EVENT source=ctrl_enter kind=CTRL_ENTER "
                            "path=AIM_GETMESSAGE_WM_KEYDOWN repeat=0 "
                            "hwnd=0x%p session=%d pane=copilot_sidebar",
                            static_cast<void*>(chatInput), sid);
                        WriteInputEventEvidence(line);
                        // Issue #49: same agent routing as Send button.
                        if (isAgentModeActive()) {
                            WriteInputEventEvidence(
                                "INPUT_EVENT path=AGENT_MODE_AGENTIC_LOOP "
                                "AGENT_MODE=ACTIVE source=ctrl_enter");
                            onAgenticLoopRunTask();
                        } else {
                            HandleCopilotSend();
                        }
                    } else {
                        WriteInputEventEvidence(
                            "INPUT_EVENT source=ctrl_enter "
                            "kind=HELD_KEY_REPEAT_SUPPRESSED "
                            "path=AIM_GETMESSAGE_WM_KEYDOWN");
                    }
                    continue;
                }
                if (msg.message == WM_KEYDOWN && msg.wParam == VK_RETURN &&
                    !ctrlDown) {
                    // Enter alone = newline (ES_WANTRETURN); never send.
                    WriteInputEventEvidence(
                        "INPUT_EVENT kind=ENTER_NEWLINE "
                        "path=AIM_GETMESSAGE_WM_KEYDOWN");
                }
                if (msg.message == WM_CHAR && ctrlDown &&
                    (msg.wParam == VK_RETURN || msg.wParam == '\r' ||
                     msg.wParam == '\n')) {
                    continue;
                }
            }
        }
        // Do not let IsDialogMessage steal Enter from multiline chat (ES_WANTRETURN).
        const HWND chatInputForDlg = m_hwndCopilotChatInput;
        const bool skipDialog =
            chatInputForDlg && IsWindow(chatInputForDlg) &&
            (msg.hwnd == chatInputForDlg || GetFocus() == chatInputForDlg);
        if (skipDialog || !IsDialogMessageA(m_hwndMain, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }
    }
    if (fileAcceleratorTable) DestroyAcceleratorTable(fileAcceleratorTable);
    onCreateBreadcrumb(msg.message == WM_QUIT ? "messageLoop.WM_QUIT" : "messageLoop.exit");
    return static_cast<int>(msg.wParam);
}

// ---------------------------------------------------------------------------
// Editor surface
// ---------------------------------------------------------------------------
void Win32IDE::onSizeSeh(int width, int height)
{
#if defined(_MSC_VER)
    __try {
        onSize(width, height);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        g_onSizeDepth = 0;
        onCreateBreadcrumb("onSize.seh");
    }
#else
    try {
        onSize(width, height);
    } catch (...) {
        g_onSizeDepth = 0;
        onCreateBreadcrumb("onSize.seh");
    }
#endif
}

void Win32IDE::onSize(int width, int height)
{
    if (width <= 0 || height <= 0) {
        return;
    }
    // Iconic/minimized clients are tiny (often ~160x24). Applying dock math
    // then collapses IDC_PANEL_CONTAINER to tab-strip height (74AA 1380x24).
    if (m_hwndMain && IsWindow(m_hwndMain) && IsIconic(m_hwndMain)) {
        return;
    }
    // Skip while WM_CREATE chrome is still assembling â€” child CreateWindow
    // WS_VISIBLE can deliver WM_SIZE mid-onCreate (A4B95 AV @ onSize dock).
    if (g_inOnCreateChrome) {
        return;
    }
    // Skip until finishSession arms layout (showWindow sync WM_SIZE race â†’
    // post-CreateWindow 0xC0000005 on half-initialized chrome).
    if (!g_layoutReady) {
        return;
    }
    // Re-entrancy guard: TabCtrl / ShowWindow / hidePowerShellPanel nest here
    // during create â†’ stack death (INTEG_007 / A4B95 onSize@1376).
    if (g_onSizeDepth > 0) {
        return;
    }
    ++g_onSizeDepth;
    struct OnSizeDepthGuard {
        ~OnSizeDepthGuard() { --g_onSizeDepth; }
    } onSizeGuard;
    (void)onSizeGuard;
    int statusHeight = 0;
    if (m_hwndStatusBar && IsWindow(m_hwndStatusBar)) {
        SendMessageA(m_hwndStatusBar, WM_SIZE, 0, 0);
        RECT statusRect{};
        if (GetClientRect(m_hwndStatusBar, &statusRect)) {
            statusHeight = statusRect.bottom - statusRect.top;
        }
    }
    if (m_hwndToolbar && IsWindow(m_hwndToolbar)) {
        MoveWindow(m_hwndToolbar, 0, 0, width, 40, TRUE);
        layoutTitleBar(width);
    }
    const int toolbarHeight = (m_hwndToolbar && IsWindow(m_hwndToolbar)) ? 40 : 0;
    const int contentTop = toolbarHeight + DOC_TAB_HEIGHT;
    if (m_hwndDocTabs && IsWindow(m_hwndDocTabs)) {
        MoveWindow(m_hwndDocTabs, 0, toolbarHeight, width, DOC_TAB_HEIGHT, TRUE);
    }

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
    // Four-panel dock (IDC_PANEL_CONTAINER) owns bottom height when
    // m_panelVisible. Prior path used terminal/output strip heights only and
    // left PANEL_CONTAINER VisId=0 after ensurePanelVisible (no layout).
    const int desiredBottom = m_outputPanelVisible
        ? (m_panelVisible ? std::clamp(m_panelHeight > 0 ? m_panelHeight : 250, 160, 420)
           : (powerShellVisible ? requestedPowerShellHeight
              : (terminalVisible ? m_terminalHeight : m_outputTabHeight))) : 0;
    // Prior: availableHeight-100 could yield 24 on small/iconic clients and
    // overwrite finishSession's dockH=250 with a tab-strip-only shell.
    int bottomHeight = std::min(desiredBottom, std::max(0, availableHeight - 100));
    if (m_outputPanelVisible && m_panelVisible && desiredBottom > 0) {
        constexpr int kMinPanelDock = 160;
        constexpr int kMinEditor = 80;
        if (availableHeight >= kMinPanelDock + kMinEditor) {
            bottomHeight = std::max(kMinPanelDock,
                std::min(desiredBottom, availableHeight - kMinEditor));
        } else if (availableHeight >= kMinPanelDock) {
            bottomHeight = kMinPanelDock;
        } else {
            bottomHeight = std::max(0, availableHeight);
        }
    }
    const int workHeight = std::max(0, availableHeight - bottomHeight);
    const int bottomTop = contentTop + workHeight;

    if (m_hwndActivityBar) {
        MoveWindow(m_hwndActivityBar, 0, contentTop, activityWidth, workHeight, TRUE);
        ShowWindow(m_hwndActivityBar, activityWidth ? SW_SHOW : SW_HIDE);
        // Keep the bottom activity actions anchored to the resized bar. The
        // activity bar is created before the first WM_SIZE with a bootstrap
        // height, so leaving the original coordinates would strand Settings
        // and Accounts in the middle of a taller window.
        const int buttonHeight = 48;
        for (int i = 0; i < 7; ++i) {
            if (!m_activityBarButtons[i]) continue;
            const int y = (i < 5)
                ? (i * buttonHeight)
                : std::max(0, workHeight - (7 - i) * buttonHeight);
            MoveWindow(m_activityBarButtons[i], 0, y,
                       activityWidth, buttonHeight, TRUE);
        }
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

    // Splitter is placed once after bottom-dock body layout (below) so it stays
    // above Output/Terminal siblings and visible on the dock top edge.

    if (m_hwndSecondarySidebar) {
        MoveWindow(m_hwndSecondarySidebar, width - rightWidth, contentTop, rightWidth, workHeight, TRUE);
        ShowWindow(m_hwndSecondarySidebar, rightWidth > 0 ? SW_SHOW : SW_HIDE);
        constexpr int chatContentTop = 240;
        // The right sidebar can be shorter than the full chat form when the
        // output dock is open or the main window is not maximized.  In that
        // compact geometry the old fixed timeline (88px) consumed the entire
        // transcript budget, leaving EDIT 1203 at height zero.  Preserve the
        // full timeline when space exists, but collapse it in compact mode so
        // the real ChatWindow transcript always has usable client area.
        const bool compactChat = workHeight < 500;
        const int stepStripHeight = compactChat ? 0 : 88;
        const int transcriptTop = chatContentTop + stepStripHeight + 5;
        const int buttonY = std::max(transcriptTop + 5, workHeight - 35);
        const int inputHeight = compactChat
            ? 45
            : std::min(80, std::max(45, buttonY - transcriptTop - 5));
        const int inputY = std::max(transcriptTop, buttonY - inputHeight - 5);
        const int outputHeight = std::max(0, inputY - transcriptTop);
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
        if (m_hwndMaxTokensSlider) ShowWindow(m_hwndMaxTokensSlider, SW_HIDE);
        if (m_hwndMaxTokensSelector) {
            MoveWindow(m_hwndMaxTokensSelector, 95, 128, std::max(0, rightWidth - 100), 24, TRUE);
            SendMessageA(m_hwndMaxTokensSelector, CB_SETDROPPEDWIDTH, 180, 0);
        }
        if (m_hwndMaxTokensLabel) ShowWindow(m_hwndMaxTokensLabel, SW_HIDE);
        if (m_hwndContextCaption) MoveWindow(m_hwndContextCaption, 5, 145, 85, 18, TRUE);
        if (m_hwndContextLabel) ShowWindow(m_hwndContextLabel, SW_HIDE);
        if (m_hwndContextSlider) ShowWindow(m_hwndContextSlider, SW_HIDE);
        if (m_hwndContextSelector) {
            MoveWindow(m_hwndContextSelector, 95, 163, std::max(0, rightWidth - 100), 24, TRUE);
            SendMessageA(m_hwndContextSelector, CB_SETDROPPEDWIDTH, 180, 0);
        }
        if (m_hwndReasoningLabel) MoveWindow(m_hwndReasoningLabel, 5, 190, 85, 18, TRUE);
        if (m_hwndReasoningSelector) {
            MoveWindow(m_hwndReasoningSelector, 95, 188, std::max(0, rightWidth - 100), 24, TRUE);
            SendMessageA(m_hwndReasoningSelector, CB_SETDROPPEDWIDTH, 260, 0);
        }
        if (m_hwndWebBrowseToggle) MoveWindow(m_hwndWebBrowseToggle, 5, 217, std::max(0, rightWidth - 10), 18, TRUE);
        m_agentStepTimeline.layout(5, chatContentTop, std::max(0, rightWidth - 10), stepStripHeight);
        if (m_hwndCopilotChatOutput) MoveWindow(m_hwndCopilotChatOutput, 5, transcriptTop, std::max(0, rightWidth - 10), outputHeight, TRUE);
        if (m_hwndCopilotChatInput) MoveWindow(m_hwndCopilotChatInput, 5, inputY, std::max(0, rightWidth - 10), inputHeight, TRUE);
        const int buttonWidth = std::max(0, (rightWidth - 20) / 3);
        if (m_hwndCopilotSendBtn) MoveWindow(m_hwndCopilotSendBtn, 5, buttonY, buttonWidth, 30, TRUE);
        if (m_hwndCopilotClearBtn) MoveWindow(m_hwndCopilotClearBtn, 10 + buttonWidth, buttonY, buttonWidth, 30, TRUE);
        if (m_hwndCopilotStopBtn) MoveWindow(m_hwndCopilotStopBtn, 15 + buttonWidth * 2, buttonY, buttonWidth, 30, TRUE);
    }

    // Bottom dock: ONE reserved rectangle. When m_panelVisible, IDC_PANEL_CONTAINER
    // owns it; Output/Terminal/Problems/Debug share via panel tabs. Peer
    // m_hwndPowerShellPanel is never stacked over that dock (covers chat /
    // clips console / hides tabs+splitter). Exclusive PS only if panel off.
    const bool onTerminalTab = (m_activePanelTab == PanelTab::Terminal);
    const bool onOutputTab = (m_activePanelTab == PanelTab::Output);
    const bool onProblemsTab = (m_activePanelTab == PanelTab::Problems);
    const bool onDebugTab = (m_activePanelTab == PanelTab::DebugConsole);
    const bool panelDockWanted =
        m_outputPanelVisible && m_panelVisible && m_hwndPanelContainer &&
        bottomHeight > 0;
    // Legacy strip only when four-panel dock is intentionally off.
    const bool showLegacyOutputStrip =
        m_outputPanelVisible && !panelDockWanted && !powerShellVisible &&
        bottomHeight > 0;
    const int bodyTop = bottomTop + 24;
    const int bodyH = std::max(0, bottomHeight - 24);

    if (m_hwndOutputTabs && IsWindow(m_hwndOutputTabs)) {
        MoveWindow(m_hwndOutputTabs, 0, bottomTop, std::max(0, width - 150), 24, TRUE);
        ShowWindow(m_hwndOutputTabs, showLegacyOutputStrip ? SW_SHOW : SW_HIDE);
    }
    if (m_hwndSeverityFilter && IsWindow(m_hwndSeverityFilter)) {
        MoveWindow(m_hwndSeverityFilter, std::max(0, width - 145), bottomTop + 2, 140, 100, TRUE);
        ShowWindow(m_hwndSeverityFilter, showLegacyOutputStrip ? SW_SHOW : SW_HIDE);
    }

    // Panel shell first so tab chrome exists under any body siblings.
    if (m_hwndPanelContainer && IsWindow(m_hwndPanelContainer)) {
        int panelShellHeight = panelDockWanted ? bottomHeight : 0;
        if (panelDockWanted && panelShellHeight < 160) {
            panelShellHeight = 160;
        }
        SetWindowPos(m_hwndPanelContainer, nullptr, 0, bottomTop,
                     std::max(0, width), std::max(0, panelShellHeight),
                     SWP_NOZORDER | SWP_NOACTIVATE);
        ShowWindow(m_hwndPanelContainer, panelDockWanted ? SW_SHOW : SW_HIDE);
        if (panelDockWanted) {
            if (m_hwndPanelTabs && IsWindow(m_hwndPanelTabs)) {
                MoveWindow(m_hwndPanelTabs, 0, 0, std::max(0, width - 200), 24, TRUE);
            }
            if (m_hwndPanelToolbar && IsWindow(m_hwndPanelToolbar)) {
                MoveWindow(m_hwndPanelToolbar, std::max(0, width - 200), 0, 200, 24, TRUE);
            }
            if (m_hwndProblemsListView && IsWindow(m_hwndProblemsListView)) {
                MoveWindow(m_hwndProblemsListView, 0, 26, std::max(0, width),
                           std::max(0, bottomHeight - 26), TRUE);
                ShowWindow(m_hwndProblemsListView, onProblemsTab ? SW_SHOW : SW_HIDE);
            }
            if (m_hwndDebugConsole && IsWindow(m_hwndDebugConsole)) {
                MoveWindow(m_hwndDebugConsole, 0, 26, std::max(0, width),
                           std::max(0, bottomHeight - 26), TRUE);
                ShowWindow(m_hwndDebugConsole, onDebugTab ? SW_SHOW : SW_HIDE);
            }
        }
    }

    // Output RichEdit bodies: only the active channel, only in the dock body.
    if (!m_outputWindows.empty()) {
        for (const auto& output : m_outputWindows) {
            if (!output.second || !IsWindow(output.second)) continue;
            MoveWindow(output.second, 0, bodyTop, width, bodyH, TRUE);
            const bool showOut =
                ((panelDockWanted && onOutputTab) || showLegacyOutputStrip) &&
                output.first == m_activeOutputTab;
            if (showOut) {
                SetWindowPos(output.second, HWND_TOP, 0, 0, 0, 0,
                             SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_SHOWWINDOW);
            } else {
                ShowWindow(output.second, SW_HIDE);
            }
        }
    }

    if (panelDockWanted) {
        // Four-panel owns the dock: peer PowerShell must stay hidden.
        if (m_hwndPowerShellPanel) {
            ShowWindow(m_hwndPowerShellPanel, SW_HIDE);
        }
        if (m_powerShellPanelVisible) {
            m_powerShellPanelVisible = false;
        }
        if (m_hwndCommandInput) ShowWindow(m_hwndCommandInput, SW_HIDE);
        if (m_hwndDebuggerContainer) ShowWindow(m_hwndDebuggerContainer, SW_HIDE);
        if (onTerminalTab) {
            layoutTerminalPanes(width, bodyTop, bodyH);
            for (auto& pane : m_terminalPanes) {
                if (pane.hwnd && IsWindow(pane.hwnd)) {
                    SetWindowPos(pane.hwnd, HWND_TOP, 0, 0, 0, 0,
                                 SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_SHOWWINDOW);
                }
                if (pane.input && IsWindow(pane.input)) {
                    SetWindowPos(pane.input, HWND_TOP, 0, 0, 0, 0,
                                 SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_SHOWWINDOW);
                }
                if (pane.execute && IsWindow(pane.execute)) {
                    SetWindowPos(pane.execute, HWND_TOP, 0, 0, 0, 0,
                                 SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_SHOWWINDOW);
                }
                if (pane.stop && IsWindow(pane.stop)) {
                    SetWindowPos(pane.stop, HWND_TOP, 0, 0, 0, 0,
                                 SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_SHOWWINDOW);
                }
                if (pane.clear && IsWindow(pane.clear)) {
                    SetWindowPos(pane.clear, HWND_TOP, 0, 0, 0, 0,
                                 SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_SHOWWINDOW);
                }
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
        // Tabs + toolbar above body siblings so they stay visible.
        if (m_hwndPanelTabs && IsWindow(m_hwndPanelTabs)) {
            SetWindowPos(m_hwndPanelTabs, HWND_TOP, 0, 0, 0, 0,
                         SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_SHOWWINDOW);
        }
        if (m_hwndPanelToolbar && IsWindow(m_hwndPanelToolbar)) {
            SetWindowPos(m_hwndPanelToolbar, HWND_TOP, 0, 0, 0, 0,
                         SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_SHOWWINDOW);
        }
    } else if (powerShellVisible) {
        for (const auto& output : m_outputWindows) {
            if (output.second) ShowWindow(output.second, SW_HIDE);
        }
        if (m_hwndCommandInput) ShowWindow(m_hwndCommandInput, SW_HIDE);
        if (m_hwndPanelContainer) ShowWindow(m_hwndPanelContainer, SW_HIDE);
        if (m_hwndDebuggerContainer) ShowWindow(m_hwndDebuggerContainer, SW_HIDE);
        SetWindowPos(m_hwndPowerShellPanel, nullptr, 0, bodyTop,
            std::max(0, width), bodyH,
            SWP_NOZORDER | SWP_NOACTIVATE | SWP_SHOWWINDOW);
        updatePowerShellPanelLayout(std::max(0, width), bodyH);
        for (auto& pane : m_terminalPanes) {
            if (pane.hwnd) ShowWindow(pane.hwnd, SW_HIDE);
            if (pane.input) ShowWindow(pane.input, SW_HIDE);
            if (pane.execute) ShowWindow(pane.execute, SW_HIDE);
            if (pane.stop) ShowWindow(pane.stop, SW_HIDE);
            if (pane.clear) ShowWindow(pane.clear, SW_HIDE);
        }
        // Legacy PowerShell tab strip stays above exclusive body.
        if (m_hwndOutputTabs && IsWindow(m_hwndOutputTabs)) {
            MoveWindow(m_hwndOutputTabs, 0, bottomTop, std::max(0, width - 150), 24, TRUE);
            ShowWindow(m_hwndOutputTabs, SW_SHOW);
            SetWindowPos(m_hwndOutputTabs, HWND_TOP, 0, 0, 0, 0,
                         SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
        }
    } else {
        if (m_hwndCommandInput) ShowWindow(m_hwndCommandInput, SW_HIDE);
        if (m_hwndPowerShellPanel) ShowWindow(m_hwndPowerShellPanel, SW_HIDE);
        if (m_hwndDebuggerContainer) ShowWindow(m_hwndDebuggerContainer, SW_HIDE);
        for (auto& pane : m_terminalPanes) {
            if (pane.hwnd) ShowWindow(pane.hwnd, SW_HIDE);
            if (pane.input) ShowWindow(pane.input, SW_HIDE);
            if (pane.execute) ShowWindow(pane.execute, SW_HIDE);
            if (pane.stop) ShowWindow(pane.stop, SW_HIDE);
            if (pane.clear) ShowWindow(pane.clear, SW_HIDE);
        }
    }

    // Splitter always sits on the dock top edge when a bottom surface exists.
    if (m_hwndSplitter && IsWindow(m_hwndSplitter)) {
        const int splitterHeight = 4;
        const int splitterY = std::max(contentTop, bottomTop - splitterHeight);
        m_splitterY = splitterY;
        MoveWindow(m_hwndSplitter, 0, splitterY, std::max(0, width), splitterHeight, TRUE);
        ShowWindow(m_hwndSplitter, bottomHeight > 0 ? SW_SHOW : SW_HIDE);
        if (bottomHeight > 0) {
            SetWindowPos(m_hwndSplitter, HWND_TOP, 0, 0, 0, 0,
                         SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
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
    // Force RICHEDIT50W when available: RichEdit20W stores CJK as '?' (T07).
    m_hwndEditor = CreateWindowExW(
        WS_EX_CLIENTEDGE, MSFTEDIT_CLASS, L"",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL |
            WS_TABSTOP | ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL |
            ES_WANTRETURN,
        0, 0, 400, 300, m_hwndMain, reinterpret_cast<HMENU>(IDC_EDITOR), m_hInstance, nullptr);
    if (!m_hwndEditor) {
        m_hwndEditor = CreateWindowExW(
            WS_EX_CLIENTEDGE, RICHEDIT_CLASSW, L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL |
                WS_TABSTOP | ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL |
                ES_WANTRETURN,
            0, 0, 400, 300, m_hwndMain, reinterpret_cast<HMENU>(IDC_EDITOR), m_hInstance, nullptr);
    }
    if (m_hwndEditor) {
        SendMessageW(m_hwndEditor, EM_EXLIMITTEXT, 0, 64 * 1024 * 1024);
        SendMessageW(m_hwndEditor, EM_SETEVENTMASK, 0, ENM_CHANGE);
        const LRESULT langOpts = SendMessageW(m_hwndEditor, EM_GETLANGOPTIONS, 0, 0);
        SendMessageW(m_hwndEditor, EM_SETLANGOPTIONS, 0, langOpts & ~IMF_AUTOFONT);
        SendMessageW(m_hwndEditor, EM_SETBKGNDCOLOR, 0, RGB(30, 30, 30));
        CHARFORMAT2W initialFormat{};
        initialFormat.cbSize = sizeof(initialFormat);
        initialFormat.dwMask = CFM_COLOR | CFM_FACE | CFM_SIZE | CFM_CHARSET;
        initialFormat.bCharSet = DEFAULT_CHARSET;
        initialFormat.crTextColor = RGB(220, 220, 220);
        initialFormat.yHeight = 200;
        wcsncpy_s(initialFormat.szFaceName, LF_FACESIZE, L"Microsoft YaHei UI", _TRUNCATE);
        SendMessageW(m_hwndEditor, EM_SETCHARFORMAT, SCF_ALL,
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
void Win32IDE::reclaimDocumentTabControlId()
{
    if (!m_hwndDocTabs || !m_hwndMain) return;
    // Harness keys off GetDlgCtrlID==1030. Later panel/chat tab controls can
    // steal that ID; reclaim on every mutation so IDC_DOC_TABS stays unique.
    SetWindowLongPtrW(m_hwndDocTabs, GWLP_ID, IDC_DOC_TABS);
    // Unique property so external probes can bind the accumulating strip even
    // if another child transiently shares ID 1030 (T08 harness mismatch).
    SetPropW(m_hwndDocTabs, L"RawrXDDocTabs", reinterpret_cast<HANDLE>(1));
    EnumChildWindows(m_hwndMain,
        [](HWND child, LPARAM self) -> BOOL {
            if (child == reinterpret_cast<HWND>(self)) return TRUE;
            if (GetDlgCtrlID(child) == IDC_DOC_TABS) {
                SetWindowLongPtrW(child, GWLP_ID, 1099);
            }
            if (GetPropW(child, L"RawrXDDocTabs") &&
                child != reinterpret_cast<HWND>(self)) {
                RemovePropW(child, L"RawrXDDocTabs");
            }
            return TRUE;
        },
        reinterpret_cast<LPARAM>(m_hwndDocTabs));
}

void Win32IDE::createDocumentTabs()
{
    if (m_hwndDocTabs) return;

    RECT client{};
    GetClientRect(m_hwndMain, &client);
    const int tabTop = m_hwndToolbar ? 40 : 0;
    onCreateBreadcrumb("docTabs.create");

    // Unicode tab control + W inserts: A-entry inserts were observed to leave
    // TCM_GETITEMCOUNT stuck at 1 while vectors grew (T08).
    // During WM_CREATE use WS_CHILD only (no WS_VISIBLE) â€” visible tab create
    // was observed to stall the CreateWindowExA user-callback (MAIN_HWND=0).
    const DWORD tabStyle = WS_CHILD | WS_CLIPSIBLINGS | TCS_TABS | TCS_SINGLELINE |
        (g_inOnCreateChrome ? 0u : WS_VISIBLE);
    m_hwndDocTabs = CreateWindowExW(0, WC_TABCONTROLW, L"",
        tabStyle,
        0, tabTop, client.right, DOC_TAB_HEIGHT,
        m_hwndMain, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_DOC_TABS)),
        m_hInstance, nullptr);
    if (!m_hwndDocTabs) {
        onCreateBreadcrumb("docTabs.createFAIL");
        return;
    }
    SetWindowLongPtrW(m_hwndDocTabs, GWLP_ID, IDC_DOC_TABS);
    onCreateBreadcrumb("docTabs.hwndReady");

    // Keep bookkeeping light during WM_CREATE. Session restore + EnumChild
    // reclaim + first Untitled tab are finished after CreateWindowExA returns.
    if (g_inOnCreateChrome) {
        m_activeDocument = -1;
        onCreateBreadcrumb("docTabs.doneLite");
        return;
    }

    reclaimDocumentTabControlId();
    m_openDocuments.clear();
    m_documentBuffers.clear();
    m_openDocuments.reserve(kMaxOpenDocuments);
    m_documentBuffers.reserve(kMaxOpenDocuments);
    m_activeDocument = -1;
    loadEditorSession();
    if (m_openDocuments.empty()) {
        addDocumentTab(std::string());
    }
    ShowWindow(m_hwndDocTabs, SW_SHOW);
    onCreateBreadcrumb("docTabs.done");
}

void Win32IDE::loadEditorSession()
{
    loadIdeSession();
}

void Win32IDE::saveEditorSession()
{
    saveIdeSession();
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

    // Refuse leaf-only / illegal names so they never become stuck tabs.
    if (!path.empty() && !isOpenableDocumentPath(path)) {
        const std::string leaf = extractLeafName(path);
        char msg[320];
        wsprintfA(msg,
            "\"%s\" is not a valid file name.\n"
            "Open a real path (drive + folders + file), or use Untitled.",
            leaf.empty() ? path.c_str() : leaf.c_str());
        MessageBoxA(m_hwndMain, msg, "Invalid File Name", MB_OK | MB_ICONWARNING);
        return;
    }

    // Non-empty path already open ÃƒÂ¢Ã¢â‚¬Â Ã¢â‚¬â„¢ activate only (no duplicate tab).
    // Empty path ("Untitled") may only exist once; a second "" activates it.
    const int existing = findDocumentTab(path);
    if (existing >= 0) {
        switchDocumentTab(existing);
        return;
    }

    if (m_openDocuments.size() >= kMaxOpenDocuments) {
        char msg[160];
        wsprintfA(msg,
            "Cannot open more documents ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â maximum of %u is open.\nClose a tab and try again.",
            static_cast<unsigned>(kMaxOpenDocuments));
        MessageBoxA(m_hwndMain, msg, "Document Limit", MB_OK | MB_ICONWARNING);
        return;
    }

    // Snapshot the outgoing editor into the current buffer before we grow.
    if (m_activeDocument >= 0 &&
        m_activeDocument < static_cast<int>(m_documentBuffers.size()) &&
        m_hwndEditor) {
        auto& current = m_documentBuffers[static_cast<size_t>(m_activeDocument)];
        current.path = m_currentFile;
        current.text = getEditorTextUtf8ForFile();
        current.modified = m_fileModified ||
            (SendMessageW(m_hwndEditor, EM_GETMODIFY, 0, 0) != 0);
        CHARRANGE sel{};
        SendMessageW(m_hwndEditor, EM_EXGETSEL, 0, reinterpret_cast<LPARAM>(&sel));
        current.selStart = static_cast<int>(sel.cpMin);
        current.selEnd = static_cast<int>(sel.cpMax);
        current.firstVisibleLine = static_cast<int>(
            SendMessageW(m_hwndEditor, EM_GETFIRSTVISIBLELINE, 0, 0));
        current.hasViewState = true;
        if (m_activeDocument < static_cast<int>(m_openDocuments.size())) {
            m_openDocuments[static_cast<size_t>(m_activeDocument)] = m_currentFile;
        }
    }

    if (m_documentBuffers.size() + 1 > m_documentBuffers.capacity()) {
        const size_t growTo = (std::min)(
            kMaxOpenDocuments,
            m_documentBuffers.capacity() + 32);
        m_documentBuffers.reserve(growTo);
        m_openDocuments.reserve(growTo);
    }

    const std::string label = (path.empty() ? std::string("Untitled")
                                            : extractLeafName(path)) + "  x";
    // Vectors are authoritative. Rebuild the TabCtrl from them so insert
    // index never drifts past TCM_GETITEMCOUNT (T08 stuck-at-1 root cause).
    m_documentBuffers.push_back(DocumentBuffer{path, label, std::string(), false});
    m_openDocuments.push_back(path);
    m_activeDocument = static_cast<int>(m_openDocuments.size()) - 1;
    updateDocumentTabs();
    {
        reclaimDocumentTabControlId();
        const int tc = static_cast<int>(SendMessageW(m_hwndDocTabs, TCM_GETITEMCOUNT, 0, 0));
        const int id = GetDlgCtrlID(m_hwndDocTabs);
        std::ofstream trace(
            "F:\\rawrxd\\evidence\\PROGRESSION_FINISH25_001\\EDITOR\\t08_tab_trace.txt",
            std::ios::app);
        if (trace) {
            trace << "addDocumentTab path=" << path
                  << " vectors=" << m_openDocuments.size()
                  << " tabctrl=" << tc
                  << " id=" << id
                  << " hwnd=" << static_cast<unsigned long long>(
                         reinterpret_cast<uintptr_t>(m_hwndDocTabs))
                  << '\n';
        }
    }
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
    if (index < static_cast<int>(m_documentBuffers.size())) {
        m_documentBuffers.erase(m_documentBuffers.begin() + index);
    }

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

void Win32IDE::closeDocumentTab(int index)
{
    if (index < 0 || index >= static_cast<int>(m_openDocuments.size())) return;
    if (index != m_activeDocument) switchDocumentTab(index);
    if (m_fileModified && !promptSaveChanges()) return;

    removeDocumentTab(index);
    if (m_openDocuments.empty()) return;
    const int next = std::min(index, static_cast<int>(m_openDocuments.size()) - 1);
    m_activeDocument = -1;
    switchDocumentTab(next);
}

void Win32IDE::switchDocumentTab(int index)
{
    if (!m_hwndDocTabs || index < 0 ||
        index >= static_cast<int>(m_openDocuments.size())) {
        return;
    }
    // Same tab: do not re-load (would wipe live unsaved HWND text if the
    // prior capture path was empty ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â T08 FAIL_PRESERVED_1).  Cold launch may
    // have restored m_activeDocument before the editor existed (T10).
    const bool deferMaterialize = m_pendingSessionEditorMaterialize;
    if (index == m_activeDocument && !deferMaterialize) {
        TabCtrl_SetCurSel(m_hwndDocTabs, index);
        return;
    }
    if (index == m_activeDocument) {
        TabCtrl_SetCurSel(m_hwndDocTabs, index);
        m_pendingSessionEditorMaterialize = false;
    }

    const int outgoing = deferMaterialize ? -1 : m_activeDocument;
    DocumentBuffer outgoingSnap{};
    bool haveOutgoingSnap = false;
    if (outgoing >= 0 &&
        outgoing < static_cast<int>(m_documentBuffers.size()) &&
        m_hwndEditor) {
        auto& current = m_documentBuffers[static_cast<size_t>(outgoing)];
        current.path = m_currentFile;
        current.text = getEditorTextUtf8ForFile();
        current.modified = m_fileModified ||
            (SendMessageW(m_hwndEditor, EM_GETMODIFY, 0, 0) != 0);
        CHARRANGE sel{};
        SendMessageW(m_hwndEditor, EM_EXGETSEL, 0, reinterpret_cast<LPARAM>(&sel));
        current.selStart = static_cast<int>(sel.cpMin);
        current.selEnd = static_cast<int>(sel.cpMax);
        current.firstVisibleLine = static_cast<int>(
            SendMessageW(m_hwndEditor, EM_GETFIRSTVISIBLELINE, 0, 0));
        current.hasViewState = true;
        if (outgoing < static_cast<int>(m_openDocuments.size())) {
            m_openDocuments[static_cast<size_t>(outgoing)] = m_currentFile;
        }
        outgoingSnap = current;
        haveOutgoingSnap = true;
    }

    m_activeDocument = index;
    TabCtrl_SetCurSel(m_hwndDocTabs, index);

    const std::string& path = m_openDocuments[static_cast<size_t>(index)];
    bool loaded = false;
    if (index < static_cast<int>(m_documentBuffers.size()) &&
        (!m_documentBuffers[static_cast<size_t>(index)].text.empty() ||
         m_documentBuffers[static_cast<size_t>(index)].modified ||
         m_documentBuffers[static_cast<size_t>(index)].hasViewState ||
         path.empty())) {
        const auto& buffer = m_documentBuffers[static_cast<size_t>(index)];
        const bool wasSuppressed = m_suppressEditorDirty;
        m_suppressEditorDirty = true;
        setEditorText(buffer.text);
        m_suppressEditorDirty = wasSuppressed;
        m_currentFile = path;
        m_fileModified = buffer.modified;
        if (m_hwndEditor) {
            SendMessageW(m_hwndEditor, EM_SETMODIFY, buffer.modified ? TRUE : FALSE, 0);
            if (buffer.hasViewState) {
                CHARRANGE sel{buffer.selStart, buffer.selEnd};
                SendMessageW(m_hwndEditor, EM_EXSETSEL, 0, reinterpret_cast<LPARAM>(&sel));
                const int cur = static_cast<int>(
                    SendMessageW(m_hwndEditor, EM_GETFIRSTVISIBLELINE, 0, 0));
                SendMessageW(m_hwndEditor, EM_LINESCROLL, 0,
                             buffer.firstVisibleLine - cur);
            }
        }
        updateTitleBarText();
        loaded = true;
    } else if (!path.empty()) {
        loaded = loadFileIntoEditor(path);
    } else {
        m_currentFile.clear();
        newFile();
        loaded = true;
    }

    // Fail-closed rollback: restore outgoing tab if incoming load failed.
    // Dead tabs with unopenable paths (e.g. leaf-only "t8 01 doc") used to
    // remain selected in the vector but never activate ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â demote them so the
    // UI cannot stick on a non-file name.
    if (!loaded) {
        const int badIndex = index;
        const std::string badPath = path;
        if (haveOutgoingSnap && outgoing >= 0) {
            m_activeDocument = outgoing;
            TabCtrl_SetCurSel(m_hwndDocTabs, outgoing);
            const bool wasSuppressed = m_suppressEditorDirty;
            m_suppressEditorDirty = true;
            setEditorText(outgoingSnap.text);
            m_suppressEditorDirty = wasSuppressed;
            m_currentFile = outgoingSnap.path;
            m_fileModified = outgoingSnap.modified;
            if (m_hwndEditor) {
                SendMessageW(m_hwndEditor, EM_SETMODIFY,
                             outgoingSnap.modified ? TRUE : FALSE, 0);
            }
            updateTitleBarText();
        }
        if (!badPath.empty() &&
            badIndex >= 0 &&
            badIndex < static_cast<int>(m_openDocuments.size()) &&
            m_openDocuments[static_cast<size_t>(badIndex)] == badPath) {
            const std::string leaf = extractLeafName(badPath);
            char msg[512];
            wsprintfA(msg,
                "\"%s\" is not an openable file path.\n"
                "The stuck tab was converted to Untitled so the IDE can continue.",
                leaf.c_str());
            if (badIndex < static_cast<int>(m_documentBuffers.size())) {
                auto& buffer = m_documentBuffers[static_cast<size_t>(badIndex)];
                buffer.path.clear();
                buffer.label = "Untitled  x";
                buffer.modified = false;
                buffer.hasViewState = false;
            }
            m_openDocuments[static_cast<size_t>(badIndex)].clear();
            updateDocumentTabs();
            MessageBoxA(m_hwndMain, msg, "Invalid Document Tab",
                        MB_OK | MB_ICONWARNING);
        }
    }

    updateMenuEnableStates();
    if (m_hwndEditor && IsWindowVisible(m_hwndEditor)) {
        SetFocus(m_hwndEditor);
    }
}

void Win32IDE::updateDocumentTabs()
{
    if (!m_hwndDocTabs) return;
    const bool wasUpdating = m_updatingDocumentTabs;
    m_updatingDocumentTabs = true;
    reclaimDocumentTabControlId();
    SendMessageW(m_hwndDocTabs, TCM_DELETEALLITEMS, 0, 0);
    for (size_t i = 0; i < m_openDocuments.size(); ++i) {
        if (i >= m_documentBuffers.size()) break;
        auto& buffer = m_documentBuffers[i];
        buffer.label = (m_openDocuments[i].empty()
            ? std::string("Untitled") : extractLeafName(m_openDocuments[i])) + "  x";
        // Wide insert into WC_TABCONTROLW. Append at live count so index never
        // advances past TCM_GETITEMCOUNT (historical T08 stuck-at-1).
        wchar_t wideLabel[256];
        const int wideLen = MultiByteToWideChar(
            CP_UTF8, 0, buffer.label.c_str(), -1, wideLabel, 256);
        if (wideLen <= 0) {
            MultiByteToWideChar(CP_ACP, 0, buffer.label.c_str(), -1, wideLabel, 256);
        }
        TCITEMW tie{};
        tie.mask = TCIF_TEXT;
        tie.pszText = wideLabel;
        const int at = static_cast<int>(SendMessageW(m_hwndDocTabs, TCM_GETITEMCOUNT, 0, 0));
        SendMessageW(m_hwndDocTabs, TCM_INSERTITEMW, static_cast<WPARAM>(at),
                     reinterpret_cast<LPARAM>(&tie));
    }
    if (m_activeDocument >= 0 &&
        m_activeDocument < static_cast<int>(m_openDocuments.size())) {
        SendMessageW(m_hwndDocTabs, TCM_SETCURSEL,
                     static_cast<WPARAM>(m_activeDocument), 0);
    }
    reclaimDocumentTabControlId();
    m_updatingDocumentTabs = wasUpdating;
}
