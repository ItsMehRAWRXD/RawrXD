// ============================================================================
// RawrXD IDE - DEBUGGER IMPLEMENTATION
// ============================================================================
// Full debugger with breakpoints, variables, call stack, and watch expressions

#include "Win32IDE.h"
#include "Win32NativeDebugBackend.h"
#include <sstream>
#include <algorithm>
#include <vector>
#include <cstdlib>

// Heap-allocated strings retained by ListView controls (LVIF_TEXT does not
// copy text; it retains the pointer).  Cleared at the start of each update
// cycle after ListView_DeleteAllItems removes the items that referenced them.
static std::vector<char*> g_debuggerStringHeap;
static std::vector<char*> g_varStringHeap;
static std::vector<char*> g_watchStringHeap;
static std::vector<char*> g_stackStringHeap;

// Debugger Control IDs
#define IDC_DEBUGGER_CONTAINER 2100
#define IDC_DEBUGGER_TOOLBAR 2101
#define IDC_DEBUGGER_TABS 2102
#define IDC_DEBUGGER_BTN_CONTINUE 2103
#define IDC_DEBUGGER_BTN_STEP_OVER 2104
#define IDC_DEBUGGER_BTN_STEP_INTO 2105
#define IDC_DEBUGGER_BTN_STEP_OUT 2106
#define IDC_DEBUGGER_BTN_STOP 2107
#define IDC_DEBUGGER_BTN_RESTART 2108
#define IDC_DEBUGGER_STATUS_TEXT 2109
#define IDC_DEBUGGER_BREAKPOINT_LIST 2110
#define IDC_DEBUGGER_WATCH_LIST 2111
// H02: unify with IDC_DEBUGGER_VARIABLES (1317). Was 2112 TreeView — harness
// SESSION_REAL uses LVM_GETITEMCOUNT on 1317 / sidebar 6043.
#define IDC_DEBUGGER_VARIABLE_TREE 1317
#define IDC_DEBUGGER_STACK_LIST 2113
#define IDC_DEBUGGER_MEMORY 2114
#define IDC_DEBUGGER_INPUT 2115

// ============================================================================
// DEBUGGER UI CREATION
// ============================================================================

void Win32IDE::createDebuggerUI()
{
    if (!m_hwndMain) return;

    // Create main debugger container (at bottom, alongside terminal)
    m_hwndDebuggerContainer = CreateWindowExA(
        WS_EX_CLIENTEDGE,
        "STATIC",
        "Debugger",
        WS_CHILD | WS_VISIBLE,
        0, 0, 400, 200,
        m_hwndMain,
        (HMENU)IDC_DEBUGGER_CONTAINER,
        m_hInstance,
        nullptr
    );

    if (!m_hwndDebuggerContainer) return;

    // Create toolbar with control buttons
    m_hwndDebuggerToolbar = CreateWindowExA(
        0,
        "STATIC",
        "",
        WS_CHILD | WS_VISIBLE,
        0, 0, 400, 30,
        m_hwndDebuggerContainer,
        (HMENU)IDC_DEBUGGER_TOOLBAR,
        m_hInstance,
        nullptr
    );

    // Create toolbar buttons
    HWND btnContinue = CreateWindowExA(
        0, "BUTTON", " Continue",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        5, 5, 80, 22,
        m_hwndDebuggerToolbar,
        (HMENU)IDC_DEBUGGER_BTN_CONTINUE,
        m_hInstance,
        nullptr
    );

    HWND btnStepOver = CreateWindowExA(
        0, "BUTTON", " Step Over",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        90, 5, 80, 22,
        m_hwndDebuggerToolbar,
        (HMENU)IDC_DEBUGGER_BTN_STEP_OVER,
        m_hInstance,
        nullptr
    );

    HWND btnStepInto = CreateWindowExA(
        0, "BUTTON", " Step Into",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        175, 5, 80, 22,
        m_hwndDebuggerToolbar,
        (HMENU)IDC_DEBUGGER_BTN_STEP_INTO,
        m_hInstance,
        nullptr
    );

    HWND btnStepOut = CreateWindowExA(
        0, "BUTTON", " Step Out",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        260, 5, 75, 22,
        m_hwndDebuggerToolbar,
        (HMENU)IDC_DEBUGGER_BTN_STEP_OUT,
        m_hInstance,
        nullptr
    );

    HWND btnStop = CreateWindowExA(
        0, "BUTTON", " Stop",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        340, 5, 55, 22,
        m_hwndDebuggerToolbar,
        (HMENU)IDC_DEBUGGER_BTN_STOP,
        m_hInstance,
        nullptr
    );

    // Create status text
    m_hwndDebuggerStatus = CreateWindowExA(
        0,
        "STATIC",
        "Debugger: Not Attached",
        WS_CHILD | WS_VISIBLE,
        5, 35, 390, 20,
        m_hwndDebuggerContainer,
        (HMENU)IDC_DEBUGGER_STATUS_TEXT,
        m_hInstance,
        nullptr
    );

    // Create tab control for different debugger views
    m_hwndDebuggerTabs = CreateWindowExA(
        0,
        WC_TABCONTROLA,
        "",
        WS_CHILD | WS_VISIBLE | TCS_TABS | TCS_FIXEDWIDTH,
        5, 60, 390, 135,
        m_hwndDebuggerContainer,
        (HMENU)IDC_DEBUGGER_TABS,
        m_hInstance,
        nullptr
    );

    // Add tabs
    TCITEMA tie;
    tie.mask = TCIF_TEXT;
    
    tie.pszText = const_cast<char*>("Breakpoints");
    TabCtrl_InsertItem(m_hwndDebuggerTabs, 0, &tie);
    
    tie.pszText = const_cast<char*>("Watch");
    TabCtrl_InsertItem(m_hwndDebuggerTabs, 1, &tie);
    
    tie.pszText = const_cast<char*>("Variables");
    TabCtrl_InsertItem(m_hwndDebuggerTabs, 2, &tie);
    
    tie.pszText = const_cast<char*>("Stack Trace");
    TabCtrl_InsertItem(m_hwndDebuggerTabs, 3, &tie);
    
    tie.pszText = const_cast<char*>("Memory");
    TabCtrl_InsertItem(m_hwndDebuggerTabs, 4, &tie);

    // Create tab content windows
    m_hwndDebuggerBreakpoints = CreateWindowExA(
        WS_EX_CLIENTEDGE,
        WC_LISTVIEWA,
        "",
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL,
        10, 85, 380, 100,
        m_hwndDebuggerContainer,
        (HMENU)IDC_DEBUGGER_BREAKPOINT_LIST,
        m_hInstance,
        nullptr
    );

    m_hwndDebuggerWatch = CreateWindowExA(
        WS_EX_CLIENTEDGE,
        WC_LISTVIEWA,
        "",
        WS_CHILD | LVS_REPORT | LVS_SINGLESEL,
        10, 85, 380, 100,
        m_hwndDebuggerContainer,
        (HMENU)IDC_DEBUGGER_WATCH_LIST,
        m_hInstance,
        nullptr
    );

    m_hwndDebuggerVariables = CreateWindowExA(
        WS_EX_CLIENTEDGE,
        WC_LISTVIEWA,
        "",
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL,
        10, 85, 380, 100,
        m_hwndDebuggerContainer,
        (HMENU)IDC_DEBUGGER_VARIABLE_TREE,
        m_hInstance,
        nullptr
    );
    if (m_hwndDebuggerVariables) {
        ListView_SetExtendedListViewStyle(m_hwndDebuggerVariables,
                                          LVS_EX_FULLROWSELECT);
        LVCOLUMNA col{};
        col.mask = LVCF_TEXT | LVCF_WIDTH;
        col.pszText = const_cast<char*>("Name");
        col.cx = 140;
        ListView_InsertColumn(m_hwndDebuggerVariables, 0, &col);
        col.pszText = const_cast<char*>("Value");
        col.cx = 220;
        ListView_InsertColumn(m_hwndDebuggerVariables, 1, &col);
    }

    m_hwndDebuggerStackTrace = CreateWindowExA(
        WS_EX_CLIENTEDGE,
        WC_LISTVIEWA,
        "",
        WS_CHILD | LVS_REPORT | LVS_SINGLESEL,
        10, 85, 380, 100,
        m_hwndDebuggerContainer,
        (HMENU)IDC_DEBUGGER_STACK_LIST,
        m_hInstance,
        nullptr
    );

    m_hwndDebuggerMemory = CreateWindowExA(
        WS_EX_CLIENTEDGE,
        WC_EDITA,
        "",
        WS_CHILD | ES_MULTILINE | ES_READONLY | WS_VSCROLL,
        10, 85, 380, 100,
        m_hwndDebuggerContainer,
        (HMENU)IDC_DEBUGGER_MEMORY,
        m_hInstance,
        nullptr
    );

    // Setup list view columns
    LVCOLUMNA lvc;
    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;

    // Breakpoints columns
    lvc.iSubItem = 0;
    lvc.pszText = const_cast<char*>("File");
    lvc.cx = 150;
    lvc.fmt = LVCFMT_LEFT;
    ListView_InsertColumn(m_hwndDebuggerBreakpoints, 0, &lvc);

    lvc.iSubItem = 1;
    lvc.pszText = const_cast<char*>("Line");
    lvc.cx = 60;
    ListView_InsertColumn(m_hwndDebuggerBreakpoints, 1, &lvc);

    lvc.iSubItem = 2;
    lvc.pszText = const_cast<char*>("Hits");
    lvc.cx = 50;
    ListView_InsertColumn(m_hwndDebuggerBreakpoints, 2, &lvc);

    // Watch columns
    lvc.iSubItem = 0;
    lvc.pszText = const_cast<char*>("Expression");
    lvc.cx = 150;
    ListView_InsertColumn(m_hwndDebuggerWatch, 0, &lvc);

    lvc.iSubItem = 1;
    lvc.pszText = const_cast<char*>("Value");
    lvc.cx = 150;
    ListView_InsertColumn(m_hwndDebuggerWatch, 1, &lvc);

    lvc.iSubItem = 2;
    lvc.pszText = const_cast<char*>("Type");
    lvc.cx = 80;
    ListView_InsertColumn(m_hwndDebuggerWatch, 2, &lvc);

    // Stack trace columns
    lvc.iSubItem = 0;
    lvc.pszText = const_cast<char*>("Function");
    lvc.cx = 150;
    ListView_InsertColumn(m_hwndDebuggerStackTrace, 0, &lvc);

    lvc.iSubItem = 1;
    lvc.pszText = const_cast<char*>("File");
    lvc.cx = 150;
    ListView_InsertColumn(m_hwndDebuggerStackTrace, 1, &lvc);

    lvc.iSubItem = 2;
    lvc.pszText = const_cast<char*>("Line");
    lvc.cx = 60;
    ListView_InsertColumn(m_hwndDebuggerStackTrace, 2, &lvc);

    m_debuggerEnabled = true;
    updateDebuggerUI();
}

// ============================================================================
// DEBUGGER STATE MANAGEMENT
// ============================================================================

void Win32IDE::ensureNativeDebugBackend()
{
    if (m_nativeDebug) {
        return;
    }
    m_nativeDebug = std::make_unique<rawrxd::Win32NativeDebugBackend>();
    m_nativeDebug->setOutputCallback([this](const std::string& text) {
        if (m_hwndMain) {
            char* heap = _strdup(text.c_str());
            PostMessageA(m_hwndMain, kRawrxdNativeDebugState, 1, reinterpret_cast<LPARAM>(heap));
        }
    });
    m_nativeDebug->setStateCallback([this](const rawrxd::NativeDebugSnapshot& snap) {
        if (!m_hwndMain) {
            return;
        }
        auto* heap = new rawrxd::NativeDebugSnapshot(snap);
        PostMessageA(m_hwndMain, kRawrxdNativeDebugState, 0, reinterpret_cast<LPARAM>(heap));
    });
}

bool Win32IDE::launchNativeDebuggee()
{
    ensureNativeDebugBackend();
    char envPath[MAX_PATH] = {};
    const DWORD envLen = GetEnvironmentVariableA("RAWRXD_DEBUGGEE", envPath, MAX_PATH);
    std::string path;
    if (envLen > 0 && envLen < MAX_PATH) {
        path = envPath;
    } else if (!m_nativeDebuggeePath.empty()) {
        path = m_nativeDebuggeePath;
    } else {
        char mod[MAX_PATH] = {};
        GetModuleFileNameA(nullptr, mod, MAX_PATH);
        std::string dir(mod);
        const size_t slash = dir.find_last_of("\\/");
        if (slash != std::string::npos) {
            dir = dir.substr(0, slash + 1);
        }
        path = dir + "debuggee_fixture.exe";
    }
    m_nativeDebuggeePath = path;
    m_nativeDebug->addBreakpointExport("break_site");
    if (!m_nativeDebug->launch(path)) {
        appendToOutput(std::string("Native debug launch failed: ") + path + "\n",
                       "Errors", OutputSeverity::Error);
        return false;
    }
    m_debuggerAttached = true;
    m_debuggingActive = true;
    m_debuggerPaused = false;
    if (m_hwndDebuggerStatus) {
        SetWindowTextA(m_hwndDebuggerStatus, "Native debugger: Running (WaitForDebugEvent)");
    }
    appendToOutput(std::string("Native debug launched: ") + path + "\n",
                   "Debug", OutputSeverity::Info);
    // START often arrives via SendMessage(WM_COMMAND). BP snapshots are
    // PostMessage'd from the WaitForDebugEvent thread and would otherwise sit
    // queued until the outer pump runs — leaving SESSION_REAL=0 / vars empty
    // while the debuggee is already paused. Drain + poll here on the UI thread.
    {
        const DWORD deadline = GetTickCount() + 2500;
        while (GetTickCount() < deadline) {
            MSG msg{};
            while (m_hwndMain &&
                   PeekMessageA(&msg, m_hwndMain, kRawrxdNativeDebugState,
                                kRawrxdNativeDebugState, PM_REMOVE)) {
                DispatchMessageA(&msg);
            }
            if (!m_nativeDebug) {
                break;
            }
            const rawrxd::NativeDebugSnapshot snap = m_nativeDebug->snapshot();
            if (snap.state == rawrxd::NativeDebugState::Paused ||
                snap.state == rawrxd::NativeDebugState::Stepping ||
                !snap.variables.empty()) {
                applyNativeDebugSnapshot(snap);
                if (m_debuggerPaused || !m_localVariables.empty()) {
                    break;
                }
            }
            if (snap.state == rawrxd::NativeDebugState::Terminated ||
                snap.state == rawrxd::NativeDebugState::Error) {
                applyNativeDebugSnapshot(snap);
                break;
            }
            Sleep(15);
        }
    }
    return true;
}

void Win32IDE::applyNativeDebugSnapshot(const rawrxd::NativeDebugSnapshot& snap)
{
    // Sidebar vars (IDC 6043) are the SESSION_REAL witness — update before panel UI.
    m_debuggerPaused = (snap.state == rawrxd::NativeDebugState::Paused ||
                        snap.state == rawrxd::NativeDebugState::Stepping);
    m_debuggerAttached = (snap.state != rawrxd::NativeDebugState::Idle &&
                          snap.state != rawrxd::NativeDebugState::Terminated &&
                          snap.state != rawrxd::NativeDebugState::Error);
    m_debuggingActive = m_debuggerAttached || snap.state == rawrxd::NativeDebugState::Terminated;

    m_callStack.clear();
    for (const auto& f : snap.stack) {
        StackFrame frame;
        frame.function = f.symbol.empty() ? f.module : f.symbol;
        frame.file = f.module;
        frame.line = 0;
        frame.locals = snap.variables;
        m_callStack.push_back(frame);
    }
    m_localVariables.clear();
    for (const auto& kv : snap.variables) {
        Variable var;
        var.name = kv.first;
        var.value = kv.second;
        var.type = "native";
        var.expanded = false;
        m_localVariables.push_back(var);
    }
    for (auto& w : m_watchList) {
        auto it = snap.variables.find(w.expression);
        if (it != snap.variables.end()) {
            w.value = it->second;
            w.type = "native";
        } else if (m_nativeDebug) {
            std::string ev;
            if (m_nativeDebug->evaluateExpression(w.expression, ev)) {
                w.value = ev;
                w.type = "native";
            }
        }
    }
    if (snap.stopReason.rfind("breakpoint:", 0) == 0) {
        m_debuggerCurrentFile = "debuggee_fixture.c";
        m_debuggerCurrentLine = 1;
        for (auto& bp : m_breakpoints) {
            if (bp.enabled) {
                bp.hitCount++;
            }
        }
    }
    if (m_hwndDebuggerStatus) {
        std::ostringstream oss;
        oss << "Native debug: " << snap.stopReason << " rip=0x" << std::hex << snap.rip;
        if (snap.state == rawrxd::NativeDebugState::Terminated) {
            oss << " exit=" << std::dec << snap.exitCode;
        }
        SetWindowTextA(m_hwndDebuggerStatus, oss.str().c_str());
    }
    updateDebugVariables();
    updateDebuggerUI();
}

LRESULT Win32IDE::handleNativeDebugState(WPARAM wParam, LPARAM lParam)
{
    if (wParam == 1) {
        char* text = reinterpret_cast<char*>(lParam);
        if (text) {
            appendToOutput(std::string(text) + "\n", "Debug", OutputSeverity::Debug);
            free(text);
        }
        return 0;
    }
    auto* snap = reinterpret_cast<rawrxd::NativeDebugSnapshot*>(lParam);
    if (!snap) {
        return 0;
    }
    applyNativeDebugSnapshot(*snap);
    if (snap->stopReason.rfind("breakpoint:", 0) == 0) {
        appendToOutput("Breakpoint hit (native WaitForDebugEvent)\n", "Debug",
                       OutputSeverity::Warning);
    } else if (snap->state == rawrxd::NativeDebugState::Terminated) {
        appendToOutput(std::string("Debuggee exited code=") +
                           std::to_string(snap->exitCode) + "\n",
                       "Debug", OutputSeverity::Info);
        m_debuggerAttached = false;
        m_debuggingActive = false;
    }
    delete snap;
    return 0;
}

void Win32IDE::attachDebugger()
{
    if (m_debuggerAttached) {
        return;
    }
    launchNativeDebuggee();
}

void Win32IDE::detachDebugger()
{
    if (m_nativeDebug) {
        m_nativeDebug->stop(true);
    }
    m_debuggerAttached = false;
    m_debuggerPaused = false;
    m_debuggingActive = false;
    m_callStack.clear();
    m_localVariables.clear();
    if (m_hwndDebuggerStatus) {
        SetWindowTextA(m_hwndDebuggerStatus, "Debugger Detached");
    }
    appendToOutput("Native debugger detached\n", "Debug", OutputSeverity::Info);
    updateDebuggerUI();
}

void Win32IDE::pauseExecution()
{
    ensureNativeDebugBackend();
    if (!m_nativeDebug || !m_debuggerAttached || m_debuggerPaused) {
        return;
    }
    m_nativeDebug->pauseExecution();
}

void Win32IDE::resumeExecution()
{
    ensureNativeDebugBackend();
    if (!m_nativeDebug || !m_debuggerAttached) {
        return;
    }
    if (m_nativeDebug->continueExecution()) {
        m_debuggerPaused = false;
        if (m_hwndDebuggerStatus) {
            SetWindowTextA(m_hwndDebuggerStatus, "Native debugger: Running");
        }
        appendToOutput("Continue (native)\n", "Debug", OutputSeverity::Info);
    }
}

void Win32IDE::stepOverExecution()
{
    ensureNativeDebugBackend();
    if (!m_nativeDebug || !m_debuggerAttached) {
        return;
    }
    m_nativeDebug->stepOver();
}

void Win32IDE::stepIntoExecution()
{
    ensureNativeDebugBackend();
    if (!m_nativeDebug || !m_debuggerAttached) {
        return;
    }
    m_nativeDebug->stepInto();
}

void Win32IDE::stepOutExecution()
{
    ensureNativeDebugBackend();
    if (!m_nativeDebug || !m_debuggerAttached) {
        return;
    }
    m_nativeDebug->stepOut();
}

void Win32IDE::stopDebugger()
{
    detachDebugger();
    if (m_hwndDebuggerStatus) {
        SetWindowTextA(m_hwndDebuggerStatus, "Debugger Stopped");
    }
}

void Win32IDE::restartDebugger()
{
    ensureNativeDebugBackend();
    if (m_nativeDebug && m_nativeDebug->restart()) {
        m_debuggerAttached = true;
        m_debuggingActive = true;
        m_nativeDebug->addBreakpointExport("break_site");
        if (m_hwndDebuggerStatus) {
            SetWindowTextA(m_hwndDebuggerStatus, "Native debugger: Restarted");
        }
        return;
    }
    stopDebugger();
    launchNativeDebuggee();
}

// ============================================================================
// BREAKPOINT MANAGEMENT
// ============================================================================

void Win32IDE::addBreakpoint(const std::string& file, int line)
{
    // Check if breakpoint already exists
    for (auto& bp : m_breakpoints) {
        if (bp.file == file && bp.line == line) {
            bp.enabled = true;
            updateBreakpointList();
            return;
        }
    }

    // Add new breakpoint
    Breakpoint bp;
    bp.file = file;
    bp.line = line;
    bp.enabled = true;
    bp.condition = "";
    bp.hitCount = 0;

    m_breakpoints.push_back(bp);
    updateBreakpointList();

    std::string msg = " Breakpoint added at " + file + ":" + std::to_string(line);
    appendToOutput(msg, "Output", OutputSeverity::Debug);
}

void Win32IDE::removeBreakpoint(const std::string& file, int line)
{
    auto it = std::find_if(m_breakpoints.begin(), m_breakpoints.end(),
        [&](const Breakpoint& bp) { return bp.file == file && bp.line == line; });

    if (it != m_breakpoints.end()) {
        m_breakpoints.erase(it);
        updateBreakpointList();
        
        std::string msg = " Breakpoint removed from " + file + ":" + std::to_string(line);
        appendToOutput(msg, "Output", OutputSeverity::Debug);
    }
}

void Win32IDE::toggleBreakpoint(const std::string& file, int line)
{
    auto it = std::find_if(m_breakpoints.begin(), m_breakpoints.end(),
        [&](const Breakpoint& bp) { return bp.file == file && bp.line == line; });

    if (it != m_breakpoints.end()) {
        it->enabled = !it->enabled;
        updateBreakpointList();
    } else {
        addBreakpoint(file, line);
    }
}

void Win32IDE::clearAllBreakpoints()
{
    m_breakpoints.clear();
    updateBreakpointList();
    appendToOutput(" All breakpoints cleared", "Output", OutputSeverity::Info);
}

void Win32IDE::updateBreakpointList()
{
    if (!m_hwndDebuggerBreakpoints) return;

    // Free heap-allocated lParam strings from previous cycle.
    LVITEMA lvi = { 0 };
    lvi.mask = LVIF_PARAM;
    int count = ListView_GetItemCount(m_hwndDebuggerBreakpoints);
    for (int i = count - 1; i >= 0; --i) {
        lvi.iItem = i;
        if (ListView_GetItem(m_hwndDebuggerBreakpoints, &lvi)) {
            delete[] reinterpret_cast<char*>(lvi.lParam);
        }
    }
    g_debuggerStringHeap.clear();

    ListView_DeleteAllItems(m_hwndDebuggerBreakpoints);

    LVITEMA item{};
    item.mask = LVIF_TEXT | LVIF_PARAM;

    for (size_t i = 0; i < m_breakpoints.size(); ++i) {
        const auto& bp = m_breakpoints[i];

        item.iItem = static_cast<int>(i);
        item.iSubItem = 0;
        item.pszText = const_cast<char*>(bp.file.c_str());
        item.lParam = reinterpret_cast<LPARAM>(new char[bp.file.length() + 1]);
        strcpy_s(reinterpret_cast<char*>(item.lParam), bp.file.length() + 1, bp.file.c_str());
        ListView_InsertItem(m_hwndDebuggerBreakpoints, &item);

        item.iSubItem = 1;
        char lineBuf[32];
        _snprintf_s(lineBuf, sizeof(lineBuf), "%d", bp.line);
        char* lineHeap = new char[strlen(lineBuf) + 1];
        strcpy_s(lineHeap, strlen(lineBuf) + 1, lineBuf);
        g_debuggerStringHeap.push_back(lineHeap);
        item.pszText = lineHeap;
        item.lParam = reinterpret_cast<LPARAM>(lineHeap);
        ListView_SetItem(m_hwndDebuggerBreakpoints, &item);

        item.iSubItem = 2;
        char hitsBuf[32];
        _snprintf_s(hitsBuf, sizeof(hitsBuf), "%d", bp.hitCount);
        char* hitsHeap = new char[strlen(hitsBuf) + 1];
        strcpy_s(hitsHeap, strlen(hitsBuf) + 1, hitsBuf);
        g_debuggerStringHeap.push_back(hitsHeap);
        item.pszText = hitsHeap;
        item.lParam = reinterpret_cast<LPARAM>(hitsHeap);
        ListView_SetItem(m_hwndDebuggerBreakpoints, &item);
    }
}

// ============================================================================
// WATCH EXPRESSION MANAGEMENT
// ============================================================================

void Win32IDE::addWatchExpression(const std::string& expression)
{
    WatchItem item;
    item.expression = expression;
    item.value = "...";
    item.type = "unknown";
    item.enabled = true;

    m_watchList.push_back(item);
    updateWatchList();

    std::string msg = " Watch added: " + expression;
    appendToOutput(msg, "Output", OutputSeverity::Debug);
}

void Win32IDE::removeWatchExpression(const std::string& expression)
{
    auto it = std::find_if(m_watchList.begin(), m_watchList.end(),
        [&](const WatchItem& item) { return item.expression == expression; });

    if (it != m_watchList.end()) {
        m_watchList.erase(it);
        updateWatchList();
        
        std::string msg = " Watch removed: " + expression;
        appendToOutput(msg, "Output", OutputSeverity::Debug);
    }
}

void Win32IDE::updateWatchList()
{
    if (!m_hwndDebuggerWatch) return;

    // Free heap-allocated strings from previous cycle.
    g_watchStringHeap.clear();

    ListView_DeleteAllItems(m_hwndDebuggerWatch);

    LVITEMA lvi;
    lvi.mask = LVIF_TEXT | LVIF_PARAM;

    for (size_t i = 0; i < m_watchList.size(); ++i) {
        auto& item = m_watchList[i];

        lvi.iItem = static_cast<int>(i);
        lvi.iSubItem = 0;
        char* exprHeap = new char[item.expression.length() + 1];
        strcpy_s(exprHeap, item.expression.length() + 1, item.expression.c_str());
        lvi.pszText = exprHeap;
        lvi.lParam = reinterpret_cast<LPARAM>(exprHeap);
        g_watchStringHeap.push_back(exprHeap);
        ListView_InsertItem(m_hwndDebuggerWatch, &lvi);

        lvi.iSubItem = 1;
        char* valHeap = new char[item.value.length() + 1];
        strcpy_s(valHeap, item.value.length() + 1, item.value.c_str());
        lvi.pszText = valHeap;
        lvi.lParam = reinterpret_cast<LPARAM>(valHeap);
        g_watchStringHeap.push_back(valHeap);
        ListView_SetItem(m_hwndDebuggerWatch, &lvi);

        lvi.iSubItem = 2;
        char* typeHeap = new char[item.type.length() + 1];
        strcpy_s(typeHeap, item.type.length() + 1, item.type.c_str());
        lvi.pszText = typeHeap;
        lvi.lParam = reinterpret_cast<LPARAM>(typeHeap);
        g_watchStringHeap.push_back(typeHeap);
        ListView_SetItem(m_hwndDebuggerWatch, &lvi);
    }
}

void Win32IDE::evaluateWatch(WatchItem& item)
{
    ensureNativeDebugBackend();
    if (m_nativeDebug && m_nativeDebug->isActive()) {
        std::string value;
        if (m_nativeDebug->evaluateExpression(item.expression, value)) {
            item.value = value;
            item.type = "native";
            return;
        }
    }
    item.value = "<unavailable>";
    item.type = "native";
}

// ============================================================================
// VARIABLE & STACK INSPECTION
// ============================================================================

void Win32IDE::updateVariables()
{
    // Prefer live locals already filled from native snapshot; else stack frame.
    if (m_localVariables.empty() && !m_callStack.empty()) {
        const auto& frame = m_callStack.back();
        for (const auto& local : frame.locals) {
            Variable var;
            var.name = local.first;
            var.value = local.second;
            var.type = "auto";
            var.expanded = false;
            m_localVariables.push_back(var);
        }
    }

    // H02: id 1317 is ListView (LVM_GETITEMCOUNT). Also mirror sidebar 6043.
    if (m_hwndDebuggerVariables) {
        ListView_DeleteAllItems(m_hwndDebuggerVariables);
        for (char* p : g_varStringHeap) delete[] p;
        g_varStringHeap.clear();
        LVITEMA lvi{};
        lvi.mask = LVIF_TEXT;
        for (size_t i = 0; i < m_localVariables.size(); ++i) {
            const auto& var = m_localVariables[i];
            char* nameHeap = new char[var.name.length() + 1];
            memcpy(nameHeap, var.name.c_str(), var.name.length() + 1);
            g_varStringHeap.push_back(nameHeap);
            char* valHeap = new char[var.value.length() + 1];
            memcpy(valHeap, var.value.c_str(), var.value.length() + 1);
            g_varStringHeap.push_back(valHeap);
            lvi.iItem = static_cast<int>(i);
            lvi.iSubItem = 0;
            lvi.pszText = nameHeap;
            ListView_InsertItem(m_hwndDebuggerVariables, &lvi);
            lvi.iSubItem = 1;
            lvi.pszText = valHeap;
            ListView_SetItem(m_hwndDebuggerVariables, &lvi);
        }
    }
    updateDebugVariables();
}

void Win32IDE::updateCallStack()
{
    if (!m_hwndDebuggerStackTrace) return;

    // Free heap-allocated strings from previous cycle.
    g_stackStringHeap.clear();

    ListView_DeleteAllItems(m_hwndDebuggerStackTrace);

    LVITEMA lvi;
    lvi.mask = LVIF_TEXT | LVIF_PARAM;

    for (size_t i = 0; i < m_callStack.size(); ++i) {
        const auto& frame = m_callStack[i];

        lvi.iItem = static_cast<int>(i);
        lvi.iSubItem = 0;
        char* funcHeap = new char[frame.function.length() + 1];
        strcpy_s(funcHeap, frame.function.length() + 1, frame.function.c_str());
        lvi.pszText = funcHeap;
        lvi.lParam = reinterpret_cast<LPARAM>(funcHeap);
        g_stackStringHeap.push_back(funcHeap);
        ListView_InsertItem(m_hwndDebuggerStackTrace, &lvi);

        lvi.iSubItem = 1;
        char* fileHeap = new char[frame.file.length() + 1];
        strcpy_s(fileHeap, frame.file.length() + 1, frame.file.c_str());
        lvi.pszText = fileHeap;
        lvi.lParam = reinterpret_cast<LPARAM>(fileHeap);
        g_stackStringHeap.push_back(fileHeap);
        ListView_SetItem(m_hwndDebuggerStackTrace, &lvi);

        lvi.iSubItem = 2;
        char lineBuf[32];
        _snprintf_s(lineBuf, sizeof(lineBuf), "%d", frame.line);
        char* lineHeap = new char[strlen(lineBuf) + 1];
        strcpy_s(lineHeap, strlen(lineBuf) + 1, lineBuf);
        lvi.pszText = lineHeap;
        lvi.lParam = reinterpret_cast<LPARAM>(lineHeap);
        g_stackStringHeap.push_back(lineHeap);
        ListView_SetItem(m_hwndDebuggerStackTrace, &lvi);
    }
}

void Win32IDE::updateMemoryView()
{
    if (!m_hwndDebuggerMemory) return;

    std::ostringstream oss;
    oss << "Memory Inspector\n";
    oss << "================\n\n";
    oss << "Max Memory: " << (m_debuggerMaxMemory / 1024 / 1024) << " MB\n";
    oss << "Watch Size: " << m_watchList.size() << " expressions\n";
    oss << "Breakpoints: " << m_breakpoints.size() << "\n";
    oss << "Stack Depth: " << m_callStack.size() << " frames\n";

    SetWindowTextA(m_hwndDebuggerMemory, oss.str().c_str());
}

void Win32IDE::updateDebuggerUI()
{
    updateBreakpointList();
    updateWatchList();
    updateVariables();
    updateCallStack();
    updateMemoryView();
}

// ============================================================================
// DEBUGGER CALLBACKS
// ============================================================================

void Win32IDE::onDebuggerBreakpoint(const std::string& file, int line)
{
    pauseExecution();
    m_debuggerCurrentFile = file;
    m_debuggerCurrentLine = line;

    std::string msg = " Breakpoint hit at " + file + ":" + std::to_string(line);
    appendToOutput(msg, "Output", OutputSeverity::Warning);
    
    highlightDebuggerLine(file, line);
}

void Win32IDE::onDebuggerException(const std::string& message)
{
    pauseExecution();
    std::string msg = " Exception: " + message;
    appendToOutput(msg, "Output", OutputSeverity::Error);
}

void Win32IDE::onDebuggerOutput(const std::string& text)
{
    appendToOutput(" " + text, "Output", OutputSeverity::Debug);
}

void Win32IDE::onDebuggerContinued()
{
    resumeExecution();
    clearDebuggerHighlight();
}

void Win32IDE::onDebuggerTerminated()
{
    stopDebugger();
}

// ============================================================================
// HELPER METHODS
// ============================================================================

void Win32IDE::highlightDebuggerLine(const std::string& file, int line)
{
    // In a real implementation, would highlight the line in the editor
    m_debuggerCurrentFile = file;
    m_debuggerCurrentLine = line;
}

void Win32IDE::clearDebuggerHighlight()
{
    m_debuggerCurrentFile = "";
    m_debuggerCurrentLine = -1;
}

bool Win32IDE::isBreakpointAtLine(const std::string& file, int line) const
{
    return std::any_of(m_breakpoints.begin(), m_breakpoints.end(),
        [&](const Breakpoint& bp) { return bp.file == file && bp.line == line && bp.enabled; });
}

void Win32IDE::expandVariable(const std::string& name)
{
    auto it = std::find_if(m_localVariables.begin(), m_localVariables.end(),
        [&](const Variable& var) { return var.name == name; });

    if (it != m_localVariables.end()) {
        it->expanded = true;
        updateVariables();
    }
}

void Win32IDE::collapseVariable(const std::string& name)
{
    auto it = std::find_if(m_localVariables.begin(), m_localVariables.end(),
        [&](const Variable& var) { return var.name == name; });

    if (it != m_localVariables.end()) {
        it->expanded = false;
        updateVariables();
    }
}

std::string Win32IDE::formatDebuggerValue(const std::string& value, const std::string& type)
{
    return "(" + type + ") " + value;
}

void Win32IDE::debuggerStepCommand(const std::string& command)
{
    if (command == "over") {
        stepOverExecution();
    } else if (command == "into") {
        stepIntoExecution();
    } else if (command == "out") {
        stepOutExecution();
    } else if (command == "continue") {
        resumeExecution();
    } else if (command == "pause") {
        pauseExecution();
    }
}

void Win32IDE::debuggerSetVariable(const std::string& name, const std::string& value)
{
    auto it = std::find_if(m_localVariables.begin(), m_localVariables.end(),
        [&](const Variable& var) { return var.name == name; });

    if (it != m_localVariables.end()) {
        it->value = value;
        updateVariables();
        
        std::string msg = " Set " + name + " = " + value;
        appendToOutput(msg, "Output", OutputSeverity::Info);
    }
}

void Win32IDE::debuggerInspectMemory(uint64_t address, size_t bytes)
{
    std::ostringstream oss;
    oss << "Memory at 0x" << std::hex << address << " (" << std::dec << bytes << " bytes):\n";
    appendToOutput(oss.str(), "Output", OutputSeverity::Debug);
}

void Win32IDE::debuggerEvaluateExpression(const std::string& expression)
{
    ensureNativeDebugBackend();
    std::string value = "<unavailable>";
    if (m_nativeDebug) {
        m_nativeDebug->evaluateExpression(expression, value);
    }
    appendToOutput(std::string("Evaluate: ") + expression + " = " + value + "\n",
                   "Debug", OutputSeverity::Debug);
}

void Win32IDE::toggleDebugger()
{
    if (m_debuggerAttached) {
        detachDebugger();
    } else {
        attachDebugger();
    }
}
