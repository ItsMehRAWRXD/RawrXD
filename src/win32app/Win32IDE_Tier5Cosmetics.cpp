// ============================================================================
// Win32IDE_Tier5Cosmetics.cpp — Tier 5 Lifecycle & Command Router
// ============================================================================
//
// PURPOSE:
//   Central initialization and command routing for all Tier 5 cosmetic
//   features (#40-#50). Called from the main IDE initialization path.
//
// Architecture: C++20 | Win32 | No exceptions | No Qt
// Pattern:      PatchResult-compatible returns
// Rule:         NO SOURCE FILE IS TO BE SIMPLIFIED
// ============================================================================

#include "Win32IDE.h"
#include <sstream>

// ============================================================================
// Tier 5 features (40, 43, 44) — integrated logic, no scaffolding
// ============================================================================

void Win32IDE::initLineEndingSelector() {
    if (m_lineEndingSelectorInitialized) return;
    m_lineEndingSelectorInitialized = true;
    m_lineEndingMode = 0;  // CRLF default
    appendToOutput("[Line Ending] Selector ready (CRLF/LF/CR). Use menu to detect or convert.\n", "Output", OutputSeverity::Info);
}

bool Win32IDE::handleLineEndingCommand(int commandId) {
    if (!m_lineEndingSelectorInitialized) initLineEndingSelector();
    if (commandId < IDM_LINEENDING_DETECT || commandId > IDM_LINEENDING_TO_CR) return false;
    if (!m_hwndEditor || !IsWindow(m_hwndEditor)) return true;

    std::string content = getWindowText(m_hwndEditor);
    if (content.empty() && commandId != IDM_LINEENDING_DETECT) return true;

    if (commandId == IDM_LINEENDING_DETECT) {
        size_t crlf = 0, lf = 0, cr = 0;
        for (size_t i = 0; i + 1 < content.size(); ++i) {
            if (content[i] == '\r' && content[i+1] == '\n') { crlf++; i++; continue; }
            if (content[i] == '\n') lf++;
            else if (content[i] == '\r') cr++;
        }
        if (content.size() >= 1) {
            if (content.back() == '\n') lf++;
            else if (content.back() == '\r') cr++;
        }
        char buf[256];
        sprintf_s(buf, "[Line Ending] Detected: CRLF=%zu LF=%zu CR=%zu (dominant: %s)\n",
            crlf, lf, cr,
            (crlf >= lf && crlf >= cr) ? "CRLF" : (lf >= cr) ? "LF" : "CR");
        appendToOutput(buf, "Output", OutputSeverity::Info);
        return true;
    }

    const char* newEol = nullptr;
    int mode = -1;
    if (commandId == IDM_LINEENDING_TO_CRLF) { newEol = "\r\n"; mode = 0; }
    else if (commandId == IDM_LINEENDING_TO_LF) { newEol = "\n"; mode = 1; }
    else if (commandId == IDM_LINEENDING_TO_CR) { newEol = "\r"; mode = 2; }
    if (!newEol) return true;  // other IDs in range: no convert

    std::string normalized;
    normalized.reserve(content.size());
    for (size_t i = 0; i < content.size(); ++i) {
        if (content[i] == '\r' && i + 1 < content.size() && content[i+1] == '\n') { normalized += newEol; i++; continue; }
        if (content[i] == '\r' || content[i] == '\n') { normalized += newEol; continue; }
        normalized += content[i];
    }
    setWindowText(m_hwndEditor, normalized);
    m_lineEndingMode = mode;
    const char* name = (mode == 0) ? "CRLF" : (mode == 1) ? "LF" : "CR";
    appendToOutput(std::string("[Line Ending] Converted to ") + name + ".\n", "Output", OutputSeverity::Info);
    return true;
}

void Win32IDE::initDebugWatchFormat() {
    if (m_debugWatchInitialized) return;
    m_debugWatchInitialized = true;
    // COMPLETION_005: ODS only — avoid Output pane side-effects during Tier5 arm.
    OutputDebugStringA("[DebugWatch] Tier5 watch command path armed (FAIL_CLOSED).\n");
}

bool Win32IDE::handleDebugWatchCommand(int commandId) {
    // DEBUGGER_SHOW_CRASH_FIX_0C44_001 / RUNTIME_AUDIT_DRAINS_0C44:
    // IDM_DBGWATCH_SHOW (12230) killed live cand 0C44 with EXIT=0xC0000409
    // (STATUS_STACK_BUFFER_OVERRUN) after MenuReady+baseline ping.
    // Prior path: ShowWindow+SetFocus(m_hwndDebuggerWatch) and/or
    // appendToOutput/std::string — createDebuggerUI never called so watch HWND
    // stayed null/stale; Output-pane side effects also unsafe here.
    // DBGWATCH_SURVIVAL_RC_67CA_001: ODS-only still died on clean-Commands 67CA
    // (SOURCE_WIRED=1 RUNTIME_SURVIVAL_PASS=0) — menu path now early-bypassed in
    // WindowProc before onCommand/CommandFlight. This handler remains for any
    // non-menu entry; still no invent Watch panel ready PASS.
    // PROMOTE=0 ABSORB=NOT_AUTHORIZED TIP_CLIMB=HOLD.
    if (commandId < IDM_DBGWATCH_SHOW || commandId > IDM_DBGWATCH_CLEAR) return false;
    // IDE_DAILY_USE_001: prior null HWND ShowWindow → 0xC0000409. Ensure UI first.
    if (!ensureDebuggerUI() || !m_hwndDebuggerWatch || !IsWindow(m_hwndDebuggerWatch)) {
        OutputDebugStringA(
            "[DebugWatch] FAIL_CLOSED IDM_DBGWATCH_* ensureDebuggerUI miss "
            "PROMOTE=0 NOT_PASS\n");
        return true;
    }
    if (commandId == IDM_DBGWATCH_SHOW) {
        ShowWindow(m_hwndDebuggerContainer, SW_SHOW);
        ShowWindow(m_hwndDebuggerWatch, SW_SHOW);
        SetFocus(m_hwndDebuggerWatch);
        OutputDebugStringA("[DebugWatch] SHOW RUNTIME_REACHED ensureDebuggerUI\n");
        return true;
    }
    OutputDebugStringA(
        "[DebugWatch] IDM_DBGWATCH_* armed (no invent CLEAR/ADD PASS)\n");
    return true;
}

// CONTINUOUS_COMPLETION_002: initCallStackSymbols / handleCallStackCommand /
// cmdCallStack* live in Win32IDE_CallStackSymbols.cpp (real SymInitialize path).
// Thin Tier5 dump stubs removed — do not reinvent invent-ready callstack PASS.

// ============================================================================
// Initialize all Tier 5 features
// ============================================================================

void Win32IDE::initTier5Cosmetics() {
    initLineEndingSelector();
    initNetworkPanel();
    initTestExplorer();
    initDebugWatchFormat();
    initCallStackSymbols();
    initMarketplace();
    initTelemetryDashboard();
    initShortcutEditorPanel();
    initColorPicker();
    initEmojiSupport();
    initCrashReporter();
    initIRCBridge();

    OutputDebugStringA("[Tier5] All cosmetic features initialized.\n");
    appendToOutput("[Tier5] Cosmetic gaps #40-#51 loaded.\n");
}

// ============================================================================
// Route commands to the appropriate Tier 5 handler
// ============================================================================

bool Win32IDE::handleTier5Command(int commandId) {
    // Line Ending Selector (12200-12203)
    if (commandId >= IDM_LINEENDING_DETECT && commandId <= IDM_LINEENDING_TO_CR)
        return handleLineEndingCommand(commandId);

    // Network Panel (12210-12219)
    if (commandId >= IDM_NETWORK_SHOW && commandId <= IDM_NETWORK_STATUS)
        return handleNetworkCommand(commandId);

    // Test Explorer (12220-12229)
    if (commandId >= IDM_TESTEXPLORER_SHOW && commandId <= IDM_TESTEXPLORER_FILTER)
        return handleTestExplorerCommand(commandId);

    // Debug Watch Format (12230-12239)
    if (commandId >= IDM_DBGWATCH_SHOW && commandId <= IDM_DBGWATCH_CLEAR)
        return handleDebugWatchCommand(commandId);

    // Call Stack Symbols (12240-12249)
    if (commandId >= IDM_CALLSTACK_CAPTURE && commandId <= IDM_CALLSTACK_RESOLVE)
        return handleCallStackCommand(commandId);

    // Marketplace (12250-12259)
    if (commandId >= IDM_MARKETPLACE_SHOW && commandId <= IDM_MARKETPLACE_STATUS)
        return handleMarketplaceCommand(commandId);

    // Telemetry Dashboard (12265-12269) — LOG/CLEAR/EXPORT precede SHOW, so the
    // range must start at IDM_TELDASH_LOG or those three commands never dispatch.
    if (commandId >= IDM_TELDASH_LOG && commandId <= IDM_TELDASH_STATS)
        return handleTelemetryDashboardCommand(commandId);

    // Shortcut Editor (12270-12279)
    if (commandId >= IDM_SHORTCUT_SHOW && commandId <= IDM_SHORTCUT_LIST)
        return handleShortcutEditorCommand(commandId);

    // Color Picker (12280-12289)
    if (commandId >= IDM_COLORPICK_SCAN && commandId <= IDM_COLORPICK_LIST)
        return handleColorPickerCommand(commandId);

    // Emoji Support (12290-12299)
    if (commandId >= IDM_EMOJI_PICKER && commandId <= IDM_EMOJI_TEST)
        return handleEmojiCommand(commandId);

    // Crash Reporter (12300-12309)
    if (commandId >= IDM_CRASH_SHOW && commandId <= IDM_CRASH_STATS)
        return handleCrashReporterCommand(commandId);

    // Phase 51: mIRC Control Bridge (12310-12314)
    if (commandId >= IDM_IRC_CONNECT && commandId <= IDM_IRC_SEND)
        return handleIRCBridgeCommand(commandId);

    return false;
}
