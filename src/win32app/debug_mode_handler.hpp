#pragma once
// ============================================================================
// debug_mode_handler.hpp — Debug Mode (G04): debugger-oriented agentic lane
// ============================================================================
// SOURCE_WIRED only this seal. Full attach/launch/break/step/stack/watch E2E
// is RUNTIME — NOT_RUN until MAIN_HWND + tip absorb/relink. Fail-closed:
// never imply default-model or invent debugger attach PASS.
// ============================================================================

#include <string>

namespace RawrXD {

inline const char* DebugModeSystemPrompt() {
    return
        "You are in Debug mode in RawrXD IDE. Prefer debugger-oriented steps: "
        "attach/launch hypotheses, break/step plans, stack and watch inspection, "
        "and minimal repro. Do not claim a live debugger session unless the host "
        "reports one. Cite file:line when proposing breakpoints.";
}

inline std::string DebugModeUserPrefix() {
    return "[Debug mode: debugger-oriented; no invented attach] ";
}

} // namespace RawrXD
