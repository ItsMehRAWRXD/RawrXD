#include "Win32IDE.h"
#include <windows.h>

// Fail-closed DEMO gate: never emit FinishedAction / synthetic RunTerminal
// without a real process exit code. Product run history must not record PASS.
static void GateStub(Win32IDE* ide) {
    OutputDebugStringA(
        "[ToolActionStatus] GATED_STUB SYNTHETIC=1 DEMO "
        "NOT_PRODUCT_PATH FinishedAction forbidden without real process exit\n");
    if (!ide) return;
    ide->appendToOutput(
        "[ToolActionStatus] GATED_STUB SYNTHETIC=1 DEMO NOT_PRODUCT_PATH "
        "no FinishedAction / no success toast\n",
        "Tools", Win32IDE::OutputSeverity::Warning);
}

void HandleToolActionStatus(void* idePtr) {
    GateStub(static_cast<Win32IDE*>(idePtr));
}
