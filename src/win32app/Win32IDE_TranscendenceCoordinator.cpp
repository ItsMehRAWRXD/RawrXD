#include "Win32IDE.h"
#include <windows.h>
#include <string>

/* Fiction coordinator — honest deferred, not valuation theater init. */
extern "C" void HandleTranscendenceCoordinator(void* idePtr) {
    Win32IDE* ide = static_cast<Win32IDE*>(idePtr);
    const char* msg =
        "DEFERRED FEATURE_FICTION=1\n"
        "TranscendenceCoordinator is not a product surface.\n"
        "Use Deep2 generateStream / IDE chat / MCP / IOCP instead.";
    if (ide) {
        ide->appendToOutput(std::string("[Transcendence] ") + msg + "\n",
                            "System", Win32IDE::OutputSeverity::Warning);
    }
    MessageBoxA(ide ? ide->getMainWindow() : nullptr, msg,
                "Transcendence Coordinator", MB_ICONWARNING | MB_OK);
}
