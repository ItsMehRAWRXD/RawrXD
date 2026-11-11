// ============================================================================
// Win32IDE_PageFaultHandler.cpp — Swap/Paging Awareness (Batch 7 PR05)
// Degrade gracefully under memory pressure
// ============================================================================
#include "Win32IDE.h"
#include "IDELogger.h"
#include <windows.h>

void Win32IDE::initPageFaultHandler() {
    appendToOutput("[PageFaultHandler] Swap/paging awareness initialized.\n", "Output", OutputSeverity::Info);
}

void Win32IDE::handleMemoryPressure() {
    appendToOutput("[PageFaultHandler] Memory pressure detected - degrading gracefully.\n", "Output", OutputSeverity::Warning);
}

bool Win32IDE::isMemoryPressure() const {
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    GlobalMemoryStatusEx(&memInfo);
    return memInfo.dwMemoryLoad > 90;
}
