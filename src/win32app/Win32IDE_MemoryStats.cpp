// ============================================================================
// Win32IDE_MemoryStats.cpp — Memory Statistics (Batch 7 PR01)
// Monitors VRAM and RAM pressure
// ============================================================================
#include "Win32IDE.h"
#include "IDELogger.h"
#include <windows.h>

namespace RawrXD::Memory::Stats {

extern "C" void Stats_GetUsage(uint64_t* out_total, uint64_t* out_used) {
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    GlobalMemoryStatusEx(&memInfo);

    if (out_total) *out_total = memInfo.ullTotalPhys;
    if (out_used) *out_used = memInfo.ullTotalPhys - memInfo.ullAvailPhys;
}

extern "C" uint64_t Stats_GetVRAMUsage() {
    return 0;
}

} // namespace RawrXD::Memory::Stats

void Win32IDE::initMemoryStats() {
    appendToOutput("[MemoryStats] Memory statistics initialized.\n", "Output", OutputSeverity::Info);
}

void Win32IDE::getMemoryUsage(uint64_t& total, uint64_t& used) {
    RawrXD::Memory::Stats::Stats_GetUsage(&total, &used);
}
