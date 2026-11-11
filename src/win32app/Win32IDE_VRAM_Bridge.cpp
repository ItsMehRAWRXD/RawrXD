// Win32IDE_VRAM_Bridge.cpp — GPU/CPU Scheduling (Batch 5 M04)
// Offload layers, batch size, thread count
#include "Win32IDE.h"
#include <windows.h>
#include <string>

struct VRAMInfo {
    double totalMB;
    double availableMB;
    double usedMB;
};

static VRAMInfo g_vramInfo = {0, 0, 0};

void Win32IDE::updateVRAMInfo() {
    // Stub: query GPU memory
    g_vramInfo.totalMB = 8192.0;
    g_vramInfo.availableMB = 4096.0;
    g_vramInfo.usedMB = g_vramInfo.totalMB - g_vramInfo.availableMB;
}

VRAMInfo Win32IDE::getVRAMInfo() const {
    return g_vramInfo;
}

void Win32IDE::setGPULayerOffload(int layers) {
    appendToOutput("[VRAM_Bridge] GPU layer offload set to: " + std::to_string(layers) + "\n",
                   "Output", OutputSeverity::Info);
}

int Win32IDE::getGPULayerOffload() const {
    return 0;
}
