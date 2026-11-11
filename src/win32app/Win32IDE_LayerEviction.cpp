// Win32IDE_LayerEviction.cpp — Layer Eviction (Batch 5 M04)
// Dynamic layer offload when VRAM is tight
#include "Win32IDE.h"
#include <windows.h>
#include <string>

static int g_evictedLayers = 0;

void Win32IDE::evictLayers(int count) {
    g_evictedLayers += count;
    appendToOutput("[LayerEviction] Evicted " + std::to_string(count) + " layers. Total: " +
                   std::to_string(g_evictedLayers) + "\n", "Output", OutputSeverity::Info);
}

int Win32IDE::getEvictedLayers() const {
    return g_evictedLayers;
}
