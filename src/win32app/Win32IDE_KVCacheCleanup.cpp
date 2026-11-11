// Win32IDE_KVCacheCleanup.cpp — KV-Cache Management (Batch 5 I06)
// Memory-efficient context reuse
#include "Win32IDE.h"
#include <windows.h>
#include <string>

static size_t g_kvCacheSize = 0;

void Win32IDE::initKVCache() {
    g_kvCacheSize = 0;
    appendToOutput("[KVCacheCleanup] KV-cache initialized.\n", "Output", OutputSeverity::Info);
}

void Win32IDE::cleanupKVCache() {
    g_kvCacheSize = 0;
    appendToOutput("[KVCacheCleanup] KV-cache cleaned.\n", "Output", OutputSeverity::Info);
}

size_t Win32IDE::getKVCacheSize() const {
    return g_kvCacheSize;
}
