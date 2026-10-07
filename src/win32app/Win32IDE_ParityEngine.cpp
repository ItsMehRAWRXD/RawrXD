// Win32IDE_ParityEngine.cpp - Production Implementation
// Provides parity engine for Win32IDE
// ============================================================================

#include <windows.h>
#include <cstdint>
#include <cstring>

#define MAX_CHECKS      256
#define MAX_CHECK_NAME  128

struct CheckEntry {
    volatile LONG active;
    uint32_t checkId;
    char name[MAX_CHECK_NAME];
    uint64_t expected;
    uint64_t actual;
    uint32_t passed;
    uint64_t checkedAt;
};

static volatile LONG g_initialized = 0;
static CheckEntry g_checks[MAX_CHECKS];
static volatile LONG g_nextCheckId = 1;
static volatile LONG g_passCount = 0;
static volatile LONG g_failCount = 0;

extern "C" __declspec(dllexport) int Win32IDE_ParityEngine_Init() {
    LONG was = InterlockedCompareExchange(&g_initialized, 1, 0);
    if (was != 0) return 1;
    InterlockedExchange(&g_nextCheckId, 1);
    InterlockedExchange(&g_passCount, 0);
    InterlockedExchange(&g_failCount, 0);
    memset(g_checks, 0, sizeof(g_checks));
    return 1;
}

extern "C" __declspec(dllexport) int Win32IDE_ParityEngine_Shutdown() {
    InterlockedExchange(&g_initialized, 0);
    return 0;
}

extern "C" __declspec(dllexport) int Win32IDE_ParityEngine_RegisterCheck(const char* name, uint64_t expected, uint32_t* outCheckId) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    if (!name || !outCheckId) return 0;
    int slot = -1;
    for (int i = 0; i < MAX_CHECKS; ++i) {
        if (InterlockedCompareExchange(&g_checks[i].active, 0, 0) == 0) { slot = i; break; }
    }
    if (slot < 0) return 0;
    CheckEntry* chk = &g_checks[slot];
    chk->checkId = InterlockedIncrement(&g_nextCheckId);
    size_t len = strlen(name);
    if (len >= MAX_CHECK_NAME) len = MAX_CHECK_NAME - 1;
    memcpy(chk->name, name, len);
    chk->name[len] = 0;
    chk->expected = expected;
    chk->actual = 0;
    chk->passed = 0;
    chk->checkedAt = 0;
    InterlockedExchange(&chk->active, 1);
    *outCheckId = chk->checkId;
    return 1;
}

extern "C" __declspec(dllexport) int Win32IDE_ParityEngine_ReportActual(uint32_t checkId, uint64_t actual) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_CHECKS; ++i) {
        if (InterlockedCompareExchange(&g_checks[i].active, 0, 0) == 1 && g_checks[i].checkId == checkId) {
            g_checks[i].actual = actual;
            g_checks[i].checkedAt = GetTickCount64();
            if (actual == g_checks[i].expected) {
                g_checks[i].passed = 1;
                InterlockedIncrement(&g_passCount);
                return 1;
            } else {
                g_checks[i].passed = 0;
                InterlockedIncrement(&g_failCount);
                return 0;
            }
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int Win32IDE_ParityEngine_GetStats(int* passCount, int* failCount) {
    if (passCount) *passCount = static_cast<int>(InterlockedCompareExchange(&g_passCount, 0, 0));
    if (failCount) *failCount = static_cast<int>(InterlockedCompareExchange(&g_failCount, 0, 0));
    return 1;
}
