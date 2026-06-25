// Win32IDE_ExecutionTruth.cpp - Production Implementation
// Provides execution truth tracking for Win32IDE
// ============================================================================

#include <windows.h>
#include <cstdint>
#include <cstring>

#define MAX_TRUTHS      256
#define MAX_TRUTH_NAME  128

enum TruthState {
    TRUTH_UNKNOWN = 0,
    TRUTH_VERIFIED,
    TRUTH_FAILED,
    TRUTH_PENDING
};

struct TruthEntry {
    volatile LONG active;
    uint32_t truthId;
    char name[MAX_TRUTH_NAME];
    TruthState state;
    uint64_t verifiedAt;
    uint32_t checksum;
    uint32_t retryCount;
};

static volatile LONG g_initialized = 0;
static TruthEntry g_truths[MAX_TRUTHS];
static volatile LONG g_nextTruthId = 1;
static volatile LONG g_verifiedCount = 0;
static volatile LONG g_failedCount = 0;

extern "C" __declspec(dllexport) int Win32IDE_ExecutionTruth_Init() {
    LONG was = InterlockedCompareExchange(&g_initialized, 1, 0);
    if (was != 0) return 1;
    InterlockedExchange(&g_nextTruthId, 1);
    InterlockedExchange(&g_verifiedCount, 0);
    InterlockedExchange(&g_failedCount, 0);
    memset(g_truths, 0, sizeof(g_truths));
    return 1;
}

extern "C" __declspec(dllexport) int Win32IDE_ExecutionTruth_Shutdown() {
    InterlockedExchange(&g_initialized, 0);
    return 0;
}

extern "C" __declspec(dllexport) int Win32IDE_ExecutionTruth_RegisterTruth(const char* name, uint32_t* outTruthId) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    if (!name || !outTruthId) return 0;
    int slot = -1;
    for (int i = 0; i < MAX_TRUTHS; ++i) {
        if (InterlockedCompareExchange(&g_truths[i].active, 0, 0) == 0) { slot = i; break; }
    }
    if (slot < 0) return 0;
    TruthEntry* truth = &g_truths[slot];
    truth->truthId = InterlockedIncrement(&g_nextTruthId);
    size_t len = strlen(name);
    if (len >= MAX_TRUTH_NAME) len = MAX_TRUTH_NAME - 1;
    memcpy(truth->name, name, len);
    truth->name[len] = 0;
    truth->state = TRUTH_PENDING;
    truth->verifiedAt = 0;
    truth->checksum = 0;
    truth->retryCount = 0;
    InterlockedExchange(&truth->active, 1);
    *outTruthId = truth->truthId;
    return 1;
}

extern "C" __declspec(dllexport) int Win32IDE_ExecutionTruth_VerifyTruth(uint32_t truthId, uint32_t checksum) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_TRUTHS; ++i) {
        if (InterlockedCompareExchange(&g_truths[i].active, 0, 0) == 1 && g_truths[i].truthId == truthId) {
            g_truths[i].checksum = checksum;
            g_truths[i].verifiedAt = GetTickCount64();
            g_truths[i].state = TRUTH_VERIFIED;
            InterlockedIncrement(&g_verifiedCount);
            return 1;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int Win32IDE_ExecutionTruth_FailTruth(uint32_t truthId) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_TRUTHS; ++i) {
        if (InterlockedCompareExchange(&g_truths[i].active, 0, 0) == 1 && g_truths[i].truthId == truthId) {
            g_truths[i].state = TRUTH_FAILED;
            InterlockedIncrement(&g_failedCount);
            return 1;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int Win32IDE_ExecutionTruth_GetTruthState(uint32_t truthId, int* outState, uint32_t* outChecksum, uint32_t* outRetryCount) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_TRUTHS; ++i) {
        if (InterlockedCompareExchange(&g_truths[i].active, 0, 0) == 1 && g_truths[i].truthId == truthId) {
            if (outState) *outState = static_cast<int>(g_truths[i].state);
            if (outChecksum) *outChecksum = g_truths[i].checksum;
            if (outRetryCount) *outRetryCount = g_truths[i].retryCount;
            return 1;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int Win32IDE_ExecutionTruth_GetStats(int* verified, int* failed) {
    if (verified) *verified = static_cast<int>(InterlockedCompareExchange(&g_verifiedCount, 0, 0));
    if (failed) *failed = static_cast<int>(InterlockedCompareExchange(&g_failedCount, 0, 0));
    return 1;
}
