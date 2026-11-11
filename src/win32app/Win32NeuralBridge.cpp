// Win32NeuralBridge.cpp - Production Implementation
// Provides neural bridge for Win32IDE
// ============================================================================

#include <windows.h>
#include <cstdint>
#include <cstring>

#define MAX_NEURAL_OPS      128
#define MAX_OP_NAME         64

enum NeuralOpType {
    OP_INFERENCE = 0,
    OP_TRAINING,
    OP_EVALUATION,
    OP_EXPORT,
    OP_IMPORT
};

struct NeuralOpEntry {
    volatile LONG active;
    uint32_t opId;
    char name[MAX_OP_NAME];
    NeuralOpType type;
    uint32_t modelId;
    uint64_t startTime;
    uint64_t endTime;
    uint32_t completed;
    float accuracy;
};

static volatile LONG g_initialized = 0;
static NeuralOpEntry g_ops[MAX_NEURAL_OPS];
static volatile LONG g_nextOpId = 1;
static volatile LONG g_completedCount = 0;

extern "C" __declspec(dllexport) int Win32NeuralBridge_Init() {
    LONG was = InterlockedCompareExchange(&g_initialized, 1, 0);
    if (was != 0) return 1;
    InterlockedExchange(&g_nextOpId, 1);
    InterlockedExchange(&g_completedCount, 0);
    memset(g_ops, 0, sizeof(g_ops));
    return 1;
}

extern "C" __declspec(dllexport) int Win32NeuralBridge_Shutdown() {
    InterlockedExchange(&g_initialized, 0);
    return 0;
}

extern "C" __declspec(dllexport) int Win32NeuralBridge_CreateOp(const char* name, int type, uint32_t modelId, uint32_t* outOpId) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    if (!name || !outOpId) return 0;
    int slot = -1;
    for (int i = 0; i < MAX_NEURAL_OPS; ++i) {
        if (InterlockedCompareExchange(&g_ops[i].active, 0, 0) == 0) { slot = i; break; }
    }
    if (slot < 0) return 0;
    NeuralOpEntry* op = &g_ops[slot];
    op->opId = InterlockedIncrement(&g_nextOpId);
    size_t len = strlen(name);
    if (len >= MAX_OP_NAME) len = MAX_OP_NAME - 1;
    memcpy(op->name, name, len);
    op->name[len] = 0;
    op->type = static_cast<NeuralOpType>(type);
    op->modelId = modelId;
    op->startTime = GetTickCount64();
    op->endTime = 0;
    op->completed = 0;
    op->accuracy = 0.0f;
    InterlockedExchange(&op->active, 1);
    *outOpId = op->opId;
    return 1;
}

extern "C" __declspec(dllexport) int Win32NeuralBridge_CompleteOp(uint32_t opId, float accuracy) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_NEURAL_OPS; ++i) {
        if (InterlockedCompareExchange(&g_ops[i].active, 0, 0) == 1 && g_ops[i].opId == opId) {
            g_ops[i].completed = 1;
            g_ops[i].endTime = GetTickCount64();
            g_ops[i].accuracy = accuracy;
            InterlockedIncrement(&g_completedCount);
            return 1;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int Win32NeuralBridge_GetOpInfo(uint32_t opId, char* outName, uint32_t maxLen, int* outType, uint32_t* outCompleted, float* outAccuracy) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_NEURAL_OPS; ++i) {
        if (InterlockedCompareExchange(&g_ops[i].active, 0, 0) == 1 && g_ops[i].opId == opId) {
            if (outName) {
                size_t len = strlen(g_ops[i].name);
                if (len >= maxLen) len = maxLen - 1;
                memcpy(outName, g_ops[i].name, len);
                outName[len] = 0;
            }
            if (outType) *outType = static_cast<int>(g_ops[i].type);
            if (outCompleted) *outCompleted = g_ops[i].completed;
            if (outAccuracy) *outAccuracy = g_ops[i].accuracy;
            return 1;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int Win32NeuralBridge_GetCompletedCount() {
    return static_cast<int>(InterlockedCompareExchange(&g_completedCount, 0, 0));
}
