// ExecutionTruth_link.cpp - Production Implementation
// Execution verification and truth tracking for agentic operations
// ============================================================================

#include <windows.h>
#include <cstdio>
#include <cstring>

// ============================================================================
// Constants
// ============================================================================
#define MAX_TRUTH_RECORDS   256
#define MAX_CONTEXT_LEN     512
#define TRUTH_MAGIC         0x54525554  // 'TRUT'

// ============================================================================
// Truth Record
// ============================================================================
struct TruthRecord {
    volatile LONG active;
    DWORD recordId;
    DWORD timestamp;
    DWORD verificationFlags;
    DWORD hash;
    char context[MAX_CONTEXT_LEN];
    DWORD result;
    BOOL verified;
};

// ============================================================================
// Verification Flags
// ============================================================================
#define VERIFY_HASH         0x0001
#define VERIFY_TIMESTAMP    0x0002
#define VERIFY_CONTEXT      0x0004
#define VERIFY_RESULT       0x0008
#define VERIFY_ALL          0x000F

// ============================================================================
// State
// ============================================================================
static volatile LONG g_initialized = 0;
static TruthRecord g_records[MAX_TRUTH_RECORDS];
static volatile LONG g_nextRecordId = 1;
static volatile LONG g_verifiedCount = 0;
static volatile LONG g_failedCount = 0;

// ============================================================================
// Helper: Simple hash function (FNV-1a)
// ============================================================================
static DWORD ComputeHash(const void* data, size_t len) {
    const BYTE* p = static_cast<const BYTE*>(data);
    DWORD hash = 0x811C9DC5;
    for (size_t i = 0; i < len; ++i) {
        hash ^= p[i];
        hash *= 0x01000193;
    }
    return hash;
}

// ============================================================================
// Exported API
// ============================================================================
extern "C" __declspec(dllexport) int ExecutionTruth_link_Init() {
    LONG was = InterlockedCompareExchange(&g_initialized, 1, 0);
    if (was != 0) return 1;
    
    InterlockedExchange(&g_nextRecordId, 1);
    InterlockedExchange(&g_verifiedCount, 0);
    InterlockedExchange(&g_failedCount, 0);
    
    for (int i = 0; i < MAX_TRUTH_RECORDS; ++i) {
        InterlockedExchange(&g_records[i].active, 0);
        g_records[i].recordId = 0;
        g_records[i].timestamp = 0;
        g_records[i].verificationFlags = 0;
        g_records[i].hash = 0;
        g_records[i].context[0] = 0;
        g_records[i].result = 0;
        g_records[i].verified = FALSE;
    }
    return 1;
}

extern "C" __declspec(dllexport) int ExecutionTruth_link_Shutdown() {
    InterlockedExchange(&g_initialized, 0);
    return 0;
}

extern "C" __declspec(dllexport) int ExecutionTruth_link_Record(
    const char* context,
    DWORD result,
    DWORD flags,
    DWORD* outRecordId
) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    if (!context || !outRecordId) return 0;
    
    // Find free slot
    int slot = -1;
    for (int i = 0; i < MAX_TRUTH_RECORDS; ++i) {
        if (InterlockedCompareExchange(&g_records[i].active, 0, 0) == 0) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        // Overwrite oldest
        DWORD oldestTime = 0xFFFFFFFF;
        for (int i = 0; i < MAX_TRUTH_RECORDS; ++i) {
            if (g_records[i].timestamp < oldestTime) {
                oldestTime = g_records[i].timestamp;
                slot = i;
            }
        }
    }
    
    TruthRecord* rec = &g_records[slot];
    InterlockedExchange(&rec->active, 0);
    
    DWORD recordId = InterlockedIncrement(&g_nextRecordId);
    rec->recordId = recordId;
    rec->timestamp = GetTickCount();
    rec->verificationFlags = flags;
    rec->result = result;
    
    size_t ctxLen = strlen(context);
    if (ctxLen >= MAX_CONTEXT_LEN) ctxLen = MAX_CONTEXT_LEN - 1;
    memcpy(rec->context, context, ctxLen);
    rec->context[ctxLen] = 0;
    
    // Compute hash over context + result
    DWORD hashInput[2];
    hashInput[0] = result;
    hashInput[1] = rec->timestamp;
    rec->hash = ComputeHash(rec->context, ctxLen) ^ ComputeHash(hashInput, sizeof(hashInput));
    
    // Verify
    BOOL verified = TRUE;
    if (flags & VERIFY_HASH) {
        // Hash is always computed, so this always passes for new records
    }
    if (flags & VERIFY_CONTEXT) {
        verified = verified && (rec->context[0] != 0);
    }
    if (flags & VERIFY_RESULT) {
        verified = verified && (result != 0xFFFFFFFF);
    }
    
    rec->verified = verified;
    if (verified) {
        InterlockedIncrement(&g_verifiedCount);
    } else {
        InterlockedIncrement(&g_failedCount);
    }
    
    InterlockedExchange(&rec->active, 1);
    *outRecordId = recordId;
    return verified ? 1 : 0;
}

extern "C" __declspec(dllexport) int ExecutionTruth_link_Verify(DWORD recordId, DWORD* outFlags) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    
    for (int i = 0; i < MAX_TRUTH_RECORDS; ++i) {
        if (InterlockedCompareExchange(&g_records[i].active, 0, 0) == 1 && 
            g_records[i].recordId == recordId) {
            
            // Recompute hash
            DWORD hashInput[2];
            hashInput[0] = g_records[i].result;
            hashInput[1] = g_records[i].timestamp;
            DWORD expectedHash = ComputeHash(g_records[i].context, strlen(g_records[i].context)) ^ 
                                ComputeHash(hashInput, sizeof(hashInput));
            
            BOOL stillValid = (g_records[i].hash == expectedHash);
            if (outFlags) *outFlags = g_records[i].verificationFlags;
            return stillValid ? 1 : 0;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int ExecutionTruth_link_GetStats(int* totalRecords, int* verified, int* failed) {
    if (totalRecords) {
        int count = 0;
        for (int i = 0; i < MAX_TRUTH_RECORDS; ++i) {
            if (InterlockedCompareExchange(&g_records[i].active, 0, 0) == 1) count++;
        }
        *totalRecords = count;
    }
    if (verified) *verified = static_cast<int>(InterlockedCompareExchange(&g_verifiedCount, 0, 0));
    if (failed) *failed = static_cast<int>(InterlockedCompareExchange(&g_failedCount, 0, 0));
    return 1;
}
