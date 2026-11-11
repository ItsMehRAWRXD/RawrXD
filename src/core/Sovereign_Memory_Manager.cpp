// ============================================================================
// Sovereign Memory Manager — Hardware-Direct Arena Allocator
// Phase 1 of Sovereign Architecture: Zero-Copy Memory Fabric
// 
// Features:
//   - SeLockMemoryPrivilege elevation for MEM_LARGE_PAGES
//   - 2MB huge-page allocation (minimizes TLB misses)
//   - 256-byte alignment enforcement (RDNA3 optimal)
//   - Physical residency locking (no paging)
//   - Optional residency verification (SOVEREIGN_VERIFY_RESIDENCY)
//
// Target: AMD RX 7800 XT (RDNA3) + AMD Ryzen 7800X3D
// ============================================================================

#include "Sovereign_Memory_Manager.h"
#include <windows.h>
#include <stdio.h>
#include <assert.h>

// ============================================================================
// Configuration
// ============================================================================
#define SOVEREIGN_ARENA_DEFAULT_SIZE (4ULL * 1024ULL * 1024ULL * 1024ULL)  // 4GB
#define SOVEREIGN_ALIGNMENT 256                                           // RDNA3 cache line
#define SOVEREIGN_HUGE_PAGE_SIZE (2ULL * 1024ULL * 1024ULL)              // 2MB

// ============================================================================
// Internal State
// ============================================================================
static struct {
    void* arena_base;
    size_t arena_size;
    size_t used_offset;
    bool privilege_acquired;
    bool initialized;
} g_sovereign = { nullptr, 0, 0, false, false };

// ============================================================================
// Privilege Escalation
// ============================================================================
static bool AcquireLockMemoryPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }

    if (!LookupPrivilegeValueW(nullptr, L"SeLockMemoryPrivilege", &luid)) {
        CloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr)) {
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);
    return GetLastError() != ERROR_NOT_ALL_ASSIGNED;
}

// ============================================================================
// Arena Initialization
// ============================================================================
bool SovereignArena_Initialize(size_t size) {
    if (g_sovereign.initialized) {
        return true;  // Already initialized
    }

    // Default to 4GB if not specified
    if (size == 0) {
        size = SOVEREIGN_ARENA_DEFAULT_SIZE;
    }

    // Round up to 2MB huge-page boundary
    size = (size + SOVEREIGN_HUGE_PAGE_SIZE - 1) & ~(SOVEREIGN_HUGE_PAGE_SIZE - 1);

    // Acquire privilege first
    g_sovereign.privilege_acquired = AcquireLockMemoryPrivilege();
    if (!g_sovereign.privilege_acquired) {
        // Fall back to standard allocation (warning logged)
        OutputDebugStringA("[Sovereign] Warning: SeLockMemoryPrivilege not acquired, falling back to standard pages\n");
    }

    // Allocate with large pages
    DWORD allocFlags = MEM_RESERVE | MEM_COMMIT;
    if (g_sovereign.privilege_acquired) {
        allocFlags |= MEM_LARGE_PAGES;
    }

    g_sovereign.arena_base = VirtualAlloc(nullptr, size, allocFlags, PAGE_READWRITE);
    if (!g_sovereign.arena_base) {
        DWORD err = GetLastError();
        char msg[256];
        snprintf(msg, sizeof(msg), "[Sovereign] VirtualAlloc failed: %lu\n", err);
        OutputDebugStringA(msg);
        return false;
    }

    // Lock pages in physical memory (prevent paging)
    if (g_sovereign.privilege_acquired) {
        if (!VirtualLock(g_sovereign.arena_base, size)) {
            // Non-fatal: continue without locking
            OutputDebugStringA("[Sovereign] Warning: VirtualLock failed, pages may page out\n");
        }
    }

    g_sovereign.arena_size = size;
    g_sovereign.used_offset = 0;
    g_sovereign.initialized = true;

    char msg[512];
    snprintf(msg, sizeof(msg), 
        "[Sovereign] Arena initialized: %zu MB at %p (huge_pages=%s, locked=%s)\n",
        size / (1024 * 1024),
        g_sovereign.arena_base,
        g_sovereign.privilege_acquired ? "yes" : "no",
        g_sovereign.privilege_acquired ? "yes" : "no");
    OutputDebugStringA(msg);

    return true;
}

// ============================================================================
// Arena Shutdown
// ============================================================================
void SovereignArena_Shutdown() {
    if (!g_sovereign.initialized) {
        return;
    }

    if (g_sovereign.arena_base) {
        VirtualUnlock(g_sovereign.arena_base, g_sovereign.arena_size);
        VirtualFree(g_sovereign.arena_base, 0, MEM_RELEASE);
        g_sovereign.arena_base = nullptr;
    }

    g_sovereign.arena_size = 0;
    g_sovereign.used_offset = 0;
    g_sovereign.initialized = false;
    g_sovereign.privilege_acquired = false;

    OutputDebugStringA("[Sovereign] Arena shutdown complete\n");
}

// ============================================================================
// Aligned Allocation from Arena
// ============================================================================
void* SovereignArena_Allocate(size_t size, size_t alignment) {
    if (!g_sovereign.initialized) {
        return nullptr;
    }

    if (alignment == 0) {
        alignment = SOVEREIGN_ALIGNMENT;
    }

    // Round up to alignment boundary
    size_t aligned_offset = (g_sovereign.used_offset + alignment - 1) & ~(alignment - 1);
    
    // Check bounds
    if (aligned_offset + size > g_sovereign.arena_size) {
        OutputDebugStringA("[Sovereign] Arena out of memory\n");
        return nullptr;
    }

    void* ptr = static_cast<char*>(g_sovereign.arena_base) + aligned_offset;
    g_sovereign.used_offset = aligned_offset + size;

    return ptr;
}

// ============================================================================
// Bulk Allocation (for GGUF weights)
// ============================================================================
void* SovereignArena_AllocateWeights(size_t tensor_size) {
    // Weights need 256-byte alignment for RDNA3 MFMA
    return SovereignArena_Allocate(tensor_size, 256);
}

// ============================================================================
// Residency Verification (Diagnostic only)
// ============================================================================
#ifdef SOVEREIGN_VERIFY_RESIDENCY
bool SovereignArena_VerifyResidency(void* ptr, size_t size) {
    if (!g_sovereign.initialized || !ptr) {
        return false;
    }

    // QueryWorkingSetEx to check if pages are resident
    PSAPI_WORKING_SET_EX_INFORMATION wsInfo;
    wsInfo.VirtualAddress = ptr;
    
    SIZE_T resultSize = 0;
    if (!QueryWorkingSetEx(GetCurrentProcess(), &wsInfo, sizeof(wsInfo))) {
        return false;
    }

    return wsInfo.VirtualAttributes.Valid != 0;
}

void SovereignArena_DumpStats() {
    if (!g_sovereign.initialized) {
        printf("[Sovereign] Arena not initialized\n");
        return;
    }

    size_t used_mb = g_sovereign.used_offset / (1024 * 1024);
    size_t total_mb = g_sovereign.arena_size / (1024 * 1024);
    size_t free_mb = total_mb - used_mb;

    printf("[Sovereign] Arena Stats:\n");
    printf("  Base:     %p\n", g_sovereign.arena_base);
    printf("  Size:     %zu MB total, %zu MB used, %zu MB free\n", total_mb, used_mb, free_mb);
    printf("  Used:     %.2f%%\n", (100.0 * g_sovereign.used_offset) / g_sovereign.arena_size);
    printf("  Privilege: %s\n", g_sovereign.privilege_acquired ? "acquired" : "not acquired");
}
#endif

// ============================================================================
// Arena Reset (for model hot-swapping)
// ============================================================================
void SovereignArena_Reset() {
    if (!g_sovereign.initialized) {
        return;
    }

    g_sovereign.used_offset = 0;
    
    // Zero the memory for security
    SecureZeroMemory(g_sovereign.arena_base, g_sovereign.arena_size);
    
    OutputDebugStringA("[Sovereign] Arena reset\n");
}

// ============================================================================
// Getters for external integration
// ============================================================================
void* SovereignArena_GetBase() {
    return g_sovereign.arena_base;
}

size_t SovereignArena_GetSize() {
    return g_sovereign.arena_size;
}

size_t SovereignArena_GetUsed() {
    return g_sovereign.used_offset;
}

bool SovereignArena_IsInitialized() {
    return g_sovereign.initialized;
}
