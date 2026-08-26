// ============================================================================
// spengine_bridge.cpp — Real Self-Patch Engine memory patch implementation
// Replaces spengine_stubs.cpp with actual memory patching via Win32 API
// ============================================================================

#include <windows.h>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <vector>
#include <mutex>

// Patch journal for rollback support
struct PatchEntry {
    void* targetAddr;
    std::vector<uint8_t> originalBytes;
    uint64_t timestamp;
    bool active;
};

static std::vector<PatchEntry> g_patchJournal;
static std::mutex g_patchMutex;
static uint64_t g_patchCount = 0;

extern "C" {

// ============================================================================
// CPU Optimization
// ============================================================================

void asm_spengine_cpu_optimize() {
    // Real CPU optimization: set thread affinity and priority for inference
    DWORD_PTR processAffinityMask = 0;
    DWORD_PTR systemAffinityMask = 0;
    
    if (GetProcessAffinityMask(GetCurrentProcess(), &processAffinityMask, &systemAffinityMask)) {
        // Use all available cores
        SetThreadAffinityMask(GetCurrentThread(), processAffinityMask);
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
        OutputDebugStringA("[SPEngine] asm_spengine_cpu_optimize: thread optimized for inference\n");
    } else {
        OutputDebugStringA("[SPEngine] asm_spengine_cpu_optimize: failed to set affinity\n");
    }
}

// ============================================================================
// Memory Patch
// ============================================================================

void asm_apply_memory_patch(void* addr, size_t size, const void* data) {
    if (!addr || !data || size == 0) {
        OutputDebugStringA("[SPEngine] asm_apply_memory_patch: invalid parameters\n");
        return;
    }
    
    std::lock_guard<std::mutex> lock(g_patchMutex);
    
    // Save original bytes for rollback
    PatchEntry entry;
    entry.targetAddr = addr;
    entry.originalBytes.resize(size);
    entry.timestamp = GetTickCount64();
    entry.active = true;
    
    // Read original bytes
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(GetCurrentProcess(), addr, entry.originalBytes.data(), size, &bytesRead)) {
        OutputDebugStringA("[SPEngine] asm_apply_memory_patch: failed to read original bytes\n");
        return;
    }
    
    // Change memory protection to allow writing
    DWORD oldProtect;
    if (!VirtualProtect(addr, size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        OutputDebugStringA("[SPEngine] asm_apply_memory_patch: failed to change protection\n");
        return;
    }
    
    // Apply patch
    std::memcpy(addr, data, size);
    
    // Restore original protection
    VirtualProtect(addr, size, oldProtect, &oldProtect);
    
    // Flush instruction cache
    FlushInstructionCache(GetCurrentProcess(), addr, size);
    
    // Add to journal
    g_patchJournal.push_back(entry);
    g_patchCount++;
    
    char buf[256];
    snprintf(buf, sizeof(buf), "[SPEngine] asm_apply_memory_patch: applied %zu bytes at %p (patch #%llu)\n", 
             size, addr, g_patchCount);
    OutputDebugStringA(buf);
}

// ============================================================================
// Patch Rollback
// ============================================================================

bool asm_rollback_memory_patch(void* addr) {
    if (!addr) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(g_patchMutex);
    
    // Find the most recent active patch for this address
    for (auto it = g_patchJournal.rbegin(); it != g_patchJournal.rend(); ++it) {
        if (it->targetAddr == addr && it->active) {
            // Change memory protection
            DWORD oldProtect;
            if (!VirtualProtect(addr, it->originalBytes.size(), PAGE_EXECUTE_READWRITE, &oldProtect)) {
                OutputDebugStringA("[SPEngine] asm_rollback_memory_patch: failed to change protection\n");
                return false;
            }
            
            // Restore original bytes
            std::memcpy(addr, it->originalBytes.data(), it->originalBytes.size());
            
            // Restore protection
            VirtualProtect(addr, it->originalBytes.size(), oldProtect, &oldProtect);
            
            // Flush instruction cache
            FlushInstructionCache(GetCurrentProcess(), addr, it->originalBytes.size());
            
            // Mark as inactive
            it->active = false;
            
            char buf[256];
            snprintf(buf, sizeof(buf), "[SPEngine] asm_rollback_memory_patch: rolled back patch at %p\n", addr);
            OutputDebugStringA(buf);
            
            return true;
        }
    }
    
    OutputDebugStringA("[SPEngine] asm_rollback_memory_patch: no active patch found\n");
    return false;
}

// ============================================================================
// Patch Verification
// ============================================================================

bool asm_verify_memory_patch(void* addr, const void* expected, size_t size) {
    if (!addr || !expected || size == 0) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(g_patchMutex);
    
    // Read current bytes
    std::vector<uint8_t> current(size);
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(GetCurrentProcess(), addr, current.data(), size, &bytesRead)) {
        OutputDebugStringA("[SPEngine] asm_verify_memory_patch: failed to read memory\n");
        return false;
    }
    
    bool match = (std::memcmp(current.data(), expected, size) == 0);
    
    char buf[256];
    snprintf(buf, sizeof(buf), "[SPEngine] asm_verify_memory_patch: %s at %p\n", 
             match ? "VERIFIED" : "MISMATCH", addr);
    OutputDebugStringA(buf);
    
    return match;
}

// ============================================================================
// Patch Statistics
// ============================================================================

uint64_t asm_get_patch_count() {
    std::lock_guard<std::mutex> lock(g_patchMutex);
    return g_patchCount;
}

uint64_t asm_get_active_patch_count() {
    std::lock_guard<std::mutex> lock(g_patchMutex);
    uint64_t active = 0;
    for (const auto& entry : g_patchJournal) {
        if (entry.active) active++;
    }
    return active;
}

} // extern "C"
