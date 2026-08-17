#include <windows.h>
#include <cstdint>
#include <vector>
#include <string>
#include <mutex>
#include <map>

namespace {
    // Patch record for tracking applied patches
    struct PatchRecord {
        void* target;
        std::vector<uint8_t> originalBytes;
        size_t size;
        bool active;
    };
    
    std::map<void*, PatchRecord> g_patches;
    std::mutex g_patchesMutex;
    
    // Minimum size for a safe patch
    constexpr size_t kMinPatchSize = 5;
    constexpr size_t kMaxPatchSize = 64;
}

// Apply a hotpatch: replace target function with jump to replacement
bool hotpatch(void* target, void* replacement) {
    if (!target || !replacement) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(g_patchesMutex);
    
    // Check if already patched
    if (g_patches.count(target) > 0) {
        return false;  // Already patched
    }
    
    // Make target memory writable
    DWORD oldProtect;
    if (!VirtualProtect(target, kMinPatchSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return false;
    }
    
    // Save original bytes
    PatchRecord record;
    record.target = target;
    record.size = kMinPatchSize;
    record.originalBytes.assign(
        static_cast<uint8_t*>(target),
        static_cast<uint8_t*>(target) + kMinPatchSize
    );
    record.active = true;
    
    // Apply patch: JMP rel32 (E9 <offset>)
    uint8_t* p = static_cast<uint8_t*>(target);
    p[0] = 0xE9;  // JMP opcode
    
    // Calculate relative offset: dest - (src + 5)
    int32_t offset = static_cast<int32_t>(
        reinterpret_cast<uintptr_t>(replacement) - 
        (reinterpret_cast<uintptr_t>(target) + 5)
    );
    *reinterpret_cast<int32_t*>(p + 1) = offset;
    
    // Fill remaining bytes with NOPs
    for (size_t i = 5; i < kMinPatchSize; ++i) {
        p[i] = 0x90;  // NOP
    }
    
    // Restore original protection
    DWORD dummy;
    VirtualProtect(target, kMinPatchSize, oldProtect, &dummy);
    
    // Flush instruction cache
    FlushInstructionCache(GetCurrentProcess(), target, kMinPatchSize);
    
    // Store patch record
    g_patches[target] = std::move(record);
    
    return true;
}

// Remove a hotpatch and restore original function
bool hotpatch_remove(void* target) {
    if (!target) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(g_patchesMutex);
    
    auto it = g_patches.find(target);
    if (it == g_patches.end()) {
        return false;  // Not patched
    }
    
    PatchRecord& record = it->second;
    if (!record.active) {
        return false;  // Already removed
    }
    
    // Make target memory writable
    DWORD oldProtect;
    if (!VirtualProtect(target, record.size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return false;
    }
    
    // Restore original bytes
    std::memcpy(target, record.originalBytes.data(), record.size);
    
    // Restore original protection
    DWORD dummy;
    VirtualProtect(target, record.size, oldProtect, &dummy);
    
    // Flush instruction cache
    FlushInstructionCache(GetCurrentProcess(), target, record.size);
    
    // Mark as inactive
    record.active = false;
    g_patches.erase(it);
    
    return true;
}

// Check if a function is currently patched
bool hotpatch_is_active(void* target) {
    if (!target) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(g_patchesMutex);
    auto it = g_patches.find(target);
    return (it != g_patches.end()) && it->second.active;
}

// Get the number of active patches
size_t hotpatch_count() {
    std::lock_guard<std::mutex> lock(g_patchesMutex);
    return g_patches.size();
}

// Remove all patches
void hotpatch_remove_all() {
    std::lock_guard<std::mutex> lock(g_patchesMutex);
    
    // Copy patches to avoid modifying during iteration
    auto patches = g_patches;
    
    for (auto& pair : patches) {
        // Make target memory writable
        DWORD oldProtect;
        if (VirtualProtect(pair.first, pair.second.size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            // Restore original bytes
            std::memcpy(pair.first, pair.second.originalBytes.data(), pair.second.size);
            
            // Restore protection
            DWORD dummy;
            VirtualProtect(pair.first, pair.second.size, oldProtect, &dummy);
            
            // Flush cache
            FlushInstructionCache(GetCurrentProcess(), pair.first, pair.second.size);
        }
    }
    
    g_patches.clear();
}

// Apply a patch with a larger trampoline (for hooking)
bool hotpatch_trampoline(void* target, void* replacement, void** trampoline) {
    if (!target || !replacement || !trampoline) {
        return false;
    }
    
    // Allocate trampoline memory
    void* tramp = VirtualAlloc(nullptr, 32, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!tramp) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(g_patchesMutex);
    
    // Check if already patched
    if (g_patches.count(target) > 0) {
        VirtualFree(tramp, 0, MEM_RELEASE);
        return false;
    }
    
    // Make target memory writable
    DWORD oldProtect;
    if (!VirtualProtect(target, kMinPatchSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        VirtualFree(tramp, 0, MEM_RELEASE);
        return false;
    }
    
    // Build trampoline: copy original bytes + jump back to original + 5
    uint8_t* trampPtr = static_cast<uint8_t*>(tramp);
    std::memcpy(trampPtr, target, kMinPatchSize);
    
    // Add jump back to original function after the patch
    trampPtr[kMinPatchSize] = 0xE9;
    *reinterpret_cast<int32_t*>(trampPtr + kMinPatchSize + 1) = static_cast<int32_t>(
        (reinterpret_cast<uintptr_t>(target) + kMinPatchSize) - 
        (reinterpret_cast<uintptr_t>(tramp) + kMinPatchSize + 5)
    );
    
    // Save original bytes
    PatchRecord record;
    record.target = target;
    record.size = kMinPatchSize;
    record.originalBytes.assign(
        static_cast<uint8_t*>(target),
        static_cast<uint8_t*>(target) + kMinPatchSize
    );
    record.active = true;
    
    // Apply patch to target
    uint8_t* p = static_cast<uint8_t*>(target);
    p[0] = 0xE9;  // JMP opcode
    *reinterpret_cast<int32_t*>(p + 1) = static_cast<int32_t>(
        reinterpret_cast<uintptr_t>(replacement) - 
        (reinterpret_cast<uintptr_t>(target) + 5)
    );
    
    // Fill remaining bytes with NOPs
    for (size_t i = 5; i < kMinPatchSize; ++i) {
        p[i] = 0x90;
    }
    
    // Restore original protection
    DWORD dummy;
    VirtualProtect(target, kMinPatchSize, oldProtect, &dummy);
    
    // Flush instruction cache
    FlushInstructionCache(GetCurrentProcess(), target, kMinPatchSize);
    FlushInstructionCache(GetCurrentProcess(), tramp, 32);
    
    // Store patch record
    g_patches[target] = std::move(record);
    
    *trampoline = tramp;
    return true;
}
