// ============================================================================
// hotpatch.cpp - Full Hotpatch System Implementation
// Runtime code patching with trampoline support
// ============================================================================

#include "hotpatch.h"
#include <windows.h>
#include <vector>
#include <memory>
#include <mutex>
#include <cstring>

namespace RawrXD {

// ============================================================================
// Patch Metadata
// ============================================================================
struct PatchMetadata {
    uint32_t id;
    std::string name;
    std::string version;
    std::string targetFunction;
    void* targetAddress;
    void* replacementAddress;
    void* trampolineAddress;
    size_t patchSize;
    bool applied;
    bool hasTrampoline;
    uint8_t originalBytes[16];
    size_t originalSize;
    std::chrono::steady_clock::time_point applyTime;
};

// ============================================================================
// HotpatchManager Implementation
// ============================================================================

class HotpatchManagerImpl {
public:
    HotpatchManagerImpl() : nextPatchId_(1) {}
    
    ~HotpatchManagerImpl() {
        // Restore all patches on destruction
        RestoreAll();
    }
    
    bool Initialize() {
        std::lock_guard<std::mutex> lock(mutex_);
        patches_.clear();
        nextPatchId_ = 1;
        return true;
    }
    
    void Shutdown() {
        RestoreAll();
    }
    
    // Validate patch before applying
    bool ValidatePatch(const void* data, size_t size) {
        if (!data || size == 0) {
            return false;
        }
        
        // Minimum patch size check
        if (size < 5) {
            return false; // Need at least 5 bytes for JMP instruction
        }
        
        // Check patch header (simple magic number)
        const uint8_t* bytes = static_cast<const uint8_t*>(data);
        if (bytes[0] != 0x52 || bytes[1] != 0x41 || bytes[2] != 0x57 || bytes[3] != 0x52) {
            // "RAWR" magic not found - might still be valid but warn
        }
        
        return true;
    }
    
    // Apply a patch
    uint32_t ApplyPatch(const std::string& name, 
                        const std::string& version,
                        void* target, 
                        void* replacement,
                        bool createTrampoline = true) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        if (!target || !replacement) {
            return 0;
        }
        
        // Check if target is already patched
        for (const auto& patch : patches_) {
            if (patch.targetAddress == target && patch.applied) {
                return 0; // Already patched
            }
        }
        
        uint32_t patchId = nextPatchId_++;
        
        PatchMetadata patch;
        patch.id = patchId;
        patch.name = name;
        patch.version = version;
        patch.targetAddress = target;
        patch.replacementAddress = replacement;
        patch.patchSize = 5; // JMP rel32
        patch.applied = false;
        patch.hasTrampoline = false;
        patch.originalSize = 0;
        
        // Save original bytes
        if (!SaveOriginalBytes(target, patch.patchSize, patch)) {
            return 0;
        }
        
        // Create trampoline if requested
        if (createTrampoline) {
            patch.trampolineAddress = CreateTrampoline(target, patch.patchSize);
            if (patch.trampolineAddress) {
                patch.hasTrampoline = true;
            }
        }
        
        // Apply the patch
        if (!DoPatch(target, replacement)) {
            // Cleanup trampoline on failure
            if (patch.trampolineAddress) {
                VirtualFree(patch.trampolineAddress, 0, MEM_RELEASE);
            }
            return 0;
        }
        
        patch.applied = true;
        patch.applyTime = std::chrono::steady_clock::now();
        
        patches_.push_back(patch);
        
        return patchId;
    }
    
    // Restore original code
    bool RestorePatch(uint32_t patchId) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        for (auto& patch : patches_) {
            if (patch.id == patchId && patch.applied) {
                return RestoreOriginal(patch);
            }
        }
        
        return false;
    }
    
    // Restore all patches
    void RestoreAll() {
        std::lock_guard<std::mutex> lock(mutex_);
        
        for (auto& patch : patches_) {
            if (patch.applied) {
                RestoreOriginal(patch);
            }
        }
        
        patches_.clear();
    }
    
    // Get patch info
    bool GetPatchInfo(uint32_t patchId, std::string& name, std::string& version, bool& applied) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        for (const auto& patch : patches_) {
            if (patch.id == patchId) {
                name = patch.name;
                version = patch.version;
                applied = patch.applied;
                return true;
            }
        }
        
        return false;
    }
    
    // Get trampoline for a patched function
    void* GetTrampoline(uint32_t patchId) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        for (const auto& patch : patches_) {
            if (patch.id == patchId && patch.hasTrampoline) {
                return patch.trampolineAddress;
            }
        }
        
        return nullptr;
    }
    
    // List all patches
    std::vector<uint32_t> GetPatchIds() const {
        std::lock_guard<std::mutex> lock(mutex_);
        
        std::vector<uint32_t> ids;
        for (const auto& patch : patches_) {
            ids.push_back(patch.id);
        }
        
        return ids;
    }

private:
    bool SaveOriginalBytes(void* target, size_t size, PatchMetadata& patch) {
        patch.originalSize = size;
        if (size > sizeof(patch.originalBytes)) {
            size = sizeof(patch.originalBytes);
        }
        
        // Make target readable
        DWORD oldProtect;
        if (!VirtualProtect(target, size, PAGE_EXECUTE_READ, &oldProtect)) {
            return false;
        }
        
        std::memcpy(patch.originalBytes, target, size);
        
        // Restore protection
        VirtualProtect(target, size, oldProtect, &oldProtect);
        
        return true;
    }
    
    bool DoPatch(void* target, void* replacement) {
        // Make target writable
        DWORD oldProtect;
        if (!VirtualProtect(target, 16, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            return false;
        }
        
        uint8_t* p = static_cast<uint8_t*>(target);
        
        // Write JMP rel32 instruction
        p[0] = 0xE9; // JMP opcode
        
        // Calculate relative offset: dest - (src + 5)
        int32_t offset = static_cast<int32_t>(
            static_cast<uint8_t*>(replacement) - (p + 5)
        );
        
        std::memcpy(p + 1, &offset, sizeof(offset));
        
        // Restore protection
        VirtualProtect(target, 16, oldProtect, &oldProtect);
        
        return true;
    }
    
    bool RestoreOriginal(PatchMetadata& patch) {
        if (!patch.applied) {
            return true;
        }
        
        // Make target writable
        DWORD oldProtect;
        if (!VirtualProtect(patch.targetAddress, patch.originalSize, 
                           PAGE_EXECUTE_READWRITE, &oldProtect)) {
            return false;
        }
        
        // Restore original bytes
        std::memcpy(patch.targetAddress, patch.originalBytes, patch.originalSize);
        
        // Restore protection
        VirtualProtect(patch.targetAddress, patch.originalSize, oldProtect, &oldProtect);
        
        patch.applied = false;
        
        // Free trampoline
        if (patch.trampolineAddress) {
            VirtualFree(patch.trampolineAddress, 0, MEM_RELEASE);
            patch.trampolineAddress = nullptr;
            patch.hasTrampoline = false;
        }
        
        return true;
    }
    
    void* CreateTrampoline(void* target, size_t originalSize) {
        // Allocate executable memory for trampoline
        void* trampoline = VirtualAlloc(nullptr, 32, 
                                        MEM_COMMIT | MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE);
        if (!trampoline) {
            return nullptr;
        }
        
        uint8_t* tramp = static_cast<uint8_t*>(trampoline);
        uint8_t* orig = static_cast<uint8_t*>(target);
        
        // Copy original bytes
        std::memcpy(tramp, orig, originalSize);
        
        // Add JMP back to original code after patch
        tramp[originalSize] = 0xE9;
        int32_t offset = static_cast<int32_t>(
            (orig + originalSize) - (tramp + originalSize + 5)
        );
        std::memcpy(tramp + originalSize + 1, &offset, sizeof(offset));
        
        return trampoline;
    }

private:
    mutable std::mutex mutex_;
    std::vector<PatchMetadata> patches_;
    std::atomic<uint32_t> nextPatchId_;
};

// ============================================================================
// Global Instance
// ============================================================================

static HotpatchManagerImpl* g_hotpatchManager = nullptr;
static std::mutex g_initMutex;

// ============================================================================
// C API Implementation
// ============================================================================

bool InitializeHotpatchManager() {
    std::lock_guard<std::mutex> lock(g_initMutex);
    
    if (!g_hotpatchManager) {
        g_hotpatchManager = new HotpatchManagerImpl();
    }
    
    return g_hotpatchManager->Initialize();
}

void ShutdownHotpatchManager() {
    std::lock_guard<std::mutex> lock(g_initMutex);
    
    if (g_hotpatchManager) {
        g_hotpatchManager->Shutdown();
        delete g_hotpatchManager;
        g_hotpatchManager = nullptr;
    }
}

HotpatchManagerImpl* GetGlobalHotpatchManager() {
    return g_hotpatchManager;
}

// Legacy C API
extern "C" {

__declspec(dllexport) bool RawrXD_Hotpatch_Initialize() {
    return InitializeHotpatchManager();
}

__declspec(dllexport) void RawrXD_Hotpatch_Shutdown() {
    ShutdownHotpatchManager();
}

__declspec(dllexport) uint32_t RawrXD_Hotpatch_Apply(const char* name, 
                                                       const char* version,
                                                       void* target, 
                                                       void* replacement) {
    if (!g_hotpatchManager || !name || !target || !replacement) {
        return 0;
    }
    
    std::string ver = version ? version : "1.0.0";
    return g_hotpatchManager->ApplyPatch(name, ver, target, replacement, true);
}

__declspec(dllexport) bool RawrXD_Hotpatch_Restore(uint32_t patchId) {
    if (!g_hotpatchManager) return false;
    return g_hotpatchManager->RestorePatch(patchId);
}

__declspec(dllexport) void* RawrXD_Hotpatch_GetTrampoline(uint32_t patchId) {
    if (!g_hotpatchManager) return nullptr;
    return g_hotpatchManager->GetTrampoline(patchId);
}

__declspec(dllexport) bool RawrXD_Hotpatch_Validate(const void* data, size_t size) {
    if (!g_hotpatchManager) return false;
    return g_hotpatchManager->ValidatePatch(data, size);
}

// Simple hotpatch function (legacy)
__declspec(dllexport) bool hotpatch(void* target, void* replacement) {
    if (!InitializeHotpatchManager()) {
        return false;
    }
    
    uint32_t patchId = g_hotpatchManager->ApplyPatch(
        "legacy", "1.0", target, replacement, false
    );
    
    return patchId != 0;
}

} // extern "C"

} // namespace RawrXD
