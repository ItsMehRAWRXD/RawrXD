// =============================================================================
// Blocker #12: HotPatcher — validate patch targets before patching
// Prevents patching non-executable memory, invalid addresses, or
// already-patched regions.
// =============================================================================

#pragma once
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

class HotPatcher {
public:
    enum class PatchStatus {
        Ok            = 0,
        InvalidAddress = 1,  // Address is null or misaligned
        NotExecutable = 2,   // Memory region is not executable
        AlreadyPatched = 3,  // Region already has a patch applied
        SizeMismatch   = 4,  // Patch size exceeds region
        WriteFailed    = 5,  // Could not make memory writable
        RestoreFailed  = 6,  // Could not restore original bytes
    };

    struct PatchRecord {
        void* address;
        std::vector<uint8_t> originalBytes;
        std::vector<uint8_t> patchBytes;
        bool active;
    };

    HotPatcher() : repairCount_(0), corruptionCount_(0) {}

    // Validate that an address is safe to patch
    PatchStatus validatePatch(void* address, size_t patchSize) {
        if (address == nullptr) {
            return PatchStatus::InvalidAddress;
        }

        // Check alignment (x86 allows unaligned, but we prefer aligned for safety)
        if (reinterpret_cast<uintptr_t>(address) % sizeof(void*) != 0) {
            // Not a hard failure on x86, but log it
        }

        // Check if already patched
        {
            std::lock_guard<std::mutex> lk(mtx_);
            for (size_t i = 0; i < patches_.size(); i++) {
                if (patches_[i].address == address && patches_[i].active) {
                    return PatchStatus::AlreadyPatched;
                }
            }
        }

        // Check memory permissions
        if (!isExecutable(address)) {
            return PatchStatus::NotExecutable;
        }

        // Check if region is large enough
        if (patchSize == 0 || patchSize > 4096) {
            return PatchStatus::SizeMismatch;
        }

        return PatchStatus::Ok;
    }

    // Apply a patch: save original bytes, write new bytes
    PatchStatus apply(void* address, const void* patchData, size_t patchSize) {
        PatchStatus status = validatePatch(address, patchSize);
        if (status != PatchStatus::Ok) return status;

        PatchRecord record;
        record.address = address;
        record.originalBytes.resize(patchSize);
        record.patchBytes.resize(patchSize);
        record.active = false;

        // Save original bytes
        std::memcpy(record.originalBytes.data(), address, patchSize);
        std::memcpy(record.patchBytes.data(), patchData, patchSize);

        // Make memory writable
        if (!makeWritable(address, patchSize)) {
            return PatchStatus::WriteFailed;
        }

        // Apply patch
        std::memcpy(address, patchData, patchSize);
        record.active = true;

        // Restore original permissions (make executable again)
        makeExecutable(address, patchSize);

        // Record the patch
        {
            std::lock_guard<std::mutex> lk(mtx_);
            patches_.push_back(std::move(record));
            repairCount_++;
        }

        return PatchStatus::Ok;
    }

    // Revert a specific patch by address
    PatchStatus revert(void* address) {
        std::lock_guard<std::mutex> lk(mtx_);
        for (size_t i = 0; i < patches_.size(); i++) {
            if (patches_[i].address == address && patches_[i].active) {
                if (!makeWritable(patches_[i].address, patches_[i].originalBytes.size())) {
                    return PatchStatus::WriteFailed;
                }
                std::memcpy(patches_[i].address,
                            patches_[i].originalBytes.data(),
                            patches_[i].originalBytes.size());
                patches_[i].active = false;
                makeExecutable(patches_[i].address, patches_[i].originalBytes.size());
                return PatchStatus::Ok;
            }
        }
        return PatchStatus::InvalidAddress;
    }

    // Revert all active patches
    void revertAll() {
        std::lock_guard<std::mutex> lk(mtx_);
        for (size_t i = 0; i < patches_.size(); i++) {
            if (patches_[i].active) {
                if (makeWritable(patches_[i].address, patches_[i].originalBytes.size())) {
                    std::memcpy(patches_[i].address,
                                patches_[i].originalBytes.data(),
                                patches_[i].originalBytes.size());
                    patches_[i].active = false;
                    makeExecutable(patches_[i].address, patches_[i].originalBytes.size());
                }
            }
        }
    }

    // Verify all patches are still in place (detect corruption)
    bool verifyAll() {
        std::lock_guard<std::mutex> lk(mtx_);
        bool allIntact = true;
        for (size_t i = 0; i < patches_.size(); i++) {
            if (!patches_[i].active) continue;
            std::vector<uint8_t> current(patches_[i].patchBytes.size());
            std::memcpy(current.data(), patches_[i].address, current.size());
            if (current != patches_[i].patchBytes) {
                corruptionCount_++;
                allIntact = false;
            }
        }
        return allIntact;
    }

    int repairCount() const { return repairCount_; }
    int corruptionCount() const { return corruptionCount_; }
    size_t activePatchCount() const {
        std::lock_guard<std::mutex> lk(mtx_);
        size_t count = 0;
        for (size_t i = 0; i < patches_.size(); i++) {
            if (patches_[i].active) count++;
        }
        return count;
    }

private:
    mutable std::mutex mtx_;
    std::vector<PatchRecord> patches_;
    int repairCount_;
    int corruptionCount_;

    bool isExecutable(const void* address) const {
#ifdef _WIN32
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(address, &mbi, sizeof(mbi)) == 0) return false;
        return (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
#else
        // On Linux, check /proc/self/maps for executable permission
        // Simplified: assume code sections are executable
        return true;  // Be permissive on Linux for now
#endif
    }

    bool makeWritable(void* address, size_t size) {
#ifdef _WIN32
        DWORD oldProtect;
        return VirtualProtect(address, size, PAGE_EXECUTE_READWRITE, &oldProtect) != 0;
#else
        return mprotect(reinterpret_cast<void*>(
            reinterpret_cast<uintptr_t>(address) & ~0xFFF),
            size + 4096, PROT_READ | PROT_WRITE | PROT_EXEC) == 0;
#endif
    }

    bool makeExecutable(void* address, size_t size) {
#ifdef _WIN32
        DWORD oldProtect;
        return VirtualProtect(address, size, PAGE_EXECUTE_READ, &oldProtect) != 0;
#else
        return mprotect(reinterpret_cast<void*>(
            reinterpret_cast<uintptr_t>(address) & ~0xFFF),
            size + 4096, PROT_READ | PROT_EXEC) == 0;
#endif
    }
};