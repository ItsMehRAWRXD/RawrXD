// model_memory_hotpatch.cpp — Memory-Layer Hotpatching (Layer 1) Implementation
// Direct RAM patching using OS protection APIs.
// Expanded from Qt version — batch patching, region cookies, undo journaling,
// CRC32 integrity, conflict detection, direct memory manipulation API.
// Rule: NO SOURCE FILE IS TO BE SIMPLIFIED
#include "model_memory_hotpatch.hpp"
#include "license_enforcement.h"
#include <cstring>
#include <iostream>
#include <algorithm>
#include <chrono>
#include <vector>
#include <string>
#include <unordered_map>
#include <map>

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------
static std::mutex             g_memPatchMutex;
static std::recursive_mutex   g_windowMutex;  // Serializes begin/end_writable_window across threads
static MemoryPatchStats       g_memPatchStats;

// ---------------------------------------------------------------------------
// RegionProtectCookie — Tracks VirtualProtect state for writable windows
//
// VirtualProtect operates on whole pages.  A byte range [offset, offset+size)
// may span multiple pages, and those pages can have *different* original
// protections (e.g. PAGE_READONLY for a read-only data section adjacent to
// PAGE_READWRITE for a mutable tensor).  Capturing a single oldProtection
// value and restoring it across the entire aligned range would corrupt pages
// whose original protection differed.
//
// We therefore walk VirtualQuery page-by-page, record each page's protection
// individually, and restore them independently on close.
// ---------------------------------------------------------------------------
struct PageProtectionEntry {
    void*  pageStart;
    size_t pageSize;
    DWORD  originalProtect;
};

struct RegionProtectCookie {
    size_t                              alignedStart{0};
    size_t                              alignedSize{0};
    std::vector<PageProtectionEntry>    pages;  // one entry per page in the window
};

// ---------------------------------------------------------------------------
// NamedPatchEntry — Named patch with full metadata (batch system)
// ---------------------------------------------------------------------------
struct NamedPatchEntry {
    std::string           name;
    size_t                offset{0};
    size_t                size{0};
    std::vector<uint8_t>  patchBytes;
    std::vector<uint8_t>  originalBytes;
    bool                  enabled{true};
    bool                  verifyChecksum{false};
    uint64_t              checksumBefore{0};
    uint64_t              checksumAfter{0};
    int                   priority{0};
    uint64_t              timesApplied{0};
};

// ---------------------------------------------------------------------------
// PatchConflict
// ---------------------------------------------------------------------------
struct PatchConflict {
    NamedPatchEntry existingPatch;
    NamedPatchEntry incomingPatch;
    std::string     reason;
};

// ---------------------------------------------------------------------------
// ModelMemoryHotpatchState — Full model-attached state (replaces QObject)
// ---------------------------------------------------------------------------
struct ModelMemoryHotpatchState {
    void*                                              modelPtr{nullptr};
    size_t                                             modelSize{0};
    bool                                               attached{false};
    std::vector<uint8_t>                               fullBackup;
    std::unordered_map<std::string, NamedPatchEntry>   patches;
    uint32_t                                           integrityHash{0};
    uint64_t                                           totalApplied{0};
    uint64_t                                           totalReverted{0};
    uint64_t                                           totalFailed{0};
    uint64_t                                           bytesModified{0};
    uint64_t                                           conflictsDetected{0};
    std::mutex                                         mtx;
};

static ModelMemoryHotpatchState g_modelState;

#if defined(_MSC_VER)
static bool safe_memcpy_seh(void* dst, const void* src, size_t size) {
    __try {
        std::memcpy(dst, src, size);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}
#else
static bool safe_memcpy_seh(void* dst, const void* src, size_t size) {
    std::memcpy(dst, src, size);
    return true;
}
#endif

// ---------------------------------------------------------------------------
// safe_bounds_check — Overflow-safe range validation
// Returns true iff [offset, offset+size) is entirely within [0, regionSize).
// Rejects wrap-around (offset + size < offset) and zero-size with nonzero offset.
// ---------------------------------------------------------------------------
static bool safe_bounds_check(size_t offset, size_t size, size_t regionSize) {
    if (size == 0) return offset == 0;  // zero-length op only valid at offset 0
    if (offset > regionSize) return false;
    if (size > regionSize - offset) return false;  // cannot overflow: offset <= regionSize
    return true;
}

// Overload for two ranges (e.g. copy/swap src+dst)
static bool safe_bounds_check2(size_t off1, size_t off2, size_t size, size_t regionSize) {
    return safe_bounds_check(off1, size, regionSize) &&
           safe_bounds_check(off2, size, regionSize);
}

// ---------------------------------------------------------------------------
// is_valid_mapped_region — Verify [ptr, ptr+size) is a committed, readable
// memory region via VirtualQuery.  Prevents attach() from accepting dangling
// pointers, stack addresses, or unmapped ranges.
// ---------------------------------------------------------------------------
static bool is_valid_mapped_region(const void* ptr, size_t size) {
    if (!ptr || size == 0) return false;

    MEMORY_BASIC_INFORMATION mbi;
    const char* cursor = static_cast<const char*>(ptr);
    const char* end    = cursor + size;

    while (cursor < end) {
        SIZE_T q = VirtualQuery(cursor, &mbi, sizeof(mbi));
        if (q == 0) return false;

        // Must be committed (not free/reserved)
        if (mbi.State != MEM_COMMIT) return false;

        // Must be readable
        DWORD prot = mbi.Protect;
        bool readable = (prot & (PAGE_READONLY | PAGE_READWRITE |
                                  PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                                  PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)) != 0;
        if (!readable) return false;

        // Advance to next region boundary
        cursor = static_cast<const char*>(mbi.BaseAddress) + mbi.RegionSize;
    }
    return true;
}

// ---------------------------------------------------------------------------
// apply_memory_patch
// ---------------------------------------------------------------------------
PatchResult apply_memory_patch(void* addr, size_t size, const void* data) {
    if (!RawrXD::Enforce::LicenseEnforcer::Instance().allow(
        RawrXD::License::FeatureID::MemoryHotpatching, __FUNCTION__))
        return PatchResult::error("[LICENSE] Memory hotpatching requires Enterprise license", -1);

    if (!addr || !data || size == 0) {
        return PatchResult::error("Null address, data, or zero size", 1);
    }

    std::lock_guard<std::mutex> lock(g_memPatchMutex);

    // Attempt to make memory writable
    DWORD oldProtect = 0;
    if (!VirtualProtect(addr, size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        g_memPatchStats.totalFailed.fetch_add(1, std::memory_order_relaxed);
        return PatchResult::error("VirtualProtect (make writable) failed", static_cast<int>(GetLastError()));
    }
    g_memPatchStats.protectionChanges.fetch_add(1, std::memory_order_relaxed);

    // Write patch data
    if (!safe_memcpy_seh(addr, data, size)) {
        DWORD dummy = 0;
        VirtualProtect(addr, size, oldProtect, &dummy);
        g_memPatchStats.protectionChanges.fetch_add(1, std::memory_order_relaxed);
        g_memPatchStats.totalFailed.fetch_add(1, std::memory_order_relaxed);
        return PatchResult::error("SEH exception while writing patch bytes", 2);
    }

    // Restore original protection
    DWORD dummy = 0;
    if (!VirtualProtect(addr, size, oldProtect, &dummy)) {
        g_memPatchStats.totalFailed.fetch_add(1, std::memory_order_relaxed);
        return PatchResult::error("VirtualProtect (restore protection) failed", static_cast<int>(GetLastError()));
    }
    g_memPatchStats.protectionChanges.fetch_add(1, std::memory_order_relaxed);

    // Flush instruction cache (critical if patching code)
    FlushInstructionCache(GetCurrentProcess(), addr, size);

    g_memPatchStats.totalApplied.fetch_add(1, std::memory_order_relaxed);
    return PatchResult::ok("Memory patch applied");
}

// ---------------------------------------------------------------------------
// revert_memory_patch
// ---------------------------------------------------------------------------
PatchResult revert_memory_patch(MemoryPatchEntry* entry) {
    if (!entry) {
        return PatchResult::error("Null entry", 1);
    }
    if (!entry->applied) {
        return PatchResult::error("Patch not currently applied", 2);
    }
    if (entry->originalSize == 0) {
        return PatchResult::error("No backup data to restore", 3);
    }

    std::lock_guard<std::mutex> lock(g_memPatchMutex);

    void* addr = reinterpret_cast<void*>(entry->targetAddr);
    DWORD oldProtect = 0;
    if (!VirtualProtect(addr, entry->originalSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        g_memPatchStats.totalFailed.fetch_add(1, std::memory_order_relaxed);
        return PatchResult::error("VirtualProtect (revert) failed", static_cast<int>(GetLastError()));
    }
    g_memPatchStats.protectionChanges.fetch_add(1, std::memory_order_relaxed);

    if (!safe_memcpy_seh(addr, entry->originalBytes, entry->originalSize)) {
        DWORD dummy = 0;
        VirtualProtect(addr, entry->originalSize, oldProtect, &dummy);
        g_memPatchStats.protectionChanges.fetch_add(1, std::memory_order_relaxed);
        g_memPatchStats.totalFailed.fetch_add(1, std::memory_order_relaxed);
        return PatchResult::error("SEH exception while restoring original bytes", 4);
    }

    DWORD dummy = 0;
    if (!VirtualProtect(addr, entry->originalSize, oldProtect, &dummy)) {
        g_memPatchStats.totalFailed.fetch_add(1, std::memory_order_relaxed);
        return PatchResult::error("VirtualProtect (restore protection after revert) failed",
                                  static_cast<int>(GetLastError()));
    }
    g_memPatchStats.protectionChanges.fetch_add(1, std::memory_order_relaxed);

    FlushInstructionCache(GetCurrentProcess(), addr, entry->originalSize);

    entry->applied = false;
    g_memPatchStats.totalReverted.fetch_add(1, std::memory_order_relaxed);
    return PatchResult::ok("Memory patch reverted");
}

// ---------------------------------------------------------------------------
// apply_memory_patch_tracked
// ---------------------------------------------------------------------------
PatchResult apply_memory_patch_tracked(MemoryPatchEntry* entry) {
    if (!entry) {
        return PatchResult::error("Null entry", 1);
    }
    if (entry->patchSize == 0 || !entry->patchData) {
        return PatchResult::error("Invalid patch entry (zero size or null data)", 2);
    }
    if (entry->patchSize > sizeof(entry->originalBytes)) {
        return PatchResult::error("Patch size exceeds backup buffer (64 bytes max)", 3);
    }

    std::lock_guard<std::mutex> lock(g_memPatchMutex);

    void* addr = reinterpret_cast<void*>(entry->targetAddr);

    // Backup original bytes
    DWORD oldProtect = 0;
    if (!VirtualProtect(addr, entry->patchSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        g_memPatchStats.totalFailed.fetch_add(1, std::memory_order_relaxed);
        return PatchResult::error("VirtualProtect (backup read) failed", static_cast<int>(GetLastError()));
    }
    g_memPatchStats.protectionChanges.fetch_add(1, std::memory_order_relaxed);

    if (!safe_memcpy_seh(entry->originalBytes, addr, entry->patchSize)) {
        DWORD dummy = 0;
        VirtualProtect(addr, entry->patchSize, oldProtect, &dummy);
        g_memPatchStats.protectionChanges.fetch_add(1, std::memory_order_relaxed);
        g_memPatchStats.totalFailed.fetch_add(1, std::memory_order_relaxed);
        return PatchResult::error("SEH exception while backing up original bytes", 4);
    }
    entry->originalSize = entry->patchSize;

    // Write new data
    if (!safe_memcpy_seh(addr, entry->patchData, entry->patchSize)) {
        DWORD dummy = 0;
        VirtualProtect(addr, entry->patchSize, oldProtect, &dummy);
        g_memPatchStats.protectionChanges.fetch_add(1, std::memory_order_relaxed);
        g_memPatchStats.totalFailed.fetch_add(1, std::memory_order_relaxed);
        return PatchResult::error("SEH exception while writing tracked patch bytes", 5);
    }

    // Restore protection
    DWORD dummy = 0;
    if (!VirtualProtect(addr, entry->patchSize, oldProtect, &dummy)) {
        g_memPatchStats.totalFailed.fetch_add(1, std::memory_order_relaxed);
        return PatchResult::error("VirtualProtect (restore tracked protection) failed",
                                  static_cast<int>(GetLastError()));
    }
    g_memPatchStats.protectionChanges.fetch_add(1, std::memory_order_relaxed);

    FlushInstructionCache(GetCurrentProcess(), addr, entry->patchSize);

    entry->applied = true;
    g_memPatchStats.totalApplied.fetch_add(1, std::memory_order_relaxed);
    return PatchResult::ok("Tracked memory patch applied");
}

// ---------------------------------------------------------------------------
// query_memory_protection
// ---------------------------------------------------------------------------
PatchResult query_memory_protection(void* addr, size_t size, DWORD* outProtect) {
    if (!addr || !outProtect) {
        return PatchResult::error("Null address or output pointer", 1);
    }

    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T result = VirtualQuery(addr, &mbi, sizeof(mbi));
    if (result == 0) {
        return PatchResult::error("VirtualQuery failed", static_cast<int>(GetLastError()));
    }

    *outProtect = mbi.Protect;
    return PatchResult::ok("Protection queried");
}

// ---------------------------------------------------------------------------
// get_memory_patch_stats / reset_memory_patch_stats
// ---------------------------------------------------------------------------
const MemoryPatchStats& get_memory_patch_stats() {
    return g_memPatchStats;
}

void reset_memory_patch_stats() {
    g_memPatchStats.totalApplied.store(0, std::memory_order_relaxed);
    g_memPatchStats.totalReverted.store(0, std::memory_order_relaxed);
    g_memPatchStats.totalFailed.store(0, std::memory_order_relaxed);
    g_memPatchStats.protectionChanges.store(0, std::memory_order_relaxed);
}

// ===========================================================================
// System page size helper
// ===========================================================================
static size_t getSystemPageSize() {
    static size_t pageSize = 0;
    if (pageSize == 0) {
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        pageSize = si.dwPageSize;
    }
    return pageSize;
}

// ===========================================================================
// beginWritableWindow / endWritableWindow — Region cookies
// ===========================================================================
PatchResult begin_writable_window(void* modelPtr, size_t modelSize,
                                  size_t offset, size_t size, void*& cookie) {
    // Serialize window operations across threads.  Without this, two threads
    // opening windows on the same page would race: Thread A captures RO and
    // makes RW, Thread B captures RW and makes RW, Thread A restores RO,
    // Thread B restores RW — leaving the page incorrectly writable.
    // The recursive mutex is locked here and unlocked in end_writable_window.
    g_windowMutex.lock();

    if (!modelPtr || !safe_bounds_check(offset, size, modelSize)) {
        g_windowMutex.unlock();
        return PatchResult::error("Invalid offset or size for writable window", 1001);
    }

    size_t pageSize = getSystemPageSize();
    char*  startAddr    = static_cast<char*>(modelPtr) + offset;
    size_t alignedStart = reinterpret_cast<size_t>(startAddr) & ~(pageSize - 1);
    size_t endAddr      = reinterpret_cast<size_t>(startAddr) + size;
    size_t alignedEnd   = (endAddr + pageSize - 1) & ~(pageSize - 1);
    size_t alignedSize  = alignedEnd - alignedStart;

    auto* rc = new RegionProtectCookie();
    rc->alignedStart = alignedStart;
    rc->alignedSize  = alignedSize;

    // Walk VirtualQuery page-by-page to capture each page's original
    // protection.  This handles ranges that span pages with heterogeneous
    // protections (e.g. PAGE_READONLY adjacent to PAGE_READWRITE).
    char* cursor = reinterpret_cast<char*>(alignedStart);
    char* regionEnd = reinterpret_cast<char*>(alignedEnd);
    while (cursor < regionEnd) {
        MEMORY_BASIC_INFORMATION mbi;
        SIZE_T q = VirtualQuery(cursor, &mbi, sizeof(mbi));
        if (q == 0) {
            int err = static_cast<int>(GetLastError());
            // Roll back any pages we already made writable
            for (auto& p : rc->pages) {
                DWORD dummy = 0;
                VirtualProtect(p.pageStart, p.pageSize, p.originalProtect, &dummy);
            }
            delete rc;
            g_windowMutex.unlock();
            return PatchResult::error("VirtualQuery failed during window open", err);
        }

        // Clamp the page extent to our region boundary
        char* pageEnd = reinterpret_cast<char*>(mbi.BaseAddress) + mbi.RegionSize;
        if (pageEnd > regionEnd) pageEnd = regionEnd;
        size_t thisChunk = static_cast<size_t>(pageEnd - cursor);

        PageProtectionEntry pe;
        pe.pageStart = cursor;
        pe.pageSize  = thisChunk;
        pe.originalProtect = mbi.Protect;
        rc->pages.push_back(pe);

        cursor = pageEnd;
    }

    // Now make the entire aligned range writable in one call.  VirtualProtect
    // will set all pages to PAGE_EXECUTE_READWRITE and return the *first*
    // page's old protection (which we ignore — we have per-page values).
    DWORD firstOldProt = 0;
    if (!VirtualProtect(reinterpret_cast<void*>(alignedStart), alignedSize,
                        PAGE_EXECUTE_READWRITE, &firstOldProt)) {
        int err = static_cast<int>(GetLastError());
        delete rc;
        g_windowMutex.unlock();
        return PatchResult::error("VirtualProtect (open window) failed", err);
    }

    cookie = rc;
    return PatchResult::ok("Writable window opened");
}

PatchResult end_writable_window(void* cookie) {
    if (!cookie) {
        g_windowMutex.unlock();  // Match the lock from begin_writable_window
        return PatchResult::error("Invalid cookie", 1004);
    }

    auto* rc = static_cast<RegionProtectCookie*>(cookie);
    bool allOk = true;

    // Restore each page's original protection individually.  This correctly
    // handles ranges that span pages with heterogeneous protections.
    for (const auto& pe : rc->pages) {
        DWORD dummy = 0;
        if (!VirtualProtect(pe.pageStart, pe.pageSize, pe.originalProtect, &dummy)) {
            allOk = false;
            std::cerr << "[MemHotpatch] WARNING: VirtualProtect restore failed for page at "
                      << pe.pageStart << " (err=" << GetLastError() << ")\n";
        }
    }

    delete rc;
    g_windowMutex.unlock();  // Release the lock held since begin_writable_window
    return allOk ? PatchResult::ok("Protection restored")
                 : PatchResult::error("Some pages failed protection restore",
                                      static_cast<int>(GetLastError()));
}

// ===========================================================================
// safe_memory_write — Protected write with region cookie pattern
// ===========================================================================
PatchResult safe_memory_write(void* modelPtr, size_t modelSize,
                              size_t offset, const void* data, size_t dataSize) {
    if (!modelPtr || !data || dataSize == 0) {
        return PatchResult::error("Invalid args for safe_memory_write", 2001);
    }
    if (!safe_bounds_check(offset, dataSize, modelSize)) {
        return PatchResult::error("Out of bounds", 2002);
    }

    void* cookie = nullptr;
    PatchResult openRes = begin_writable_window(modelPtr, modelSize, offset, dataSize, cookie);
    if (!openRes.success) return openRes;

    std::memcpy(static_cast<char*>(modelPtr) + offset, data, dataSize);

    PatchResult closeRes = end_writable_window(cookie);
    if (!closeRes.success) {
        std::cerr << "[MemHotpatch] WARNING: Write succeeded but protection restore failed\n";
    }

    FlushInstructionCache(GetCurrentProcess(),
                          static_cast<char*>(modelPtr) + offset, dataSize);
    return PatchResult::ok("Safe write completed");
}

// ===========================================================================
// CRC32 integrity check
// ===========================================================================
uint32_t calculate_crc32(const void* ptr, size_t offset, size_t size, size_t maxSize) {
    if (!ptr || !safe_bounds_check(offset, size, maxSize)) return 0;

    static constexpr uint32_t CRC32_POLY = 0xEDB88320u;
    uint32_t crc = 0xFFFFFFFFu;
    const uint8_t* data = static_cast<const uint8_t*>(ptr) + offset;

    for (size_t i = 0; i < size; ++i) {
        crc ^= data[i];
        for (int j = 0; j < 8; ++j) {
            crc = (crc & 1) ? ((crc >> 1) ^ CRC32_POLY) : (crc >> 1);
        }
    }
    return crc ^ 0xFFFFFFFFu;
}

// ===========================================================================
// FNV-1a 64-bit checksum (for patch verification)
// ===========================================================================
uint64_t calculate_checksum64(const void* ptr, size_t offset, size_t size, size_t maxSize) {
    if (!ptr || !safe_bounds_check(offset, size, maxSize)) return 0;

    const char* data = static_cast<const char*>(ptr) + offset;
    uint64_t hash  = 0xcbf29ce484222325ULL;
    const uint64_t prime = 0x100000001b3ULL;

    for (size_t i = 0; i < size; ++i) {
        hash ^= static_cast<uint64_t>(data[i]);
        hash *= prime;
    }
    return hash;
}

// ===========================================================================
// Model attach / detach
// ===========================================================================
PatchResult model_hotpatch_attach(void* modelPtr, size_t modelSize) {
    std::lock_guard<std::mutex> lock(g_modelState.mtx);

    if (g_modelState.attached) {
        return PatchResult::error("Already attached — detach first", 1);
    }
    if (!modelPtr || modelSize == 0) {
        return PatchResult::error("Invalid model pointer or size", 2);
    }

    // Verify the region is actually committed, readable memory — prevents
    // accepting dangling pointers, stack addresses, or unmapped ranges.
    if (!is_valid_mapped_region(modelPtr, modelSize)) {
        return PatchResult::error("Model region is not valid committed memory", 3);
    }

    g_modelState.modelPtr    = modelPtr;
    g_modelState.modelSize   = modelSize;
    g_modelState.attached    = true;
    g_modelState.totalApplied  = 0;
    g_modelState.totalReverted = 0;
    g_modelState.totalFailed   = 0;
    g_modelState.bytesModified = 0;
    g_modelState.patches.clear();
    g_modelState.fullBackup.clear();

    std::cout << "[MemHotpatch] Attached to model at " << modelPtr
              << " (" << modelSize << " bytes)\n";
    return PatchResult::ok("Model attached");
}

PatchResult model_hotpatch_detach() {
    std::lock_guard<std::mutex> lock(g_modelState.mtx);

    if (!g_modelState.attached) {
        return PatchResult::error("Not attached", 1);
    }

    g_modelState.modelPtr  = nullptr;
    g_modelState.modelSize = 0;
    g_modelState.attached  = false;
    g_modelState.patches.clear();
    g_modelState.fullBackup.clear();

    std::cout << "[MemHotpatch] Detached from model\n";
    return PatchResult::ok("Model detached");
}

// ===========================================================================
// Full model backup / restore
// ===========================================================================
PatchResult model_create_backup() {
    std::lock_guard<std::mutex> lock(g_modelState.mtx);

    if (!g_modelState.attached) {
        return PatchResult::error("Not attached", 5001);
    }

    g_modelState.fullBackup.resize(g_modelState.modelSize);
    std::memcpy(g_modelState.fullBackup.data(), g_modelState.modelPtr,
                g_modelState.modelSize);

    std::cout << "[MemHotpatch] Full backup created (" << g_modelState.modelSize << " bytes)\n";
    return PatchResult::ok("Full model backup created");
}

PatchResult model_restore_backup() {
    std::lock_guard<std::mutex> lock(g_modelState.mtx);

    if (!g_modelState.attached || g_modelState.fullBackup.empty()) {
        return PatchResult::error("Not attached or no backup exists", 6001);
    }
    if (g_modelState.fullBackup.size() != g_modelState.modelSize) {
        return PatchResult::error("Backup size mismatch — aborting restore", 6002);
    }

    PatchResult res = safe_memory_write(g_modelState.modelPtr, g_modelState.modelSize,
                                        0, g_modelState.fullBackup.data(),
                                        g_modelState.fullBackup.size());
    if (res.success) {
        g_modelState.totalApplied  = 0;
        g_modelState.totalReverted = 0;
        g_modelState.bytesModified = 0;
        std::cout << "[MemHotpatch] Full backup restored\n";
    }
    return res;
}

// ===========================================================================
// Named patch management — add / remove / apply / revert / conflict check
// ===========================================================================
static bool check_patch_conflict(const NamedPatchEntry& newPatch,
                                 PatchConflict& conflict) {
    for (const auto& [name, existing] : g_modelState.patches) {
        if (existing.name == newPatch.name) continue;
        if (existing.size == 0 || newPatch.size == 0) continue;

        // Overflow-safe half-open interval overlap check:
        // [eStart, eEnd) ∩ [nStart, nEnd) ≠ ∅  iff  nStart < eEnd && eStart < nEnd
        size_t eStart = existing.offset;
        size_t eEnd   = existing.offset + existing.size;  // safe: size > 0, checked above
        size_t nStart = newPatch.offset;
        size_t nEnd   = newPatch.offset + newPatch.size;

        if (nStart < eEnd && eStart < nEnd) {
            if (newPatch.priority <= existing.priority) {
                conflict.existingPatch = existing;
                conflict.incomingPatch = newPatch;
                conflict.reason = "Memory overlap detected — incoming priority too low";
                return true;
            }
        }
    }
    return false;
}

PatchResult model_add_named_patch(const char* name, size_t offset, size_t size,
                                  const void* patchData, int priority) {
    std::lock_guard<std::mutex> lock(g_modelState.mtx);

    if (!name || !patchData || size == 0) {
        return PatchResult::error("Invalid patch args", 3000);
    }

    std::string patchName(name);
    if (g_modelState.patches.count(patchName)) {
        return PatchResult::error("Patch name already exists", 3001);
    }

    NamedPatchEntry entry;
    entry.name     = patchName;
    entry.offset   = offset;
    entry.size     = size;
    entry.priority = priority;
    entry.patchBytes.resize(size);
    std::memcpy(entry.patchBytes.data(), patchData, size);

    // Back up original bytes
    if (g_modelState.attached && safe_bounds_check(offset, size, g_modelState.modelSize)) {
        entry.originalBytes.resize(size);
        std::memcpy(entry.originalBytes.data(),
                    static_cast<char*>(g_modelState.modelPtr) + offset, size);
    }

    // Conflict check
    PatchConflict conflict;
    if (check_patch_conflict(entry, conflict)) {
        g_modelState.conflictsDetected++;
        return PatchResult::error("Patch conflict detected — overlap with existing patch", 3003);
    }

    g_modelState.patches[patchName] = std::move(entry);
    return PatchResult::ok("Named patch added");
}

PatchResult model_apply_named_patch(const char* name) {
    std::lock_guard<std::mutex> lock(g_modelState.mtx);

    if (!g_modelState.attached) {
        return PatchResult::error("Not attached", 3010);
    }

    auto it = g_modelState.patches.find(std::string(name));
    if (it == g_modelState.patches.end()) {
        return PatchResult::error("Patch not found", 3011);
    }

    NamedPatchEntry& patch = it->second;
    if (!patch.enabled) {
        return PatchResult::ok("Patch skipped (disabled)");
    }

    // Checksum verification before apply
    if (patch.verifyChecksum && patch.checksumBefore != 0) {
        uint64_t current = calculate_checksum64(g_modelState.modelPtr,
                                                 patch.offset, patch.size,
                                                 g_modelState.modelSize);
        if (current != patch.checksumBefore) {
            g_modelState.totalFailed++;
            return PatchResult::error("Checksum mismatch — model region changed", 3012);
        }
    }

    PatchResult res = safe_memory_write(g_modelState.modelPtr, g_modelState.modelSize,
                                        patch.offset, patch.patchBytes.data(),
                                        patch.patchBytes.size());
    if (res.success) {
        patch.timesApplied++;
        g_modelState.totalApplied++;
        g_modelState.bytesModified += patch.size;
    } else {
        g_modelState.totalFailed++;
    }
    return res;
}

PatchResult model_revert_named_patch(const char* name) {
    std::lock_guard<std::mutex> lock(g_modelState.mtx);

    if (!g_modelState.attached) {
        return PatchResult::error("Not attached", 4010);
    }

    auto it = g_modelState.patches.find(std::string(name));
    if (it == g_modelState.patches.end()) {
        return PatchResult::error("Patch not found", 4011);
    }

    NamedPatchEntry& patch = it->second;
    if (patch.originalBytes.empty()) {
        return PatchResult::error("No original bytes to restore", 4012);
    }

    PatchResult res = safe_memory_write(g_modelState.modelPtr, g_modelState.modelSize,
                                        patch.offset, patch.originalBytes.data(),
                                        patch.originalBytes.size());
    if (res.success) {
        g_modelState.totalReverted++;
    }
    return res;
}

PatchResult model_remove_named_patch(const char* name) {
    std::lock_guard<std::mutex> lock(g_modelState.mtx);

    auto it = g_modelState.patches.find(std::string(name));
    if (it == g_modelState.patches.end()) {
        return PatchResult::error("Patch not found", 3020);
    }
    if (it->second.timesApplied > 0 && !it->second.originalBytes.empty()) {
        std::cerr << "[MemHotpatch] Warning: removing applied patch '" << name << "'\n";
    }
    g_modelState.patches.erase(it);
    return PatchResult::ok("Patch removed");
}

// ===========================================================================
// Batch operations
// ===========================================================================
PatchResult model_apply_all_patches() {
    // Collect enabled patches sorted by offset
    std::map<size_t, std::string> sorted;
    {
        std::lock_guard<std::mutex> lock(g_modelState.mtx);
        for (const auto& [name, patch] : g_modelState.patches) {
            if (patch.enabled) sorted[patch.offset] = name;
        }
    }

    bool overallOk = true;
    for (const auto& [offset, name] : sorted) {
        PatchResult res = model_apply_named_patch(name.c_str());
        if (!res.success) {
            overallOk = false;
            std::cerr << "[MemHotpatch] Batch apply failed for '" << name
                      << "': " << res.detail << "\n";
        }
    }
    return overallOk ? PatchResult::ok("All patches applied")
                     : PatchResult::error("Some patches failed during batch apply", -1);
}

PatchResult model_revert_all_patches() {
    std::vector<std::string> names;
    {
        std::lock_guard<std::mutex> lock(g_modelState.mtx);
        for (const auto& [name, _] : g_modelState.patches) {
            names.push_back(name);
        }
    }

    bool overallOk = true;
    for (const auto& name : names) {
        PatchResult res = model_revert_named_patch(name.c_str());
        if (!res.success) overallOk = false;
    }
    return overallOk ? PatchResult::ok("All patches reverted")
                     : PatchResult::error("Some patches failed during batch revert", -1);
}

// ===========================================================================
// GGUF model integrity verification
// ===========================================================================
PatchResult model_verify_integrity() {
    std::lock_guard<std::mutex> lock(g_modelState.mtx);

    if (!g_modelState.attached || !g_modelState.modelPtr) {
        return PatchResult::error("Not attached", 7001);
    }

    // Verify GGUF signature
    const char* sig = static_cast<const char*>(g_modelState.modelPtr);
    if (g_modelState.modelSize < 4 || std::strncmp(sig, "GGUF", 4) != 0) {
        return PatchResult::error("Invalid GGUF signature", 7002);
    }

    // CRC32 of first 64KB
    size_t checkSize = (std::min)(g_modelState.modelSize, static_cast<size_t>(65536));
    uint32_t crc = calculate_crc32(g_modelState.modelPtr, 0, checkSize, g_modelState.modelSize);

    if (g_modelState.integrityHash != 0 && g_modelState.integrityHash != crc) {
        return PatchResult::error("Integrity hash mismatch", 7003);
    }

    g_modelState.integrityHash = crc;
    return PatchResult::ok("Model integrity verified");
}

// ===========================================================================
// Direct memory manipulation API (mirrors Qt version)
// ===========================================================================
void* model_get_direct_pointer(size_t offset) {
    std::lock_guard<std::mutex> lock(g_modelState.mtx);
    if (!g_modelState.attached || offset >= g_modelState.modelSize) return nullptr;
    // Ensure at least 1 byte is accessible at offset
    if (!safe_bounds_check(offset, 1, g_modelState.modelSize)) return nullptr;
    return static_cast<char*>(g_modelState.modelPtr) + offset;
}

PatchResult model_direct_read(size_t offset, size_t size, void* dest) {
    std::lock_guard<std::mutex> lock(g_modelState.mtx);

    if (!g_modelState.attached || !dest) {
        return PatchResult::error("Not attached or null dest", 6001);
    }
    if (!safe_bounds_check(offset, size, g_modelState.modelSize)) {
        return PatchResult::error("Read out of bounds", 6002);
    }

    std::memcpy(dest, static_cast<char*>(g_modelState.modelPtr) + offset, size);
    return PatchResult::ok("Direct read completed");
}

PatchResult model_direct_write(size_t offset, const void* data, size_t size) {
    if (!g_modelState.attached) {
        return PatchResult::error("Not attached", 6003);
    }
    return safe_memory_write(g_modelState.modelPtr, g_modelState.modelSize,
                             offset, data, size);
}

PatchResult model_direct_fill(size_t offset, size_t size, uint8_t value) {
    std::lock_guard<std::mutex> lock(g_modelState.mtx);

    if (!g_modelState.attached) return PatchResult::error("Not attached", 6005);
    if (!safe_bounds_check(offset, size, g_modelState.modelSize)) return PatchResult::error("Fill out of bounds", 6006);

    void* cookie = nullptr;
    PatchResult openRes = begin_writable_window(g_modelState.modelPtr,
                                                g_modelState.modelSize,
                                                offset, size, cookie);
    if (!openRes.success) return openRes;

    std::memset(static_cast<char*>(g_modelState.modelPtr) + offset, value, size);
    g_modelState.bytesModified += size;

    end_writable_window(cookie);
    return PatchResult::ok("Fill completed");
}

PatchResult model_direct_copy(size_t srcOffset, size_t dstOffset, size_t size) {
    std::lock_guard<std::mutex> lock(g_modelState.mtx);

    if (!g_modelState.attached) return PatchResult::error("Not attached", 6007);
    if (!safe_bounds_check2(srcOffset, dstOffset, size, g_modelState.modelSize)) {
        return PatchResult::error("Copy out of bounds", 6008);
    }

    // Use a single writable window covering both src and dst to handle
    // overlapping regions correctly — memmove handles the copy semantics,
    // but the source bytes may live in a page that needs write access
    // when src and dst overlap.
    size_t winOff = (std::min)(srcOffset, dstOffset);
    size_t winEnd = (std::max)(srcOffset, dstOffset) + size;
    void* cookie = nullptr;
    PatchResult openRes = begin_writable_window(g_modelState.modelPtr,
                                                g_modelState.modelSize,
                                                winOff, winEnd - winOff, cookie);
    if (!openRes.success) return openRes;

    std::memmove(static_cast<char*>(g_modelState.modelPtr) + dstOffset,
                 static_cast<char*>(g_modelState.modelPtr) + srcOffset, size);
    g_modelState.bytesModified += size;

    end_writable_window(cookie);
    return PatchResult::ok("Copy completed");
}

int64_t model_direct_search(size_t startOffset, const void* pattern, size_t patternLen) {
    std::lock_guard<std::mutex> lock(g_modelState.mtx);

    if (!g_modelState.attached || !pattern || patternLen == 0) return -1;
    if (startOffset >= g_modelState.modelSize) return -1;
    if (patternLen > g_modelState.modelSize - startOffset) return -1;  // pattern longer than remaining

    const char* base = static_cast<const char*>(g_modelState.modelPtr);
    const char* haystack = base + startOffset;
    size_t haystackLen   = g_modelState.modelSize - startOffset;

    const char* found = std::search(haystack, haystack + haystackLen,
                                    static_cast<const char*>(pattern),
                                    static_cast<const char*>(pattern) + patternLen);
    if (found != haystack + haystackLen) {
        return static_cast<int64_t>(found - base);
    }
    return -1;
}

PatchResult model_direct_swap(size_t offset1, size_t offset2, size_t size) {
    std::lock_guard<std::mutex> lock(g_modelState.mtx);

    if (!g_modelState.attached) return PatchResult::error("Not attached", 6009);
    if (!safe_bounds_check2(offset1, offset2, size, g_modelState.modelSize)) {
        return PatchResult::error("Swap out of bounds", 6010);
    }

    std::vector<uint8_t> temp(size);
    std::memcpy(temp.data(), static_cast<char*>(g_modelState.modelPtr) + offset1, size);

    // Use a single writable window covering [min, max+size) to handle
    // overlapping regions correctly — two separate windows would race
    // on protection restoration when offset1 and offset2 overlap.
    size_t winOff = (std::min)(offset1, offset2);
    size_t winEnd = (std::max)(offset1, offset2) + size;
    void* cookie = nullptr;
    PatchResult openRes = begin_writable_window(g_modelState.modelPtr,
                                                g_modelState.modelSize,
                                                winOff, winEnd - winOff, cookie);
    if (!openRes.success) {
        return PatchResult::error("Swap: failed to open combined writable window", 6011);
    }

    std::memcpy(static_cast<char*>(g_modelState.modelPtr) + offset1,
                static_cast<char*>(g_modelState.modelPtr) + offset2, size);
    std::memcpy(static_cast<char*>(g_modelState.modelPtr) + offset2, temp.data(), size);

    end_writable_window(cookie);

    g_modelState.bytesModified += 2 * size;
    return PatchResult::ok("Swap completed");
}
