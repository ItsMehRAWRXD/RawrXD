// ============================================================================
// VRAMManager.hpp - MARS: Memory Allocation + Routing System
// Allocate, Evict, Migrate, Restore
// ============================================================================

#pragma once

#include "VRAMLease.hpp"
#include <vector>
#include <unordered_map>
#include <mutex>
#include <functional>
#include <memory>

namespace Deep2 {
namespace MARS {

// ============================================================================
// Migration Record (for rollback)
// ============================================================================
struct MigrationRecord {
    uint64_t tensorId;
    int      fromGPU;
    int      toGPU;
    size_t   bytes;
    uint64_t timestamp;
};

// ============================================================================
// VRAM Manager
// Manages tensor leases across dual GPUs with dynamic routing.
// ============================================================================
class VRAMManager {
public:
    VRAMManager();
    ~VRAMManager();

    // ------------------------------------------------------------------------
    // Lifecycle
    // ------------------------------------------------------------------------
    bool Initialize(size_t gpu0TotalBytes, size_t gpu1TotalBytes);
    void Shutdown();
    bool IsInitialized() const { return initialized_; }

    // ------------------------------------------------------------------------
    // Core Operations
    // ------------------------------------------------------------------------
    // Allocate a lease on the best GPU (or host if nowhere fits)
    VRAMLease* Allocate(
        uint64_t tensorId,
        const std::string& name,
        size_t bytes,
        float priority = 1.0f,
        bool hotpatchable = true);

    // Evict lease to host memory / SSD
    bool Evict(VRAMLease* lease);

    // Migrate lease to target GPU
    bool Migrate(VRAMLease* lease, int targetGPU);

    // Restore evicted lease back to VRAM
    bool Restore(VRAMLease* lease, int preferredGPU = -1);

    // Free lease and reclaim VRAM
    void Free(VRAMLease* lease);

    // ------------------------------------------------------------------------
    // Bulk Operations
    // ------------------------------------------------------------------------
    void EvictAllOnGPU(int gpu);
    void MigrateAll(int fromGPU, int toGPU);
    void FreeAll();

    // ------------------------------------------------------------------------
    // Queries
    // ------------------------------------------------------------------------
    VRAMLease* GetLease(uint64_t tensorId);
    const VRAMLease* GetLease(uint64_t tensorId) const;
    size_t GetUsedVRAM(int gpu) const;
    size_t GetFreeVRAM(int gpu) const;
    size_t GetTotalVRAM(int gpu) const;
    size_t GetLeaseCount() const;
    size_t GetResidentCount(int gpu) const;

    // Snapshot of live lease pointers (valid until Free/Shutdown).
    std::vector<VRAMLease*> SnapshotLeases() const;

    // ------------------------------------------------------------------------
    // Dynamic Parity
    // ------------------------------------------------------------------------
    void UpdateGPUState(int gpu, const GPUState& state);
    DynamicParity GetDynamicParity() const;

    // ------------------------------------------------------------------------
    // Strategy
    // ------------------------------------------------------------------------
    int SelectBestGPU(size_t bytes, float priority, bool preferLowLatency) const;

    // ------------------------------------------------------------------------
    // Events
    // ------------------------------------------------------------------------
    using EvictCallback = std::function<void(const VRAMLease&)>;
    using MigrateCallback = std::function<void(const VRAMLease&, int from, int to)>;
    using OOMCallback = std::function<bool(size_t bytes, int gpu)>;

    void SetEvictCallback(EvictCallback cb);
    void SetMigrateCallback(MigrateCallback cb);
    void SetOOMCallback(OOMCallback cb);

    // ------------------------------------------------------------------------
    // Rollback
    // ------------------------------------------------------------------------
    bool RollbackLastMigration(uint64_t tensorId);
    void ClearMigrationHistory(uint64_t tensorId);

    // ------------------------------------------------------------------------
    // Stats
    // ------------------------------------------------------------------------
    struct Stats {
        uint64_t totalAllocated = 0;
        uint64_t totalFreed = 0;
        uint64_t totalMigrated = 0;
        uint64_t totalEvicted = 0;
        uint64_t totalRestored = 0;
        uint64_t oomCount = 0;
        uint64_t rollbackCount = 0;
        uint64_t peakUsed[2] = {0, 0};
        uint64_t bytesHostToGpu = 0;
        uint64_t bytesNvmeToRam = 0;
        uint32_t residencyMisses = 0;
        uint32_t spillToRam = 0;
        uint32_t spillToNvme = 0;
    };
    Stats GetStats() const;
    void ResetStats();
    void ResetRunPeaks();
    void NoteNvmeToRam(uint64_t bytes);
    void NoteResidencyMiss();
    void NoteSpillToNvme();

    // Live snapshot for INV-4 / Resource Map
    struct LiveSnapshot {
        uint64_t usedVram[2] = {0, 0};
        uint64_t peakVram[2] = {0, 0};
        uint64_t totalVram[2] = {0, 0};
        uint64_t peakVramTotal = 0;
        uint64_t bytesHostToGpu = 0;
        uint64_t bytesNvmeToRam = 0;
        uint32_t migrations = 0;
        uint32_t residencyMisses = 0;
        uint32_t spillToRam = 0;
        uint32_t spillToNvme = 0;
        uint32_t residentCount = 0;
    };
    LiveSnapshot SnapshotLive() const;

private:
    bool initialized_ = false;

    // Per-GPU VRAM tracking
    size_t gpuTotal_[2] = {0, 0};
    size_t gpuUsed_[2]  = {0, 0};
    size_t gpuPeak_[2]  = {0, 0};
    mutable std::mutex gpuMutex_;

    // Lease registry
    std::unordered_map<uint64_t, std::unique_ptr<VRAMLease>> leases_;
    mutable std::mutex leaseMutex_;

    // Migration history for rollback
    std::unordered_map<uint64_t, std::vector<MigrationRecord>> migrationHistory_;
    mutable std::mutex historyMutex_;

    // GPU state
    GPUState gpuState_[2];
    mutable std::mutex stateMutex_;

    // Callbacks
    EvictCallback onEvict_;
    MigrateCallback onMigrate_;
    OOMCallback onOOM_;

    // Stats
    Stats stats_;
    mutable std::mutex statsMutex_;

    // Internal
    bool TryReserveVRAM(int gpu, size_t bytes);
    void ReleaseVRAM(int gpu, size_t bytes);
    int FindVictimGPU(size_t bytesNeeded, int requestingGPU) const;
    void RecordMigration(const VRAMLease& lease, int from, int to);
};

} // namespace MARS
} // namespace Deep2
