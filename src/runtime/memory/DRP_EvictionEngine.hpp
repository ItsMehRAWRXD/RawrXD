// ============================================================================
// DRP_EvictionEngine.hpp
// Dynamic Residency Policy — eviction + flush orchestration.
//
// Exposes:
//   DRP_RunEvictionScan()   — clock-hand scan under RAM pressure
//   DRP_EnqueueSSDFlush()   — async dirty-block write-back
//
// Integration point for StreamingMatMul:
//   StreamingMatMul
//        │
//        ▼
//   Residency lookup (BlockTable)
//        │
//        ├── RAM hit ───────────────► compute
//        ├── SSD resident ──────────► promote RAM ─► compute
//        └── VRAM resident ────────► GPU compute
//        │
//        ▼
//   access accounting
//        │
//        ▼
//   pressure detection
//        │
//        ▼
//   DRP_RunEvictionScan()
// ============================================================================
#pragma once

#include "BlockTable.hpp"
#include "SSDWriteBackQueue.hpp"
#include <cstdint>
#include <string>
#include <functional>

namespace RawrXD {
namespace Memory {

// ── Residency lookup result ────────────────────────────────────────────────

struct ResidencyLookupResult {
    enum class Action {
        RAM_HIT,        // block in RAM, ready for compute
        SSD_PROMOTE,    // block on SSD, must load to RAM first
        VRAM_HIT,       // block in VRAM, GPU compute
        VRAM_STALE,     // block in VRAM but stale, re-upload needed
        NOT_FOUND       // block unknown
    };
    Action      action = Action::NOT_FOUND;
    BlockId     blockId = 0;
    uint64_t    dataPtr = 0;        // host VA or device VA
    uint64_t    bytes   = 0;
    uint64_t    ssdOffset = 0;      // for SSD_PROMOTE
};

// ── DRP Eviction Engine ──────────────────────────────────────────────────────

class DRPEvictionEngine {
public:
    DRPEvictionEngine(BlockTable& table, SSDWriteBackQueue& queue);
    ~DRPEvictionEngine() = default;

    // Non-copyable, non-movable.
    DRPEvictionEngine(const DRPEvictionEngine&) = delete;
    DRPEvictionEngine& operator=(const DRPEvictionEngine&) = delete;

    // ── Configuration ────────────────────────────────────────────────────────

    struct Config {
        uint64_t ramPressureThreshold = 48ULL * 1024 * 1024 * 1024; // 48 GB
        uint64_t vramPressureThreshold = 28ULL * 1024 * 1024 * 1024; // 28 GB
        size_t   maxScanPerEviction   = 256;   // blocks to inspect per scan
        uint32_t flushBatchSize       = 8;     // max flushes per trigger
        bool     enableSecondChance   = true;
    };
    void setConfig(const Config& cfg) { m_cfg = cfg; }
    const Config& config() const { return m_cfg; }

    // ── Residency lookup (hot path) ──────────────────────────────────────────

    // Fast O(n) lookup by block ID.  Does NOT modify state.
    ResidencyLookupResult lookup(BlockId id) const;

    // ── Access accounting ────────────────────────────────────────────────────

    // Call after every tensor access to update lastAccess / secondChance.
    void recordAccess(BlockId id);

    // ── Pressure detection ───────────────────────────────────────────────────

    bool ramUnderPressure() const;
    bool vramUnderPressure() const;

    // ── Eviction ───────────────────────────────────────────────────────────────

    // Run one eviction scan.  Returns number of bytes freed.
    // If 'flushDirtyFirst' is true, dirty blocks are flushed before eviction.
    uint64_t runEvictionScan(bool flushDirtyFirst = true);

    // ── Flush ──────────────────────────────────────────────────────────────────

    // Enqueue all dirty blocks for async SSD write-back.
    // Returns number of blocks enqueued.
    size_t enqueueAllDirtyFlushes();

    // Enqueue a single dirty block for flush.
    bool enqueueSSDFlush(BlockId id);

    // ── Promotion ────────────────────────────────────────────────────────────

    // Promote block from SSD to RAM (synchronous load).
    // 'loader' reads bytes from SSD offset into host buffer.
    bool promoteFromSSD(BlockId id,
                        std::function<bool(uint64_t ssdOffset, uint64_t bytes, void* dst)> loader);

    // ── GPU upload ─────────────────────────────────────────────────────────────

    // Initiate GPU upload from RAM.  Block transitions: RAM_CLEAN → GPU_UPLOAD_PENDING.
    // Actual upload is asynchronous; completion transitions to VRAM_GPU_VALID.
    bool beginGPUUpload(BlockId id, uint64_t deviceBufferPtr);

    // Mark GPU upload complete (called by DMA completion / fence signal).
    bool completeGPUUpload(BlockId id);

    // ── Telemetry ──────────────────────────────────────────────────────────────

    struct Telemetry {
        uint64_t evictionScans = 0;
        uint64_t blocksEvicted = 0;
        uint64_t bytesEvicted = 0;
        uint64_t dirtyFlushesEnqueued = 0;
        uint64_t promotionsFromSSD = 0;
        uint64_t gpuUploadsStarted = 0;
        uint64_t gpuUploadsCompleted = 0;
    };
    Telemetry telemetry() const { return m_telemetry; }
    void resetTelemetry() { m_telemetry = Telemetry{}; }

private:
    BlockTable&            m_table;
    SSDWriteBackQueue&     m_queue;
    Config                 m_cfg;
    Telemetry              m_telemetry;
    mutable std::mutex     m_telemetryMtx;
};

} // namespace Memory
} // namespace RawrXD
