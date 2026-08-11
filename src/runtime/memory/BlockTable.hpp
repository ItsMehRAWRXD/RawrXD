// ============================================================================
// BlockTable.hpp
// Clock-hand eviction over a fixed-capacity block table.
//
// Invariants:
//   - RefCount > 0  →  block is pinned, NEVER evicted
//   - dirty == true  →  block must be flushed before eviction
//   - state == FLUSH_PENDING  →  block is in-flight, skip eviction
//   - state == SSD_WRITE_COMPLETE  →  block is clean, safe to evict
//   - generation tracks CPU/GPU/SSD coherence
// ============================================================================
#pragma once

#include "ResidencyStateMachine.hpp"
#include <cstdint>
#include <cstring>
#include <vector>
#include <atomic>
#include <mutex>
#include <string>

namespace RawrXD {
namespace Memory {

using BlockId = uint64_t;

// ── Per-block metadata ───────────────────────────────────────────────────────

struct BlockMeta {
    BlockId                 id              = 0;
    BlockResidencyState     state           = BlockResidencyState::UNINITIALISED;
    uint64_t                bytes           = 0;
    uint32_t                refCount        = 0;
    uint64_t                lastAccess      = 0;      // monotonic clock tick
    uint64_t                secondChance    = 0;      // clock-hand second-chance bit
    BlockGeneration         generation;
    uint64_t                dataPtr         = 0;        // host VA (RAM) or device VA (VRAM)
    uint64_t                ssdOffset       = 0;        // byte offset in backing SSD file
    std::string             debugName;                  // tensor name (optional)

    BlockMeta() = default;
    BlockMeta(const BlockMeta&) = default;
    BlockMeta(BlockMeta&&) = default;
    BlockMeta& operator=(const BlockMeta& o) {
        id = o.id; state = o.state; bytes = o.bytes; refCount = o.refCount;
        lastAccess = o.lastAccess; secondChance = o.secondChance;
        generation = o.generation;
        dataPtr = o.dataPtr; ssdOffset = o.ssdOffset; debugName = o.debugName;
        return *this;
    }
    BlockMeta& operator=(BlockMeta&& o) noexcept {
        id = o.id; state = o.state; bytes = o.bytes; refCount = o.refCount;
        lastAccess = o.lastAccess; secondChance = o.secondChance;
        generation = std::move(o.generation);
        dataPtr = o.dataPtr; ssdOffset = o.ssdOffset; debugName = std::move(o.debugName);
        return *this;
    }

    // Quick predicate: is this block safe to evict?
    bool evictable() const noexcept {
        if (refCount != 0) return false;
        if (state == BlockResidencyState::RAM_DIRTY) return false;
        if (state == BlockResidencyState::FLUSH_PENDING) return false;
        if (state == BlockResidencyState::GPU_UPLOAD_PENDING) return false;
        if (state == BlockResidencyState::EVICTING) return false;
        return (state == BlockResidencyState::RAM_CLEAN ||
                state == BlockResidencyState::SSD_WRITE_COMPLETE);
    }

    bool residentInRam() const noexcept {
        return state == BlockResidencyState::RAM_CLEAN ||
               state == BlockResidencyState::RAM_DIRTY ||
               state == BlockResidencyState::FLUSH_PENDING ||
               state == BlockResidencyState::SSD_WRITE_COMPLETE;
    }

    bool residentInVram() const noexcept {
        return state == BlockResidencyState::VRAM_GPU_VALID ||
               state == BlockResidencyState::VRAM_STALE;
    }

    bool residentInSsd() const noexcept {
        return state == BlockResidencyState::SSD_CLEAN;
    }
};

// ── BlockTable ───────────────────────────────────────────────────────────────

class BlockTable {
public:
    explicit BlockTable(size_t maxBlocks);
    ~BlockTable() = default;

    // Non-copyable, non-movable.
    BlockTable(const BlockTable&) = delete;
    BlockTable& operator=(const BlockTable&) = delete;

    // ── Registration ─────────────────────────────────────────────────────────

    // Insert a new block. Returns false if table is full.
    bool insert(BlockId id, uint64_t bytes, const std::string& name = "");

    // Remove a block entirely (all tiers). Returns false if not found.
    bool remove(BlockId id);

    // ── Reference counting ───────────────────────────────────────────────────

    bool acquire(BlockId id);   // increment refCount
    bool release(BlockId id);   // decrement refCount

    // ── State transitions (with validation) ──────────────────────────────────

    bool transition(BlockId id, BlockResidencyState to);

    // Dirty a block (RAM_CLEAN → RAM_DIRTY). Bumps CPU generation.
    bool dirty(BlockId id);

    // Mark flush started (RAM_DIRTY → FLUSH_PENDING)
    bool beginFlush(BlockId id);

    // Mark flush completed (FLUSH_PENDING → SSD_WRITE_COMPLETE). Bumps SSD generation.
    bool completeFlush(BlockId id);

    // Mark ready for eviction (SSD_WRITE_COMPLETE → RAM_CLEAN)
    bool markClean(BlockId id);

    // ── Clock-hand eviction scan ─────────────────────────────────────────────

    // Scan up to 'maxScan' blocks starting at clock hand.
    // Returns the BlockId of the evicted block, or 0 if none found.
    // 'pressureThreshold' is the byte count that triggers scanning.
    BlockId runEvictionScan(uint64_t pressureThreshold, uint64_t& bytesFreed, size_t maxScan = 0);

    // ── Queries ──────────────────────────────────────────────────────────────

    BlockMeta*       find(BlockId id);
    const BlockMeta* find(BlockId id) const;

    size_t residentRamBytes() const noexcept { return m_ramBytes.load(std::memory_order_relaxed); }
    size_t residentVramBytes() const noexcept { return m_vramBytes.load(std::memory_order_relaxed); }
    size_t residentSsdBytes() const noexcept { return m_ssdBytes.load(std::memory_order_relaxed); }

    size_t blockCount() const noexcept { return m_count.load(std::memory_order_relaxed); }
    size_t capacity()   const noexcept { return m_blocks.size(); }

    // Snapshot of all blocks (for telemetry / debugging).
    std::vector<BlockMeta> snapshot() const;

    // ── Clock hand position (for testing) ────────────────────────────────────
    size_t clockHand() const noexcept { return m_clockHand.load(std::memory_order_relaxed); }

private:
    size_t indexOf(BlockId id) const;

    mutable std::mutex        m_mtx;
    std::vector<BlockMeta>    m_blocks;
    std::vector<bool>           m_occupied;
    std::atomic<size_t>         m_count{0};
    std::atomic<size_t>         m_ramBytes{0};
    std::atomic<size_t>         m_vramBytes{0};
    std::atomic<size_t>         m_ssdBytes{0};
    std::atomic<size_t>         m_clockHand{0};
    uint64_t                    m_clockTick{0};
};

} // namespace Memory
} // namespace RawrXD
