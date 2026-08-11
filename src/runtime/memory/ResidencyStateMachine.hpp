// ============================================================================
// ResidencyStateMachine.hpp
// Unambiguous block ownership / state transitions for RAM / SSD / VRAM tiers.
//
// State machine (per block):
//   RAM + CLEAN
//      │ pressure + old + RefCount==0
//      ▼
//   RAM + EVICT_CANDIDATE
//      │
//      ├── dirty ──► FLUSH_PENDING ──► SSD_WRITE_COMPLETE ──► CLEAN
//      │
//      └── clean ──► SSD + CLEAN
//
//   RAM/CLEAN
//      │ GPU demand
//      ▼
//   GPU_UPLOAD_PENDING
//      │
//      ▼
//   VRAM + GPU_VALID
//
// Critical invariant: a block is NEVER evicted while dirty or in-flight.
// ============================================================================
#pragma once

#include <cstdint>
#include <atomic>

namespace RawrXD {
namespace Memory {

// ── Per-block residency state ──────────────────────────────────────────────

enum class BlockResidencyState : uint8_t {
    // Resident in RAM, authoritative copy matches SSD
    RAM_CLEAN = 0,

    // Resident in RAM, modified since last SSD persistence
    RAM_DIRTY = 1,

    // Async SSD write in progress; block still in RAM
    FLUSH_PENDING = 2,

    // SSD write completed; block may now be evicted safely
    SSD_WRITE_COMPLETE = 3,

    // Resident on SSD, not in RAM
    SSD_CLEAN = 4,

    // GPU upload in progress from RAM
    GPU_UPLOAD_PENDING = 5,

    // Resident in VRAM, generation matches CPU
    VRAM_GPU_VALID = 6,

    // VRAM copy is stale (CPU generation advanced)
    VRAM_STALE = 7,

    // Block is being evicted from RAM (transient)
    EVICTING = 8,

    // Invalid / uninitialised
    UNINITIALISED = 255
};

// ── Tier mapping ───────────────────────────────────────────────────────────

enum class ResidencyTier : uint8_t {
    UNRESIDENT = 0,
    SSD        = 1,
    RAM        = 2,
    VRAM       = 3
};

inline ResidencyTier tierFromState(BlockResidencyState s) noexcept {
    switch (s) {
        case BlockResidencyState::RAM_CLEAN:
        case BlockResidencyState::RAM_DIRTY:
        case BlockResidencyState::FLUSH_PENDING:
        case BlockResidencyState::SSD_WRITE_COMPLETE:
            return ResidencyTier::RAM;
        case BlockResidencyState::SSD_CLEAN:
            return ResidencyTier::SSD;
        case BlockResidencyState::GPU_UPLOAD_PENDING:
        case BlockResidencyState::VRAM_GPU_VALID:
        case BlockResidencyState::VRAM_STALE:
            return ResidencyTier::VRAM;
        default:
            return ResidencyTier::UNRESIDENT;
    }
}

// ── Transition validation table ──────────────────────────────────────────────
// Returns true if 'from → to' is a legal transition.
inline bool IsLegalTransition(BlockResidencyState from, BlockResidencyState to) noexcept {
    switch (from) {
        case BlockResidencyState::UNINITIALISED:
            return to == BlockResidencyState::RAM_CLEAN || to == BlockResidencyState::SSD_CLEAN;

        case BlockResidencyState::RAM_CLEAN:
            return to == BlockResidencyState::RAM_DIRTY
                || to == BlockResidencyState::EVICTING
                || to == BlockResidencyState::GPU_UPLOAD_PENDING
                || to == BlockResidencyState::SSD_CLEAN;   // direct demotion (rare)

        case BlockResidencyState::RAM_DIRTY:
            return to == BlockResidencyState::FLUSH_PENDING
                || to == BlockResidencyState::RAM_CLEAN;     // in-place overwrite

        case BlockResidencyState::FLUSH_PENDING:
            return to == BlockResidencyState::SSD_WRITE_COMPLETE
                || to == BlockResidencyState::RAM_DIRTY;     // re-dirtied while flushing

        case BlockResidencyState::SSD_WRITE_COMPLETE:
            return to == BlockResidencyState::RAM_CLEAN
                || to == BlockResidencyState::EVICTING;

        case BlockResidencyState::SSD_CLEAN:
            return to == BlockResidencyState::RAM_CLEAN        // promotion
                || to == BlockResidencyState::GPU_UPLOAD_PENDING; // direct to VRAM (bypass RAM)

        case BlockResidencyState::EVICTING:
            return to == BlockResidencyState::SSD_CLEAN;

        case BlockResidencyState::GPU_UPLOAD_PENDING:
            return to == BlockResidencyState::VRAM_GPU_VALID
                || to == BlockResidencyState::RAM_CLEAN;       // upload failed / cancelled

        case BlockResidencyState::VRAM_GPU_VALID:
            return to == BlockResidencyState::VRAM_STALE
                || to == BlockResidencyState::RAM_CLEAN;       // eviction from VRAM

        case BlockResidencyState::VRAM_STALE:
            return to == BlockResidencyState::GPU_UPLOAD_PENDING // re-upload
                || to == BlockResidencyState::RAM_CLEAN;       // discard VRAM copy

        default:
            return false;
    }
}

// ── Generation / version tracking ──────────────────────────────────────────
// Every resident object has a generation relationship:
//   CPU generation = 17, GPU generation = 16  →  VRAM is stale
//   After upload: CPU = 17, GPU = 17          →  VRAM is valid
// -----------------------------------------------------------------------------

struct BlockGeneration {
    std::atomic<uint64_t> cpuGen{0};
    std::atomic<uint64_t> gpuGen{0};
    std::atomic<uint64_t> ssdGen{0};

    BlockGeneration() = default;
    BlockGeneration(const BlockGeneration& o)
        : cpuGen(o.cpuGen.load(std::memory_order_relaxed))
        , gpuGen(o.gpuGen.load(std::memory_order_relaxed))
        , ssdGen(o.ssdGen.load(std::memory_order_relaxed)) {}
    BlockGeneration(BlockGeneration&& o) noexcept
        : cpuGen(o.cpuGen.load(std::memory_order_relaxed))
        , gpuGen(o.gpuGen.load(std::memory_order_relaxed))
        , ssdGen(o.ssdGen.load(std::memory_order_relaxed)) {}
    BlockGeneration& operator=(const BlockGeneration& o) {
        cpuGen.store(o.cpuGen.load(std::memory_order_relaxed), std::memory_order_relaxed);
        gpuGen.store(o.gpuGen.load(std::memory_order_relaxed), std::memory_order_relaxed);
        ssdGen.store(o.ssdGen.load(std::memory_order_relaxed), std::memory_order_relaxed);
        return *this;
    }
    BlockGeneration& operator=(BlockGeneration&& o) noexcept {
        cpuGen.store(o.cpuGen.load(std::memory_order_relaxed), std::memory_order_relaxed);
        gpuGen.store(o.gpuGen.load(std::memory_order_relaxed), std::memory_order_relaxed);
        ssdGen.store(o.ssdGen.load(std::memory_order_relaxed), std::memory_order_relaxed);
        return *this;
    }

    void bumpCpu() noexcept { cpuGen.fetch_add(1, std::memory_order_relaxed); }
    void bumpGpu() noexcept { gpuGen.fetch_add(1, std::memory_order_relaxed); }
    void bumpSsd() noexcept { ssdGen.fetch_add(1, std::memory_order_relaxed); }

    bool gpuValid() const noexcept {
        return cpuGen.load(std::memory_order_acquire) == gpuGen.load(std::memory_order_acquire);
    }
    bool ssdValid() const noexcept {
        return cpuGen.load(std::memory_order_acquire) == ssdGen.load(std::memory_order_acquire);
    }
};

// ── Human-readable names (debug / telemetry) ─────────────────────────────────

inline const char* StateName(BlockResidencyState s) noexcept {
    switch (s) {
        case BlockResidencyState::RAM_CLEAN:           return "RAM_CLEAN";
        case BlockResidencyState::RAM_DIRTY:           return "RAM_DIRTY";
        case BlockResidencyState::FLUSH_PENDING:       return "FLUSH_PENDING";
        case BlockResidencyState::SSD_WRITE_COMPLETE:   return "SSD_WRITE_COMPLETE";
        case BlockResidencyState::SSD_CLEAN:            return "SSD_CLEAN";
        case BlockResidencyState::GPU_UPLOAD_PENDING:   return "GPU_UPLOAD_PENDING";
        case BlockResidencyState::VRAM_GPU_VALID:       return "VRAM_GPU_VALID";
        case BlockResidencyState::VRAM_STALE:           return "VRAM_STALE";
        case BlockResidencyState::EVICTING:             return "EVICTING";
        case BlockResidencyState::UNINITIALISED:        return "UNINITIALISED";
        default:                                        return "UNKNOWN";
    }
}

inline const char* TierName(ResidencyTier t) noexcept {
    switch (t) {
        case ResidencyTier::UNRESIDENT: return "UNRESIDENT";
        case ResidencyTier::SSD:        return "SSD";
        case ResidencyTier::RAM:        return "RAM";
        case ResidencyTier::VRAM:       return "VRAM";
        default:                        return "UNKNOWN";
    }
}

} // namespace Memory
} // namespace RawrXD
