// ============================================================================
// PlacementPolicy.hpp
// Shared types for the Predictive Memory & Tensor Placement subsystem.
// ============================================================================
#pragma once

#include <cstdint>
#include <atomic>
#include <chrono>
#include <intrin.h>

namespace RawrXD {
namespace Memory {

using TensorId = uint64_t;
using DeviceId = uint32_t;

// ── Tier & State ─────────────────────────────────────────────────────────────

enum class MemoryTier : uint8_t {
    VRAM        = 0,
    SYSTEM_RAM  = 1,
    SSD         = 2,
    UNRESIDENT  = 3
};

enum class ResidencyState : uint8_t {
    Cold        = 0,
    Prefetching = 1,
    Resident    = 2,
    Evicting    = 3,
    Pinned      = 4,
    Failed      = 5
};

// ── Tensor residency record ──────────────────────────────────────────────────

struct TensorResidency {
    TensorId        id                = 0;
    MemoryTier      tier              = MemoryTier::UNRESIDENT;
    ResidencyState  state             = ResidencyState::Cold;
    uint64_t        bytes             = 0;
    uint64_t        address           = 0;      // host or device VA
    uint64_t        lastUse           = 0;      // monotonic ns
    uint64_t        nextPredictedUse  = 0;      // monotonic ns
    uint32_t        useCount          = 0;
    uint32_t        predictionScore   = 0;      // 0–1000 fixed-point
    bool            pinned            = false;
    bool            dirty             = false;
};

// ── Per-device VRAM pool ─────────────────────────────────────────────────────

struct DeviceMemoryPool {
    DeviceId  device           = 0;
    uint64_t  capacity         = 0;
    uint64_t  reserved         = 0;
    uint64_t  used             = 0;
    uint64_t  highWatermark    = 0;
    uint64_t  emergencyReserve = 0;
};

// ── Capacity policy knobs ────────────────────────────────────────────────────

struct CapacityPolicy {
    double targetUtilization  = 0.90;
    double prefetchCeiling    = 0.95;
    double emergencyReserve   = 0.03;
};

// ── Transfer request ─────────────────────────────────────────────────────────

enum class TransferPriority : uint32_t {
    Blocking      = 0,  // stalls inference until complete
    Imminent      = 1,  // next layer
    Lookahead     = 2,  // 2-3 layers ahead
    Speculative   = 3,  // prefetch prediction
    Opportunistic = 4   // best-effort background
};

struct TransferRequest {
    TensorId         tensor      = 0;
    MemoryTier       source      = MemoryTier::UNRESIDENT;
    MemoryTier       destination = MemoryTier::VRAM;
    uint64_t         bytes       = 0;
    uint64_t         deadline    = 0;   // monotonic ns; 0 = ASAP
    TransferPriority priority    = TransferPriority::Speculative;
    bool             speculative = false;
};

// ── Transfer completion token (async notification primitive) ─────────────────
// Replaces spin-wait loops with a proper synchronization primitive.
// States: Pending → Ready | Failed | Evicted
// ─────────────────────────────────────────────────────────────────────────────

enum class TransferCompletionState : uint8_t {
    Pending  = 0,
    Ready    = 1,
    Failed   = 2,
    Evicted  = 3
};

struct TransferCompletionToken {
    std::atomic<TransferCompletionState> state{TransferCompletionState::Pending};
    std::atomic<uint64_t>                address{0};   // resident VA when Ready
    std::atomic<uint64_t>                transferTimeNs{0};

    void signalReady(uint64_t addr, uint64_t t_ns = 0) noexcept {
        address.store(addr, std::memory_order_relaxed);
        transferTimeNs.store(t_ns, std::memory_order_relaxed);
        state.store(TransferCompletionState::Ready, std::memory_order_release);
    }

    void signalFailed() noexcept {
        state.store(TransferCompletionState::Failed, std::memory_order_release);
    }

    void signalEvicted() noexcept {
        state.store(TransferCompletionState::Evicted, std::memory_order_release);
    }

    // Blocking wait with optional timeout. Returns final state.
    TransferCompletionState wait(uint32_t timeoutMs = 0) const noexcept {
        if (timeoutMs == 0) {
            while (state.load(std::memory_order_acquire) == TransferCompletionState::Pending) {
                _mm_pause();
            }
            return state.load(std::memory_order_relaxed);
        }
        auto deadline = std::chrono::steady_clock::now()
                      + std::chrono::milliseconds(timeoutMs);
        while (state.load(std::memory_order_acquire) == TransferCompletionState::Pending) {
            if (std::chrono::steady_clock::now() >= deadline) {
                return TransferCompletionState::Pending;
            }
            _mm_pause();
        }
        return state.load(std::memory_order_relaxed);
    }

    bool isReady() const noexcept {
        return state.load(std::memory_order_acquire) == TransferCompletionState::Ready;
    }
};

// ── Runtime memory budget ────────────────────────────────────────────────────

struct RuntimeMemoryBudget {
    uint64_t weights   = 0;
    uint64_t kvCache   = 0;
    uint64_t staging   = 0;
    uint64_t kernels   = 0;
    uint64_t emergency = 0;
};

// ── Eviction score helper ────────────────────────────────────────────────────

// Higher score = better candidate for eviction.
// Caller supplies reuseDistance (seconds) and transferCostMs (ms).
// Pinned tensors always return 0.
inline double evictionScore(const TensorResidency& t,
                            double reuseDistanceSec,
                            double transferCostMs) noexcept {
    if (t.pinned) return 0.0;
    double ps = static_cast<double>(t.predictionScore) / 1000.0;  // 0..1
    return reuseDistanceSec * (1.0 - ps) * transferCostMs;
}

// ── Placement score ──────────────────────────────────────────────────────────

// Returns a 0–1000 fixed-point prediction score.
// Inputs:
//   executionProbability  – 0..1  (1 = certain)
//   reuseProbability      – 0..1  (1 = will be reused immediately)
//   transferCostNorm      – 0..1  (1 = very cheap to move)
//   memoryPressure        – 0..1  (0 = no pressure, 1 = critical)
inline uint32_t placementScore(double executionProbability,
                               double reuseProbability,
                               double transferCostNorm,
                               double memoryPressure) noexcept {
    double s = executionProbability
             * reuseProbability
             * transferCostNorm
             * (1.0 - memoryPressure);
    if (s < 0.0) s = 0.0;
    if (s > 1.0) s = 1.0;
    return static_cast<uint32_t>(s * 1000.0);
}

} // namespace Memory
} // namespace RawrXD
