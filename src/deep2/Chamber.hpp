// ============================================================================
// Chamber.hpp — SM0-DSP Clash Detector + Deterministic Routing
// Productionized from Sovereign Engine architecture
// ============================================================================

#pragma once

#include <cstddef>
#include <cstdint>
#include <atomic>
#include <array>

namespace rawrxd {

// ============================================================================
// ChamberResult — Binary pass/collapse decision
// ============================================================================
enum class ChamberResult {
    PASS,      // Hidden state aligns with mirror
    CLASH,     // Hidden state diverges from mirror
    NOT_READY  // Mirror uninitialized — explicit no-decision state
};

// ============================================================================
// FormulaRoute — Deterministic routing entry
// ============================================================================
struct FormulaRoute {
    uint64_t context_hash = 0;
    uint32_t route_id     = 0;
    bool     valid        = false;
};

// ============================================================================
// TransitionState — Deterministic hash utilities
// ============================================================================
namespace TransitionState {
    // FNV-1a 64-bit hash of float bits.
    // Returns 0 on null input or zero dimension.
    uint64_t hashHiddenState(const float* hidden_state, size_t dim);
} // namespace TransitionState

// ============================================================================
// Chamber — Fixed-size clash detector + deterministic route table
//
// Invariants:
//   - mirror_vector_ is inline (object lifetime, no separate allocation)
//   - routing table is bounded and uses linear probing
//   - duplicate hashes replace existing routes (update semantics)
//   - table load factor is capped to prevent unbounded probing
// ============================================================================
class Chamber {
public:
    static constexpr size_t   MIRROR_DIM         = 4096;
    static constexpr size_t   ROUTE_TABLE_SIZE     = 256;
    static constexpr float    DEFAULT_CLASH_THRESHOLD = 0.5f;
    static constexpr float    LOAD_FACTOR_MAX      = 0.70f;
    static constexpr float    EPSILON              = 1e-5f;

    Chamber();

    // Initialize mirror vector from external weights.
    // Zero-pads if count < MIRROR_DIM.
    bool initMirror(const float* weights, size_t count);

    // Evaluate hidden state against mirror.
    // Returns NOT_READY if mirror is uninitialized.
    ChamberResult evaluate(const float* hidden_state, size_t dim);

    // Deterministic route lookup by context hash.
    // Returns invalid FormulaRoute if no match.
    FormulaRoute routePrimitive(uint64_t context_hash) const;

    // Populate routing table from an array of routes.
    // Rejects if table would exceed load-factor cap or if any insertion fails.
    bool populateRoutingTable(const FormulaRoute* routes, size_t count);

    // Mirror residency invariant: inline by construction
    bool mirrorResident() const { return true; }

    // Mirror initialization state
    bool mirrorInitialized() const { return mirror_initialized_; }

    // Statistics
    float clashRate() const;
    uint64_t passCount() const { return pass_count_.load(std::memory_order_relaxed); }
    uint64_t clashCount() const { return clash_count_.load(std::memory_order_relaxed); }

private:
    float dotProductSIMD(const float* a, const float* b, size_t dim) const;

    float               mirror_vector_[MIRROR_DIM];
    bool                mirror_initialized_ = false;
    float               clash_threshold_;

    std::array<FormulaRoute, ROUTE_TABLE_SIZE> routing_table_;

    std::atomic<uint64_t> pass_count_{0};
    std::atomic<uint64_t> clash_count_{0};
};

} // namespace rawrxd
