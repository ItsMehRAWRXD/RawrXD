// ============================================================================
// Chamber.hpp — Deterministic Routing + SM0-DSP Clash Detector
// Productionized from Sovereign Engine architecture discussion
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <array>
#include <vector>
#include <atomic>
#include <cstring>
#include <cmath>

namespace rawrxd {

// ============================================================================
// TransitionResult — Honest state machine return (no Success lie)
// ============================================================================
enum class TransitionResult : uint8_t {
    Success   = 0,   // provisional — engine "guessed" with confidence
    Partial   = 1,   // degraded but continuing (low confidence, throttled)
    Failure   = 2,   // terminal, requires reset
};

// ============================================================================
// Primitive — Crystallized token_id, no probability attached
// Only primitives persist across forward passes
// ============================================================================
struct Primitive {
    uint32_t    token_id = 0;           // crystallized, no probability
    uint64_t    seq_pos = 0;            // absolute position in KV-cache
    bool        human_validated = false; // false until gate passes
    uint64_t    guess_id = 0;           // for audit trail
};

// ============================================================================
// FormulaRoute — Deterministic routing table entry
// No softmax. No temperature. No sampling.
// ============================================================================
struct FormulaRoute {
    uint64_t    context_hash = 0;       // deterministic key
    uint32_t    primitive_output = 0;   // fixed token_id value
    uint32_t    route_id = 0;           // opaque route identifier for tests/telemetry
    bool        valid = false;          // route exists in table
};

// ============================================================================
// TransitionState — 32×64 register vector (256 bytes)
// Fits in 4 cache lines. Detachable in 32 instructions.
// ============================================================================
struct alignas(64) TransitionState {
    uint64_t r[32];  // 32 × 64-bit = 256 bytes

    void zero() { std::memset(r, 0, sizeof(r)); }

    // Deterministic hash of hidden_state → context_hash
    static uint64_t hashHiddenState(const float* hidden_state, size_t dim);
};

// ============================================================================
// ChamberResult — Binary pass/collapse (no probability mass)
// ============================================================================
enum class ChamberResult : uint8_t {
    PASS      = 0,   // ~99% fast path
    CLASH     = 1,   // ~1% prediction miss → forced resample or eos
    NOT_READY = 2,   // mirror not initialized — engine must wait
};

// ============================================================================
// Chamber — SM0-DSP clash detector + deterministic routing
// The only component that transforms. Everything else moves or stores.
// ============================================================================
class Chamber {
public:
    static constexpr size_t MIRROR_DIM = 4096;
    static constexpr float DEFAULT_CLASH_THRESHOLD = 0.85f;
    static constexpr float LOAD_FACTOR_MAX = 0.70f;  // reject inserts above this load

    Chamber();
    ~Chamber() = default;

    // Initialize mirror vector from weight tensor (deterministic, not random)
    bool initMirror(const float* weights, size_t count);

    // Evaluate hidden_state against mirror → PASS or CLASH
    // Branch predictor trained on pass > clash
    ChamberResult evaluate(const float* hidden_state, size_t dim);

    // Deterministic routing: context_hash → primitive
    // Invariant: same input → same output, always
    FormulaRoute routePrimitive(uint64_t context_hash) const;

    // Populate routing table from GGUF tensor structure (absolute offsets)
    bool populateRoutingTable(const FormulaRoute* routes, size_t count);

    // SM0-DSP phase detector (dot product SIMD)
    float dotProductSIMD(const float* a, const float* b, size_t dim) const;

    // Mirror initialization state
    bool mirrorInitialized() const { return mirror_initialized_; }

    // Mirror storage is inline and cache-line aligned.
    // Does not guarantee hardware cache residency.
    bool mirrorResident() const;

    // Telemetry
    uint64_t passCount() const { return pass_count_.load(std::memory_order_relaxed); }
    uint64_t clashCount() const { return clash_count_.load(std::memory_order_relaxed); }
    float clashRate() const;

    // Threshold control
    void setClashThreshold(float t) {
        if (!std::isfinite(t)) return;
        clash_threshold_ = t;
    }
    float clashThreshold() const { return clash_threshold_; }

    // Routing table: sparse hash → FormulaRoute
    // For production: use flat array with modulo masking for O(1)
    static constexpr size_t ROUTE_TABLE_SIZE = 65536;  // 64K entries

private:
    alignas(64) float mirror_vector_[MIRROR_DIM];
    float clash_threshold_ = DEFAULT_CLASH_THRESHOLD;
    std::atomic<uint64_t> pass_count_{0};
    std::atomic<uint64_t> clash_count_{0};
    bool mirror_initialized_ = false;

    // Routing table: heap-allocated to avoid 1.5MB stack blow on Windows
    std::vector<FormulaRoute> routing_table_;
};

// ============================================================================
// FastenerType — Velcro vs. Shoestring classification
// ============================================================================
enum class FastenerType : uint8_t {
    Velcro    = 0,   // O(ms) attach/detach, no stream stall
    Shoestring = 1,  // O(s) or stream-fatal to detach
};

struct ResidencyObject {
    FastenerType type;
    uint64_t     inertia_mass;     // bytes + compute dependency count
    uint32_t     detach_deadline;  // max ms before stream corruption
};

// ============================================================================
// ThermalZone — Cold/Warm/Hot classification for scheduler
// ============================================================================
enum class ThermalZone : uint8_t {
    Cold  = 0,  // SSD: powdered, ∄ access without arc cloud load
    Warm  = 1,  // VRAM: baby bottle, ready to drink, passive
    Hot   = 2,  // Registers: in mouth, active computation only
};

struct WeightBottle {
    float*       vram_ptr = nullptr;
    ThermalZone  zone = ThermalZone::Cold;
};

} // namespace rawrxd
