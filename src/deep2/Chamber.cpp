// ============================================================================
// Chamber.cpp — SM0-DSP Clash Detector + Deterministic Routing
// Productionized from Sovereign Engine architecture
// ============================================================================

#include "Chamber.hpp"
#include <cmath>
#include <algorithm>
#include <cstring>

#if defined(__AVX2__)
    #include <immintrin.h>
#endif

namespace rawrxd {

// ============================================================================
// TransitionState — Deterministic hash (FNV-1a variant)
// ============================================================================
uint64_t TransitionState::hashHiddenState(const float* hidden_state, size_t dim) {
    if (!hidden_state || dim == 0) return 0;

    // FNV-1a 64-bit hash of float bits, processed byte-by-byte
    // for explicit cross-platform determinism.
    constexpr uint64_t FNV_OFFSET_BASIS = 0xCBF29CE484222325ULL;
    constexpr uint64_t FNV_PRIME        = 0x100000001B3ULL;

    uint64_t hash = FNV_OFFSET_BASIS;
    for (size_t i = 0; i < dim; ++i) {
        uint32_t bits;
        static_assert(sizeof(bits) == sizeof(float), "float size mismatch");
        std::memcpy(&bits, &hidden_state[i], sizeof(float));

        // Hash each byte explicitly to avoid endianness ambiguity
        for (unsigned byte = 0; byte < 4; ++byte) {
            hash ^= static_cast<uint8_t>(bits >> (byte * 8));
            hash *= FNV_PRIME;
        }
    }
    return hash;
}

// ============================================================================
// Chamber — Construction / Init
// ============================================================================
Chamber::Chamber() : clash_threshold_(DEFAULT_CLASH_THRESHOLD) {
    std::memset(mirror_vector_, 0, sizeof(mirror_vector_));
    // All routes default to invalid
    for (auto& route : routing_table_) {
        route = FormulaRoute{};
    }
}

bool Chamber::initMirror(const float* weights, size_t count) {
    if (!weights || count == 0) return false;
    size_t to_copy = std::min(count, MIRROR_DIM);
    std::memcpy(mirror_vector_, weights, to_copy * sizeof(float));
    // Zero-pad remainder
    if (to_copy < MIRROR_DIM) {
        std::memset(mirror_vector_ + to_copy, 0, (MIRROR_DIM - to_copy) * sizeof(float));
    }
    mirror_initialized_ = true;
    return true;
}

// ============================================================================
// Chamber::evaluate — Binary pass/collapse
// Branch predictor trained on pass > clash (~99% fast path)
// ============================================================================
ChamberResult Chamber::evaluate(const float* hidden_state, size_t dim) {
    if (!hidden_state || dim == 0) {
        ++clash_count_;
        return ChamberResult::CLASH;
    }

    if (!mirror_initialized_) {
        // Explicit no-decision: uninitialized mirror cannot validate alignment
        return ChamberResult::NOT_READY;
    }

    float alignment = dotProductSIMD(hidden_state, mirror_vector_, std::min(dim, MIRROR_DIM));

    if (!std::isfinite(alignment)) {
        ++clash_count_;
        return ChamberResult::CLASH;
    }

    // Epsilon deadband for numerical stability between SIMD and scalar paths
    float threshold = clash_threshold_;
    if (alignment > threshold + EPSILON) {
        ++pass_count_;
        return ChamberResult::PASS;
    }
    if (alignment < threshold - EPSILON) {
        ++clash_count_;
        return ChamberResult::CLASH;
    }

    // Near-threshold: deterministic policy — treat as CLASH (conservative)
    ++clash_count_;
    return ChamberResult::CLASH;
}

// ============================================================================
// Chamber::routePrimitive — O(1) deterministic lookup
// Invariant: same input → same output, always
// ============================================================================
FormulaRoute Chamber::routePrimitive(uint64_t context_hash) const {
    size_t start = static_cast<size_t>(context_hash & (ROUTE_TABLE_SIZE - 1));

    for (size_t probe = 0; probe < ROUTE_TABLE_SIZE; ++probe) {
        size_t idx = (start + probe) & (ROUTE_TABLE_SIZE - 1);
        const FormulaRoute& route = routing_table_[idx];
        if (!route.valid) {
            break;  // Empty slot — route does not exist
        }
        if (route.context_hash == context_hash) {
            return route;  // Exact match
        }
    }
    // No valid route → return invalid (engine must handle as Partial)
    FormulaRoute invalid{};
    invalid.valid = false;
    return invalid;
}

bool Chamber::populateRoutingTable(const FormulaRoute* routes, size_t count) {
    if (!routes || count == 0) return false;

    // Enforce load-factor cap to keep probing bounded
    if (static_cast<float>(count) > LOAD_FACTOR_MAX * static_cast<float>(ROUTE_TABLE_SIZE)) {
        return false;
    }

    // Clear existing
    for (auto& route : routing_table_) {
        route = FormulaRoute{};
    }

    // Insert routes with bounded linear probing
    for (size_t i = 0; i < count; ++i) {
        uint64_t hash = routes[i].context_hash;
        size_t start = static_cast<size_t>(hash & (ROUTE_TABLE_SIZE - 1));
        bool inserted = false;

        for (size_t probe = 0; probe < ROUTE_TABLE_SIZE; ++probe) {
            size_t idx = (start + probe) & (ROUTE_TABLE_SIZE - 1);
            FormulaRoute& slot = routing_table_[idx];
            if (!slot.valid || slot.context_hash == hash) {
                slot = routes[i];
                inserted = true;
                break;
            }
            // Collision: continue probing
        }

        if (!inserted) {
            // Rollback: leave table empty on failure to maintain determinism
            for (auto& route : routing_table_) {
                route = FormulaRoute{};
            }
            return false;
        }
    }
    return true;
}

// ============================================================================
// Chamber::dotProductSIMD — AVX2 fast path with scalar fallback
// ============================================================================
float Chamber::dotProductSIMD(const float* a, const float* b, size_t dim) const {
    if (!a || !b || dim == 0) return 0.0f;

    float result = 0.0f;

    #if defined(__AVX2__)
        // AVX2 path: process 8 floats at a time
        __m256 sum_vec = _mm256_setzero_ps();
        size_t i = 0;
        size_t simd_limit = dim & ~7ULL;  // Round down to multiple of 8

        for (; i < simd_limit; i += 8) {
            __m256 va = _mm256_loadu_ps(a + i);
            __m256 vb = _mm256_loadu_ps(b + i);
            __m256 prod = _mm256_mul_ps(va, vb);
            sum_vec = _mm256_add_ps(sum_vec, prod);
        }

        // Horizontal sum of 8 floats
        __m256 hsum = _mm256_hadd_ps(sum_vec, sum_vec);
        hsum = _mm256_hadd_ps(hsum, hsum);
        // Extract lower 128 bits and upper 128 bits, add them
        __m128 lo = _mm256_castps256_ps128(hsum);
        __m128 hi = _mm256_extractf128_ps(hsum, 1);
        __m128 final_sum = _mm_add_ps(lo, hi);
        result = _mm_cvtss_f32(final_sum);

        // Scalar tail
        for (; i < dim; ++i) {
            result += a[i] * b[i];
        }
    #else
        // Scalar fallback
        for (size_t i = 0; i < dim; ++i) {
            result += a[i] * b[i];
        }
    #endif

    return result;
}

float Chamber::clashRate() const {
    uint64_t passes = pass_count_.load(std::memory_order_relaxed);
    uint64_t clashes = clash_count_.load(std::memory_order_relaxed);
    uint64_t total = passes + clashes;
    if (total == 0) return 0.0f;
    return static_cast<float>(clashes) / static_cast<float>(total);
}

} // namespace rawrxd
