// ============================================================================
// VAL-051.7 — Residency/Remap Elimination + Performance Baseline Fixture
// ============================================================================
// This header adds lightweight counters to the forward path for before/after
// comparison.  It intentionally does NOT change semantics.
//
// Usage:
//   #include "ResidencyCounters.hpp"
//   ResidencyCounters::Reset();
//   ... run inference ...
//   ResidencyCounters::Print();
// ============================================================================

#ifndef RESIDENCY_COUNTERS_HPP
#define RESIDENCY_COUNTERS_HPP

#include <cstdint>
#include <cstdio>
#include <chrono>

namespace Deep2 {

struct ResidencyCounters {
    // ── Counters ─────────────────────────────────────────────────────
    static inline uint64_t forwardCount = 0;
    static inline uint64_t layerCount = 0;
    static inline uint64_t remapCount = 0;
    static inline uint64_t remapBytes = 0;
    static inline uint64_t weightLookupCount = 0;
    static inline uint64_t matMulCount = 0;
    static inline uint64_t batchedMatMulCount = 0;

    // ── Residency counters (VAL-051.7+) ─────────────────────────────
    static inline uint64_t acquireCount = 0;
    static inline uint64_t releaseCount = 0;
    static inline uint64_t evictionCount = 0;
    static inline uint64_t mappedBytes = 0;
    static inline uint64_t peakResidentBytes = 0;
    static inline uint64_t currentResidentBytes = 0;

    // ── Timing ───────────────────────────────────────────────────────
    static inline double totalForwardMs = 0.0;
    static inline double totalLayerMs = 0.0;

    // ── Per-call scratch ─────────────────────────────────────────────
    static inline std::chrono::high_resolution_clock::time_point forwardT0;
    static inline std::chrono::high_resolution_clock::time_point layerT0;

    static void Reset() {
        forwardCount = 0;
        layerCount = 0;
        remapCount = 0;
        remapBytes = 0;
        weightLookupCount = 0;
        matMulCount = 0;
        batchedMatMulCount = 0;
        totalForwardMs = 0.0;
        totalLayerMs = 0.0;
        acquireCount = 0;
        releaseCount = 0;
        evictionCount = 0;
        mappedBytes = 0;
        peakResidentBytes = 0;
        currentResidentBytes = 0;
    }

    static void BeginForward() {
        forwardT0 = std::chrono::high_resolution_clock::now();
    }

    static void EndForward() {
        auto t1 = std::chrono::high_resolution_clock::now();
        totalForwardMs += std::chrono::duration<double, std::milli>(t1 - forwardT0).count();
        forwardCount++;
    }

    static void BeginLayer() {
        layerT0 = std::chrono::high_resolution_clock::now();
    }

    static void EndLayer() {
        auto t1 = std::chrono::high_resolution_clock::now();
        totalLayerMs += std::chrono::duration<double, std::milli>(t1 - layerT0).count();
        layerCount++;
    }

    static void OnRemap(size_t bytes) {
        remapCount++;
        remapBytes += bytes;
    }

    static void OnWeightLookup() {
        weightLookupCount++;
    }

    static void OnMatMul() {
        matMulCount++;
    }

    static void OnBatchedMatMul() {
        batchedMatMulCount++;
    }

    static void OnAcquire(size_t bytes) {
        acquireCount++;
        mappedBytes += bytes;
        currentResidentBytes += bytes;
        if (currentResidentBytes > peakResidentBytes) {
            peakResidentBytes = currentResidentBytes;
        }
    }

    static void OnRelease(size_t bytes) {
        releaseCount++;
        if (currentResidentBytes >= bytes) {
            currentResidentBytes -= bytes;
        } else {
            currentResidentBytes = 0;
        }
    }

    static void OnEvict(size_t bytes) {
        evictionCount++;
        if (currentResidentBytes >= bytes) {
            currentResidentBytes -= bytes;
        } else {
            currentResidentBytes = 0;
        }
    }

    static void Print() {
        printf("\n============================================================\n");
        printf("RESIDENCY COUNTERS\n");
        printf("============================================================\n");
        printf("forwardCount       = %llu\n", (unsigned long long)forwardCount);
        printf("layerCount         = %llu\n", (unsigned long long)layerCount);
        printf("remapCount         = %llu\n", (unsigned long long)remapCount);
        printf("remapBytes         = %llu\n", (unsigned long long)remapBytes);
        printf("weightLookupCount  = %llu\n", (unsigned long long)weightLookupCount);
        printf("matMulCount        = %llu\n", (unsigned long long)matMulCount);
        printf("batchedMatMulCount = %llu\n", (unsigned long long)batchedMatMulCount);
        printf("acquireCount       = %llu\n", (unsigned long long)acquireCount);
        printf("releaseCount       = %llu\n", (unsigned long long)releaseCount);
        printf("evictionCount      = %llu\n", (unsigned long long)evictionCount);
        printf("mappedBytes        = %llu\n", (unsigned long long)mappedBytes);
        printf("peakResidentBytes  = %llu\n", (unsigned long long)peakResidentBytes);
        printf("currentResidentBytes = %llu\n", (unsigned long long)currentResidentBytes);
        printf("totalForwardMs     = %.3f\n", totalForwardMs);
        printf("totalLayerMs       = %.3f\n", totalLayerMs);
        if (forwardCount > 0) {
            printf("avgForwardMs       = %.3f\n", totalForwardMs / forwardCount);
        }
        if (layerCount > 0) {
            printf("avgLayerMs         = %.3f\n", totalLayerMs / layerCount);
        }
        printf("============================================================\n");
    }
};

} // namespace Deep2

#endif // RESIDENCY_COUNTERS_HPP
