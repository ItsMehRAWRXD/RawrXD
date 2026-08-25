// ============================================================================
// VAL-051.7 ΓÇö Residency/Remap Elimination + Performance Baseline Fixture
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
    // ΓöÇΓöÇ Counters ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
    static inline uint64_t forwardCount = 0;
    static inline uint64_t layerCount = 0;
    static inline uint64_t remapCount = 0;
    static inline uint64_t remapBytes = 0;
    static inline uint64_t weightLookupCount = 0;
    static inline uint64_t matMulCount = 0;
    static inline uint64_t batchedMatMulCount = 0;

    // ΓöÇΓöÇ Timing ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
    static inline double totalForwardMs = 0.0;
    static inline double totalLayerMs = 0.0;

    // ΓöÇΓöÇ Per-call scratch ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
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

    static void OnUnmap(size_t bytes) {
        remapBytes -= bytes;
    }

    static void OnEvict(size_t bytes) {
        remapBytes -= bytes;
    }

    static void OnAcquire(size_t bytes) {
        // Track acquire events for accounting
    }

    static void OnMap(size_t bytes) {
        // Track map events for accounting
    }

    static void OnRelease(size_t bytes) {
        // Track release events for accounting
    }

    static void OnReleaseError() {
        // Track release errors for diagnostics
    }

    static void OnTensorAcquireFailure() {
        // Track tensor acquire failures
    }

    static void OnMappingError() {
        // Track mapping failures
    }

    static void OnResidencyError() {
        // Track general residency errors
    }

    static void OnStaleLease() {
        // Track stale lease detections
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
