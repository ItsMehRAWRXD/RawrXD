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
    static inline uint64_t mapCount = 0;
    static inline uint64_t unmapCount = 0;
    static inline uint64_t evictionCount = 0;
    static inline uint64_t mappedBytes = 0;
    static inline uint64_t bytesUnmapped = 0;
    static inline uint64_t peakResidentBytes = 0;
    static inline uint64_t currentResidentBytes = 0;
    static inline uint64_t activeLeaseCount = 0;
    static inline uint64_t staleLeaseCount = 0;
    static inline uint64_t residencyErrors = 0;
    static inline uint64_t mappingErrors = 0;
    static inline uint64_t releaseErrors = 0;
    static inline uint64_t layerTransitions = 0;
    static inline uint64_t forwardTransitions = 0;
    static inline uint64_t activeWindowOffset = 0;
    static inline uint64_t activeWindowLength = 0;
    static inline uint64_t windowGeneration = 0;
    static inline uint64_t tensorAcquireFailures = 0;
    static inline uint64_t tensorReleaseFailures = 0;

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
        mapCount = 0;
        unmapCount = 0;
        evictionCount = 0;
        mappedBytes = 0;
        bytesUnmapped = 0;
        peakResidentBytes = 0;
        currentResidentBytes = 0;
        activeLeaseCount = 0;
        staleLeaseCount = 0;
        residencyErrors = 0;
        mappingErrors = 0;
        releaseErrors = 0;
        layerTransitions = 0;
        forwardTransitions = 0;
        activeWindowOffset = 0;
        activeWindowLength = 0;
        windowGeneration = 0;
        tensorAcquireFailures = 0;
        tensorReleaseFailures = 0;
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
        activeLeaseCount++;
        if (currentResidentBytes > peakResidentBytes) {
            peakResidentBytes = currentResidentBytes;
        }
    }

    static void OnRelease(size_t bytes) {
        releaseCount++;
        bytesUnmapped += bytes;
        if (activeLeaseCount > 0) activeLeaseCount--;
        if (currentResidentBytes >= bytes) {
            currentResidentBytes -= bytes;
        } else {
            currentResidentBytes = 0;
        }
    }

    static void OnMap(size_t bytes) {
        mapCount++;
        mappedBytes += bytes;
        currentResidentBytes += bytes;
        if (currentResidentBytes > peakResidentBytes) {
            peakResidentBytes = currentResidentBytes;
        }
    }

    static void OnUnmap(size_t bytes) {
        unmapCount++;
        bytesUnmapped += bytes;
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

    static void OnStaleLease() {
        staleLeaseCount++;
        residencyErrors++;
    }

    static void OnResidencyError() {
        residencyErrors++;
    }

    static void OnMappingError() {
        mappingErrors++;
    }

    static void OnReleaseError() {
        releaseErrors++;
        tensorReleaseFailures++;
    }

    static void OnTensorAcquireFailure() {
        tensorAcquireFailures++;
        residencyErrors++;
    }

    static void OnLayerTransition() {
        layerTransitions++;
    }

    static void OnForwardTransition() {
        forwardTransitions++;
    }

    static void SetWindowState(size_t offset, size_t length, size_t generation) {
        activeWindowOffset = offset;
        activeWindowLength = length;
        windowGeneration = generation;
    }

    static void Print() {
        printf("\n============================================================\n");
        printf("RESIDENCY COUNTERS — VAL-051.7 Baseline\n");
        printf("============================================================\n");
        printf("forwardCount         = %llu\n", (unsigned long long)forwardCount);
        printf("layerCount           = %llu\n", (unsigned long long)layerCount);
        printf("remapCount           = %llu\n", (unsigned long long)remapCount);
        printf("remapBytes           = %llu\n", (unsigned long long)remapBytes);
        printf("weightLookupCount    = %llu\n", (unsigned long long)weightLookupCount);
        printf("matMulCount          = %llu\n", (unsigned long long)matMulCount);
        printf("batchedMatMulCount   = %llu\n", (unsigned long long)batchedMatMulCount);
        printf("acquireCount         = %llu\n", (unsigned long long)acquireCount);
        printf("releaseCount         = %llu\n", (unsigned long long)releaseCount);
        printf("mapCount             = %llu\n", (unsigned long long)mapCount);
        printf("unmapCount           = %llu\n", (unsigned long long)unmapCount);
        printf("evictionCount        = %llu\n", (unsigned long long)evictionCount);
        printf("mappedBytes          = %llu\n", (unsigned long long)mappedBytes);
        printf("bytesUnmapped        = %llu\n", (unsigned long long)bytesUnmapped);
        printf("peakResidentBytes    = %llu\n", (unsigned long long)peakResidentBytes);
        printf("currentResidentBytes = %llu\n", (unsigned long long)currentResidentBytes);
        printf("activeLeaseCount     = %llu\n", (unsigned long long)activeLeaseCount);
        printf("staleLeaseCount      = %llu\n", (unsigned long long)staleLeaseCount);
        printf("residencyErrors      = %llu\n", (unsigned long long)residencyErrors);
        printf("mappingErrors        = %llu\n", (unsigned long long)mappingErrors);
        printf("releaseErrors        = %llu\n", (unsigned long long)releaseErrors);
        printf("layerTransitions     = %llu\n", (unsigned long long)layerTransitions);
        printf("forwardTransitions   = %llu\n", (unsigned long long)forwardTransitions);
        printf("activeWindowOffset   = %llu\n", (unsigned long long)activeWindowOffset);
        printf("activeWindowLength   = %llu\n", (unsigned long long)activeWindowLength);
        printf("windowGeneration     = %llu\n", (unsigned long long)windowGeneration);
        printf("tensorAcquireFailures= %llu\n", (unsigned long long)tensorAcquireFailures);
        printf("tensorReleaseFailures= %llu\n", (unsigned long long)tensorReleaseFailures);
        printf("totalForwardMs       = %.3f\n", totalForwardMs);
        printf("totalLayerMs         = %.3f\n", totalLayerMs);
        if (forwardCount > 0) {
            printf("avgForwardMs         = %.3f\n", totalForwardMs / forwardCount);
        }
        if (layerCount > 0) {
            printf("avgLayerMs           = %.3f\n", totalLayerMs / layerCount);
        }
        printf("============================================================\n");
    }
};

} // namespace Deep2

#endif // RESIDENCY_COUNTERS_HPP
