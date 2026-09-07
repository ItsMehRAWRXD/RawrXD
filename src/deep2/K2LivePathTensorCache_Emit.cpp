// K2LivePathTensorCache_Emit.cpp — bound/telemetry witnesses
#include "K2LivePathTensorCache.hpp"

namespace Deep2 {

void K2LiveCache_Emit(FILE* f) {
    if (!f) f = stdout;
    auto s = K2LiveCache_Snapshot();
    const double hitRate = (s.hits + s.misses)
        ? (double)s.hits / (double)(s.hits + s.misses) : 0.0;
    fprintf(f, "LIVE_CACHE_BYTES=%llu\n", (unsigned long long)s.bytes);
    fprintf(f, "LIVE_CACHE_BYTES_PEAK=%llu\n", (unsigned long long)s.bytesPeak);
    fprintf(f, "LIVE_CACHE_BUDGET=%llu\n", (unsigned long long)s.budget);
    fprintf(f, "LIVE_CACHE_ENTRY_PEAK=%u\n", s.entriesPeak);
    fprintf(f, "CACHE_HIT_RATE=%.6f\n", hitRate);
    fprintf(f, "CACHE_BYTES_SAVED=%llu\n", (unsigned long long)s.bytesSaved);
    fprintf(f, "CACHE_EVICTIONS=%llu\n", (unsigned long long)s.evictionCount);
    fprintf(f, "CACHE_EVICTION_BYTES=%llu\n", (unsigned long long)s.evictionBytes);
    fprintf(f, "PREFETCH_ACCEPTED=%llu\n", (unsigned long long)s.prefetchAccepted);
    fprintf(f, "PREFETCH_SUPPRESSED=%llu\n", (unsigned long long)s.prefetchSuppressed);
    fprintf(f, "PREFETCH_ALREADY_RESIDENT=%llu\n",
            (unsigned long long)s.prefetchAlreadyResident);
    fprintf(f, "OUTPUT_WEIGHT_RESIDENCY=%llu\n",
            (unsigned long long)s.outputWeightBytes);
    fprintf(f, "CACHE_BYTES_AFTER_WARM=%llu\n",
            (unsigned long long)s.bytesAfterWarm);
    fprintf(f, "TRAMP_OUTPUT_WEIGHT_HITS=%llu\n",
            (unsigned long long)s.trampOutHits);
    fprintf(f, "TRAMP_OUTPUT_WEIGHT_BYTES_SAVED=%llu\n",
            (unsigned long long)s.trampOutBytesSaved);
    fprintf(f, "CYCLONE_LAYER_ACQUIRES=%llu\n",
            (unsigned long long)s.cycloneLayerAcquires);
    fprintf(f, "CYCLONE_LAYER_HITS=%llu\n",
            (unsigned long long)s.cycloneLayerHits);
    fprintf(f, "ELASTIC_RESIDENT_HITS=%llu\n",
            (unsigned long long)s.elasticResidentHits);
    fprintf(f, "COMBINED_DUPLICATE_ACQUIRES=%llu\n",
            (unsigned long long)s.combinedDupAcquires);
    fprintf(f, "COMBINED_REDUNDANT_BYTES=%llu\n",
            (unsigned long long)s.combinedRedundantBytes);
    fprintf(f, "COMBINED_WAIT_US=%llu\n",
            (unsigned long long)s.combinedWaitUs);
    fflush(f);
}

} // namespace Deep2
