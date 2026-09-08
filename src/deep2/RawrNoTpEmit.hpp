// RawrNoTpEmit.hpp — SPACE_SUFFICIENT seal (not VRAM_SUFFICIENT).
#pragma once
#include "RawrNoTpResidency.hpp"

namespace Deep2 {

inline void RawrEmitNoTpFlags(FILE* f) {
    if (!f) return;
    const int noTp = RawrNoTpWanted() ? 1 : 0;
    const int bound = RawrBoundedResidencyWanted() ? 1 : 0;
    std::fprintf(f,
        "MODEL_SIZE_INDEPENDENT_LOAD=1\n"
        "RAWRXD_NO_TP=%d\n"
        "QUANTIZED_STORAGE_PRESERVED=1\n"
        "FULL_MODEL_RESIDENCY_REQUIRED=0\n"
        "FULL_LAYER_RESIDENCY_REQUIRED=0\n"
        "VRAM_REQUIRED=0\n"
        "VRAM_BYTES_REQUIRED=0\n"
        "WEIGHT_RESIDENCY_BOUNDED=%d\n"
        "KV_RESIDENCY_BOUNDED=%d\n"
        "EXECUTION_OWNER_PER_TENSOR=1\n"
        "TENSOR_PARTITIONS=0\n"
        "CROSS_DEVICE_COLLECTIVES=0\n"
        "ALL_REDUCE_OPS=0\n"
        "ONE_TENSOR_ONE_OWNER=1\n",
        noTp, bound, bound);
}

inline void RawrEmitNoTpContract(FILE* f) {
    if (!f) return;
    RawrEmitNoTpFlags(f);
    std::fprintf(f, "SPACE_SUFFICIENT=0\n");
}

inline void RawrEmitNoTpContract(FILE* f, const RawrWorkingSet& w,
                                 const RawrSpaceState& s) {
    if (!f) return;
    RawrEmitNoTpFlags(f);
    const uint64_t ws = RawrWorkingSetBytes(w);
    const int ok = RawrSpaceSufficient(w, s) ? 1 : 0;
    std::fprintf(f,
        "WEIGHT_WINDOW_BYTES=%llu\n"
        "ACTIVATION_LIVE_BYTES=%llu\n"
        "KV_HOT_BYTES=%llu\n"
        "SCRATCH_BYTES=%llu\n"
        "WORKING_SET_BYTES=%llu\n"
        "SPACE_CAPACITY_BYTES=%llu\n"
        "SPACE_OCCUPIED_BYTES=%llu\n"
        "SPACE_RECLAIMABLE_BYTES=%llu\n"
        "SPACE_SUFFICIENT=%d\n",
        (unsigned long long)w.weightBytes,
        (unsigned long long)w.activationBytes,
        (unsigned long long)w.kvHotBytes,
        (unsigned long long)w.scratchBytes,
        (unsigned long long)ws,
        (unsigned long long)s.capacityBytes,
        (unsigned long long)s.occupiedBytes,
        (unsigned long long)s.reclaimableBytes, ok);
}

} // namespace Deep2
