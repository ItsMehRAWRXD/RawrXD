#pragma once
// Deep2 integration shim example.
// This is intentionally header-only and dependency-free.
// Wire run_real_segment() to your existing layer execution function.

#include "beaconism_99.hpp"
#include <cstddef>
#include <cstdint>

namespace rawrxd::beaconism {

template<class RealSegmentFn>
bool execute_or_replay(
    BeaconReplayCache& cache,
    const SegmentDesc& seg,
    const void* input_state,
    size_t input_bytes,
    void* output_state,
    size_t output_bytes,
    RealSegmentFn&& run_real_segment)
{
    if (cache.try_replay(seg, input_state, input_bytes, output_state, output_bytes))
        return true; // real work avoided

    run_real_segment(); // must populate output_state
    cache.account_executed(seg.nominal_work_units);

    // A commit failure never changes correctness; it only loses acceleration.
    (void)cache.commit(seg, input_state, input_bytes, output_state, output_bytes);
    return false;
}

} // namespace rawrxd::beaconism
