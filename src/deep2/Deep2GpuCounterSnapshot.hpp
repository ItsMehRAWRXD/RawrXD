#pragma once
/* Map Deep2::GpuForwardCounters → D2GpuCounterSnapshot (BIND16). */
#include "d2_engine_ssvk_bind16.h"
#include "Deep2GpuForward.hpp"

namespace Deep2 {

inline D2GpuCounterSnapshot D2GpuCounterSnapshot_From(
    const GpuForwardCounters& c) noexcept {
    D2GpuCounterSnapshot s{};
    s.host_forward_layer_calls = c.hostForwardLayerCalls;
    s.host_materializations = c.hostMaterializations;
    s.cpu_f32_expands = c.cpuF32Expands;
    s.forward_slot0 = c.forwardSlot[0];
    s.forward_slot1 = c.forwardSlot[1];
    s.q2k_packed_ops = c.q2kPackedOps;
    s.critical_path_nvme_reads = 0;
    s.external_runtime_calls = 0;
    return s;
}

inline D2GpuCounterSnapshot D2Bind16Snapshot(
    const GpuForwardCounters& c) noexcept {
    return D2GpuCounterSnapshot_From(c);
}

} // namespace Deep2

using Deep2::D2Bind16Snapshot;
