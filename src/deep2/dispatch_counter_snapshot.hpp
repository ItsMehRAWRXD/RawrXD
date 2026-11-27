// dispatch_counter_snapshot.hpp — RAWRXD_RET_CANONICAL_SNAPSHOT_CONTRACT_111
// Dependency-light telemetry contract shared by the dispatcher and the Deep2
// backend. Imports NO Vulkan header. Canonical namespace: rawrxd::deep2.
#pragma once
#include <cstdint>

namespace rawrxd {
namespace deep2 {

struct DispatchCounterSnapshot {
    std::uint64_t submits = 0;
    std::uint64_t waits = 0;
    double submit_ms = 0.0;
    double fence_wait_ms = 0.0;
};

DispatchCounterSnapshot GpuCountersSnapshot();

} // namespace deep2
} // namespace rawrxd