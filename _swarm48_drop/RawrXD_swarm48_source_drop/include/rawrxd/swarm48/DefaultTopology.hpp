#pragma once
#include "DeviceLeaseManager.hpp"
#include "PagedKVPool.hpp"

namespace rawrxd::swarm48 {
struct DeviceTopologyPreset { DeviceBudget device; KvPoolConfig kv; };
inline DeviceTopologyPreset r9700_default() {
    return {{0, "Radeon AI PRO R9700", 32ull<<30, 2ull<<30, 16, 32, true}, {6ull<<30, 256u<<10}};
}
inline DeviceTopologyPreset rx7800xt_default() {
    return {{1, "Radeon RX 7800 XT", 16ull<<30, 2ull<<30, 8, 16, true}, {3ull<<30, 256u<<10}};
}
} // namespace rawrxd::swarm48
