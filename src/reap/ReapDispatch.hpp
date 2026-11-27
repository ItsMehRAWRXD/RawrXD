// ReapDispatch.hpp — RAWRXD S03.6I (inference dispatch request source)
// Builds a validated dispatch request from a bound descriptor + retained-expert
// router mappings + PR-06 identity. The engine executes dispatch using these;
// explicit Virtual/Streaming must never substitute original weights (fail-closed).
// Storage-independent; no RNG.
#pragma once
#include "reap/ReapDescriptorBind.hpp"
#include <cstdint>
#include <vector>

namespace RawrXD::Reap {

struct DispatchRequest {
    bool valid = false;
    uint64_t identity = 0;
    uint32_t binding = 0;
    std::vector<uint32_t> routerMapping;   // retained-expert remapping
};

inline DispatchRequest MakeDispatch(const DescriptorBinding& b,
                                    const std::vector<uint32_t>& routerMap,
                                    bool selectionValid) {
    DispatchRequest d;
    d.identity = b.identity; d.binding = b.binding; d.routerMapping = routerMap;
    if (!selectionValid || !b.valid || b.expertBytes == 0) return d;   // fail closed
    if (routerMap.empty()) return d;                                   // no routing => invalid
    d.valid = true; return d;
}

} // namespace RawrXD::Reap