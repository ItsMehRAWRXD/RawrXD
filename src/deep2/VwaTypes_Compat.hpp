// VwaTypes_Compat.hpp — thin aliases onto VirtualTensorRange (no second authority)
#pragma once
#include <cstdint>

namespace Deep2 {
namespace Vwa {

using QuantBlockRange = ::Deep2::QuantBlockRange;
using QuantBlockGeometry = ::Deep2::QuantBlockGeometry;

struct VwaTensorId {
    uint32_t mount = 0;
    uint32_t tensor = 0;
};

struct PhysicalSpan {
    uint32_t shard = 0;
    uint64_t fileOffset = 0;
    uint64_t byteCount = 0;
};

struct VwaRequest {
    VwaTensorId tensor{};
    QuantBlockRange blocks{};
};

inline bool ResolvePhysicalSpan(const VirtualTensorDesc& desc,
                                const QuantBlockGeometry& geo,
                                const QuantBlockRange& range,
                                PhysicalSpan& out) {
    // Prefer type from desc; geo.bytesPerBlock must match table if provided.
    (void)geo;
    PhysicalTensorRange pr{};
    if (!ResolveQuantBlockRange(desc, range, pr)) {
        out = PhysicalSpan{};
        return false;
    }
    out.shard = pr.shardId;
    out.fileOffset = pr.absoluteFileOffset;
    out.byteCount = pr.byteCount;
    return true;
}

} // namespace Vwa
} // namespace Deep2
