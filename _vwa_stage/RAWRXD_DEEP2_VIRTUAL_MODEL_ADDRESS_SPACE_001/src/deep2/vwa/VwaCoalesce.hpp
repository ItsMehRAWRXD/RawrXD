// VwaCoalesce.hpp — coalesce ONLY inside one tensor; never erase ROM identity
#pragma once
#include "VwaTypes.hpp"
#include <algorithm>
#include <vector>
namespace Deep2 { namespace vwa {
inline std::vector<PhysicalRange> CoalesceRanges(std::vector<PhysicalRange> in,
                                                uint64_t* merges = nullptr) {
    std::sort(in.begin(), in.end(), [](const PhysicalRange& a, const PhysicalRange& b) {
        if (a.shard != b.shard) return a.shard < b.shard;
        if (a.id != b.id) return a.id < b.id;
        return a.offset < b.offset;
    });
    std::vector<PhysicalRange> out;
    uint64_t m = 0;
    for (const auto& r : in) {
        if (!out.empty()) {
            auto& prev = out.back();
            if (prev.shard == r.shard && prev.id == r.id &&
                r.offset >= prev.offset && r.offset - prev.offset <= prev.bytes &&
                prev.bytes <= UINT64_MAX - prev.offset &&
                r.bytes <= UINT64_MAX - r.offset) {
                const uint64_t end = (std::max)(prev.offset + prev.bytes,
                                                r.offset + r.bytes);
                prev.bytes = end - prev.offset;
                ++m;
                continue;
            }
        }
        out.push_back(r);
    }
    if (merges) *merges = m;
    return out;
}
} }
