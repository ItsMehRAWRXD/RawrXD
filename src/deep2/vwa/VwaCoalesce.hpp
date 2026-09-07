// vwa/VwaCoalesce.hpp — merge adjacent same-shard physical ranges
#pragma once
#include "VwaTypes.hpp"
#include <algorithm>
#include <vector>

namespace Deep2 {
namespace vwa {

inline std::vector<PhysicalRange> CoalesceRanges(
    std::vector<PhysicalRange> in, uint64_t* merges = nullptr) {
    if (in.empty()) return in;
    std::sort(in.begin(), in.end(), [](const PhysicalRange& a, const PhysicalRange& b) {
        if (a.shard != b.shard) return a.shard < b.shard;
        return a.offset < b.offset;
    });
    std::vector<PhysicalRange> out;
    out.reserve(in.size());
    out.push_back(in[0]);
    uint64_t m = 0;
    for (size_t i = 1; i < in.size(); ++i) {
        auto& last = out.back();
        const auto& cur = in[i];
        if (cur.shard == last.shard && cur.offset <= last.offset + last.bytes) {
            const uint64_t end = (std::max)(last.offset + last.bytes, cur.offset + cur.bytes);
            last.bytes = end - last.offset;
            ++m;
        } else {
            out.push_back(cur);
        }
    }
    if (merges) *merges = m;
    return out;
}

} // namespace vwa
} // namespace Deep2
