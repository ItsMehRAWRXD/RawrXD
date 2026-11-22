#pragma once
#include <cstddef>
#include <cstdint>
#include <limits>

namespace Deep2 { namespace Mla {
// Matches deep2_ops.comp OP_MLA_ATTN: cache [layer, position, head, dim],
// query [head,key dimension], output [head,value dimension].
struct Geometry {
    size_t keyElements = 0, valueElements = 0;
    uint64_t keyCacheElements = 0, valueCacheElements = 0;
    uint64_t keyOffset = 0, valueOffset = 0;
    uint32_t groups = 0;
    uint32_t p0 = 0, p1 = 0, p2 = 0, p3 = 0, p4 = 0, p5 = 0;
};
inline bool Build(uint32_t heads, uint32_t keyLen, uint32_t valueLen,
                  uint32_t layers, uint32_t capacity, uint32_t layer,
                  uint32_t pos, Geometry& out) noexcept {
    out = {};
    if (!heads || !keyLen || !valueLen || !layers || !capacity ||
        layer >= layers || pos >= capacity) return false;
    // The shader uses uint indexing; reject shapes that cannot be addressed
    // without wrapping. Bound host byte conversions as well.
    constexpr uint64_t shaderLimit = std::numeric_limits<uint32_t>::max();
    constexpr uint64_t hostLimit = std::numeric_limits<size_t>::max() / sizeof(float);
    constexpr uint64_t limit = shaderLimit < hostLimit ? shaderLimit : hostLimit;
    const uint64_t k = uint64_t(heads) * keyLen;
    const uint64_t v = uint64_t(heads) * valueLen;
    const uint64_t slots = uint64_t(layers) * capacity;
    if (k > limit || v > limit || slots > limit / k || slots > limit / v) return false;
    const uint64_t index = uint64_t(layer) * capacity + pos;
    const uint64_t groups = (v + 63u) / 64u;
    // All supported Vulkan implementations guarantee at least 65535 groups.
    if (groups > 65535u) return false;
    out.keyElements = static_cast<size_t>(k);
    out.valueElements = static_cast<size_t>(v);
    out.keyCacheElements = slots * k;
    out.valueCacheElements = slots * v;
    out.keyOffset = index * k;
    out.valueOffset = index * v;
    out.groups = static_cast<uint32_t>(groups);
    out.p0 = keyLen; out.p1 = valueLen; out.p2 = heads;
    out.p3 = pos + 1; out.p4 = capacity; out.p5 = layer;
    return true;
}
} } // namespace Deep2::Mla
