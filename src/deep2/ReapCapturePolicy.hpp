#pragma once
#include <cstddef>
#include <cstdint>
#include <limits>
#include <vector>

namespace Deep2 { namespace ReapCapture {
constexpr uint32_t AllLayers = std::numeric_limits<uint32_t>::max();
constexpr uint64_t AllSteps = std::numeric_limits<uint64_t>::max();
inline bool Matches(uint32_t filterLayer, uint64_t filterStep,
                    uint32_t layer, uint64_t step, bool allLayers) noexcept {
    return (filterLayer == layer || (allLayers && filterLayer == AllLayers)) &&
           (filterStep == AllSteps || filterStep == step);
}
inline bool CaptureRouting(bool done, bool streaming, uint32_t filterLayer,
                           uint64_t filterStep, uint32_t layer, uint64_t step) noexcept {
    return (!done || streaming) && Matches(filterLayer, filterStep, layer, step, streaming);
}
inline bool CompleteCounts(uint64_t routes, uint64_t shared, uint64_t routed,
                           uint64_t records, uint32_t topK) noexcept {
    constexpr auto max = std::numeric_limits<uint64_t>::max();
    return routes != 0 && topK != 0 && shared == routes && routes <= max / topK &&
           routed == routes * topK && shared <= max - routed && records == shared + routed;
}
struct LayerCounts {
    uint64_t routes = 0, shared = 0, routed = 0, records = 0;
};
// The caller derives expected layers from loaded source router tensors, not
// from the observed subset. Unexpected layers or empty expected layers fail.
inline bool CompleteCoverage(const std::vector<bool>& expected,
                             const std::vector<LayerCounts>& counts,
                             uint32_t topK) noexcept {
    if (expected.size() != counts.size()) return false;
    bool any = false;
    for (std::size_t i = 0; i < expected.size(); ++i) {
        const auto& c = counts[i];
        if (expected[i]) {
            any = true;
            if (!CompleteCounts(c.routes,c.shared,c.routed,c.records,topK)) return false;
        } else if (c.routes || c.shared || c.routed || c.records) return false;
    }
    return any;
}
} } // namespace Deep2::ReapCapture
