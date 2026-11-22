#pragma once
#include <cstdint>
#include <limits>

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
} } // namespace Deep2::ReapCapture
