#pragma once
// Shared R01/R02 layer traversal contract, independent of the model runtime.
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace reap {
struct LogicalVisit {
    uint32_t pass = 0;
    uint32_t layerOrdinal = 0;
    uint32_t physicalLayer = 0;
};
struct LoopSchedule {
    uint64_t blocks, passes, begin, end, visits;
};

// R01 inventory uses inclusive loop.end for inkling2_loop. For other
// architectures preserve R02's exclusive end and zero-as-default convention.
// Normalize once, then use half-open intervals throughout the IR.
inline LoopSchedule NormalizeLoop(const std::string& architecture,
                                  uint64_t blocks, uint64_t passes,
                                  uint64_t begin, uint64_t end) {
    constexpr auto limit = uint64_t{std::numeric_limits<uint32_t>::max()};
    if (blocks > limit || passes > limit)
        throw std::invalid_argument("layer/pass count exceeds IR index width");
    if (passes <= 1) return {blocks, 1, 0, blocks, blocks};
    if (architecture == "inkling2_loop") {
        if (end >= blocks) throw std::invalid_argument("inclusive loop end outside topology");
        ++end;
    } else if (end == 0) {
        end = blocks;
    }
    if (begin >= end || end > blocks)
        throw std::invalid_argument("invalid recurrent layer range");
    const uint64_t width = end - begin;
    if (passes - 1 > (limit - blocks) / width)
        throw std::overflow_error("logical visit count exceeds IR index width");
    return {blocks, passes, begin, end, blocks + (passes - 1) * width};
}
inline uint64_t VisitMultiplicity(const LoopSchedule& loop, uint64_t layer) {
    if (layer >= loop.blocks) throw std::invalid_argument("physical layer outside topology");
    return layer >= loop.begin && layer < loop.end ? loop.passes : 1;
}
inline std::vector<LogicalVisit> BuildLayerVisits(const LoopSchedule& loop) {
    std::vector<LogicalVisit> out;
    out.reserve(static_cast<size_t>(loop.visits));
    auto emit = [&](uint64_t begin, uint64_t end, uint64_t pass) {
        for (uint64_t layer = begin; layer < end; ++layer)
            out.push_back({static_cast<uint32_t>(pass), static_cast<uint32_t>(out.size()),
                           static_cast<uint32_t>(layer)});
    };
    emit(0, loop.begin, 0);
    for (uint64_t pass = 0; pass < loop.passes; ++pass)
        emit(loop.begin, loop.end, pass);
    emit(loop.end, loop.blocks, loop.passes - 1);
    return out;
}
} // namespace reap
