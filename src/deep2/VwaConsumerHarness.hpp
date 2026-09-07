// VwaConsumerHarness.hpp — shared synthetic RMV+Q4_K shard for consumer certs
#pragma once
#include "VirtualTensorRange.hpp"
#include "VirtualTensorRangePlanner.hpp"
#include <cstdint>
#include <vector>

namespace Deep2 {
namespace vwa_harness {

struct Shard {
    VirtualTensorDesc desc{};
    uint32_t blockBytes = 0;
    uint32_t blockElems = 0;
    uint64_t dataAbs = 0;
    std::vector<uint8_t> bytes;
};

inline bool MakeQ4KShard(Shard& s, uint64_t dataAbs, uint64_t nBlocks,
                         uint64_t mountGen = 1) {
    QuantBlockGeometry g{};
    if (!GetQuantBlockGeometry(12, g)) return false;
    s.blockBytes = g.bytesPerBlock;
    s.blockElems = g.elementsPerBlock;
    s.dataAbs = dataAbs;
    const uint64_t payload = nBlocks * s.blockBytes;
    s.bytes.assign(static_cast<size_t>(dataAbs + payload), 0);
    for (size_t i = 0; i < s.bytes.size(); ++i)
        s.bytes[i] = static_cast<uint8_t>((i * 19u + 3u) & 0xFFu);
    s.desc = MakeDescFromGguf(11, 0, dataAbs, 0, payload, 12);
    s.desc.id = 11;
    (void)mountGen;
    return s.desc.addressed;
}

inline bool ResolveBlocks(const Shard& s, uint64_t first, uint64_t count,
                          PhysicalTensorRange& out, uint64_t gen = 1) {
    return ResolveQuantBlockRange(s.desc, s.blockBytes, {first, count}, out, gen);
}

} // namespace vwa_harness
} // namespace Deep2
