// VwaGeneratedBridge.hpp — project generated ROM + ExpertBank -> canonical VWA.
// Include ModelExport.generated.hpp in the caller, then use these templates.
#pragma once
#include "VwaSpace.hpp"
#include "VwaExpert.hpp"
#include <limits>
#include <unordered_map>
#include <vector>

namespace Deep2 { namespace vwa {
// ModelGenie::GGMLType is a compiler-local ordinal, NOT canonical ggml_type.
// Every numeric cast from the generated enum must pass this explicit bridge.
inline bool CompilerTypeToGgml(uint32_t encoded, uint32_t& canonical) {
    switch (encoded) {
    case 0: canonical = 0; return true;  // F32
    case 1: canonical = 12; return true; // Q4_K
    case 2: canonical = 6; return true;  // Q5_0
    case 3: canonical = 14; return true; // Q6_K
    case 4: canonical = 8; return true;  // Q8_0
    default: return false;
    }
}
template <typename TensorROM, typename ExpertBank>
bool RegisterGeneratedRom(VwaSpace& space, const TensorROM* rom, size_t tensors,
                          uint64_t ggufDataStart, const ExpertBank* banks,
                          size_t nBanks, uint32_t shard = 0) {
    if (!rom || !tensors || (nBanks && !banks)) return false;
    std::unordered_map<TensorId, uint32_t> routedCounts;
    for (size_t i = 0; i < nBanks; ++i) {
        const auto& e = banks[i];
        if (e.routedExpertCount == 0) continue;
        for (uint32_t id : {e.routedDownTensorIds[0],
                            e.routedGateTensorIds[0], e.routedUpTensorIds[0]})
            routedCounts[static_cast<TensorId>(id) + 1] = e.routedExpertCount;
    }
    // Validate every descriptor BEFORE mutating the VWA directory.
    for (size_t i = 0; i < tensors; ++i) {
        const auto& t = rom[i];
        uint32_t ggml = 0;
        uint64_t abs = 0;
        if (!CompilerTypeToGgml(static_cast<uint32_t>(t.type), ggml) ||
            !CheckedAddU64(ggufDataStart, t.dataOffset, abs) ||
            t.encodedBytes == 0 || t.elementCount == 0 ||
            !CheckedAddU64(abs, t.encodedBytes, abs)) return false;
        auto it = routedCounts.find(static_cast<TensorId>(t.tensorId) + 1);
        if (it != routedCounts.end() && t.encodedBytes % it->second) return false;
        if (space.Find(static_cast<TensorId>(t.tensorId) + 1)) return false;
    }
    for (size_t i = 0; i < tensors; ++i) {
        const auto& t = rom[i];
        uint32_t ggml = 0; CompilerTypeToGgml(static_cast<uint32_t>(t.type), ggml);
        VirtualTensorDesc d = MakeDescFromGguf(static_cast<TensorId>(t.tensorId) + 1,
            shard, ggufDataStart, t.dataOffset, t.encodedBytes, ggml);
        const auto it = routedCounts.find(d.id);
        const uint32_t experts = it == routedCounts.end() ? 0 : it->second;
        const uint64_t stride = experts ? t.encodedBytes / experts : 0;
        if (!space.Register(d, t.elementCount, experts, stride, 2)) return false;
        auto* r = space.Find(d.id);
        if (experts && (stride % r->blockBytes ||
            stride / r->blockBytes > UINT32_MAX)) return false;
    }
    return true;
}
template <typename ExpertBank>
bool RangesForSelectedExperts(const VwaSpace& space, const ExpertBank& bank,
                              const uint32_t* expertIds, size_t n,
                              std::vector<BlockRange>& out) {
    const TensorId gate = static_cast<TensorId>(bank.routedGateTensorIds[0]) + 1;
    const TensorId up = static_cast<TensorId>(bank.routedUpTensorIds[0]) + 1;
    const TensorId down = static_cast<TensorId>(bank.routedDownTensorIds[0]) + 1;
    const auto* g = space.Find(gate);
    const auto* u = space.Find(up);
    const auto* d = space.Find(down);
    if (!g || !u || !d || !expertIds || !n || n > bank.activeExpertCount)
        return false;
    return PlanExpertBlocks(*g, *u, *d, expertIds, n, out);
}
} }
