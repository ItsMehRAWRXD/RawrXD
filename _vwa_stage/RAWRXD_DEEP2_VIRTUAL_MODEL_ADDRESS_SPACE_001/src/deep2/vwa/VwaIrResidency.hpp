// VwaIrResidency.hpp — use real generated OperationIR::input/weight accessors.
// No GGUF reparse, tensor-name matching, or parallel residency manager.
#pragma once
#include "VwaTypes.hpp"
#include <algorithm>
#include <cstdint>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace Deep2 { namespace vwa {
class IrNextUseIndex {
public:
    template <typename OperationIR>
    bool Build(const OperationIR* ops, size_t n) {
        ops_.clear(); uses_.clear();
        if (!ops || n == 0 || n > UINT32_MAX) return false;
        ops_.resize(n);
        for (size_t i = 0; i < n; ++i) {
            const auto& op = ops[i];
            if (op.inputCount > 8 || op.weightCount > 8) { ops_.clear(); uses_.clear(); return false; }
            std::unordered_set<TensorId> unique;
            // OperandDomain::RomTensor == 1 in the frozen ModelGenome.hpp.
            // ModelGenie ROM IDs are 0-based; VWA reserves ID 0, so +1.
            auto add = [&](const auto& operand) {
                if (static_cast<uint32_t>(operand.domain) == 1)
                    unique.insert(static_cast<TensorId>(operand.id) + 1);
            };
            for (uint32_t j = 0; j < op.inputCount; ++j) add(op.input(j));
            for (uint32_t j = 0; j < op.weightCount; ++j) add(op.weight(j));
            auto& dst = ops_[i]; dst.assign(unique.begin(), unique.end());
            std::sort(dst.begin(), dst.end());
            for (TensorId id : dst) uses_[id].push_back(static_cast<uint32_t>(i));
        }
        return true;
    }
    size_t Count() const { return ops_.size(); }
    const std::vector<TensorId>& Tensors(size_t op) const { return ops_.at(op); }
    uint32_t RefCount(TensorId id) const {
        const auto it = uses_.find(id);
        return it == uses_.end() ? 0u : static_cast<uint32_t>(it->second.size());
    }
    uint32_t NextUseOp(TensorId id, uint32_t after) const {
        const auto it = uses_.find(id);
        if (it == uses_.end() || it->second.empty() || ops_.empty()) return UINT32_MAX;
        const auto& v = it->second;
        auto p = std::upper_bound(v.begin(), v.end(), after);
        return p == v.end() ? v.front() : *p;
    }
    // Distance in a repeating decode-cycle, strictly AFTER current op.
    // Unreferenced spans score infinity and are evicted first.
    uint64_t Distance(TensorId id, uint32_t after) const {
        if (ops_.empty()) return UINT64_MAX;
        const uint32_t next = NextUseOp(id, after);
        if (next == UINT32_MAX) return UINT64_MAX;
        const uint64_t n = ops_.size();
        return (n + next - (static_cast<uint64_t>(after) % n)) % n == 0 ? n :
               (n + next - (static_cast<uint64_t>(after) % n)) % n;
    }
private:
    std::vector<std::vector<TensorId>> ops_;
    std::unordered_map<TensorId, std::vector<uint32_t>> uses_;
};

struct GpuPlacementChoice { uint8_t gpu = 0; uint64_t cost = UINT64_MAX; bool admissible = false; };
inline GpuPlacementChoice ChooseGpuPlacement(
        uint64_t missingWeightBytes, const uint64_t activationBytes[2],
        const uint64_t syncCostBytes[2], const uint64_t available[2],
        const uint64_t transferPenalty[2]) {
    GpuPlacementChoice best{};
    for (uint8_t g = 0; g < 2; ++g) {
        if (available[g] < missingWeightBytes) continue;
        const uint64_t cap = UINT64_MAX - missingWeightBytes;
        if (activationBytes[g] > cap) continue;
        const uint64_t one = missingWeightBytes + activationBytes[g];
        if (syncCostBytes[g] > UINT64_MAX - one) continue;
        const uint64_t two = one + syncCostBytes[g];
        if (transferPenalty[g] > UINT64_MAX - two) continue;
        const uint64_t cost = two + transferPenalty[g];
        if (!best.admissible || cost < best.cost) best = {g, cost, true};
    }
    return best;
}
} }
