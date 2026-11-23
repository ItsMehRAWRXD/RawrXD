#pragma once
#include "NativeTensorInventory.hpp"
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

namespace RawrXD { namespace REAP {
enum class PlanError { None, InvalidBudget, EmptyInventory, UnsupportedLayout, InsufficientBudget, Overflow };
struct PlanRequest {
    uint64_t max_artifact_bytes = 0;
    uint64_t fixed_overhead_bytes = 0;
    uint32_t output_alignment = 32;
};
struct TensorPlan {
    std::string name;
    uint32_t ggml_type = 0;
    uint64_t element_count = 0;
    uint64_t storage_bytes = 0;
};
struct CompressionPlan {
    std::vector<TensorPlan> tensors;
    uint64_t minimum_artifact_bytes = 0;
    uint64_t source_logical_bytes = 0;
    uint64_t target_budget_bytes = 0;
};
inline bool PlanAdd(uint64_t a, uint64_t b, uint64_t& out) {
    if (a > UINT64_MAX - b) return false;
    out = a + b;
    return true;
}
inline bool PlanAlign(uint64_t n, uint64_t a, uint64_t& out) {
    if (!a || (a & (a - 1)) || n > UINT64_MAX - (a - 1)) return false;
    out = (n + a - 1) & ~(a - 1);
    return true;
}
// No-transform feasibility. Reject budgets requiring unverified compression.
// A successful plan does not claim semantic quality or publish an artifact.
inline PlanError PlanLosslessPackaging(const Inventory& inventory,
                                       const PlanRequest& request,
                                       CompressionPlan& output) {
    if (!request.max_artifact_bytes || request.output_alignment < 8 ||
        request.output_alignment > 4096 ||
        (request.output_alignment & (request.output_alignment - 1)))
        return PlanError::InvalidBudget;
    if (inventory.tensors.empty()) return PlanError::EmptyInventory;
    CompressionPlan next;
    next.source_logical_bytes = inventory.logical_bytes;
    next.target_budget_bytes = request.max_artifact_bytes;
    uint64_t position = 0;
    for (const auto& tensor : inventory.tensors) {
        uint64_t block = 0, block_bytes = 0, exact = 0;
        if (!StorageLayout(tensor.ggml_type, block, block_bytes) ||
            !tensor.element_count || tensor.element_count % block)
            return PlanError::UnsupportedLayout;
        if (!CheckedMultiply(tensor.element_count / block, block_bytes, exact) ||
            exact != tensor.storage_bytes) return PlanError::Overflow;
        if (!PlanAlign(position, request.output_alignment, position) ||
            !PlanAdd(position, exact, position)) return PlanError::Overflow;
        next.tensors.push_back({tensor.name,tensor.ggml_type,tensor.element_count,exact});
    }
    uint64_t overhead = 0;
    if (!PlanAlign(request.fixed_overhead_bytes,request.output_alignment,overhead) ||
        !PlanAdd(overhead,position,next.minimum_artifact_bytes))
        return PlanError::Overflow;
    if (next.minimum_artifact_bytes > request.max_artifact_bytes)
        return PlanError::InsufficientBudget;
    output = std::move(next);
    return PlanError::None;
}
}} // namespace RawrXD::REAP
