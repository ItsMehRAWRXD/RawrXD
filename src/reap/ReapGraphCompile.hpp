// ReapGraphCompile.hpp — REAP-AutoFit R04
//
// Compiles a reap::CanonicalIR (R02) into a Deep2 execution plan. Every
// operation references a PHYSICAL tensor by index; the plan NEVER copies or
// duplicates weight storage. A recurrent layer visited N times emits N
// VisitPlans that all point at the same physical tensors.
//
// Also reports physical vs logical parameter accounting so the recurrent reuse
// (logical > physical) is explicit and measurable.

#pragma once

#include "reap/ReapCanonicalIR.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace reap {

// A reference to a physical tensor plus the op kind it feeds.
struct OpRef {
    uint32_t    physicalTensorIndex = 0;   // index into CanonicalIR::tensors
    std::string opKind;                    // family / op role
};

// One logical visit's operation list.
struct VisitPlan {
    LogicalVisit visit;
    std::vector<OpRef> ops;                // all reference physical tensors
};

struct ExecutionPlan {
    std::vector<OpRef>    preamble;        // embedding (once)
    std::vector<VisitPlan> visits;         // per logical visit
    std::vector<OpRef>    epilogue;        // output head (once)
    uint64_t physicalParamCount = 0;       // sum of unique physical weights
    uint64_t logicalParamCount  = 0;       // as executed (recurrent reuse counted)
    uint64_t recurrentMultiplier = 1;      // loop pass count
};

inline uint64_t TensorParamCount(const PhysicalTensor& t) {
    if (t.dims.empty()) return 0;
    uint64_t n = 1;
    for (uint64_t d : t.dims) {
        if (d == 0) return 0;
        if (n > UINT64_MAX / d) throw std::overflow_error("tensor parameter count overflow");
        n *= d;
    }
    return n;
}

// Compile the execution plan. Ops reference physical tensor indices only.
inline ExecutionPlan CompileGraph(const CanonicalIR& ir) {
    ExecutionPlan plan;
    plan.recurrentMultiplier =
        ir.geometry.loopCount > 0 ? ir.geometry.loopCount : 1;

    for (const auto& t : ir.tensors) {
        const uint64_t n = TensorParamCount(t);
        if (n > UINT64_MAX - plan.physicalParamCount)
            throw std::overflow_error("physical parameter count overflow");
        plan.physicalParamCount += n;
    }

    // Global tensors: embedding preamble, output head + output norm epilogue.
    for (size_t i = 0; i < ir.tensors.size(); ++i) {
        const auto& t = ir.tensors[i];
        if (t.family == "embedding")             plan.preamble.push_back({(uint32_t)i, "embedding"});
        else if (t.family == "output_head")      plan.epilogue.push_back({(uint32_t)i, "output_head"});
        else if (t.family == "output_norm")      plan.epilogue.push_back({(uint32_t)i, "output_norm"});
    }

    // Per-visit ops: tensors whose physical layer == visit.physicalLayer.
    for (const auto& v : ir.visits) {
        VisitPlan vp;
        vp.visit = v;
        for (size_t i = 0; i < ir.tensors.size(); ++i) {
            const auto& t = ir.tensors[i];
            if (t.layerIndex == v.physicalLayer)
                vp.ops.push_back({(uint32_t)i, t.family});
        }
        plan.visits.push_back(std::move(vp));
    }

    // Count the actual layer visits, not a separately interpreted loop range.
    // Global tensors are counted once; each physical layer tensor contributes
    // once per scheduled visit.
    std::vector<uint64_t> visitCounts(static_cast<size_t>(ir.geometry.blockCount), 0);
    for (const auto& visit : ir.visits) {
        if (visit.physicalLayer >= visitCounts.size())
            throw std::invalid_argument("visit outside model topology");
        ++visitCounts[visit.physicalLayer];
    }
    for (const auto& t : ir.tensors) {
        if (t.layerIndex != UINT32_MAX && t.layerIndex >= visitCounts.size())
            throw std::invalid_argument("tensor outside model topology");
        const uint64_t count = t.layerIndex == UINT32_MAX ? 1 : visitCounts[t.layerIndex];
        const uint64_t params = TensorParamCount(t);
        if (count != 0 && params > (UINT64_MAX - plan.logicalParamCount) / count)
            throw std::overflow_error("logical parameter count overflow");
        plan.logicalParamCount += params * count;
    }
    return plan;
}

} // namespace reap