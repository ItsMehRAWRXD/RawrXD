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
    for (uint64_t d : t.dims) n *= d;
    return n;
}

// Compile the execution plan. Ops reference physical tensor indices only.
inline ExecutionPlan CompileGraph(const CanonicalIR& ir) {
    ExecutionPlan plan;
    plan.recurrentMultiplier =
        ir.geometry.loopCount > 0 ? ir.geometry.loopCount : 1;

    for (const auto& t : ir.tensors)
        plan.physicalParamCount += TensorParamCount(t);

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

    // Logical params = physical + re-execution of loop layers on extra passes.
    uint64_t loopLayerParams = 0;
    const uint64_t passes = plan.recurrentMultiplier;
    if (passes > 1 && ir.geometry.blockCount > 0) {
        uint64_t start = ir.geometry.loopStart;
        uint64_t end = ir.geometry.loopEnd > 0 ? ir.geometry.loopEnd
                                               : ir.geometry.blockCount;
        if (end > ir.geometry.blockCount) end = ir.geometry.blockCount;
        if (end <= start) { start = 0; end = ir.geometry.blockCount; }
        for (const auto& t : ir.tensors) {
            if (t.layerIndex != UINT32_MAX &&
                t.layerIndex >= start && t.layerIndex < end)
                loopLayerParams += TensorParamCount(t);
        }
    }
    plan.logicalParamCount = plan.physicalParamCount + (passes - 1) * loopLayerParams;
    return plan;
}

} // namespace reap