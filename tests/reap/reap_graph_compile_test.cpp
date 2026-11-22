// reap_graph_compile_test.cpp — REAP-AutoFit R04 verification
//
// Proves the recurrent graph compiler emits one VisitPlan per logical visit
// (48 for 24 layers x 2 passes), every op references a PHYSICAL tensor index
// (no weight duplication), and physical vs logical parameter accounting is
// correct (logical > physical because loop layers are re-executed).

#include "reap/ReapGraphCompile.hpp"
#include <cstdio>
#include <string>
#include <vector>

static int failures = 0;
static void expect(bool cond, const char* name) {
    std::printf("%s %s\n", cond ? "PASS" : "FAIL", name);
    if (!cond) ++failures;
}

int main() {
    using namespace reap;

    ModelGeometry g;
    g.architecture = "inkling";
    g.embeddingLength = 4096;
    g.blockCount = 24;
    g.expertCount = 128;
    g.expertUsedCount = 8;
    g.attentionHeadCount = 32;
    g.attentionHeadCountKV = 8;
    g.loopCount = 2;
    g.loopStart = 0;
    g.loopEnd = 24;

    std::vector<PhysicalTensor> tensors;
    auto add = [&](const std::string& name, const std::string& fam, std::vector<uint64_t> dims) {
        PhysicalTensor t; t.name = name; t.family = fam; t.dims = dims;
        tensors.push_back(std::move(t));
    };
    for (uint32_t L = 0; L < 24; ++L) {
        const std::string p = "blk." + std::to_string(L) + ".";
        add(p+"attn_q.weight", "attention_q", {4096, 4096});
        add(p+"attn_k.weight", "attention_k", {1024, 4096});
        add(p+"attn_v.weight", "attention_v", {1024, 4096});
        add(p+"ffn_gate_exps.weight", "expert_gate", {128, 4096});
        add(p+"ffn_up_exps.weight", "expert_up", {128, 4096});
        add(p+"ffn_down_exps.weight", "expert_down", {4096, 128});
    }
    add("token_embd.weight", "embedding", {4096, 1000});
    add("output.weight", "output_head", {4096, 1000});

    CanonicalIR ir = BuildCanonicalIR(g, tensors);
    ExecutionPlan plan = CompileGraph(ir);

    // 1. 48 VisitPlans, matching the logical schedule.
    expect(plan.visits.size() == 48, "plan_visits_48");
    expect(plan.recurrentMultiplier == 2, "recurrent_multiplier_2");

    // 2. Every op references a PHYSICAL tensor index (no duplication).
    bool refsValid = true;
    for (const auto& vp : plan.visits)
        for (const auto& op : vp.ops)
            if (op.physicalTensorIndex >= ir.tensors.size()) refsValid = false;
    expect(refsValid, "ops_reference_physical_indices");

    // 3. The physical tensor vector is unchanged by compilation (no cloning).
    expect(ir.tensors.size() == 146, "physical_tensors_unchanged"); // 24*6 + 2

    // 4. Preamble has embedding, epilogue has output head.
    expect(plan.preamble.size() == 1 && plan.preamble[0].opKind == "embedding",
           "preamble_embedding");
    expect(plan.epilogue.size() == 1 && plan.epilogue[0].opKind == "output_head",
           "epilogue_output_head");

    // 5. Each visit carries its physical layer's ops (6 per layer).
    bool opCountsOk = true;
    for (const auto& vp : plan.visits) if (vp.ops.size() != 6) opCountsOk = false;
    expect(opCountsOk, "each_visit_has_layer_ops");

    // 6. Physical vs logical parameter accounting.
    uint64_t expectPhysical = 0;
    for (const auto& t : ir.tensors) expectPhysical += TensorParamCount(t);
    expect(plan.physicalParamCount == expectPhysical, "physical_param_count");

    // Loop layers (0..23) params counted twice total (physical + 1 extra pass).
    uint64_t layerParams = 0;
    for (const auto& t : ir.tensors)
        if (t.layerIndex != UINT32_MAX) layerParams += TensorParamCount(t);
    expect(plan.logicalParamCount == plan.physicalParamCount + layerParams,
           "logical_param_count_reuse");

    // 7. Logical > physical (recurrent reuse is real, measurable).
    expect(plan.logicalParamCount > plan.physicalParamCount, "logical_gt_physical");

    // 8. Dense (no loop) plan: logical == physical, 32 visits for 32 layers.
    ModelGeometry dense; dense.blockCount = 32; dense.loopCount = 0;
    CanonicalIR dIr = BuildCanonicalIR(dense, {});
    ExecutionPlan dPlan = CompileGraph(dIr);
    expect(dPlan.visits.size() == 32 && dPlan.logicalParamCount == dPlan.physicalParamCount,
           "dense_logical_equals_physical");

    std::printf("FAIL_COUNT=%d\n", failures);
    std::printf("PROMOTE=0\n");
    return failures == 0 ? 0 : 1;
}