// reap_canonical_ir_test.cpp — REAP-AutoFit R02 verification
//
// Proves the canonical IR separates physical tensor identity from logical
// execution visits, and that the recurrent visit schedule derived from loop
// metadata is correct (48 visits = 2 passes x 24 physical layers; loop_end
// exclusive; loop_count total passes). Physical allocations are never cloned
// per visit.

#include "reap/ReapCanonicalIR.hpp"
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

    // --- R01-derived geometry: 24 physical layers, 128 experts, 2 passes ---
    ModelGeometry inkling;
    inkling.architecture = "inkling";
    inkling.embeddingLength = 4096;
    inkling.blockCount = 24;
    inkling.contextLength = 32768;
    inkling.expertCount = 128;
    inkling.expertUsedCount = 8;
    inkling.attentionHeadCount = 32;
    inkling.attentionHeadCountKV = 8;
    inkling.loopCount = 2;     // total passes
    inkling.loopStart = 0;     // inclusive
    inkling.loopEnd = 24;      // EXCLUSIVE
    inkling.loopGateRank = 16;

    // Physical tensors: one per layer for gate/up/down (no duplication).
    std::vector<PhysicalTensor> tensors;
    for (uint32_t layer = 0; layer < 24; ++layer) {
        const std::string p = "blk." + std::to_string(layer) + ".";
        tensors.push_back({"ffn_gate_exps.weight", "expert_gate", 0, {128, 4096}, 1, 0, 0, 0, 128, UINT32_MAX});
        tensors[tensors.size()-1].name = p + "ffn_gate_exps.weight";
        tensors.push_back({"ffn_up_exps.weight", "expert_up", 0, {128, 4096}, 1, 0, 0, 0, 128, UINT32_MAX});
        tensors[tensors.size()-1].name = p + "ffn_up_exps.weight";
        tensors.push_back({"ffn_down_exps.weight", "expert_down", 0, {4096, 128}, 1, 0, 0, 0, 128, UINT32_MAX});
        tensors[tensors.size()-1].name = p + "ffn_down_exps.weight";
    }
    tensors.push_back({"token_embd.weight", "embedding", 0, {4096, 1000}, 1, 0, 0, 0, 0, UINT32_MAX});
    tensors.push_back({"output.weight", "output_head", 0, {4096, 1000}, 1, 0, 0, 0, 0, UINT32_MAX});

    CanonicalIR ir = BuildCanonicalIR(inkling, tensors);

    // 1. 48 logical visits from loop metadata (2 passes x 24 layers).
    expect(ir.visits.size() == 48, "visits_48_from_loop_metadata");
    expect(ir.PhysicalLayerCount() == 24, "physical_layers_24");
    expect(ir.tensors.size() == 74, "physical_tensors_not_cloned"); // 24*3 + 2 global

    // 2. Pass 0 covers physical layers 0..23; pass 1 repeats 0..23.
    bool pass0ok = true, pass1ok = true;
    for (size_t i = 0; i < ir.visits.size(); ++i) {
        const auto& v = ir.visits[i];
        if (i < 24) { if (v.pass != 0 || v.physicalLayer != i || v.layerOrdinal != (uint32_t)i) pass0ok = false; }
        else        { if (v.pass != 1 || v.physicalLayer != (i-24) || v.layerOrdinal != (uint32_t)i) pass1ok = false; }
    }
    expect(pass0ok, "pass0_covers_physical_0_23");
    expect(pass1ok, "pass1_repeats_physical_0_23");

    // 3. Physical tensor identity is reused, never duplicated per visit.
    //    Every visit maps to a physical layer < blockCount.
    bool allPhysical = true;
    for (const auto& v : ir.visits) if (v.physicalLayer >= ir.geometry.blockCount) allPhysical = false;
    expect(allPhysical, "visits_reference_physical_layers_only");

    // 4. Layer-index parsing: blk.N -> N, global -> UINT32_MAX.
    expect(ParseLayerIndex("blk.7.attn_q.weight") == 7, "parse_blk_layer");
    expect(ParseLayerIndex("token_embd.weight") == UINT32_MAX, "parse_global_tensor");

    // 5. Dense / no-loop model: loopCount 0 => single pass over blockCount.
    ModelGeometry dense;
    dense.architecture = "llama";
    dense.blockCount = 32;
    dense.loopCount = 0;
    CanonicalIR denseIr = BuildCanonicalIR(dense, {});
    expect(denseIr.visits.size() == 32, "dense_single_pass_visits");

    // 6. loop_end exclusive: 0..23 for end=24.
    expect(ir.visits.back().physicalLayer == 23, "loop_end_exclusive_last_23");

    std::printf("FAIL_COUNT=%d\n", failures);
    std::printf("PROMOTE=0\n");
    return failures == 0 ? 0 : 1;
}