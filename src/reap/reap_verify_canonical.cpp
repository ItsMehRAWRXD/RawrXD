// reap_verify_canonical.cpp — REAP-AutoFit R02/R04 real-checkpoint verification
//
// Loads a real GGUF checkpoint via GGUFLoader, builds the R02 CanonicalIR
// (physical tensors + logical visits) and the R04 ExecutionPlan (ops reference
// physical tensors), and verifies the plan against the checkpoint's own
// metadata. Proves the IR/compiler pipeline works on a real model, not just
// synthetic geometry.
//
// Usage: reap_verify_canonical.exe [checkpoint.gguf]
//   default: Kimi-K2 Q4_K_M shard 1 (deepseek2, 61 blocks, 384 experts).

#include "deep2/GGUFLoader.hpp"
#include "reap/ReapCanonicalIR.hpp"
#include "reap/ReapGraphCompile.hpp"
#include "reap/ReapOpSemantics.hpp"
#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>

static int failures = 0;
static void expect(bool cond, const char* name) {
    std::printf("%s %s\n", cond ? "PASS" : "FAIL", name);
    if (!cond) ++failures;
}

static std::string classifyFamily(const std::string& name, uint64_t modelExperts,
                                  uint64_t& expertCount) {
    expertCount = 0;
    if (name.find("ffn_gate_exps") != std::string::npos) { expertCount = modelExperts; return "expert_gate"; }
    if (name.find("ffn_up_exps")   != std::string::npos) { expertCount = modelExperts; return "expert_up"; }
    if (name.find("ffn_down_exps") != std::string::npos) { expertCount = modelExperts; return "expert_down"; }
    if (name.find("exp_probs_b.bias")   != std::string::npos) return "router_bias";
    if (name.find("ffn_gate_inp.weight")!= std::string::npos) return "router_input";
    if (name.find("ffn_gate_shexp") != std::string::npos) return "shared_expert";
    if (name.find("ffn_up_shexp")   != std::string::npos) return "shared_expert";
    if (name.find("ffn_down_shexp") != std::string::npos) return "shared_expert";
    if (name.find("attn_q") != std::string::npos) return "attention_q";
    if (name.find("attn_k") != std::string::npos) return "attention_k";
    if (name.find("attn_v") != std::string::npos) return "attention_v";
    if (name.find("attn_output") != std::string::npos) return "attention_output";
    if (name.find("attn_norm") != std::string::npos) return "attention_norm";
    if (name.find("ffn_norm") != std::string::npos) return "ffn_norm";
    if (name.find("token_embd") != std::string::npos) return "embedding";
    if (name.find("output.weight") != std::string::npos) return "output_head";
    if (name.find("output_norm") != std::string::npos) return "output_norm";
    return "other";
}

int main(int argc, char** argv) {
    const char* path = argc > 1 ? argv[1] :
        "F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M\\Kimi-K2-Instruct-0905-Q4_K_M-00001-of-00013.gguf";

    Deep2::GGUFLoader loader;
    if (!loader.load(path)) {
        std::printf("FAIL load %s\n", path);
        return 1;
    }

    const std::string architecture = loader.getMetaString("general.architecture", "unknown");
    auto meta = [&](const char* suffix, int64_t fb = 0) -> int64_t {
        const int64_t v = loader.getMetaInt(architecture + "." + suffix, fb);
        return v > 0 ? v : fb;
    };

    reap::ModelGeometry g;
    g.architecture        = architecture;
    g.embeddingLength     = static_cast<uint64_t>(meta("embedding_length"));
    g.blockCount          = static_cast<uint64_t>(meta("block_count"));
    g.contextLength       = static_cast<uint64_t>(meta("context_length"));
    g.expertCount         = static_cast<uint64_t>(meta("expert_count"));
    g.expertUsedCount     = static_cast<uint64_t>(meta("expert_used_count"));
    g.attentionHeadCount  = static_cast<uint64_t>(meta("attention.head_count"));
    g.attentionHeadCountKV= static_cast<uint64_t>(meta("attention.head_count_kv"));
    g.loopCount           = static_cast<uint64_t>(meta("loop.count"));
    g.loopStart           = static_cast<uint64_t>(meta("loop.start"));
    g.loopEnd             = static_cast<uint64_t>(meta("loop.end"));
    g.loopGateRank        = static_cast<uint64_t>(meta("loop.gate_rank"));

    // Build physical tensors from the real checkpoint.
    std::vector<reap::PhysicalTensor> tensors;
    for (const auto& name : loader.listTensors()) {
        const auto* t = loader.getTensor(name);
        if (!t) continue;
        reap::PhysicalTensor pt;
        pt.name = name;
        uint64_t ec = 0;
        pt.family = classifyFamily(name, g.expertCount, ec);
        pt.type = static_cast<uint32_t>(t->type);
        pt.sizeBytes = t->sizeBytes;
        for (int64_t d : t->shape) if (d > 0) pt.dims.push_back(static_cast<uint64_t>(d));
        pt.shardId = t->shardId;
        pt.fileOffset = t->fileOffset;
        pt.tensorOffset = t->tensorOffset;
        pt.expertCount = ec;
        tensors.push_back(std::move(pt));
    }

    reap::CanonicalIR ir = reap::BuildCanonicalIR(g, tensors);
    reap::ExecutionPlan plan = reap::CompileGraph(ir);

    std::printf("arch=%s blocks=%llu experts=%llu loops=%llu tensors=%zu visits=%zu\n",
                architecture.c_str(),
                (unsigned long long)g.blockCount, (unsigned long long)g.expertCount,
                (unsigned long long)(g.loopCount ? g.loopCount : 1),
                tensors.size(), ir.visits.size());
    std::printf("physicalParams=%llu logicalParams=%llu recurrentMult=%llu\n",
                (unsigned long long)plan.physicalParamCount,
                (unsigned long long)plan.logicalParamCount,
                (unsigned long long)plan.recurrentMultiplier);

    // Structural verification against the checkpoint's own metadata.
    const uint64_t passes = g.loopCount > 0 ? g.loopCount : 1;
    expect(ir.visits.size() == g.blockCount * passes, "visits_match_blockcount_x_passes");
    expect(tensors.size() == static_cast<size_t>(loader.tensorCount()), "tensor_count_matches_loader");
    expect(plan.physicalParamCount > 0, "physical_param_count_positive");
    expect(plan.visits.size() == ir.visits.size(), "plan_visits_match_ir");

    // No-loop model: logical params == physical params.
    if (passes == 1)
        expect(plan.logicalParamCount == plan.physicalParamCount, "no_loop_logical_equals_physical");
    else
        expect(plan.logicalParamCount > plan.physicalParamCount, "recurrent_logical_gt_physical");

    // Every visit's ops reference valid physical tensors.
    bool refsOk = true;
    for (const auto& vp : plan.visits)
        for (const auto& op : vp.ops)
            if (op.physicalTensorIndex >= tensors.size()) refsOk = false;
    expect(refsOk, "ops_reference_valid_physical_tensors");

    // Physical tensors are never cloned by the visit schedule.
    expect(ir.tensors.size() == tensors.size(), "physical_tensors_not_cloned");

    // R05/R06 op semantics: attention (MLA) + MoE routing per physical layer.
    std::vector<reap::LayerSemantics> layers = reap::BuildAllLayerSemantics(ir);
    expect(layers.size() == g.blockCount, "layer_semantics_count_matches_blocks");

    bool kvOk = true, topkOk = true;
    for (const auto& ls : layers) {
        if (ls.kvHeads != static_cast<uint32_t>(g.attentionHeadCountKV)) kvOk = false;
        if (ls.topK != static_cast<uint32_t>(g.expertUsedCount)) topkOk = false;
    }
    expect(kvOk, "kv_heads_from_metadata");
    expect(topkOk, "topk_from_metadata");
    expect(reap::CountRole(layers, reap::OpRole::AttnQ) > 0, "attention_present");
    expect(reap::CountRole(layers, reap::OpRole::ExpertGate) > 0, "moe_experts_present");
    if (!layers.empty())
        expect(layers[0].kvCachePerToken ==
                   static_cast<uint64_t>(layers[0].kvHeads) * layers[0].headDim,
               "kv_cache_per_token_consistent");

    std::printf("role_counts: attnQ=%llu attnK=%llu attnV=%llu attnOut=%llu "
                "routerIn=%llu expertGate=%llu expertUp=%llu expertDown=%llu shared=%llu\n",
                (unsigned long long)reap::CountRole(layers, reap::OpRole::AttnQ),
                (unsigned long long)reap::CountRole(layers, reap::OpRole::AttnK),
                (unsigned long long)reap::CountRole(layers, reap::OpRole::AttnV),
                (unsigned long long)reap::CountRole(layers, reap::OpRole::AttnOutput),
                (unsigned long long)reap::CountRole(layers, reap::OpRole::RouterInput),
                (unsigned long long)reap::CountRole(layers, reap::OpRole::ExpertGate),
                (unsigned long long)reap::CountRole(layers, reap::OpRole::ExpertUp),
                (unsigned long long)reap::CountRole(layers, reap::OpRole::ExpertDown),
                (unsigned long long)reap::CountRole(layers, reap::OpRole::SharedExpert));
    if (!layers.empty())
        std::printf("layer0: kvHeads=%u headDim=%u kvCachePerToken=%llu topK=%u attnOps=%zu moeOps=%zu\n",
                    layers[0].kvHeads, layers[0].headDim,
                    (unsigned long long)layers[0].kvCachePerToken, layers[0].topK,
                    layers[0].attention.size(), layers[0].moe.size());

    std::printf("FAIL_COUNT=%d\n", failures);
    std::printf("PROMOTE=0\n");
    return failures == 0 ? 0 : 1;
}