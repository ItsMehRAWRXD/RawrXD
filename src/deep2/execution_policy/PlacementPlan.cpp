// ============================================================================
// PlacementPlan.cpp — derive, classify, bind, auto-plan
// ============================================================================
#include "PlacementPlan.hpp"
#include "ExecutionPolicy.hpp"
#include "AutoPlanner.hpp"
#include "LearnedProfileStore.hpp"
#include "HardwareSnapshot.hpp"
#include <algorithm>
#include <cctype>
#include <string>
#include <vector>
#include <unordered_map>

namespace Deep2 {
namespace Exec {

// ============================================================================
// Tensor classification
// ============================================================================
TensorClass ClassifyTensorName(const std::string& name) {
    // Attention weights: q_proj, k_proj, v_proj, o_proj, attn*
    if (name.find("q_proj") != std::string::npos ||
        name.find("k_proj") != std::string::npos ||
        name.find("v_proj") != std::string::npos ||
        name.find("o_proj") != std::string::npos ||
        name.find("attn") != std::string::npos) {
        return TensorClass::Attention;
    }

    // FFN weights: gate_proj, up_proj, down_proj, ffn*, mlp*
    if (name.find("gate_proj") != std::string::npos ||
        name.find("up_proj") != std::string::npos ||
        name.find("down_proj") != std::string::npos ||
        name.find("ffn") != std::string::npos ||
        name.find("mlp") != std::string::npos) {
        return TensorClass::FFN;
    }

    // Embeddings: token_embd, embed, wte, wpe
    if (name.find("token_embd") != std::string::npos ||
        name.find("embedding") != std::string::npos ||
        name.find("wte") != std::string::npos ||
        name.find("wpe") != std::string::npos) {
        return TensorClass::Embeddings;
    }

    // LM Head: lm_head, output.weight, lm_head.weight
    if (name.find("lm_head") != std::string::npos ||
        name.find("output.weight") != std::string::npos ||
        name.find("final_proj") != std::string::npos) {
        return TensorClass::LmHead;
    }

    // Norms: norm, ln_, layer_norm, rms_norm
    if (name.find("norm") != std::string::npos ||
        name.find("ln_") != std::string::npos ||
        name.find("rms") != std::string::npos) {
        return TensorClass::Norms;
    }

    // KV Cache: kv_cache, key_cache, value_cache, past_kv
    if (name.find("kv_cache") != std::string::npos ||
        name.find("key_cache") != std::string::npos ||
        name.find("value_cache") != std::string::npos ||
        name.find("past_kv") != std::string::npos) {
        return TensorClass::KvCache;
    }

    // RoPE: rope, rotary, pos_emb
    if (name.find("rope") != std::string::npos ||
        name.find("rotary") != std::string::npos ||
        name.find("pos_emb") != std::string::npos) {
        return TensorClass::Rope;
    }

    // Activations: act_, hidden_states, intermediate
    if (name.find("act_") != std::string::npos ||
        name.find("hidden_states") != std::string::npos ||
        name.find("intermediate") != std::string::npos) {
        return TensorClass::Activations;
    }

    // Scratch: scratch, tmp_, buffer
    if (name.find("scratch") != std::string::npos ||
        name.find("tmp_") != std::string::npos ||
        name.find("buffer") != std::string::npos) {
        return TensorClass::Scratch;
    }

    return TensorClass::Scratch;
}

// ============================================================================
// DeviceKind -> GPU index
// ============================================================================
int DeviceKindToGpuIndex(DeviceKind d) {
    switch (d) {
        case DeviceKind::Gpu0: return 0;
        case DeviceKind::Gpu1: return 1;
        case DeviceKind::Stream: return -1;  // stream = host fallback
        case DeviceKind::Hybrid: return -1;  // hybrid = decision at runtime
        case DeviceKind::Disk: return -1;    // disk = host fallback
        case DeviceKind::Host: return -1;
        default: return -1;
    }
}

// ============================================================================
// Placement plan derivation
// ============================================================================
PlacementPlan DerivePlacementPlan(const ExecutionPolicy& policy, int nLayers) {
    PlacementPlan plan;
    plan.policyVersion = policy.version;
    plan.policySha = PolicySha256(policy);
    plan.mode = policy.mode;

    plan.vramCapBytes = policy.memory.vramBudget.present ? policy.memory.vramBudget.value.n : 0;
    plan.ramCapBytes = policy.memory.ramBudget.present ? policy.memory.ramBudget.value.n : 0;

    // GPU budgets from policy
    for (const auto& gpu : policy.memory.gpus) {
        if (gpu.index == 0) plan.gpu0Budget = gpu.budget.present ? gpu.budget.value.n : 0;
        if (gpu.index == 1) plan.gpu1Budget = gpu.budget.present ? gpu.budget.value.n : 0;
    }
    // Fallback to VRAM partition weights
    if (plan.gpu0Budget == 0 && policy.memory.vramParts.weights.present) {
        plan.gpu0Budget = policy.memory.vramParts.weights.value.n;
    }
    if (plan.gpu1Budget == 0 && policy.memory.vramParts.weights.present && policy.memory.gpus.size() > 1) {
        plan.gpu1Budget = policy.memory.vramParts.weights.value.n / 2; // split if not specified
    }

    plan.streamingEnabled = policy.streaming.enabled.present ? policy.streaming.enabled.value : false;
    plan.streamChunkBytes = policy.streaming.chunkSize.present ? policy.streaming.chunkSize.value.n : 0;
    plan.streamPrefetchDepth = policy.streaming.prefetchDepth.present ? policy.streaming.prefetchDepth.value : 3;
    plan.streamBuffers = policy.streaming.buffers.present ? policy.streaming.buffers.value : 3;

    plan.kvPlacement = policy.kv.placement.present ? policy.kv.placement.value : KVPlacement::Hybrid;
    plan.kvGpuBudget = policy.kv.gpuBudget.present ? policy.kv.gpuBudget.value.n : 0;
    plan.kvContext = policy.kv.context.present ? policy.kv.context.value : 0;

    // Resolve layer devices
    plan.layerDevice.resize(nLayers);
    for (int layer = 0; layer < nLayers; ++layer) {
        // Check layer ranges
        bool found = false;
        for (const auto& lr : policy.placement.layerRanges) {
            if (layer >= lr.first.first && (lr.first.last < 0 || layer <= lr.first.last)) {
                plan.layerDevice[layer] = lr.second;
                found = true;
                break;
            }
        }
        if (!found) {
            // Default: attention on GPU0, FFN on Hybrid
            plan.layerDevice[layer] = DeviceKind::Gpu0;
        }
    }

    plan.derived = true;
    plan.detail = "Derived from policy version " + std::to_string(policy.version);
    return plan;
}

// ============================================================================
// Model binding
// ============================================================================
void BindModelToPolicy(const std::string& modelPath,
                       const std::string& modelFingerprint) {
    auto& store = ExecutionPolicyStore::Instance();
    if (!modelPath.empty()) {
        ExecutionPolicy delta;
        delta.modelPath.force(modelPath, SettingAuthority::Session, SettingMutability::Immediate);
        store.apply(delta, SettingAuthority::Session, "BindModelToPolicy:modelPath");
    }
    if (!modelFingerprint.empty()) {
        store.setModelFingerprint(modelFingerprint);
        ExecutionPolicy delta;
        delta.modelFingerprint.force(modelFingerprint, SettingAuthority::Session, SettingMutability::Immediate);
        store.apply(delta, SettingAuthority::Session, "BindModelToPolicy:modelFingerprint");
    }
}

// ============================================================================
// Auto planner (stub - calls AutoPlanner)
// ============================================================================
void RunAutoPlanner(ExecutionPolicy& policy, int nLayers,
                    uint64_t detectedVram0, uint64_t detectedVram1,
                    uint64_t detectedRam) {
    AutoPlanHints hints;
    hints.gpuCount = (detectedVram1 > 0) ? 2 : 1;
    hints.gpu0Vram = detectedVram0;
    hints.gpu1Vram = detectedVram1;
    hints.ram = detectedRam;
    hints.totalLayers = nLayers;

    auto planned = AutoPlan(policy, hints);
    planned.mode = UiMode::Auto;

    ExecutionPolicyStore::Instance().apply(planned, SettingAuthority::AutoPlanner, "RunAutoPlanner");
}

} // namespace Exec
} // namespace Deep2