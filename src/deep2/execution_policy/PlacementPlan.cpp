// ============================================================================
// PlacementPlan.cpp — classify, derive, auto-plan
// ============================================================================
#include "PlacementPlan.hpp"
#include "ExecutionPolicyStore.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>

namespace Deep2 {
namespace Exec {
namespace fs = std::filesystem;

TensorClass ClassifyTensorName(const std::string& name) {
    std::string n = name;
    for (auto& c : n) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    if (n.find("token_embd") != std::string::npos ||
        n.find("tok_embeddings") != std::string::npos ||
        n.find("embedding") != std::string::npos)
        return TensorClass::Embeddings;
    if (n.find("output.weight") != std::string::npos ||
        n.find("lm_head") != std::string::npos ||
        n == "output")
        return TensorClass::LmHead;
    if (n.find("attn_norm") != std::string::npos ||
        n.find("ffn_norm") != std::string::npos ||
        n.find("output_norm") != std::string::npos ||
        n.find(".norm") != std::string::npos)
        return TensorClass::Norms;
    if (n.find("attn_") != std::string::npos ||
        n.find("attention") != std::string::npos ||
        n.find(".wq") != std::string::npos ||
        n.find(".wk") != std::string::npos ||
        n.find(".wv") != std::string::npos ||
        n.find(".wo") != std::string::npos)
        return TensorClass::Attention;
    if (n.find("ffn_") != std::string::npos ||
        n.find("feed_forward") != std::string::npos ||
        n.find(".w1") != std::string::npos ||
        n.find(".w2") != std::string::npos ||
        n.find(".w3") != std::string::npos ||
        n.find("moe") != std::string::npos)
        return TensorClass::FFN;
    if (n.find("rope") != std::string::npos)
        return TensorClass::Rope;
    if (n.find("cache_k") != std::string::npos ||
        n.find("cache_v") != std::string::npos ||
        n.find("kv_") != std::string::npos)
        return TensorClass::KvCache;
    return TensorClass::Scratch;
}

int DeviceKindToGpuIndex(DeviceKind d) {
    switch (d) {
    case DeviceKind::Gpu0: return 0;
    case DeviceKind::Gpu1: return 1;
    case DeviceKind::Hybrid: return 0; // plan marks hybrid as prefer GPU0; observe allows host
    default: return -1;
    }
}

namespace {

bool IsPinned(const PlacementPolicy& pp, const std::string& name) {
    for (const auto& pat : pp.pinned) {
        // reuse simple substring / exact
        if (pat == name) return true;
        if (pat.find('*') != std::string::npos) {
            // defer to resolve via pattern store — approximate: prefix before *
            auto star = pat.find('*');
            if (name.compare(0, star, pat, 0, star) == 0) return true;
        }
    }
    return false;
}

int ParseBlkLayer(const std::string& name) {
    // blk.12.attn_q.weight or layers.12...
    auto pos = name.find("blk.");
    if (pos != std::string::npos) {
        pos += 4;
        return std::atoi(name.c_str() + pos);
    }
    pos = name.find("layers.");
    if (pos != std::string::npos) {
        pos += 7;
        return std::atoi(name.c_str() + pos);
    }
    return -1;
}

} // namespace

PlacementPlan DerivePlacementPlan(const ExecutionPolicy& policy, int nLayers) {
    PlacementPlan plan;
    plan.policyVersion = policy.version;
    plan.policySha = PolicySha256(policy);
    plan.mode = policy.mode;
    plan.derived = true;

    if (policy.memory.vramBudget.present)
        plan.vramCapBytes = policy.memory.vramBudget.value.n;
    if (policy.memory.ram.hardCap.present)
        plan.ramCapBytes = policy.memory.ram.hardCap.value.n;
    else if (policy.memory.ramBudget.present)
        plan.ramCapBytes = policy.memory.ramBudget.value.n;

    if (!policy.memory.gpus.empty()) {
        for (const auto& g : policy.memory.gpus) {
            if (!g.budget.present) continue;
            if (g.index == 0) plan.gpu0Budget = g.budget.value.n;
            if (g.index == 1) plan.gpu1Budget = g.budget.value.n;
        }
    }
    if (plan.gpu0Budget == 0 && plan.vramCapBytes > 0)
        plan.gpu0Budget = plan.vramCapBytes;
    if (plan.gpu1Budget == 0 && plan.vramCapBytes > 0)
        plan.gpu1Budget = plan.vramCapBytes / 2;

    if (policy.streaming.enabled.present)
        plan.streamingEnabled = policy.streaming.enabled.value;
    if (policy.streaming.chunkSize.present)
        plan.streamChunkBytes = policy.streaming.chunkSize.value.n;
    if (policy.streaming.prefetchDepth.present)
        plan.streamPrefetchDepth = policy.streaming.prefetchDepth.value;
    if (policy.streaming.buffers.present)
        plan.streamBuffers = policy.streaming.buffers.value;

    if (policy.kv.placement.present)
        plan.kvPlacement = policy.kv.placement.value;
    if (policy.kv.gpuBudget.present)
        plan.kvGpuBudget = policy.kv.gpuBudget.value.n;
    if (policy.kv.context.present)
        plan.kvContext = policy.kv.context.value;
    else if (policy.context.present)
        plan.kvContext = policy.context.value;

    const int layers = std::max(0, nLayers);
    plan.layerDevice.assign(static_cast<size_t>(layers), DeviceKind::Host);
    for (int L = 0; L < layers; ++L) {
        // Empty tensor name → class Scratch falls through to layer/global
        plan.layerDevice[static_cast<size_t>(L)] =
            policy.resolvePlacement("blk." + std::to_string(L) + ".weight", L,
                                    TensorClass::Attention);
    }

    plan.detail = "derived nLayers=" + std::to_string(layers);
    return plan;
}

void RunAutoPlanner(ExecutionPolicy& policy, int nLayers,
                    uint64_t detectedVram0, uint64_t detectedVram1,
                    uint64_t detectedRam) {
    auto auth = SettingAuthority::AutoPlanner;
    auto fillBytes = [&](Tunable<Bytes>& t, Bytes v, SettingMutability m) {
        if (!t.present || t.authority == SettingAuthority::AutoDetect ||
            t.authority == SettingAuthority::AutoPlanner ||
            t.authority == SettingAuthority::RuntimeLearned)
            t.force(v, auth, m);
    };
    auto fillBool = [&](Tunable<bool>& t, bool v, SettingMutability m) {
        if (!t.present || t.authority == SettingAuthority::AutoDetect ||
            t.authority == SettingAuthority::AutoPlanner ||
            t.authority == SettingAuthority::RuntimeLearned)
            t.force(v, auth, m);
    };

    const uint64_t totalV = detectedVram0 + detectedVram1;
    if (totalV > 0)
        fillBytes(policy.memory.vramBudget, Bytes::Of(totalV * 90 / 100),
                  SettingMutability::TokenBoundary);
    if (detectedRam > 0)
        fillBytes(policy.memory.ramBudget, Bytes::Of(detectedRam * 80 / 100),
                  SettingMutability::TokenBoundary);

    // Layer split: early → GPU0, mid → GPU1 if present, late → stream if streaming on
    if (policy.placement.layerRanges.empty() && nLayers > 0) {
        const bool multi = detectedVram1 > 0;
        const bool stream =
            !policy.streaming.enabled.present || policy.streaming.enabled.value;
        int a = nLayers / 3;
        int b = (2 * nLayers) / 3;
        if (!multi) {
            a = (stream ? (nLayers * 2) / 3 : nLayers);
            b = nLayers;
        }
        policy.placement.layerRanges.clear();
        policy.placement.layerRanges.push_back(
            {LayerRange{0, a - 1}, DeviceKind::Gpu0});
        if (multi && a < b)
            policy.placement.layerRanges.push_back(
                {LayerRange{a, b - 1}, DeviceKind::Gpu1});
        if (stream && b < nLayers)
            policy.placement.layerRanges.push_back(
                {LayerRange{b, -1}, DeviceKind::Stream});
        else if (b < nLayers)
            policy.placement.layerRanges.push_back(
                {LayerRange{b, -1}, DeviceKind::Host});
    }

    fillBool(policy.streaming.enabled, true, SettingMutability::TokenBoundary);
    if (!policy.streaming.chunkSize.present ||
        policy.streaming.chunkSize.authority <= SettingAuthority::AutoPlanner)
        policy.streaming.chunkSize.force(Bytes::MiB(128), auth,
                                         SettingMutability::Immediate);
    if (!policy.kv.placement.present ||
        policy.kv.placement.authority <= SettingAuthority::AutoPlanner)
        policy.kv.placement.force(KVPlacement::Hybrid, auth,
                                  SettingMutability::SequenceBoundary);

    (void)ParseBlkLayer;
    (void)IsPinned;
}

void BindModelToPolicy(const std::string& modelPath,
                       const std::string& modelFingerprint) {
    auto& store = ExecutionPolicyStore::Instance();
    ExecutionPolicy delta;
    if (!modelPath.empty())
        delta.modelPath.force(modelPath, SettingAuthority::Session,
                              SettingMutability::ModelReload);
    if (!modelFingerprint.empty())
        delta.modelFingerprint.force(modelFingerprint, SettingAuthority::Session,
                                     SettingMutability::Immediate);
    if (delta.modelPath.present || delta.modelFingerprint.present)
        (void)store.apply(delta, SettingAuthority::Session, "BindModelToPolicy");
}

} // namespace Exec
} // namespace Deep2
