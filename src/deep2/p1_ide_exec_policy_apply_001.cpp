// ============================================================================
// p1_ide_exec_policy_apply_001.cpp — P1_IDE_EXEC_POLICY_APPLY_001
// IDE load seam: EnsurePolicy → plan → stamp Elastic → observe match
// ============================================================================
#include "ElasticResidencyManager.hpp"
#include "Deep2IDEIntegration.hpp"
#include "execution_policy/ExecutionPolicy.hpp"
#include "execution_policy/ExecutionPolicyStore.hpp"
#include "execution_policy/ExecutionPolicyBridge.hpp"
#include "execution_policy/ExecutionPolicyApply.hpp"
#include "execution_policy/PolicyApply.hpp"

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

namespace fs = std::filesystem;
using namespace Deep2;
using namespace Deep2::Exec;

static int g_fail = 0;
#define PRED(name, cond)                                                       \
    do {                                                                       \
        const bool ok = (cond);                                                \
        std::printf("%-36s %s\n", name, ok ? "PASS" : "FAIL");                 \
        if (!ok) ++g_fail;                                                     \
    } while (0)

static void WriteGate(const fs::path& dir, const PlacementApplyReport& r,
                      const std::string& model, bool allPass) {
    fs::create_directories(dir);
    std::ofstream g(dir / "GATE.txt");
    g << "GATE=P1_IDE_EXEC_POLICY_APPLY_001\n";
    g << "RESULT=" << (allPass ? "PASS" : "FAIL") << "\n";
    g << "MODEL=" << model << "\n";
    g << "POLICY_SHA=" << r.policySha << "\n";
    g << "POLICY_VERSION=" << r.policyVersion << "\n";
    g << "PLANNED_TENSORS=" << r.plannedTensors << "\n";
    g << "OBSERVED_TENSORS=" << r.observedTensors << "\n";
    g << "MISMATCHES=" << r.mismatches << "\n";
    g << "GPU0_LAYERS=" << r.gpu0Layers << "\n";
    g << "STREAM_LAYERS=" << r.streamLayers << "\n";
    g << "DETAIL=" << r.detail << "\n";
    std::ofstream m(dir / "MISMATCHES.txt");
    for (const auto& o : r.observations) {
        if (!o.match)
            m << o.name << " planned=" << (int)o.planned
              << " observedGpu=" << o.observedGpu << "\n";
    }
}

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("=== P1_IDE_EXEC_POLICY_APPLY_001 ===\n");

    {
        ExecutionPolicy bad = MakeDefaultPolicy();
        bad.memory.vramBudget.force(Bytes::GiB(1), SettingAuthority::UserLocked,
                                    SettingMutability::TokenBoundary);
        bad.memory.vramParts.weights.force(Bytes::GiB(2), SettingAuthority::UserOverride,
                                           SettingMutability::TokenBoundary);
        PRED("OVER_BUDGET_FAIL_CLOSED", !Validate(bad).ok);
    }
    {
        Tunable<Bytes> locked;
        locked.force(Bytes::GiB(3), SettingAuthority::UserLocked,
                     SettingMutability::TokenBoundary);
        PRED("LOCKED_OVERRIDES_PRESERVED",
             !locked.trySet(Bytes::GiB(9), SettingAuthority::AutoPlanner));
    }

    // Same seam Deep2ModelLoader::LoadSingleFile calls after Elastic register.
    EnsurePolicyLoaded();
    ExecutionPolicy expert = MakeDefaultPolicy();
    expert.mode = UiMode::Expert;
    expert.persistRuntimeChanges.force(false, SettingAuthority::Session,
                                       SettingMutability::Immediate);
    expert.placement.layerRanges.clear();
    expert.placement.layerRanges.push_back({LayerRange{0, 10}, DeviceKind::Gpu0});
    expert.placement.layerRanges.push_back({LayerRange{11, -1}, DeviceKind::Stream});
    expert.placement.embeddings.force(DeviceKind::Host, SettingAuthority::UserLocked,
                                      SettingMutability::TokenBoundary);
    expert.placement.lmHead.force(DeviceKind::Gpu0, SettingAuthority::UserLocked,
                                  SettingMutability::TokenBoundary);
    expert.placement.attentionClass.force(DeviceKind::Gpu0, SettingAuthority::UserOverride,
                                          SettingMutability::TokenBoundary);
    expert.placement.ffnClass.force(DeviceKind::Stream, SettingAuthority::UserOverride,
                                    SettingMutability::TokenBoundary);
    auto ar = ExecutionPolicyStore::Instance().apply(
        expert, SettingAuthority::Session, "P1_IDE_EXEC_POLICY_APPLY_001");
    PRED("POLICY_SESSION_APPLY", ar.ok);

    ElasticResidencyManager elastic;
    elastic.Initialize(ElasticFromPolicy(ActivePolicy()));
    elastic.RegisterTensor("token_embd.weight", ~0u, ~0u, 0, 1024,
                           TensorFormat::Q4_0, nullptr);
    elastic.RegisterTensor("blk.0.attn_q.weight", 0, ~0u, 0, 2048,
                           TensorFormat::Q4_0, nullptr);
    elastic.RegisterTensor("blk.14.ffn_down.weight", 14, ~0u, 0, 4096,
                           TensorFormat::Q4_0, nullptr);
    elastic.RegisterTensor("output.weight", ~0u, ~0u, 0, 1024,
                           TensorFormat::Q4_0, nullptr);

    auto rep = EnforcePolicyOnIdeLoad(&elastic, "synthetic:ide-load-seam", 22, 4);

    PRED("POLICY_LOADED_BEFORE_RESIDENCY", rep.policyLoaded);
    PRED("EFFECTIVE_POLICY_VISIBLE", rep.effectiveVisible && !rep.policySha.empty());
    PRED("PLACEMENT_PLAN_DERIVED", rep.planDerived);
    PRED("GPU_LAYER_COUNTS_APPLIED",
         rep.gpuLayerCountsApplied && (rep.gpu0Layers + rep.streamLayers) > 0);
    PRED("VRAM_CAPS_APPLIED", rep.vramCapsApplied);
    PRED("RAM_CAP_APPLIED", rep.ramCapApplied);
    PRED("STREAM_POLICY_APPLIED", rep.streamPolicyApplied);
    PRED("KV_POLICY_APPLIED", rep.kvPolicyApplied);
    PRED("MODEL_READY", rep.modelReady);
    PRED("OBSERVED_PLACEMENT_MATCHES_PLAN", rep.observedMatchesPlan);

    const bool all = (g_fail == 0);
    WriteGate(fs::path("evidence") / "P1_IDE_EXEC_POLICY_APPLY_001", rep,
              "synthetic:ide-load-seam", all);
    std::printf("\nGATE %s  mismatches=%zu observed=%zu sha=%s\n",
                all ? "PASS" : "FAIL", rep.mismatches, rep.observedTensors,
                rep.policySha.c_str());
    _Exit(all ? 0 : 1);
}
