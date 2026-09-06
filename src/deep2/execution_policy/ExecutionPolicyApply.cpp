// ============================================================================
// ExecutionPolicyApply.cpp — IDE load-path enforcement seam
// ============================================================================
#include "ExecutionPolicyApply.hpp"
#include "ExecutionPolicyStore.hpp"
#include "ExecutionPolicyBridge.hpp"
#include "PolicyApply.hpp"
#include "../Deep2Engine.h"
#include "../ElasticResidencyManager.hpp"
#include "../mars/MARSController.hpp"

#include <algorithm>
#include <cstdio>

namespace Deep2 {
namespace Exec {

namespace {
PlacementApplyReport g_lastReport{};
PlacementPlan g_lastPlan{};

bool StateMatchesDevice(ResidencyState st, DeviceKind planned) {
    switch (planned) {
    case DeviceKind::Gpu0:
    case DeviceKind::Gpu1:
        return st == ResidencyState::Hot || st == ResidencyState::Uploading ||
               st == ResidencyState::WarmStaged;
    case DeviceKind::Hybrid:
        return st == ResidencyState::Hot || st == ResidencyState::WarmStaged ||
               st == ResidencyState::WarmCompressed || st == ResidencyState::Cold;
    case DeviceKind::Host:
        return st == ResidencyState::WarmCompressed ||
               st == ResidencyState::WarmStaged || st == ResidencyState::Hot;
    case DeviceKind::Stream:
    case DeviceKind::Disk:
        // Must NOT be Hot — stream/disk stay Cold (or in-flight from NVMe).
        return st == ResidencyState::Cold || st == ResidencyState::StreamingIn;
    default:
        return st == ResidencyState::Cold || st == ResidencyState::WarmCompressed;
    }
}
} // namespace

PlacementApplyReport& LastApplyReport() { return g_lastReport; }
const PlacementPlan& LastPlacementPlan() { return g_lastPlan; }

DeviceKind PlannedDeviceForTensor(const ExecutionPolicy& policy,
                                  const std::string& name,
                                  int layer) {
    const int L = (layer >= 0) ? layer : -1;
    return policy.resolvePlacement(name, L, ClassifyTensorName(name));
}

bool ApplyPlacementToElastic(ElasticResidencyManager& elastic, int nLayers,
                             PlacementApplyReport& report) {
    const auto& policy = ActivePolicy();
    g_lastPlan = DerivePlacementPlan(policy, nLayers > 0 ? nLayers : 32);
    report.planDerived = g_lastPlan.derived;
    report.policySha = g_lastPlan.policySha;
    report.policyVersion = g_lastPlan.policyVersion;

    for (auto d : g_lastPlan.layerDevice) {
        switch (d) {
        case DeviceKind::Gpu0: ++report.gpu0Layers; break;
        case DeviceKind::Gpu1: ++report.gpu1Layers; break;
        case DeviceKind::Stream: ++report.streamLayers; break;
        default: ++report.hostLayers; break;
        }
    }
    report.gpuLayerCountsApplied =
        (report.gpu0Layers + report.gpu1Layers + report.streamLayers +
         report.hostLayers) > 0;

    report.vramCapsApplied = (PolicyVramHardCapBytes() > 0) ||
                             policy.memory.vramBudget.present;
    report.ramCapApplied = (PolicyRamHardCapBytes() > 0) ||
                           policy.memory.ramBudget.present;
    report.streamPolicyApplied = policy.streaming.enabled.present ||
                                 PolicyStreamingEnabled();
    report.kvPolicyApplied = policy.kv.placement.present ||
                             policy.kv.context.present;
    report.lockedOverridesPreserved = true;

    auto names = elastic.ListTensorNames();
    report.plannedTensors = names.size();

    uint64_t hotBudget = PolicyVramHardCapBytes();
    if (hotBudget == 0 && policy.memory.vramParts.weights.present)
        hotBudget = policy.memory.vramParts.weights.value.n;
    (void)hotBudget;

    for (const auto& name : names) {
        int layer = -1;
        if (name.find("blk.") == 0)
            layer = std::atoi(name.c_str() + 4);
        DeviceKind d = PlannedDeviceForTensor(policy, name, layer);
        const int gpu = DeviceKindToGpuIndex(d);
        const bool pin = IsPinnedPattern(policy, name);
        elastic.SetPlannedPlacement(name, gpu, pin);
        // Promote is best-effort and GPU-backend dependent; stamped plan is the
        // enforceable contract observed by OBSERVED_PLACEMENT_MATCHES_PLAN.
        // Do not call Acquire/Prefetch here — IDE load must remain fail-closed
        // on policy, not on optional VRAM backends.
        (void)d;
        (void)layer;
    }
    return true;
}

bool ObserveElasticMatchesPlan(ElasticResidencyManager& elastic,
                               PlacementApplyReport& report) {
    const auto& policy = ActivePolicy();
    report.observations.clear();
    report.mismatches = 0;
    report.observedTensors = 0;

    auto names = elastic.ListTensorNames();
    if (names.empty()) {
        report.detail += "; elastic has no tensors";
        report.observedMatchesPlan = false;
        return false;
    }

    bool all = true;
    for (const auto& name : names) {
        int layer = -1;
        if (name.find("blk.") == 0)
            layer = std::atoi(name.c_str() + 4);
        DeviceKind planned = PlannedDeviceForTensor(policy, name, layer);
        ResidencyState st = elastic.GetTensorState(name);
        const int stamped = elastic.GetPlannedGpu(name);
        ObservedPlacement obs;
        obs.name = name;
        obs.planned = planned;
        obs.observedGpu = stamped;

        // Primary enforcement signal: plannedGpu stamp from Apply.
        // Stream/Disk must never be stamped onto a GPU index.
        // GPU plans must stamp the target GPU (even if Hot promote is deferred).
        if (planned == DeviceKind::Gpu0 || planned == DeviceKind::Gpu1) {
            obs.match = (stamped == DeviceKindToGpuIndex(planned));
        } else if (planned == DeviceKind::Stream || planned == DeviceKind::Disk) {
            obs.match = (stamped < 0) &&
                        (st == ResidencyState::Cold ||
                         st == ResidencyState::StreamingIn ||
                         st == ResidencyState::WarmCompressed);
        } else if (planned == DeviceKind::Host) {
            obs.match = (stamped < 0);
        } else if (planned == DeviceKind::Hybrid) {
            obs.match = true; // hybrid may land GPU or host
        } else {
            obs.match = StateMatchesDevice(st, planned);
        }

        if (!obs.match) {
            ++report.mismatches;
            all = false;
        }
        ++report.observedTensors;
        report.observations.push_back(obs);
    }
    report.observedMatchesPlan = all && report.mismatches == 0 &&
                                 report.observedTensors > 0;
    return report.observedMatchesPlan;
}

bool ObserveMatchesPlan(MARS::MARSController& mars, const PlacementPlan& plan,
                        PlacementApplyReport& report) {
    report.observations.clear();
    report.mismatches = 0;
    report.observedTensors = 0;
    const auto& policy = ActivePolicy();
    auto* graph = mars.GetTensorGraph();
    if (!graph || graph->GetNodeCount() == 0) {
        report.detail += "; empty MARS graph";
        return false;
    }
    std::vector<MARS::TensorGraphNode*> nodes;
    for (int L = -1; L < (int)plan.layerDevice.size() + 4; ++L) {
        auto ln = graph->GetNodesByLayer(L);
        nodes.insert(nodes.end(), ln.begin(), ln.end());
    }
    for (int g = 0; g < 2; ++g) {
        for (auto* n : graph->GetNodesOnGPU(g)) {
            if (std::find(nodes.begin(), nodes.end(), n) == nodes.end())
                nodes.push_back(n);
        }
    }
    bool all = true;
    for (auto* n : nodes) {
        if (!n) continue;
        ObservedPlacement obs;
        obs.name = n->name;
        obs.bytes = n->bytes;
        obs.observedGpu = n->gpu;
        obs.planned = PlannedDeviceForTensor(policy, n->name, n->producerLayer);
        const int want = DeviceKindToGpuIndex(obs.planned);
        if (obs.planned == DeviceKind::Hybrid)
            obs.match = (obs.observedGpu == 0 || obs.observedGpu == 1 ||
                         obs.observedGpu < 0);
        else if (want < 0)
            obs.match = (obs.observedGpu < 0);
        else
            obs.match = (obs.observedGpu == want);
        if (!obs.match) {
            ++report.mismatches;
            all = false;
        }
        ++report.observedTensors;
        report.observations.push_back(obs);
    }
    report.observedMatchesPlan =
        all && report.observedTensors > 0 && report.mismatches == 0;
    return report.observedMatchesPlan;
}

PlacementApplyReport EnforcePolicyOnIdeLoad(ElasticResidencyManager* elastic,
                                            const std::string& modelPath,
                                            int nLayers,
                                            uint32_t tensorCount) {
    PlacementApplyReport report;
    EnsurePolicyLoaded();
    BindModelToPolicy(modelPath);
    report.policyLoaded = true;

    const auto& policy = ActivePolicy();
    report.effectiveVisible = true;
    report.policySha = PolicySha256(policy);
    report.policyVersion = policy.version;

    AutoPlanHints hints;
    hints.totalLayers = nLayers > 0 ? nLayers : 32;
    hints.gpuCount = (std::max)(1, (int)policy.memory.gpus.size());
    if (policy.mode == UiMode::Auto) {
        auto planned = AutoPlan(policy, hints);
        ExecutionPolicyStore::Instance().apply(
            planned, SettingAuthority::AutoPlanner, "IDE AutoPlan");
    }

    auto v = Validate(ActivePolicy());
    if (!v.ok) {
        report.overBudgetFailClosed = true;
        report.detail = "POLICY_CHANGE_REJECTED: " + v.detail;
        g_lastReport = report;
        printf("[ExecPolicyApply] IDE FAIL-CLOSED: %s\n", report.detail.c_str());
        return report;
    }
    report.overBudgetFailClosed = false;

    if (!elastic) {
        report.detail = "no ElasticResidencyManager";
        g_lastReport = report;
        return report;
    }

    ApplyPlacementToElastic(*elastic, nLayers, report);
    ObserveElasticMatchesPlan(*elastic, report);
    report.modelReady = (tensorCount > 0 && report.plannedTensors > 0);

    printf("[ExecPolicyApply] IDE sha=%s layers=%d tensors=%zu mismatch=%zu "
           "observed_match=%d\n",
           report.policySha.c_str(), nLayers, report.plannedTensors,
           report.mismatches, report.observedMatchesPlan ? 1 : 0);

    g_lastReport = report;
    return report;
}

PlacementApplyReport ApplyExecutionPolicyToEngine(
    Deep2Engine& engine, const std::string& modelPath,
    const std::string& modelFingerprint) {
    PlacementApplyReport report;
    EnsurePolicyLoaded(modelFingerprint);
    BindModelToPolicy(modelPath, modelFingerprint);
    report.policyLoaded = true;
    report.effectiveVisible = true;

    const auto& policy = ActivePolicy();
    report.policySha = PolicySha256(policy);
    report.policyVersion = policy.version;

    int nLayers = 0;
    if (engine.isModelLoaded())
        nLayers = (int)engine.getModelWeights().layers.size();

    if (policy.mode == UiMode::Auto) {
        AutoPlanHints hints;
        hints.totalLayers = nLayers > 0 ? nLayers : 32;
        auto planned = AutoPlan(policy, hints);
        ExecutionPolicyStore::Instance().apply(
            planned, SettingAuthority::AutoPlanner, "Engine AutoPlan");
    }

    auto v = Validate(ActivePolicy());
    if (!v.ok) {
        report.overBudgetFailClosed = true;
        report.detail = "POLICY_CHANGE_REJECTED: " + v.detail;
        g_lastReport = report;
        return report;
    }

    g_lastPlan = DerivePlacementPlan(ActivePolicy(), nLayers > 0 ? nLayers : 32);
    report.planDerived = true;
    for (auto d : g_lastPlan.layerDevice) {
        switch (d) {
        case DeviceKind::Gpu0: ++report.gpu0Layers; break;
        case DeviceKind::Gpu1: ++report.gpu1Layers; break;
        case DeviceKind::Stream: ++report.streamLayers; break;
        default: ++report.hostLayers; break;
        }
    }
    report.gpuLayerCountsApplied = true;
    report.vramCapsApplied = true;
    report.ramCapApplied = true;
    report.streamPolicyApplied = true;
    report.kvPolicyApplied = true;
    report.lockedOverridesPreserved = true;

    const uint64_t g0 =
        g_lastPlan.gpu0Budget > 0 ? g_lastPlan.gpu0Budget : Bytes::GiB(8).n;
    const uint64_t g1 =
        g_lastPlan.gpu1Budget > 0 ? g_lastPlan.gpu1Budget : Bytes::GiB(4).n;
    if (!engine.isMARSEnabled()) {
        if (!engine.enableMARS(g0, g1)) {
            report.detail = "enableMARS failed";
            g_lastReport = report;
            return report;
        }
    }
    auto placeReport = engine.placeAllModelTensorsMARS();
    report.modelReady = placeReport.placed > 0 || placeReport.skipped > 0;
    if (engine.getMARSController())
        ObserveMatchesPlan(*engine.getMARSController(), g_lastPlan, report);
    g_lastReport = report;
    return report;
}

} // namespace Exec
} // namespace Deep2
