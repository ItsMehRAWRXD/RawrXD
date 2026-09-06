// ============================================================================
// ObservationBuilder.hpp — INV-4: observe actual residency (Apply report + MARS)
// ============================================================================
#pragma once

#include "ExecutionObservation.hpp"
#include "ExecutionPolicyApply.hpp"
#include "HostRamTelemetry.hpp"
#include "../TelemetrySinks.hpp"
#include "../mars/MARSController.hpp"
#include "../mars/VRAMManager.hpp"

namespace Deep2 {
namespace Exec {

inline int ParseLayerIndex(const std::string& name) {
    auto tryParse = [&](const char* prefix) -> int {
        const size_t p = name.find(prefix);
        if (p == std::string::npos) return -1;
        size_t i = p + std::char_traits<char>::length(prefix);
        if (i >= name.size() || name[i] < '0' || name[i] > '9') return -1;
        int L = 0;
        while (i < name.size() && name[i] >= '0' && name[i] <= '9')
            L = L * 10 + (name[i++] - '0');
        if (i < name.size() && name[i] == '.') return L;
        return -1;
    };
    int L = tryParse("blk.");
    if (L < 0) L = tryParse("layers.");
    if (L < 0) L = tryParse("layer.");
    return L;
}

inline EffectivePlacement PlacementFromObservations(
    const std::vector<ObservedPlacement>& obs,
    const ExecutionPolicy& requested) {
    EffectivePlacement ep;
    ep.embeddings = requested.placement.embeddings.present
                        ? requested.placement.embeddings.value
                        : DeviceKind::Host;
    ep.lmHead = requested.placement.lmHead.present
                    ? requested.placement.lmHead.value
                    : DeviceKind::Gpu0;
    ep.pinnedObserved = requested.placement.pinned;

    std::vector<int> gpuOfLayer(256, -2);
    for (const auto& o : obs) {
        const int L = ParseLayerIndex(o.name);
        const int gpu = o.observedGpu;
        if (L >= 0 && L < 256 && gpu >= 0) gpuOfLayer[L] = gpu;
        if (o.name.find("token_embd") != std::string::npos ||
            o.name.find("embed") != std::string::npos) {
            ep.embeddings = (gpu == 0)   ? DeviceKind::Gpu0
                            : (gpu == 1) ? DeviceKind::Gpu1
                                         : DeviceKind::Host;
        }
        if (o.name.find("output.weight") != std::string::npos ||
            o.name.find("lm_head") != std::string::npos) {
            ep.lmHead = (gpu == 0) ? DeviceKind::Gpu0
                        : (gpu == 1) ? DeviceKind::Gpu1
                                     : DeviceKind::Host;
        }
        PlacementRule rule;
        rule.pattern = o.name;
        rule.device = (gpu == 0)   ? DeviceKind::Gpu0
                      : (gpu == 1) ? DeviceKind::Gpu1
                      : (gpu < 0)  ? DeviceKind::Stream
                                   : DeviceKind::Host;
        rule.authority = SettingAuthority::RuntimeLearned;
        ep.tensorRules.push_back(rule);
    }

    int start = -1, curGpu = -2;
    for (int L = 0; L <= 256; ++L) {
        const int g = (L < 256) ? gpuOfLayer[L] : -2;
        if (g == curGpu) continue;
        if (start >= 0 && curGpu >= 0) {
            DeviceKind d =
                (curGpu == 0) ? DeviceKind::Gpu0 : DeviceKind::Gpu1;
            ep.layerRanges.push_back({{start, L - 1}, d});
        }
        start = (g >= 0) ? L : -1;
        curGpu = g;
    }
    return ep;
}

inline void FillTelemetry(ExecutionObservation& o, MARS::MARSController* mars) {
    SampleRunRamPeaks();
    const auto& io = GlobalTelemetry().io;
    o.nvmeLogicalRequestedBytes = io.nvmeLogicalRequestedBytes.load();
    o.nvmePhysicalReadBytes = io.nvmePhysicalReadBytes.load();
    o.nvmeUsefulPayloadBytes = io.nvmeUsefulPayloadBytes.load();
    o.nvmePrefetchBytes = io.nvmePrefetchBytes.load();
    o.nvmeDiscardedPrefetchBytes = io.nvmeDiscardedPrefetchBytes.load();
    o.streamChurnBytes = StreamChurnBytes();
    o.bytesNvmeToRam = o.nvmePhysicalReadBytes; // legacy alias = physical only
    o.bytesHostToGpu = io.hostToGpuBytes.load();

    if (mars && mars->IsInitialized()) {
        if (auto* vm = mars->GetVRAMManager()) {
            const auto live = vm->SnapshotLive();
            o.fromLiveTelemetry = true;
            o.peakVramBytes = live.peakVramTotal;
            if (live.bytesHostToGpu > o.bytesHostToGpu)
                o.bytesHostToGpu = live.bytesHostToGpu;
            o.migrations = live.migrations;
            o.residencyMisses = live.residencyMisses;
            o.spillToRam = live.spillToRam;
            o.spillToNvme = live.spillToNvme;
            o.marsManagedRam = live.usedVram[0] + live.usedVram[1];
        }
    }

    HostRamSnapshot ram = SampleHostRam();
    o.processWorkingSetCurrent = ram.processWorkingSetCurrent;
    o.runWorkingSetPeak = ram.runWorkingSetPeak;
    o.processLifetimeWorkingSetPeak = ram.processLifetimeWorkingSetPeak;
    o.runPrivateCommitPeak = ram.runPrivateCommitPeak;
    o.peakRamBytes = PreferPeak(o.runPrivateCommitPeak, o.runWorkingSetPeak);
    o.streamingWorkingEstimate = o.nvmeUsefulPayloadBytes;
    if (o.nvmePhysicalReadBytes > 0 || o.fromLiveTelemetry || ram.fromOs)
        o.fromLiveTelemetry = true;
}

inline ExecutionObservation BuildObservation(
    const HardwareSnapshot& hw, const std::string& modelFp,
    const std::string& modelName, const std::string& quant, double tps,
    double ttftMs, bool completed, bool outputValid,
    const ExecutionPolicy& requested,
    MARS::MARSController* mars = nullptr) {
    ExecutionObservation o;
    o.hardware = hw;
    if (o.hardware.fingerprint.empty())
        o.hardware.fingerprint = MakeHardwareFingerprint(hw);
    o.modelFingerprint = modelFp;
    o.modelName = modelName;
    o.quant = quant;
    o.tokensPerSecond = tps;
    o.ttftMs = ttftMs;
    o.completed = completed;
    o.outputValid = outputValid;

    FillTelemetry(o, mars);

    // INV-4 primary source: last observe pass (actual ≠ planned).
    const auto& report = LastApplyReport();
    if (!report.observations.empty()) {
        o.actualPlacement =
            PlacementFromObservations(report.observations, requested);
        o.fromLiveTelemetry = true;
    } else if (mars && mars->GetTensorGraph() &&
               mars->GetTensorGraph()->GetNodeCount() > 0) {
        PlacementApplyReport tmp;
        ObserveMatchesPlan(*mars, LastPlacementPlan(), tmp);
        if (!tmp.observations.empty())
            o.actualPlacement =
                PlacementFromObservations(tmp.observations, requested);
    }
    // else: empty actualPlacement → metrics-only learn (no false placement)
    return o;
}

} // namespace Exec
} // namespace Deep2
