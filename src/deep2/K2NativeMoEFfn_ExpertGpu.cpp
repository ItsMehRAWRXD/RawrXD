/* K2NativeMoEFfn_ExpertGpu.cpp — DualStick device stick worklist (no host GEMV). */
#include "K2NativeMoEFfn.hpp"
#include "K2GlobalTensorIndex.hpp"
#include "K2ShardIo.hpp"
#include "MoEExpertResidencyPlace.hpp"
#include "MoEPlaceLiveCounters.hpp"
#include "K2MoEExpertAccounting.hpp"
#include "K2MoEParityCapture.hpp"
#include "QuantKernelRegistry.hpp"
#include "StickGpuLocal.hpp"
#include "StreamPathTiming.hpp"
#include "lavapath/DualStickExpertBundle.hpp"
#include "lavapath/DualStickPinCoherency.hpp"
#include "lavapath/DualStickStreamWindow.hpp"
#include "lavapath/EndDeviceStep3Diag.hpp"
#include "vulkan_compute.h"
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace Deep2 {

bool K2MoEExecExpertGpuDevice(unsigned stick, int ggmlGate, const uint8_t* g,
                              size_t gb, int ggmlUp, const uint8_t* u, size_t ub,
                              int ggmlDown, const uint8_t* d, size_t db,
                              const float* hidden, float* expertOut, size_t H,
                              size_t I, uint32_t layer, int expertId,
                              int acquireMiss);

void StickGpuCommit(const StickGpuLocal& s) {
    MoEPlaceLive().device_down_vectors += s.device_down_vectors;
    MoEPlaceLive().device_partial_accums += s.device_partial_accums;
    MoEPlaceLive().d2h_partial_vectors += s.d2h_partial_vectors;
    MoEPlaceLive().host_expert_down_vectors += s.host_expert_down_vectors;
    MoEPlaceLive().expert_gpu_exec += s.expert_gpu_exec;
    MoEPlaceLive().gpu_submits += s.gpu_submits;
    MoEPlaceLive().gpu_waits += s.gpu_waits;
    MoEPlaceLive().expert_acquire_hits += s.acquire_hits;
    MoEPlaceLive().expert_acquire_misses += s.acquire_misses;
    MoEPlaceLive().h2d_bytes += s.h2d_bytes;
    MoEPlaceLive().d2h_bytes += s.d2h_bytes;
    MoEPlaceLive().gpu0_experts += s.gpu0_experts;
    MoEPlaceLive().gpu1_experts += s.gpu1_experts;
    MoEPlaceLive().device_down_partials += s.device_down_vectors;
    MoEPlaceLive().expert_bundle_lookups += s.bundle_lookups;
    MoEPlaceLive().expert_bundle_hits += s.bundle_hits;
    MoEPlaceLive().expert_bundle_misses += s.bundle_misses;
    MoEPlaceLive().hit_bytes += s.hit_bytes;
    MoEPlaceLive().compulsory_miss_bytes += s.compulsory_miss_bytes;
    MoEPlaceLive().reload_miss_bytes += s.reload_miss_bytes;
    MoEPlaceLive().seen_bundle_keys += s.seen_bundle_keys;
}

namespace {

bool ReadSlice(const GlobalTensorIndex& index, const char* base, uint32_t expertId,
               std::vector<uint8_t>& out, int& ggmlType, size_t& outBytes,
               std::string& error) {
    auto slice = index.FindExpertSlice(base, expertId);
    if (!slice || !slice->expertStrideBytes || !slice->byteSize) {
        error = "expert slice missing";
        return false;
    }
    auto full = index.Find(base);
    if (!full || slice->byteOffset + slice->byteSize > full->byteSize) {
        error = "expert slice OOB";
        return false;
    }
    ggmlType = (int)slice->ggmlType;
    outBytes = (size_t)slice->byteSize;
    out.resize(outBytes);
    const uint64_t t0 = StreamPathTiming_NowUs();
    if (!K2ShardIo_Read(index.ShardPath(slice->shardId).string(),
                        slice->fileOffset + slice->byteOffset, out.data(),
                        out.size())) {
        error = "K2ShardIo_Read expert failed";
        return false;
    }
    StreamPathTiming_Add(SPT_shardMoe(), t0);
    return true;
}

} // namespace

bool K2MoEExecStickWorklist(const GlobalTensorIndex& index,
                            const KimiK2Config& cfg, uint32_t layer,
                            const float* normed, MoEPlacePlan& plan,
                            const uint32_t* idx, uint32_t n, unsigned stickId,
                            float* partial, StickGpuLocal& ctr,
                            std::vector<int32_t>& hotExperts,
                            std::string& error) {
    if (!partial) return true;
    unsigned stick = stickId & 1u;
    size_t H = cfg.hiddenDim;
    size_t I = cfg.moeIntermediateSize ? cfg.moeIntermediateSize : 2048u;
    /* A missing VC is handled by K2MoEPlaceAndExec's backend-admission
       branch.  Reaching this device-only function without a VC is therefore
       an invariant violation, not a place to invent a host result. */
    if (!DualStickVc(stick)) {
        error = "DualStick VC missing for stick worklist";
        return false;
    }
    ed3::BeginStick(stick, layer, normed, H);
    auto* vcHold = DualStickVc(stick);
    if (!K2MoEStickBeginDevice(stick, normed, H, I)) {
        error = "K2MoEStickBeginDevice failed";
        return false;
    }
    char gateN[64], upN[64], downN[64];
    std::snprintf(gateN, sizeof(gateN), "blk.%u.ffn_gate_exps.weight", layer);
    std::snprintf(upN, sizeof(upN), "blk.%u.ffn_up_exps.weight", layer);
    std::snprintf(downN, sizeof(downN), "blk.%u.ffn_down_exps.weight", layer);

    struct Resolved {
        int expertId;
        float weight;
        int gt, ut, dt;
        size_t gb, ub, db;
        const uint8_t *g, *u, *d;
        int acquireMiss;
        std::vector<uint8_t> gateB, upB, downB;
    };
    std::vector<Resolved> work;
    work.reserve(n);
    for (uint32_t k = 0; k < n; ++k) {
        MoEPlaceSlot& mut = plan.slots[idx[k]];
        if (mut.expertId < 0) continue;
        /* The stick worklist is the production GPU route and bypasses
           K2MoEExecExpert().  Record selection here so the opt-in matrix
           remains complete for both CPU and GPU backends. */
        K2MoEExpertAccounting::Instance().Selected(
            layer, mut.expertId);
        ctr.bundle_lookups++;
        Resolved r{};
        r.expertId = mut.expertId;
        r.weight = mut.weight;
        r.acquireMiss = 1;
        if (DualStickBundlePinsReady(stick, (int)layer, mut.expertId, H, I)) {
            DualStickBundleTouchPins(stick, (int)layer, mut.expertId, H, I);
            DualStickBundleMeta m{};
            DualStickBundleLookup((int)layer, mut.expertId, &m);
            ctr.bundle_hits++;
            ctr.hit_bytes += (uint64_t)m.gb + m.ub + m.db;
            r.gt = m.gt;
            r.ut = m.ut;
            r.dt = m.dt;
            r.gb = m.gb;
            r.ub = m.ub;
            r.db = m.db;
            r.g = r.u = r.d = nullptr;
            r.acquireMiss = 0;
        } else {
            ctr.bundle_misses++;
            if (!ReadSlice(index, gateN, (uint32_t)mut.expertId, r.gateB, r.gt,
                           r.gb, error) ||
                !ReadSlice(index, upN, (uint32_t)mut.expertId, r.upB, r.ut, r.ub,
                           error) ||
                !ReadSlice(index, downN, (uint32_t)mut.expertId, r.downB, r.dt,
                           r.db, error))
                return false;
            r.g = r.gateB.data();
            r.u = r.upB.data();
            r.d = r.downB.data();
            DualStickBundleMeta prev{};
            const int seen =
                DualStickBundleLookup((int)layer, mut.expertId, &prev);
            const uint64_t eb = (uint64_t)r.gb + r.ub + r.db;
            if (seen) ctr.reload_miss_bytes += eb;
            else {
                ctr.compulsory_miss_bytes += eb;
                ctr.seen_bundle_keys++;
            }
        }
        work.push_back(std::move(r));
    }
    /* Deterministic partial-sum order within stick (associativity lock). */
    std::sort(work.begin(), work.end(),
              [](const Resolved& a, const Resolved& b) {
                  return a.expertId < b.expertId;
              });

    /* Diagnostic-only single-expert isolation.  This is deliberately
       opt-in and layer-scoped: the production routed worklist is unchanged
       unless both variables are valid and the current layer matches.  It
       exists to make the shared scratch arena attributable to exactly one
       routed expert while investigating a numerical divergence. */
    const char* isolateLayerEnv =
        std::getenv("DEEP2_MOE_PARITY_SINGLE_LAYER");
    const char* isolateExpertEnv =
        std::getenv("DEEP2_MOE_PARITY_SINGLE_EXPERT");
    if (isolateLayerEnv && isolateLayerEnv[0] && isolateExpertEnv &&
        isolateExpertEnv[0]) {
        char* layerEnd = nullptr;
        char* expertEnd = nullptr;
        const long isolateLayer = std::strtol(isolateLayerEnv, &layerEnd, 10);
        const long isolateExpert = std::strtol(isolateExpertEnv, &expertEnd, 10);
        if (layerEnd == isolateLayerEnv || *layerEnd != '\0' ||
            expertEnd == isolateExpertEnv || *expertEnd != '\0' ||
            isolateLayer < 0 || isolateExpert < 0) {
            error = "invalid single-expert parity selector";
            return false;
        }
        if (layer == static_cast<uint32_t>(isolateLayer)) {
            std::vector<Resolved> isolated;
            isolated.reserve(1);
            for (auto& candidate : work) {
                if (candidate.expertId == static_cast<int>(isolateExpert))
                    isolated.push_back(std::move(candidate));
            }
            if (isolated.size() != 1u) {
                std::fprintf(stderr,
                             "GPU_MOE_SINGLE_EXPERT status=BLOCKED "
                             "layer=%u expert=%ld matches=%zu routed=%zu\n",
                             layer, isolateExpert, isolated.size(), work.size());
                std::fflush(stderr);
                error = "requested single-expert parity target was not routed";
                return false;
            }
            std::fprintf(stderr,
                         "GPU_MOE_SINGLE_EXPERT status=ISOLATED "
                         "layer=%u expert=%ld routed=%zu retained=1\n",
                         layer, isolateExpert, work.size());
            std::fflush(stderr);
            work.swap(isolated);
        }
    }

    /* Capture only the CPU-side packed inputs for an independent scalar
       oracle.  This is deliberately before fused command recording and
       never reads ArenaDown/ArenaFFNAct, so it cannot be mistaken for a GPU
       output witness.  At most one cold, host-visible expert is captured per
       stick worklist and the helper refuses overwrites. */
    const char* captureDir = std::getenv("DEEP2_MOE_PARITY_CAPTURE_DIR");
    const bool captureRequested = captureDir && captureDir[0] != '\0';
    const Resolved* scalarCapture = nullptr;
    int scalarCaptureExpert = -1;
    if (captureRequested) {
        bool written = false;
        int captureExpert = -1;
        /* The fused arena is reused in sorted worklist order. Capture the
           last host-visible expert so its post-fence arena contents have a
           stable expert identity for the output witness. */
        for (auto it = work.rbegin(); it != work.rend(); ++it) {
            const auto& candidate = *it;
            if (!candidate.g || !candidate.u || !candidate.d) continue;
            captureExpert = candidate.expertId;
            scalarCapture = &candidate;
            scalarCaptureExpert = candidate.expertId;
            written = k2_parity_capture::CaptureScalarInputs(
                stick, layer, candidate.expertId,
                candidate.gt, candidate.g, candidate.gb,
                candidate.ut, candidate.u, candidate.ub,
                candidate.dt, candidate.d, candidate.db,
                normed, H, I);
            break;
        }
        std::fprintf(stderr,
                     "GPU_SCALAR_INPUT_CAPTURE layer=%u stick=%u expert=%d "
                     "status=%s scope=CPU_INPUTS_ONLY\n",
                     layer, stick, captureExpert,
                     written ? "WRITTEN" : "SKIPPED");
        std::fflush(stderr);
    }

    /* Optional aggregate parity.  The fused worklist keeps each expert's
       down-vector in a device scratch arena and accumulates it into the
       partial vector before the command buffer is submitted.  Reading
       ArenaDown() between expert enqueues would compare an unsubmitted or
       stale scratch value.  Compare the post-D2H aggregate instead, using the
       same expert inputs, slices, and route weights through the reference CPU
       kernels.  This remains diagnostic-only and never changes admission. */
    const char* parityEnv = std::getenv("DEEP2_MOE_GPU_PARITY");
    const bool parityEnabled = parityEnv && parityEnv[0] == '1' && parityEnv[1] == '\0';
    uint32_t parityLimit = 1u;
    if (const char* lim = std::getenv("DEEP2_MOE_GPU_PARITY_LIMIT")) {
        char* end = nullptr;
        const unsigned long parsed = std::strtoul(lim, &end, 10);
        if (end != lim && *end == '\0' && parsed > 0 && parsed <= 64u)
            parityLimit = static_cast<uint32_t>(parsed);
    }
    auto emitAggregateParity = [&](const float* gpuAggregate) {
        if ((!parityEnabled && !captureRequested) || !gpuAggregate)
            return;
        if (parityEnabled && parityLimit < work.size()) {
            std::fprintf(stderr,
                         "GPU_MOE_AGGREGATE_PARITY layer=%u stick=%u status=SKIPPED "
                         "reason=PARITY_LIMIT limit=%u experts=%zu\n",
                         layer, stick, parityLimit, work.size());
            return;
        }
        std::vector<float> cpuAggregate(H, 0.0f);
        std::vector<float> gateOut(I, 0.0f), upOut(I, 0.0f), cpuOut(H, 0.0f);
        std::vector<float> cpuLast(H, 0.0f);
        int lastExpert = -1;
        for (const auto& r : work) {
            if (!r.g || !r.u || !r.d || !r.gb || !r.ub || !r.db) {
                std::fprintf(stderr,
                             "GPU_MOE_AGGREGATE_PARITY layer=%u stick=%u "
                             "status=BLOCKED reason=CPU_EXPERT_INPUT_UNAVAILABLE "
                             "expert=%d\n",
                             layer, stick, r.expertId);
                std::fflush(stderr);
                return;
            }
            auto gate = QuantKernelRegistry::Instance().GetGEMV(r.gt);
            auto up = QuantKernelRegistry::Instance().GetGEMV(r.ut);
            auto down = QuantKernelRegistry::Instance().GetGEMV(r.dt);
            if (!gate || !up || !down) {
                std::fprintf(stderr,
                             "GPU_MOE_AGGREGATE_PARITY layer=%u stick=%u "
                             "status=CPU_KERNEL_MISSING expert=%d\n",
                             layer, stick, r.expertId);
                return;
            }
            std::fill(gateOut.begin(), gateOut.end(), 0.0f);
            std::fill(upOut.begin(), upOut.end(), 0.0f);
            std::fill(cpuOut.begin(), cpuOut.end(), 0.0f);
            gate(r.g, normed, gateOut.data(), I, H);
            up(r.u, normed, upOut.data(), I, H);
            for (size_t i = 0; i < I; ++i) {
                const float x = gateOut[i];
                gateOut[i] = (x / (1.0f + std::exp(-x))) * upOut[i];
            }
            down(r.d, gateOut.data(), cpuOut.data(), H, I);
            for (size_t i = 0; i < H; ++i)
                cpuAggregate[i] += r.weight * cpuOut[i];
            cpuLast = cpuOut;
            lastExpert = r.expertId;
        }
        double maxAbs = 0.0, sumAbs = 0.0, sumSq = 0.0;
        double gpuSq = 0.0, cpuSq = 0.0, dot = 0.0, maxRel = 0.0;
        size_t nonFinite = 0;
        for (size_t i = 0; i < H; ++i) {
            if (!std::isfinite(gpuAggregate[i]) || !std::isfinite(cpuAggregate[i])) {
                ++nonFinite;
                continue;
            }
            const double d = std::abs((double)gpuAggregate[i] -
                                      (double)cpuAggregate[i]);
            if (d > maxAbs) maxAbs = d;
            const double denom = std::max(1.0e-12, std::abs((double)cpuAggregate[i]));
            if (d / denom > maxRel) maxRel = d / denom;
            sumAbs += d;
            sumSq += d * d;
            gpuSq += (double)gpuAggregate[i] * (double)gpuAggregate[i];
            cpuSq += (double)cpuAggregate[i] * (double)cpuAggregate[i];
            dot += (double)gpuAggregate[i] * (double)cpuAggregate[i];
        }
        const double finiteCount = H > nonFinite ? (double)(H - nonFinite) : 0.0;
        const double rmsAbs = finiteCount > 0.0 ? std::sqrt(sumSq / finiteCount) : 0.0;
        const double cosineDenom = std::sqrt(gpuSq) * std::sqrt(cpuSq);
        const double cosine = cosineDenom > 0.0 ? dot / cosineDenom : 0.0;
        std::fprintf(stderr,
                     "GPU_MOE_AGGREGATE_PARITY layer=%u stick=%u experts=%zu "
                     "status=%s scope=DIAGNOSTIC_ONLY "
                     "max_abs=%.9e mean_abs=%.9e rms_abs=%.9e "
                     "max_rel=%.9e cosine=%.9e gpu_l2=%.9e cpu_l2=%.9e "
                     "finite=%zu nonfinite=%zu\n",
                     layer, stick, work.size(),
                     nonFinite ? "NONFINITE" : "DIAGNOSTIC", maxAbs,
                     H ? sumAbs / (double)H : 0.0, rmsAbs, maxRel,
                     cosine, std::sqrt(gpuSq), std::sqrt(cpuSq),
                     H - nonFinite, nonFinite);
        std::fflush(stderr);

        /* Persist only the completed aggregate pair.  This is useful for
           layer/stick coverage audits but is never a per-expert witness. */
        if (!nonFinite) {
            if (captureRequested) {
                std::vector<int> expertIds;
                std::vector<float> routeWeights;
                expertIds.reserve(work.size());
                routeWeights.reserve(work.size());
                for (const auto& r : work) {
                    expertIds.push_back(r.expertId);
                    routeWeights.push_back(r.weight);
                }
                const bool saved = k2_parity_capture::CaptureAggregateComparison(
                    stick, layer, gpuAggregate, cpuAggregate.data(), H,
                    expertIds.data(), routeWeights.data(), work.size());
                std::fprintf(stderr,
                             "GPU_MOE_AGGREGATE_VECTOR_CAPTURE layer=%u stick=%u "
                             "status=%s scope=AGGREGATE_ONLY certified=0\n",
                             layer, stick, saved ? "WRITTEN" : "SKIPPED");
                std::fflush(stderr);
            }
        }

        const char* stageEnv = std::getenv("DEEP2_MOE_GPU_STAGE_PARITY");
        const bool stageRequested =
            stageEnv && stageEnv[0] == '1' && stageEnv[1] == '\0';
        if (stageRequested && lastExpert >= 0 && work.size() != 1u) {
            std::fprintf(stderr,
                         "GPU_MOE_LAST_STAGE_PARITY layer=%u stick=%u "
                         "status=BLOCKED reason=MULTI_EXPERT_SCRATCH_IDENTITY_UNPROVEN "
                         "experts=%zu\n", layer, stick, work.size());
            std::fflush(stderr);
        }
        if (stageRequested && lastExpert >= 0 && work.size() == 1u) {
            auto* vc = DualStickVc(stick);
            std::vector<float> gpuLast(H, 0.0f);
            std::vector<float> gpuAct(I, 0.0f);
            const bool downloaded =
                vc && vc->DownloadBuf(vc->ArenaDown(), gpuLast.data(),
                                      static_cast<uint32_t>(H));
            const bool actDownloaded =
                vc && vc->DownloadBuf(vc->ArenaFFNAct(), gpuAct.data(),
                                      static_cast<uint32_t>(I));
            double stageMax = 0.0, stageSum = 0.0, stageSq = 0.0;
            size_t stageNonFinite = 0;
            if (downloaded) {
                for (size_t i = 0; i < H; ++i) {
                    if (!std::isfinite(gpuLast[i]) || !std::isfinite(cpuLast[i])) {
                        ++stageNonFinite;
                        continue;
                    }
                    const double d = std::abs(static_cast<double>(gpuLast[i]) -
                                               static_cast<double>(cpuLast[i]));
                    stageMax = std::max(stageMax, d);
                    stageSum += d;
                    stageSq += d * d;
                }
            }
            const double stageFinite = downloaded && H > stageNonFinite
                                           ? static_cast<double>(H - stageNonFinite)
                                           : 0.0;
            std::fprintf(stderr,
                         "GPU_MOE_LAST_DOWN_PARITY layer=%u stick=%u expert=%d "
                         "status=%s scope=DIAGNOSTIC_ONLY max_abs=%.9e mean_abs=%.9e rms_abs=%.9e "
                         "finite=%zu nonfinite=%zu\n",
                         layer, stick, lastExpert,
                         downloaded ? (stageNonFinite ? "NONFINITE" :
                                      "DIAGNOSTIC_UNPROVEN_BUFFER_IDENTITY")
                                   : "DOWNLOAD_FAIL", stageMax,
                         stageFinite > 0.0 ? stageSum / stageFinite : 0.0,
                         stageFinite > 0.0 ? std::sqrt(stageSq / stageFinite) : 0.0,
                         downloaded ? H - stageNonFinite : 0u, stageNonFinite);
            std::fflush(stderr);

            double actMax = 0.0, actSum = 0.0, actSq = 0.0;
            size_t actNonFinite = 0;
            if (actDownloaded) {
                for (size_t i = 0; i < I; ++i) {
                    if (!std::isfinite(gpuAct[i]) || !std::isfinite(gateOut[i])) {
                        ++actNonFinite;
                        continue;
                    }
                    const double d = std::abs(static_cast<double>(gpuAct[i]) -
                                               static_cast<double>(gateOut[i]));
                    actMax = std::max(actMax, d);
                    actSum += d;
                    actSq += d * d;
                }
            }
            const double actFinite = actDownloaded && I > actNonFinite
                                         ? static_cast<double>(I - actNonFinite)
                                         : 0.0;
            std::fprintf(stderr,
                         "GPU_MOE_LAST_ACT_PARITY layer=%u stick=%u expert=%d "
                         "status=%s scope=DIAGNOSTIC_ONLY max_abs=%.9e mean_abs=%.9e rms_abs=%.9e "
                         "finite=%zu nonfinite=%zu\n",
                         layer, stick, lastExpert,
                         actDownloaded ? (actNonFinite ? "NONFINITE" :
                                         "DIAGNOSTIC_UNPROVEN_BUFFER_IDENTITY")
                                       : "DOWNLOAD_FAIL", actMax,
                         actFinite > 0.0 ? actSum / actFinite : 0.0,
                         actFinite > 0.0 ? std::sqrt(actSq / actFinite) : 0.0,
                         actDownloaded ? I - actNonFinite : 0u, actNonFinite);
            std::fflush(stderr);

            /* Completion-ordered per-expert witness.  The helper requires
               real device buffer identities and a nonzero submission count;
               it refuses overwrite and records certified=0.  If the captured
               host slices do not correspond to the final arena owner, fail
               closed instead of attributing another expert's output. */
            if (captureRequested) {
                bool witnessWritten = false;
                const char* reason = "IDENTITY_MISMATCH";
                if (scalarCapture && scalarCaptureExpert == lastExpert &&
                    downloaded && actDownloaded && vc &&
                    scalarCapture->d && scalarCapture->db) {
                    const uint64_t gpuDownBufferId =
                        static_cast<uint64_t>(reinterpret_cast<uintptr_t>(
                            vc->ArenaDown().buffer));
                    const uint64_t gpuActBufferId =
                        static_cast<uint64_t>(reinterpret_cast<uintptr_t>(
                            vc->ArenaFFNAct().buffer));
                    witnessWritten = k2_parity_capture::Capture(
                        stick, layer, lastExpert, scalarCapture->dt,
                        scalarCapture->d, scalarCapture->db,
                        gateOut.data(), I, cpuLast.data(), gpuLast.data(), H,
                        gpuDownBufferId, gpuActBufferId,
                        ctr.gpu_submits);
                    reason = witnessWritten ? "WRITTEN" : "CAPTURE_REJECTED";
                }
                std::fprintf(stderr,
                             "GPU_EXPERT_OUTPUT_CAPTURE layer=%u stick=%u "
                             "expert=%d status=%s scope=POST_DEVICE_COMPLETION "
                             "completion=K2MoEStickEndDevice\n",
                             layer, stick, lastExpert,
                             witnessWritten ? "WRITTEN" : reason);
                std::fflush(stderr);
            }
        }
    };

    /* Hold MoE pins for this stick worklist — peer eviction ⇒ DEVICE_LOST. */
    if (vcHold) vcHold->BeginMoePinHold();
    /* HARD_GATE: pin all weights before fuse (no mid-graph Upload submit). */
    for (auto& r : work) {
        if (!K2MoEStickPinExpert(stick, r.gt, r.g, r.gb, r.ut, r.u, r.ub, r.dt,
                                 r.d, r.db, H, I, layer, r.expertId,
                                 r.acquireMiss, ctr)) {
            if (vcHold) vcHold->EndMoePinHold();
            error = "K2MoEStickPinExpert failed";
            return false;
        }
    }
    if (!K2MoEStickBeginFused(stick)) {
        if (vcHold) vcHold->EndMoePinHold();
        error = "K2MoEStickBeginFused failed";
        return false;
    }
    for (auto& r : work) {
        const uint64_t expertStartNs = K2MoEExpertAccounting::NowNs();
        if (!K2MoEStickExpertDevice(stick, r.gt, r.g, r.gb, r.ut, r.u, r.ub,
                                    r.dt, r.d, r.db, r.weight, H, I, layer,
                                    r.expertId, r.acquireMiss, ctr)) {
            (void)DualStickVc(stick)->EndFusedLayer();
            if (vcHold) vcHold->EndMoePinHold();
            error = "K2MoEStickExpertDevice failed";
            return false;
        }
        K2MoEExpertTiming gpuTiming{};
        gpuTiming.acquireNs = 0;
        gpuTiming.readBytes = static_cast<uint64_t>(r.gb) + r.ub + r.db;
        gpuTiming.totalNs = K2MoEExpertAccounting::NowNs() - expertStartNs;
        gpuTiming.computeNs = gpuTiming.totalNs;
        K2MoEExpertAccounting::Instance().Executed(
            layer, r.expertId, true, r.acquireMiss == 0, gpuTiming);
        hotExperts.push_back(r.expertId);
    }
    if (!K2MoEStickEndFused(stick, ctr)) {
        ed3::NoteFused(0);
        ed3::NoteExperts(hotExperts.data(), (uint32_t)hotExperts.size());
        ed3::EmitBoundary("FUSED_FAIL");
        if (vcHold) vcHold->EndMoePinHold();
        error = "K2MoEStickEndFused failed";
        return false;
    }
    ed3::NoteFused(1);
    ed3::NoteExperts(hotExperts.data(), (uint32_t)hotExperts.size());
    if (vcHold) vcHold->EndMoePinHold();
    if (!K2MoEStickEndDevice(stick, partial, H, ctr)) {
        error = "K2MoEStickEndDevice failed";
        return false;
    }
    emitAggregateParity(partial);
    return true;
}

bool K2MoEExecExpertGpu(unsigned stick, int ggmlGate, const uint8_t* g,
                        size_t gb, int ggmlUp, const uint8_t* u, size_t ub,
                        int ggmlDown, const uint8_t* d, size_t db,
                        const float* hidden, float* expertOut, size_t H,
                        size_t I, uint32_t layer, int expertId) {
    /* Product DualStick path must not host-I/O DispatchGEMVQuant.
       Single-expert callers use device path; host bounce is refuse. */
    auto* vc = DualStickVc(stick);
    if (!vc) return false;
    MoEPlaceLive().expert_bundle_lookups++;
    int acquireMiss = 1;
    int gt = ggmlGate, ut = ggmlUp, dt = ggmlDown;
    size_t gb2 = gb, ub2 = ub, db2 = db;
    const uint8_t *g2 = g, *u2 = u, *d2 = d;
    if (DualStickBundlePinsReady(stick, (int)layer, expertId, H, I)) {
        DualStickBundleTouchPins(stick, (int)layer, expertId, H, I);
        DualStickBundleMeta m{};
        DualStickBundleLookup((int)layer, expertId, &m);
        MoEPlaceLive().expert_bundle_hits++;
        MoEPlaceLive().hit_bytes += (uint64_t)m.gb + m.ub + m.db;
        gt = m.gt;
        ut = m.ut;
        dt = m.dt;
        gb2 = m.gb;
        ub2 = m.ub;
        db2 = m.db;
        g2 = u2 = d2 = nullptr;
        acquireMiss = 0;
    } else {
        if (!g || !u || !d || !gb || !ub || !db) {
            MoEPlaceLive().expert_bundle_misses++;
            return false;
        }
        DualStickBundleMeta prev{};
        const int seen = DualStickBundleLookup((int)layer, expertId, &prev);
        MoEPlaceLive().expert_bundle_misses++;
        const uint64_t eb = (uint64_t)gb + ub + db;
        if (seen) MoEPlaceLive().reload_miss_bytes += eb;
        else {
            MoEPlaceLive().compulsory_miss_bytes += eb;
            MoEPlaceLive().seen_bundle_keys++;
        }
    }
    return K2MoEExecExpertGpuDevice(stick, gt, g2, gb2, ut, u2, ub2, dt, d2, db2,
                                    hidden, expertOut, H, I, layer, expertId,
                                    acquireMiss);
}

} // namespace Deep2
