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

    /* Fail closed: DownloadBuf(ArenaDown()) during a fused worklist is not
       evidence of a completed expert output. Dispatch records all experts
       before K2MoEStickEndFused; ArenaDown can be reused. Never silently
       publish a CPU/GPU parity success or capture a misleading vector.
       The independent scalar/oracle tools remain available for captures
       obtained via a separately synchronized, per-expert diagnostic. */
    const char* parityEnv = std::getenv("DEEP2_MOE_GPU_PARITY");
    const bool parityEnabled = parityEnv && parityEnv[0] == '1' && parityEnv[1] == '\0';
    const bool captureRequested = [] {
        const char* value = std::getenv("DEEP2_MOE_PARITY_CAPTURE_DIR");
        return value && value[0] != '\0';
    }();
    if (parityEnabled || captureRequested) {
        std::fprintf(stderr,
                     "GPU_EXPERT_PARITY status=BLOCKED reason=FUSED_OUTPUT_NOT_SYNCHRONIZED "
                     "layer=%u stick=%u experts=%zu\n",
                     layer, stick, work.size());
        std::fflush(stderr);
    }

    /* Preserve CPU-side packed inputs for an independently reproducible
       scalar expert evaluation. This does not read any GPU staging/arena
       buffer, and must not be interpreted as GPU numerical parity.
       At most one cold expert capture per stick worklist. */
    if (captureRequested) {
        bool written = false;
        int captureExpert = -1;
        for (const auto& candidate : work) {
            if (!candidate.g || !candidate.u || !candidate.d) continue;
            captureExpert = candidate.expertId;
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

    /* After the fused command boundary and completed device partial D2H,
       an opt-in diagnostic may capture the *aggregate stick partial*.
       This is NOT a per-expert down vector or an independent GPU activation
       witness; do not route it into the per-expert Q6_K oracle. */
    if (captureRequested) {
        const char* dirEnv = std::getenv("DEEP2_MOE_PARITY_CAPTURE_DIR");
        std::filesystem::path dir(dirEnv);
        std::error_code ec;
        bool saved = std::filesystem::is_directory(dir, ec) && !ec &&
                     !work.empty() && H > 0 && H <= 1048576u;
        const std::string stem = "k2_l" + std::to_string(layer) +
                                 "_s" + std::to_string(stick) +
                                 "_aggregate";
        const auto vecPath = dir / (stem + ".gpu_partial.txt");
        const auto metadataPath = dir / (stem + ".manifest.txt");
        if (saved) {
            for (const auto& path : {vecPath, metadataPath}) {
                if (std::filesystem::exists(path, ec) || ec) saved = false;
            }
        }
        bool vectorWritten = false;
        if (saved) {
            saved = k2_parity_capture::WriteVector(vecPath, partial, H);
            vectorWritten = saved;
        }
        if (saved) {
            std::string metadata =
                "schema=DEEP2_KIMI_STICK_PARTIAL_001\n"
                "layer=" + std::to_string(layer) +
                "\nstick=" + std::to_string(stick) +
                "\nrows=" + std::to_string(H) +
                "\nexperts=" + std::to_string(work.size()) +
                "\nsource=K2MoEStickEndDevice\n"
                "scope=AGGREGATE_STICK_PARTIAL_NOT_INDIVIDUAL_EXPERT\n"
                "certified=0\n";
            for (const auto& expert : work) {
                metadata += "expert=" + std::to_string(expert.expertId) +
                            " weight=" + std::to_string(expert.weight) + "\n";
            }
            saved = k2_parity_capture::WriteNew(
                metadataPath, metadata.data(), metadata.size());
        }
        if (!saved && vectorWritten) {
            // Only remove the vector written by this invocation.
            std::error_code ignored;
            std::filesystem::remove(vecPath, ignored);
        }
        std::fprintf(stderr,
                     "GPU_STICK_PARTIAL_CAPTURE layer=%u stick=%u status=%s "
                     "scope=AGGREGATE_ONLY\n",
                     layer, stick, saved ? "WRITTEN" : "SKIPPED");
        std::fflush(stderr);
    }
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
