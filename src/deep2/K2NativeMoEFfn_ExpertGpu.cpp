/* K2NativeMoEFfn_ExpertGpu.cpp — DualStick device stick worklist (no host GEMV). */
#include "K2NativeMoEFfn.hpp"
#include "K2GlobalTensorIndex.hpp"
#include "K2ShardIo.hpp"
#include "MoEExpertResidencyPlace.hpp"
#include "MoEPlaceLiveCounters.hpp"
#include "StickGpuLocal.hpp"
#include "StreamPathTiming.hpp"
#include "lavapath/DualStickExpertBundle.hpp"
#include "lavapath/DualStickPinCoherency.hpp"
#include "lavapath/DualStickStreamWindow.hpp"
#include "lavapath/EndDeviceStep3Diag.hpp"
#include "vulkan_compute.h"
#include <cstdio>
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
        if (!K2MoEStickExpertDevice(stick, r.gt, r.g, r.gb, r.ut, r.u, r.ub,
                                    r.dt, r.d, r.db, r.weight, H, I, layer,
                                    r.expertId, r.acquireMiss, ctr)) {
            (void)DualStickVc(stick)->EndFusedLayer();
            if (vcHold) vcHold->EndMoePinHold();
            error = "K2MoEStickExpertDevice failed";
            return false;
        }
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
