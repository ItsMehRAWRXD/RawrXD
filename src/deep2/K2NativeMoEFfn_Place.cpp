/* K2NativeMoEFfn_Place.cpp — router → Place → stick-batched exec → join. */
#include "K2NativeMoEFfn.hpp"
#include "K2MoEWeights.hpp"
#include "MoEExpertResidencyPlace.hpp"
#include "MoEPlaceLiveCounters.hpp"
#include "K2GlobalTensorIndex.hpp"
#include "K2WeightResolve.hpp"
#include "K2ShardIo.hpp"
#include "K2MLA_GpuGemv.hpp"
#include "K2NativeMoE_LayerTrace.hpp"
#include "lavapath/DualStickStreamWindow.hpp"
#include "lavapath/DualStickExpertBundle.hpp"
#include "lavapath/DualStickImbalance.hpp"
#include "lavapath/DualStickImbalance_Xfer.hpp"
#include "lavapath/GreedyDetTrace.hpp"
#include "ReapRouteTracker.hpp"
#include "MoELiveAdd.hpp"
#include "StickGpuLocal.hpp"
#include "TensorView.hpp"
#include "UniversalTensorDescriptor.hpp"
#include <cmath>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <vector>
#include <thread>
#include <atomic>
#include <algorithm>
#include "QuantKernelRegistry.hpp"
#ifdef _WIN32
#include <windows.h>
#endif

namespace Deep2 {

bool K2MoEExecExpert(const GlobalTensorIndex& index, const KimiK2Config& cfg,
                     uint32_t layer, int expertId, unsigned stick,
                     const float* hidden, float* expertOut, std::string& error);
bool K2MoEExecShared(const GlobalTensorIndex& index, const KimiK2Config& cfg,
                     uint32_t layer, const float* hidden, float* sharedOut,
                     std::string& error);
bool K2MoEExecStickWorklist(const GlobalTensorIndex& index,
                            const KimiK2Config& cfg, uint32_t layer,
                            const float* normed, MoEPlacePlan& plan,
                            const uint32_t* idx, uint32_t n, unsigned stickId,
                            float* partial, StickGpuLocal& ctr,
                            std::vector<int32_t>& hotExperts,
                            std::string& error);

namespace {

uint64_t NowNs() {
#ifdef _WIN32
    static LARGE_INTEGER f{};
    static int init = 0;
    if (!init) {
        QueryPerformanceFrequency(&f);
        init = 1;
    }
    LARGE_INTEGER c;
    QueryPerformanceCounter(&c);
    return (uint64_t)((c.QuadPart * 1000000000ull) / (uint64_t)f.QuadPart);
#else
    return 0;
#endif
}

bool LoadAndRoute(const GlobalTensorIndex& index, const KimiK2Config& cfg,
                  uint32_t layer, const float* hidden, MoERoutingResult& route,
                  std::string& error) {
    char gateN[64], biasN[64];
    std::snprintf(gateN, sizeof(gateN), "blk.%u.ffn_gate_inp.weight", layer);
    std::snprintf(biasN, sizeof(biasN), "blk.%u.exp_probs_b.bias", layer);
    WeightSpan gs{}, bs{};
    std::vector<uint8_t> gBuf, bBuf;
    if (!ResolveWeight(index, gateN, gs, gBuf, error)) return false;
    if (!ResolveWeight(index, biasN, bs, bBuf, error)) return false;
    auto gRef = index.Find(gateN);
    if (!gRef || gRef->ggmlType != 0) {
        error = "K2MoE: ffn_gate_inp must be F32";
        return false;
    }
    static thread_local KimiK2Router router;
    static thread_local bool inited = false;
    static thread_local uint32_t cachedLayer = ~0u;
    if (!inited) {
        if (!router.Initialize(cfg, error)) return false;
        inited = true;
    }
    if (cachedLayer != layer) {
        RawrXD::UniversalTensorDescriptor gd{}, bd{};
        gd.numDims = gRef->nDims;
        for (uint8_t i = 0; i < gRef->nDims && i < 8; ++i)
            gd.shape[i] = gRef->shape[i];
        gd.quantType = RawrXD::QuantType::F32;
        gd.data = const_cast<uint8_t*>(gs.data ? gs.data : gBuf.data());
        auto gate = RawrXD::TensorView::FromResident(gd);
        bd.numDims = 1;
        bd.shape[0] = cfg.numExperts ? cfg.numExperts : 384u;
        bd.quantType = RawrXD::QuantType::F32;
        bd.data = const_cast<uint8_t*>(bs.data ? bs.data : bBuf.data());
        auto bias = RawrXD::TensorView::FromResident(bd);
        router.SetRouterWeights(gate, bias);
        cachedLayer = layer;
    }
    MoEPlaceLive().moe_router_calls++;
    const bool routed = router.Route(hidden, route, error);
    if (routed && route.IsValid()) {
        // This is the actual production K2 route: expert IDs and final
        // coefficients returned by KimiK2Router.  Feed those values into the
        // installed REAP observer without inventing raw gate probabilities.
        // The empty probability vector is intentional and distinguishes
        // selected-route evidence from unobserved gate logits.
        std::vector<int> ids;
        std::vector<float> weights;
        ids.reserve(route.count);
        weights.reserve(route.count);
        for (uint32_t i = 0; i < route.count; ++i) {
            ids.push_back(static_cast<int>(route.expertIds[i]));
            weights.push_back(route.weights[i]);
        }
        ReapRouteTracker::Instance().Observe(layer, {}, ids, weights);
    }
    return routed;
}

bool ExecStickWorklist(const GlobalTensorIndex& index, const KimiK2Config& cfg,
                       uint32_t layer, const float* normed,
                       MoEPlacePlan& plan, const uint32_t* idx, uint32_t n,
                       unsigned stickId, float* partial, std::string& error,
                       uint32_t& executed, StickGpuLocal& ctr,
                       std::vector<int32_t>& hotExperts) {
    executed = 0;
    for (uint32_t k = 0; k < n; ++k)
        if (plan.slots[idx[k]].expertId >= 0) ++executed;
    if (!K2MoEExecStickWorklist(index, cfg, layer, normed, plan, idx, n, stickId,
                                partial, ctr, hotExperts, error)) {
        MoELiveAdd(MoEPlaceLive().expert_acquire_fail, 1);
        MoELiveAdd(MoEPlaceLive().worker_failures, 1);
        return false;
    }
    MoELiveAdd(MoEPlaceLive().expert_acquire_ok, executed);
    return true;
}

} // namespace

bool K2MoEPlaceAndExec(const GlobalTensorIndex& index, const KimiK2Config& cfg,
                       uint32_t layer, bool decodePhase, const float* normed,
                       float* accum, std::string& error) {
    MoERoutingResult route{};
    if (!LoadAndRoute(index, cfg, layer, normed, route, error)) return false;
    for (uint32_t i = 0; i < route.count; ++i)
        greedy_det::NoteExpert(layer, (int32_t)route.expertIds[i]);
    if (moe_ltrace::On(layer)) {
        std::fprintf(stderr, "L%u_ROUTER_DONE ids=[", layer);
        for (uint32_t i = 0; i < route.count; ++i) {
            if (i) std::fputc(',', stderr);
            std::fprintf(stderr, "%u", route.expertIds[i]);
        }
        std::fprintf(stderr, "]\n");
        std::fflush(stderr);
    }

    MoEPlaceIn pin[MOE_PLACE_MAX_K];
    uint32_t pn = 0;
    for (uint32_t i = 0; i < route.count && pn < MOE_PLACE_MAX_K; ++i) {
        pin[pn].expertId = (int32_t)route.expertIds[i];
        pin[pn].weight = route.weights[i];
        ++pn;
    }

    MoEPlaceLive().moe_place_enter++;
    MoEPlaceLive().moe_tokens++;
    MoEExpertResidencyPlace& place = MoEPlaceGlobal();
    /* Intent flags do not prove that the non-owning Vulkan contexts are live.
       Admit DualStick only after the actual owners have been bound.  A CPU
       replay therefore takes the real host expert path instead of entering a
       device worklist that can only fail with a missing VC. */
    const DualStickExec& ds = DualStickState();
    const bool dsRequested = ds.armed || ds.planned || ds.requested;
    const bool vc0Ready = DualStickVc(0) != nullptr;
    const bool vc1Ready = DualStickVc(1) != nullptr;
    /* GPU MLA admission is the same production backend intent used by the
       actual K2 quantized GEMV path.  The replay does not run the separate
       streamer arm harness, so requiring only dsRequested would silently
       send a GPU-admitted run through host MoE. */
    const bool moeGpuOnly = [] {
        const char* v = std::getenv("DEEP2_MOE_GPU_ONLY");
        return v && v[0] == '1' && v[1] == '\0';
    }();
    const bool gpuRequested = dsRequested || MLA_GpuGemvWanted() || moeGpuOnly;
    const bool useGpuMoE = gpuRequested && vc0Ready;
    const bool useDualStick = useGpuMoE && vc1Ready;
    const uint32_t sticks = useDualStick ? 2u : 1u;
    if (const char* t = std::getenv("DEEP2_MOE_PLACE_TRACE");
        t && t[0] && t[0] != '0') {
        std::fprintf(stderr,
                     "LIVE_K2_MOE_BACKEND layer=%u host=%u gpu=%u dual=%u "
                     "requested=%u vc0=%u vc1=%u\n",
                     layer, useGpuMoE ? 0u : 1u, useGpuMoE ? 1u : 0u,
                     useDualStick ? 1u : 0u, gpuRequested ? 1u : 0u,
                     vc0Ready ? 1u : 0u, vc1Ready ? 1u : 0u);
        std::fflush(stderr);
    }
    place.SetStickCount(sticks);
    struct PinProbeCtx {
        size_t H;
        size_t I;
    };
    static thread_local PinProbeCtx s_pp{};
    s_pp.H = cfg.hiddenDim;
    s_pp.I = cfg.moeIntermediateSize ? cfg.moeIntermediateSize : 2048u;
    place.SetProbe(
        [](void* ctx, int ly, int ex) -> int {
            auto* p = static_cast<PinProbeCtx*>(ctx);
            const int st = DualStickExpertStickOf(ly, ex);
            if (st < 0 || !p || !p->H || !p->I) return 0;
            if (!DualStickBundlePinsReady((unsigned)st, ly, ex, p->H, p->I))
                return 0;
            MoEPlaceGlobal().MarkHot(ly, ex, (uint32_t)st,
                                    DualStickExpertBytesOf(ly, ex));
            return 1;
        },
        &s_pp);
    if (place.Counters().place_calls == 0) {
        const uint64_t eb =
            (uint64_t)(cfg.moeIntermediateSize ? cfg.moeIntermediateSize
                                               : 2048u) *
            (uint64_t)cfg.hiddenDim;
        const char* b = std::getenv("DEEP2_MOE_PLACE_BUDGET_MIB");
        uint64_t bud =
            b && *b ? ((uint64_t)std::atoi(b) << 20) : (8192ull << 20);
        if (sticks >= 2u) {
            const char* s0 = std::getenv("DEEP2_STICK0_BUDGET_MIB");
            const char* s1 = std::getenv("DEEP2_STICK1_BUDGET_MIB");
            if (s0 && *s0 && s1 && *s1) {
                const uint64_t sum =
                    ((uint64_t)std::atoi(s0) + (uint64_t)std::atoi(s1)) << 20;
                if (sum > bud) bud = sum;
            }
        }
        place.SetBudget(bud, eb ? eb : (1ull << 20));
    }
    MoEPlaceLive().experts_selected += pn;
    MoEPlacePlan plan = place.Place((int)layer, pin, pn);
    MoEPlaceLive().moe_place_calls++;
    MoEPlaceLive().expert_cache_hits += plan.hits;
    MoEPlaceLive().expert_cache_misses += plan.misses;
    MoEPlaceLive().expert_miss_bytes += plan.bytesFetchPlan;
    if (decodePhase) {
        MoEPlaceLive().decode_moe_place_calls++;
        MoEPlaceLive().decode_experts_selected += pn;
        static thread_local uint32_t s_prevLy = ~0u;
        if (s_prevLy == ~0u || layer < s_prevLy) MoEPlaceLive().stream_generated_tokens++;
        s_prevLy = layer;
    }
    if (const char* t = std::getenv("DEEP2_MOE_PLACE_TRACE");
        t && t[0] && t[0] != '0')
        std::fprintf(stderr,
                     "LIVE_K2_MOE_PLACE layer=%u n=%u hits=%u misses=%u "
                     "miss_bytes=%llu\n",
                     layer, pn, plan.hits, plan.misses,
                     (unsigned long long)plan.bytesFetchPlan);
    if (const char* t = std::getenv("DEEP2_MOE_PLACE_TRACE");
        t && t[0] && t[0] != '0') {
        std::fprintf(stderr, "LIVE_K2_MOE_STAGE layer=%u stage=after_place count=%u\n",
                     layer, plan.count);
        std::fflush(stderr);
    }
    if (moe_ltrace::On(layer)) {
        std::fprintf(stderr, "L%u_PLACE_DONE hits=%u misses=%u\n", layer,
                     plan.hits, plan.misses);
        std::fflush(stderr);
    }

    /* V6: keyed EWMA + LPT misses; steal held until predict error collapses. */
    DualStickImbalanceSetShape(
        14u, cfg.hiddenDim,
        cfg.moeIntermediateSize ? cfg.moeIntermediateSize : 2048u);
    if (const char* t = std::getenv("DEEP2_MOE_PLACE_TRACE");
        t && t[0] && t[0] != '0') {
        std::fprintf(stderr, "LIVE_K2_MOE_STAGE layer=%u stage=after_shape\n", layer);
        std::fflush(stderr);
    }
    if (sticks >= 2u) DualStickImbalanceBeginLayer();
    auto assignOne = [&](MoEPlaceSlot& mut) {
        const int pref = DualStickExpertStickOf((int)layer, mut.expertId);
        uint64_t bytes = DualStickExpertBytesOf((int)layer, mut.expertId);
        if (!bytes) bytes = 1ull << 20;
        if (sticks >= 2u)
            mut.stick = (uint8_t)DualStickImbalanceAssign(
                (int)layer, mut.expertId, pref, bytes, (int)mut.hit);
        else
            mut.stick = 0;
        if (mut.hit) MoEPlaceLive().expert_stick_retains++;
        else MoEPlaceLive().expert_stick_assigns++;
    };
    for (uint32_t si = 0; si < plan.count; ++si)
        if (plan.slots[si].expertId >= 0 && plan.slots[si].hit)
            assignOne(plan.slots[si]);
    /* Misses after hits; LPT deferred until pin-stable (V6d). */
    for (uint32_t si = 0; si < plan.count; ++si)
        if (plan.slots[si].expertId >= 0 && !plan.slots[si].hit)
            assignOne(plan.slots[si]);
    if (const char* t = std::getenv("DEEP2_MOE_PLACE_TRACE");
        t && t[0] && t[0] != '0') {
        std::fprintf(stderr, "LIVE_K2_MOE_STAGE layer=%u stage=after_assign\n", layer);
        std::fflush(stderr);
    }

    /* Real host fallback for a non-admitted GPU path.  The route and its
       coefficients are retained; each selected expert is read from the GGUF
       shards and evaluated by K2MoEExecExpert's registered quantized GEMV
       implementation.  No zero-output or skipped-expert success is allowed. */
    if (!useGpuMoE) {
        const size_t H = cfg.hiddenDim;
        std::vector<float> expertOut(H, 0.f);
        uint32_t executedHost = 0;
        for (uint32_t si = 0; si < plan.count; ++si) {
            MoEPlaceSlot& slot = plan.slots[si];
            if (slot.expertId < 0) continue;
            std::fill(expertOut.begin(), expertOut.end(), 0.f);
            if (!K2MoEExecExpert(index, cfg, layer, slot.expertId, 0u,
                                 normed, expertOut.data(), error)) {
                if (const char* t = std::getenv("DEEP2_MOE_PLACE_TRACE");
                    t && t[0] && t[0] != '0') {
                    std::fprintf(stderr,
                                 "LIVE_K2_MOE_HOST_FAIL layer=%u expert=%d "
                                 "error=%s\n",
                                 layer, slot.expertId,
                                 error.empty() ? "(none)" : error.c_str());
                    std::fflush(stderr);
                }
                return false;
            }
            for (size_t i = 0; i < H; ++i)
                accum[i] += slot.weight * expertOut[i];
            ++executedHost;
        }
        if (executedHost != pn) {
            error = "K2MoE: HOST_EXPERT_PARITY fail selected!=executed";
            return false;
        }
        MoEPlaceLive().experts_executed += executedHost;
        if (decodePhase) MoEPlaceLive().decode_experts_executed += executedHost;

        // MiniMax-M2 has no shared expert tensor. A zero shared-expert count
        // is a real topology contract; do not call the Kimi shared-expert
        // path with missing tensors.
        if (cfg.sharedExperts > 0) {
            std::vector<float> shared(H, 0.f);
            moe_ltrace::BC(layer, "SHARED_GATE_BEGIN");
            if (!K2MoEExecShared(index, cfg, layer, normed, shared.data(), error)) {
                moe_ltrace::BC(layer, "SHARED_FAIL");
                return false;
            }
            moe_ltrace::BC(layer, "SHARED_ACCUM_DONE");
            MoEPlaceLive().shared_expert_calls++;
            for (size_t i = 0; i < H; ++i) accum[i] += shared[i];
        }
        moe_ltrace::BC(layer, "HOST_MOE_DONE");
        return true;
    }

    /* #10 steal RUNTIME_HELD until PREDICT_ERR collapses */

    /* #6/#7/#10: true parallel stick workers → one D2H partial/stick → join. */
    uint32_t ix0[MOE_PLACE_MAX_K], ix1[MOE_PLACE_MAX_K];
    uint32_t n0 = 0, n1 = 0;
    for (uint32_t si = 0; si < plan.count; ++si) {
        if (plan.slots[si].expertId < 0) continue;
        if ((plan.slots[si].stick & 1u) == 0)
            ix0[n0++] = si;
        else
            ix1[n1++] = si;
    }
    if (const char* t = std::getenv("DEEP2_MOE_PLACE_TRACE");
        t && t[0] && t[0] != '0') {
        std::fprintf(stderr, "LIVE_K2_MOE_STAGE layer=%u stage=after_partition n0=%u n1=%u\n",
                     layer, n0, n1);
        std::fflush(stderr);
    }
    std::vector<float> p0(cfg.hiddenDim, 0.f), p1(cfg.hiddenDim, 0.f);
    StickGpuLocal c0{}, c1{};
    std::vector<int32_t> hot0, hot1;
    std::string err0, err1;
    uint32_t ex0 = 0, ex1 = 0;
    bool ok0 = true, ok1 = true;
    uint64_t s0b = 0, s0e = 0, s1b = 0, s1e = 0;
    std::atomic<uint32_t> active{0}, maxActive{0};

    auto bumpActive = [&]() {
        const uint32_t now = active.fetch_add(1, std::memory_order_acq_rel) + 1;
        uint32_t seen = maxActive.load(std::memory_order_relaxed);
        while (seen < now &&
               !maxActive.compare_exchange_weak(seen, now,
                                                std::memory_order_relaxed)) {
        }
    };
    auto dropActive = [&]() {
        active.fetch_sub(1, std::memory_order_acq_rel);
    };

    const bool dual = sticks >= 2u;
    auto run0 = [&] {
        bumpActive();
        s0b = NowNs();
        try {
            ok0 = ExecStickWorklist(index, cfg, layer, normed, plan, ix0, n0, 0u,
                                    p0.data(), err0, ex0, c0, hot0);
        } catch (const std::exception& ex) {
            ok0 = false;
            err0 = std::string("DualStick stick0 exception: ") + ex.what();
        } catch (...) {
            ok0 = false;
            err0 = "DualStick stick0 unknown exception";
        }
        s0e = NowNs();
        dropActive();
    };
    auto run1 = [&] {
        bumpActive();
        s1b = NowNs();
        try {
            ok1 = ExecStickWorklist(index, cfg, layer, normed, plan, ix1, n1, 1u,
                                    p1.data(), err1, ex1, c1, hot1);
        } catch (const std::exception& ex) {
            ok1 = false;
            err1 = std::string("DualStick stick1 exception: ") + ex.what();
        } catch (...) {
            ok1 = false;
            err1 = "DualStick stick1 unknown exception";
        }
        s1e = NowNs();
        dropActive();
    };

    std::thread w0, w1;
    try {
        /* HARD_GATE: always 2 stick submits + 2 partial D2H when DualStick. */
        if (dual || n0) w0 = std::thread(run0);
        if (dual || n1) w1 = std::thread(run1);
        else if (!dual && n0) {
            /* single-stick: already launched w0 */
        }
    } catch (...) {
        if (w0.joinable()) w0.join();
        if (w1.joinable()) w1.join();
        MoEPlaceLive().worker_failures++;
        error = "DualStick stick thread create failed";
        return false;
    }
    if (const char* t = std::getenv("DEEP2_MOE_PLACE_TRACE");
        t && t[0] && t[0] != '0') {
        std::fprintf(stderr, "LIVE_K2_MOE_STAGE layer=%u stage=workers_started\n", layer);
        std::fflush(stderr);
    }
    if (w0.joinable()) w0.join();
    if (w1.joinable()) w1.join();
    /* Both worker fences and D2H partials have completed at this point.
       Release only pin marks; the next layer owns fresh admission and may
       evict these now-unpinned buffers under the bounded cache budget. */
    if (auto* vc0 = DualStickVc(0u)) vc0->ClearPinnedGemvWeights();
    if (auto* vc1 = DualStickVc(1u)) vc1->ClearPinnedGemvWeights();
    if (const char* t = std::getenv("DEEP2_MOE_PLACE_TRACE");
        t && t[0] && t[0] != '0') {
        std::fprintf(stderr, "LIVE_K2_MOE_STAGE layer=%u stage=workers_joined ok0=%u ok1=%u ex0=%u ex1=%u\n",
                     layer, ok0 ? 1u : 0u, ok1 ? 1u : 0u, ex0, ex1);
        std::fflush(stderr);
    }

    if ((dual || n0) && !ok0) {
        MoEPlaceLive().worker_failures++;
        error = err0;
        return false;
    }
    if ((dual || n1) && !ok1) {
        MoEPlaceLive().worker_failures++;
        error = err1;
        return false;
    }

    StickGpuLocal merged{};
    StickGpuMerge(merged, c0);
    StickGpuMerge(merged, c1);
    StickGpuCommit(merged);
    const uint64_t tw0 = (s0e >= s0b) ? (s0e - s0b) : 0;
    const uint64_t tw1 = (s1e >= s1b) ? (s1e - s1b) : 0;
    MoEPlaceLive().gpu0_work_ns += tw0;
    MoEPlaceLive().gpu1_work_ns += tw1;
    if (dual && s0e && s1e && std::min(s0e, s1e) > std::max(s0b, s1b))
        MoEPlaceLive().stick_overlap_ns +=
            std::min(s0e, s1e) - std::max(s0b, s1b);
    const uint64_t mc = maxActive.load(std::memory_order_relaxed);
    if (mc > MoEPlaceLive().max_concurrent_stick_workers)
        MoEPlaceLive().max_concurrent_stick_workers = mc;
    if (dual || (n0 && n1)) {
        const uint64_t last = std::max(s0e, s1e);
        const uint64_t first = std::min(s0e, s1e);
        if (last >= first) MoEPlaceLive().gpu_join_wait_ns += (last - first);
    }
    if (dual)
        DualStickImbalanceObserve(tw0, tw1, ex0, ex1, c0.h2d_bytes,
                                  c1.h2d_bytes);
    /* ATTRIBUTABLE kernel only when stick uniquely has 1 expert (no wall/n). */
    auto attr1 = [&](unsigned st, uint32_t exN, uint64_t wall,
                     uint64_t h2d, const std::vector<int32_t>& hot) {
        if (exN != 1u || hot.empty() || !wall) return;
        const uint64_t x =
            h2d ? ds_imb::TransferExecNs(st, h2d) : 0ull;
        const uint64_t k = (wall > x) ? (wall - x) : wall;
        DualStickImbalanceObserveExpert((int)layer, hot[0], st, 1, 0ull, k);
    };
    if (dual) {
        attr1(0u, ex0, tw0, c0.h2d_bytes, hot0);
        attr1(1u, ex1, tw1, c1.h2d_bytes, hot1);
    }
    MoEPlaceLive().layer_joins++;

    /* MarkHot after join (README_BIND). */
    MoEExpertResidencyPlace& placeG = MoEPlaceGlobal();
    for (int32_t ex : hot0) {
        placeG.MarkHot((int)layer, ex, 0, 0);
        MoEPlaceLive().expert_markhot++;
    }
    for (int32_t ex : hot1) {
        placeG.MarkHot((int)layer, ex, 1, 0);
        MoEPlaceLive().expert_markhot++;
    }

    for (uint32_t i = 0; i < cfg.hiddenDim; ++i)
        accum[i] += p0[i] + p1[i];
    if (dual || n0 || n1) MoEPlaceLive().moe_layers_gpu++;
    const uint32_t executed = ex0 + ex1;
    if (merged.host_expert_down_vectors != 0)
        MoEPlaceLive().product_backend_attested = 0;
    else if (merged.device_down_vectors == executed &&
             merged.device_partial_accums == executed && dual &&
             merged.gpu_submits == 2 && merged.d2h_partial_vectors == 2)
        MoEPlaceLive().product_backend_attested = 1;

    moe_ltrace::BC(layer, "ROUTED_ACCUM_DONE");
    MoEPlaceLive().experts_executed += executed;
    if (decodePhase) MoEPlaceLive().decode_experts_executed += executed;
    if (executed != pn) {
        error = "K2MoE: EXPERT_PARITY fail selected!=executed";
        return false;
    }

    if (cfg.sharedExperts > 0) {
        std::vector<float> shared(cfg.hiddenDim, 0.f);
        moe_ltrace::BC(layer, "SHARED_GATE_BEGIN");
        if (!K2MoEExecShared(index, cfg, layer, normed, shared.data(), error)) {
            moe_ltrace::BC(layer, "SHARED_FAIL");
            return false;
        }
        moe_ltrace::BC(layer, "SHARED_ACCUM_DONE");
        MoEPlaceLive().shared_expert_calls++;
        for (uint32_t i = 0; i < cfg.hiddenDim; ++i) accum[i] += shared[i];
    }

    // Layer-1 FFN diagnostic: CPU reference vs native output
    std::fprintf(stderr, "[L1_DIAG_PROBE] layer=%u env=%p\n", layer, (void*)std::getenv("DEEP2_L1_DIAG"));
    std::fflush(stderr);
    if (layer == 1 && std::getenv("DEEP2_L1_DIAG"))
    {
        const size_t H = cfg.hiddenDim;
        const size_t I = cfg.moeIntermediateSize ? cfg.moeIntermediateSize : 2048u;
        std::vector<float> cpuRef(H, 0.0f);
        auto& reg = QuantKernelRegistry::Instance();
        auto gemv = [&](int qt, const uint8_t* w, const float* x, float* y,
                        size_t rows, size_t cols) -> bool {
            auto k = reg.GetGEMV(qt);
            if (!k) return false;
            std::memset(y, 0, rows * sizeof(float));
            k(w, x, y, rows, cols);
            return true;
        };
        auto siluMul = [](float* gate, const float* up, size_t n) {
            for (size_t i = 0; i < n; ++i) {
                const float g = gate[i];
                gate[i] = (g / (1.0f + std::exp(-g))) * up[i];
            }
        };

        // CPU reference: shared expert
        {
            char gateN[64], upN[64], downN[64];
            std::snprintf(gateN, sizeof(gateN), "blk.%u.ffn_gate_shexp.weight", layer);
            std::snprintf(upN, sizeof(upN), "blk.%u.ffn_up_shexp.weight", layer);
            std::snprintf(downN, sizeof(downN), "blk.%u.ffn_down_shexp.weight", layer);

            WeightSpan gs{}, us{}, dsWt{};
            std::vector<uint8_t> gBuf, uBuf, dBuf;
            std::string loadErr;
            bool ok = ResolveWeight(index, gateN, gs, gBuf, loadErr)
                   && ResolveWeight(index, upN, us, uBuf, loadErr)
                   && ResolveWeight(index, downN, dsWt, dBuf, loadErr);
            if (ok) {
                auto gRef = index.Find(gateN);
                auto uRef = index.Find(upN);
                auto dRef = index.Find(downN);
                if (gRef && uRef && dRef) {
                    const uint8_t* gp = gs.data ? gs.data : gBuf.data();
                    const uint8_t* up_ = us.data ? us.data : uBuf.data();
                    const uint8_t* dp = dsWt.data ? dsWt.data : dBuf.data();
                    std::vector<float> gate(I, 0.0f), up(I, 0.0f);
                    if (gemv((int)gRef->ggmlType, gp, normed, gate.data(), I, H) &&
                        gemv((int)uRef->ggmlType, up_, normed, up.data(), I, H)) {
                        siluMul(gate.data(), up.data(), I);
                        gemv((int)dRef->ggmlType, dp, gate.data(), cpuRef.data(), H, I);
                    }
                }
            }
        }

        // CPU reference: routed experts (weighted)
        for (uint32_t si = 0; si < route.count; ++si) {
            int expertId = (int)route.expertIds[si];
            float weight = route.weights[si];
            if (expertId < 0) continue;

            char gateN[64], upN[64], downN[64];
            std::snprintf(gateN, sizeof(gateN), "blk.%u.ffn_gate_exps.weight", layer);
            std::snprintf(upN, sizeof(upN), "blk.%u.ffn_up_exps.weight", layer);
            std::snprintf(downN, sizeof(downN), "blk.%u.ffn_down_exps.weight", layer);

            auto gslice = index.FindExpertSlice(gateN, (uint32_t)expertId);
            auto uslice = index.FindExpertSlice(upN, (uint32_t)expertId);
            auto dslice = index.FindExpertSlice(downN, (uint32_t)expertId);
            if (!gslice || !uslice || !dslice) continue;

            std::vector<uint8_t> gateB(gslice->byteSize), upB(uslice->byteSize), downB(dslice->byteSize);

            bool ok = K2ShardIo_Read(index.ShardPath(gslice->shardId).string(),
                                   gslice->fileOffset + gslice->byteOffset,
                                   gateB.data(), gateB.size());
            ok = ok && K2ShardIo_Read(index.ShardPath(uslice->shardId).string(),
                                   uslice->fileOffset + uslice->byteOffset,
                                   upB.data(), upB.size());
            ok = ok && K2ShardIo_Read(index.ShardPath(dslice->shardId).string(),
                                   dslice->fileOffset + dslice->byteOffset,
                                   downB.data(), downB.size());
            if (!ok) continue;

            std::vector<float> gate(I, 0.0f), up(I, 0.0f), expertOut(H, 0.0f);
            if (gemv((int)gslice->ggmlType, gateB.data(), normed, gate.data(), I, H) &&
                gemv((int)uslice->ggmlType, upB.data(), normed, up.data(), I, H)) {
                siluMul(gate.data(), up.data(), I);
                gemv((int)dslice->ggmlType, downB.data(), gate.data(), expertOut.data(), H, I);
                for (size_t i = 0; i < H; ++i)
                    cpuRef[i] += weight * expertOut[i];
            }
        }

        // Compare native vs CPU reference
        double maxDiff = 0.0;
        size_t maxIdx = 0;
        size_t nonFinite = 0;
        for (size_t i = 0; i < H; ++i) {
            if (!std::isfinite(accum[i]) || !std::isfinite(cpuRef[i])) { ++nonFinite; continue; }
            double diff = std::abs((double)accum[i] - (double)cpuRef[i]);
            if (diff > maxDiff) { maxDiff = diff; maxIdx = i; }
        }
        std::fprintf(stderr,
            "[L1_DIAG] layer=1 native_vs_cpu maxDiff=%.9e at idx=%zu nonFinite=%zu\n",
            maxDiff, maxIdx, nonFinite);
        std::fflush(stderr);
    }
    return true;
}

} // namespace Deep2
