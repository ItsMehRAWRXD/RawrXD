/* K2NativeMoEFfn_Place.cpp — router → Place → stick-batched exec → join. */
#include "K2NativeMoEFfn.hpp"
#include "K2MoEWeights.hpp"
#include "MoEExpertResidencyPlace.hpp"
#include "MoEPlaceLiveCounters.hpp"
#include "K2GlobalTensorIndex.hpp"
#include "K2WeightResolve.hpp"
#include "K2NativeMoE_LayerTrace.hpp"
#include "lavapath/DualStickStreamWindow.hpp"
#include "lavapath/DualStickExpertBundle.hpp"
#include "MoELiveAdd.hpp"
#include "StickGpuLocal.hpp"
#include "TensorView.hpp"
#include "UniversalTensorDescriptor.hpp"
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <vector>
#include <thread>
#include <atomic>
#include <algorithm>
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
    return router.Route(hidden, route, error);
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
    const uint32_t sticks =
        (DualStickState().armed || DualStickState().planned ||
         DualStickState().requested)
            ? 2u
            : 1u;
    place.SetStickCount(sticks);
    place.SetProbe(
        [](void*, int ly, int ex) -> int {
            if (MoEPlaceGlobal().IsHot(ly, ex)) return 1;
            if (!DualStickExpertIsResident(ly, ex)) return 0;
            const int st = DualStickExpertStickOf(ly, ex);
            if (st < 0) return 0;
            MoEPlaceGlobal().MarkHot(ly, ex, (uint32_t)st,
                                    DualStickExpertBytesOf(ly, ex));
            return 1;
        },
        nullptr);
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
    }
    if (const char* t = std::getenv("DEEP2_MOE_PLACE_TRACE");
        t && t[0] && t[0] != '0')
        std::fprintf(stderr,
                     "LIVE_K2_MOE_PLACE layer=%u n=%u hits=%u misses=%u "
                     "miss_bytes=%llu\n",
                     layer, pn, plan.hits, plan.misses,
                     (unsigned long long)plan.bytesFetchPlan);
    if (moe_ltrace::On(layer)) {
        std::fprintf(stderr, "L%u_PLACE_DONE hits=%u misses=%u\n", layer,
                     plan.hits, plan.misses);
        std::fflush(stderr);
    }

    /* Assign sticks: retain affinity; miss → load-aware pick (#11 light). */
    for (uint32_t si = 0; si < plan.count; ++si) {
        MoEPlaceSlot& mut = plan.slots[si];
        if (mut.expertId < 0) continue;
        if (!mut.hit) {
            const int pref = DualStickExpertStickOf((int)layer, mut.expertId);
            mut.stick = (uint8_t)((pref >= 0)
                                      ? (unsigned)pref
                                      : DualStickPickStick((uint32_t)mut.expertId));
            MoEPlaceLive().expert_stick_assigns++;
        } else {
            const int pref = DualStickExpertStickOf((int)layer, mut.expertId);
            if (pref >= 0) mut.stick = (uint8_t)(unsigned)pref;
            MoEPlaceLive().expert_stick_retains++;
        }
    }

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
        ok0 = ExecStickWorklist(index, cfg, layer, normed, plan, ix0, n0, 0u,
                                p0.data(), err0, ex0, c0, hot0);
        s0e = NowNs();
        dropActive();
    };
    auto run1 = [&] {
        bumpActive();
        s1b = NowNs();
        ok1 = ExecStickWorklist(index, cfg, layer, normed, plan, ix1, n1, 1u,
                                p1.data(), err1, ex1, c1, hot1);
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
    if (w0.joinable()) w0.join();
    if (w1.joinable()) w1.join();

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
    MoEPlaceLive().gpu0_work_ns += (s0e >= s0b) ? (s0e - s0b) : 0;
    MoEPlaceLive().gpu1_work_ns += (s1e >= s1b) ? (s1e - s1b) : 0;
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

    std::vector<float> shared(cfg.hiddenDim, 0.f);
    moe_ltrace::BC(layer, "SHARED_GATE_BEGIN");
    if (!K2MoEExecShared(index, cfg, layer, normed, shared.data(), error)) {
        moe_ltrace::BC(layer, "SHARED_FAIL");
        return false;
    }
    moe_ltrace::BC(layer, "SHARED_ACCUM_DONE");
    MoEPlaceLive().shared_expert_calls++;
    for (uint32_t i = 0; i < cfg.hiddenDim; ++i) accum[i] += shared[i];
    return true;
}

} // namespace Deep2
