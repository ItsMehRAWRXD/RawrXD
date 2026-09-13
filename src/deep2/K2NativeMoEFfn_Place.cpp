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
#include "TensorView.hpp"
#include "UniversalTensorDescriptor.hpp"
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <vector>
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
                       float* partial, std::string& error, uint32_t& executed) {
    std::vector<float> expertOut(cfg.hiddenDim);
    MoEExpertResidencyPlace& place = MoEPlaceGlobal();
    for (uint32_t k = 0; k < n; ++k) {
        MoEPlaceSlot& mut = plan.slots[idx[k]];
        if (mut.expertId < 0) continue;
        if (mut.thrash) MoEPlaceLive().moe_thrash_tokens++;
        if (mut.residentHandle)
            MoEPlaceLive().secondary_lookup += 0; /* handle from Place */
        else
            MoEPlaceLive().secondary_lookup++;
        moe_ltrace::BCExpert(layer, "GATE_ACQUIRE", mut.expertId);
        if (!K2MoEExecExpert(index, cfg, layer, mut.expertId, mut.stick, normed,
                             expertOut.data(), error)) {
            MoEPlaceLive().expert_acquire_fail++;
            moe_ltrace::BCExpert(layer, "EXPERT_FAIL", mut.expertId);
            return false;
        }
        MoEPlaceLive().expert_acquire_ok++;
        place.MarkHot((int)layer, mut.expertId, mut.stick, 0);
        MoEPlaceLive().expert_markhot++;
        for (uint32_t i = 0; i < cfg.hiddenDim; ++i)
            partial[i] += mut.weight * expertOut[i];
        ++executed;
    }
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

    /* #6/#10: two stick worklists → stick-local partials → one join. */
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
    uint32_t executed = 0;
    const uint64_t tA = NowNs();
    if (n0 && !ExecStickWorklist(index, cfg, layer, normed, plan, ix0, n0,
                                 p0.data(), error, executed))
        return false;
    const uint64_t tB = NowNs();
    if (tB >= tA) MoEPlaceLive().gpu0_work_ns += (tB - tA);
    if (n1 && !ExecStickWorklist(index, cfg, layer, normed, plan, ix1, n1,
                                 p1.data(), error, executed))
        return false;
    const uint64_t tC = NowNs();
    if (tC >= tB) MoEPlaceLive().gpu1_work_ns += (tC - tB);
    const uint64_t tJ0 = NowNs();
    for (uint32_t i = 0; i < cfg.hiddenDim; ++i)
        accum[i] += p0[i] + p1[i];
    const uint64_t tJ1 = NowNs();
    if (tJ1 >= tJ0) MoEPlaceLive().gpu_join_wait_ns += (tJ1 - tJ0);
    if (n0 || n1) MoEPlaceLive().moe_layers_gpu++;

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
