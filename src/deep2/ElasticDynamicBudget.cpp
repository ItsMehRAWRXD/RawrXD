// ElasticDynamicBudget.cpp — probe host/GPU → dynamic residency caps
#include "ElasticDynamicBudget.hpp"
#include "Deep2DeviceManager.hpp"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace Deep2 {
namespace {

uint64_t EnvMiB(const char* k) {
    const char* v = std::getenv(k);
    if (!v || !*v) return 0;
    const long n = std::atol(v);
    return n > 0 ? (uint64_t)n << 20 : 0;
}

} // namespace

void ElasticBudget_ProbeHost(ElasticDynamicProbe& out) {
#ifdef _WIN32
    MEMORYSTATUSEX mx{};
    mx.dwLength = sizeof(mx);
    if (GlobalMemoryStatusEx(&mx)) {
        out.ramTotal = mx.ullTotalPhys;
        out.ramAvail = mx.ullAvailPhys;
        out.ramHeadroom =
            out.ramTotal &&
            ((double)out.ramAvail / (double)out.ramTotal) > 0.12;
    }
#endif
    DeviceManagerSnapshot snap{};
    if (Deep2Device_Enumerate(snap) && snap.deviceCount) {
        Deep2Device_ApplyPolicy(snap);
        int idx = snap.plan.primaryIndex;
        if (idx < 0) idx = 0;
        if ((unsigned)idx < snap.deviceCount)
            out.vramTotal = snap.devices[idx].dedicatedVram;
        if (!out.vramTotal)
            out.vramTotal = snap.devices[0].dedicatedVram;
    }
}

ElasticResidencyConfig ElasticBudget_Derive(const ElasticDynamicProbe& p) {
    ElasticResidencyConfig c{};
    const uint64_t ramA = p.ramAvail ? p.ramAvail : (8ull << 30);
    const uint64_t vram = p.vramTotal ? p.vramTotal : (4ull << 30);
    const uint32_t L = p.layers ? p.layers : 61;
    // Hot pin floor uses full working depth (never shrink to t1's L=1 → 512MB).
    const uint32_t Lhot = (L < 32u) ? 32u : L;
    // Working set: ~3 Q4 MLA tensors/layer × ~48 MiB ≈ 144 MiB/layer floor.
    const uint64_t layerWarm = 144ull << 20;
    const uint64_t needWarm =
        (std::min)(ramA * 55 / 100,
                   (std::max)(layerWarm * (std::min)(L, 16u),
                              p.modelBytes ? p.modelBytes / 10 : layerWarm * 4));
    c.maxWarmCompressedBytes = needWarm;
    if (uint64_t e = EnvMiB("DEEP2_WARM_COMPRESSED_MIB"))
        c.maxWarmCompressedBytes = e;

    // Staged = ephemeral dequant strip: 1–2 layers, never reverse-static 512.
    const uint64_t stage =
        (std::min)(c.maxWarmCompressedBytes / 6,
                   (std::max)(256ull << 20, layerWarm * 2));
    c.maxWarmStagedBytes = stage;
    if (uint64_t e = EnvMiB("DEEP2_WARM_STAGED_MIB"))
        c.maxWarmStagedBytes = e;

    // Hot pin window: geometry-driven, leave VRAM headroom (not 65% dump).
    const uint64_t pinNeed =
        layerWarm * (uint64_t)(std::min)(Lhot, 64u);  // ~MLA Q4 working set
    uint64_t hotCap = vram > (4ull << 30) ? (vram * 40 / 100) : (vram * 55 / 100);
    if (hotCap > (12ull << 30)) hotCap = 12ull << 30;
    if (p.vramPressure) hotCap = hotCap * 70 / 100;
    c.maxHotBytes = (std::min)(hotCap, (std::max)(pinNeed, 512ull << 20));
    if (uint64_t e = EnvMiB("DEEP2_HOT_MIB"))
        c.maxHotBytes = e;
    // DEEP2_WEIGHT_BUDGET_MIB is applied by callers to the pin window;
    // do not re-ingest it here (shallow Sync would poison later derives).

    // Lookahead: geometry + fused depth; cut on pressure — not fixed 2.
    uint32_t la = 1;
    if (L >= 32) la = 2;
    if (L >= 48 && p.ramHeadroom && !p.vramPressure) la = 3;
    if (p.experts >= 8 && !p.vramPressure) ++la;
    if (p.fusedPrefetchDepth > la) la = p.fusedPrefetchDepth;
    if (p.vramPressure || !p.ramHeadroom) la = (std::min)(la, 1u);
    if (p.vramPressure && !p.ramHeadroom) la = 0;
    c.prefetchLookahead = la;
    if (const char* e = std::getenv("DEEP2_PREFETCH_LOOKAHEAD"))
        if (*e) c.prefetchLookahead = (uint32_t)std::atoi(e);

    c.useQuantizedGpuPath = true;
    c.useGhostCache = true;
    // Unused MoE stay blanks (process of elimination) unless explicitly opted out.
    const char* elim = std::getenv("DEEP2_MOE_ELIMINATE_UNUSED");
    const bool blankUnused = !elim || elim[0] != '0';
    if (blankUnused)
        c.moeHotExpertCount = 0; // no speculative expert→VRAM vs MLA pins
    else
        c.moeHotExpertCount = p.experts ? (std::min)(p.experts, 8u) : 4;
    return c;
}

void ElasticBudget_Emit(FILE* f, const ElasticResidencyConfig& c,
                        const ElasticDynamicProbe& p) {
    if (!f) f = stdout;
    fprintf(f,
            "ELASTIC_DYNAMIC warm=%lluMB staged=%lluMB hot=%lluMB la=%u "
            "ramAvail=%lluMB vram=%lluMB L=%u pressure=%d\n",
            (unsigned long long)(c.maxWarmCompressedBytes >> 20),
            (unsigned long long)(c.maxWarmStagedBytes >> 20),
            (unsigned long long)(c.maxHotBytes >> 20), c.prefetchLookahead,
            (unsigned long long)(p.ramAvail >> 20),
            (unsigned long long)(p.vramTotal >> 20), p.layers,
            p.vramPressure ? 1 : 0);
    fflush(f);
}

} // namespace Deep2
