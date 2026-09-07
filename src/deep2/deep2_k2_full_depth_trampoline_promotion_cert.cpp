// deep2_k2_full_depth_trampoline_promotion_cert.cpp
// K2_FULL_DEPTH_TRAMPOLINE_PROMOTION_001 — reuse accelerator at 61×2
#include "Deep2LivePath.hpp"
#include "FusedLiveController.hpp"
#include "K2LivePathTensorCache.hpp"
#include "LivePathEffect.hpp"
#include "StreamTransferCounters.hpp"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif
using namespace Deep2;
namespace fs = std::filesystem;

namespace Deep2 {
struct CombinedArmDef {
    const char* id; const char* live; const char* mech; const char* fused;
};
struct CombinedArmOut {
    LivePathEffectSnap s;
    K2LiveCacheStats cache{};
    uint64_t postWarmAllocs = 0;
    std::string text;
    int32_t lastTok = -1;
    bool liveActiveAfter = true;
    FusedCounters fused{};
};
CombinedArmOut K2_CombinedPolicy_RunArm(const CombinedArmDef& d, const char* dir,
                                        uint32_t nTok, uint32_t depth,
                                        const char* prompt);
}

int main() {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    _putenv_s("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    _putenv_s("DEEP2_WEIGHT_BUDGET_MIB", "512");
    _putenv_s("DEEP2_LIVE_POLICY", "MANUAL");
    CreateDirectoryA(
        "G:\\~dev\\rawrxd\\evidence\\K2_FULL_DEPTH_TRAMPOLINE_PROMOTION_001", nullptr);
#endif
    const char* dir = std::getenv("DEEP2_K2_SHARD_DIR");
    if (!dir || !dir[0]) dir = "F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M";
    if (!fs::is_directory(dir)) {
        printf("SKIP_NO_MODEL\nK2_FULL_DEPTH_TRAMPOLINE_PROMOTION_001=SKIP\n");
        return 0;
    }
    uint32_t nTok = 2, depth = 61;
    if (const char* t = std::getenv("DEEP2_EFF_TOKENS"))
        nTok = (uint32_t)std::max(1, atoi(t));
    if (const char* d = std::getenv("DEEP2_EFF_LAYER_DEPTH"))
        depth = (uint32_t)std::max(1, atoi(d));
    static const char* kPrompt = "Write one short paragraph on local decode tok/s.";
    // fused OFF — promote trampoline reuse into full-depth lane
    static const CombinedArmDef kArms[] = {
        {"B2", "1", "trampoline", "0"},
        {"Bbest", "1", "cyclone,elastic", "0"},
        {"Promo", "1", "trampoline,cyclone,elastic", "0"},
    };
    printf("K2_FULL_DEPTH_TRAMPOLINE_PROMOTION_001\nMODEL=%s TOKENS=%u DEPTH=%u\n",
           dir, nTok, depth);
    printf("PROMO=cyclone+elastic+trampoline-reuse fused=0\n");
    CombinedArmOut arms[3];
    for (int i = 0; i < 3; ++i) {
        arms[i] = K2_CombinedPolicy_RunArm(kArms[i], dir, nTok, depth, kPrompt);
        LivePath_EmitEffect(stdout, kArms[i].id, arms[i].s);
        const int64_t growth = (int64_t)arms[i].cache.bytesPeak -
                               (int64_t)arms[i].cache.bytesAfterWarm;
        fprintf(stdout,
                "TRAMP_HITS=%u TRAMP_REUSES=%llu CACHE_HITS=%llu DUP=%llu "
                "GROWTH=%lld POST_WARM=%llu ACTIVE=%u\n",
                LivePath_Counters().trampolineHits,
                (unsigned long long)arms[i].cache.trampOutHits,
                (unsigned long long)arms[i].cache.hits,
                (unsigned long long)arms[i].cache.combinedDupAcquires,
                (long long)growth, (unsigned long long)arms[i].postWarmAllocs,
                arms[i].liveActiveAfter ? 1u : 0u);
        fflush(stdout);
    }
    const auto& B2 = arms[0], &Bb = arms[1], &P = arms[2];
    const double floorTps = 0.094;
    const double nonTrampTarget = Bb.s.decodeTps * 1.03;
    const double need = (std::max)(floorTps, (std::max)(B2.s.decodeTps, nonTrampTarget));
    const bool ok = B2.s.decodeTps > 0 && Bb.s.decodeTps > 0 && P.s.decodeTps > 0;
    const bool parity = B2.text == Bb.text && Bb.text == P.text &&
                        B2.lastTok == Bb.lastTok && Bb.lastTok == P.lastTok;
    const bool active0 = !P.liveActiveAfter;
    const int64_t growth =
        (int64_t)P.cache.bytesPeak - (int64_t)P.cache.bytesAfterWarm;
    const bool growth0 = growth <= 0;
    const bool dup0 = P.cache.combinedDupAcquires == 0;
    const bool hot0 = P.postWarmAllocs == 0;
    const bool fall0 = P.s.fallbackCount == 0;
    const bool trampReuse = P.cache.trampOutHits > 0;
    const bool cacheReuse = P.cache.hits > 0;
    const bool tpsOk = P.s.decodeTps + 1e-12 >= need;
    const bool fusedOff = P.fused.decisions == 0 && P.fused.fastBypass == 0;
    const bool trampHits = LivePath_Counters().trampolineHits > 0 || trampReuse;
    const bool pass = ok && parity && active0 && growth0 && dup0 && hot0 && fall0 &&
                      trampHits && trampReuse && cacheReuse && tpsOk && fusedOff;
    printf("B2_TPS=%.3f BBEST_TPS=%.3f PROMO_TPS=%.3f NEED=%.3f\n",
           B2.s.decodeTps, Bb.s.decodeTps, P.s.decodeTps, need);
    printf("TPS_OK=%d PARITY=%d ACTIVE0=%d GROWTH0=%d DUP0=%d HOT0=%d FALL0=%d\n",
           tpsOk ? 1 : 0, parity ? 1 : 0, active0 ? 1 : 0, growth0 ? 1 : 0,
           dup0 ? 1 : 0, hot0 ? 1 : 0, fall0 ? 1 : 0);
    printf("TRAMP_HIT=%d TRAMP_REUSE=%d CACHE_REUSE=%d FUSED_OFF=%d\n",
           trampHits ? 1 : 0, trampReuse ? 1 : 0, cacheReuse ? 1 : 0,
           fusedOff ? 1 : 0);
    printf("K2_FULL_DEPTH_TRAMPOLINE_PROMOTION_001=%s\n", pass ? "PASS" : "FAIL");
    FILE* f = fopen(
        "G:\\~dev\\rawrxd\\evidence\\K2_FULL_DEPTH_TRAMPOLINE_PROMOTION_001\\GATE_STATUS.txt",
        "w");
    if (f) {
        fprintf(f, "B2_TPS=%.3f BBEST_TPS=%.3f PROMO_TPS=%.3f NEED=%.3f\n",
                B2.s.decodeTps, Bb.s.decodeTps, P.s.decodeTps, need);
        fprintf(f, "DUP=%llu TRAMP_REUSES=%llu CACHE_HITS=%llu\n",
                (unsigned long long)P.cache.combinedDupAcquires,
                (unsigned long long)P.cache.trampOutHits,
                (unsigned long long)P.cache.hits);
        fprintf(f, "K2_FULL_DEPTH_TRAMPOLINE_PROMOTION_001=%s\n",
                pass ? "PASS" : "FAIL");
        fclose(f);
    }
    fflush(stdout);
    _exit(pass ? 0 : 2);
}
