// deep2_k2_full_depth_fused_rebench_cert.cpp
// K2_FULL_DEPTH_FUSED_REBENCH_001 — C002 vs Promo baseline (fused unfreeze gate)
#include "Deep2LivePath.hpp"
#include "FusedLiveController.hpp"
#include "K2LivePathTensorCache.hpp"
#include "LivePathEffect.hpp"
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
        "G:\\~dev\\rawrxd\\evidence\\K2_FULL_DEPTH_FUSED_REBENCH_001", nullptr);
#endif
    const char* dir = std::getenv("DEEP2_K2_SHARD_DIR");
    if (!dir || !dir[0]) dir = "F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M";
    if (!fs::is_directory(dir)) {
        printf("SKIP_NO_MODEL\nK2_FULL_DEPTH_FUSED_REBENCH_001=SKIP\n");
        return 0;
    }
    uint32_t nTok = 2, depth = 61;
    if (const char* t = std::getenv("DEEP2_EFF_TOKENS"))
        nTok = (uint32_t)std::max(1, atoi(t));
    if (const char* d = std::getenv("DEEP2_EFF_LAYER_DEPTH"))
        depth = (uint32_t)std::max(1, atoi(d));
    static const char* kPrompt = "Write one short paragraph on local decode tok/s.";
    // B = promoted baseline; C = C002 fused on same mech stack
    static const CombinedArmDef kArms[] = {
        {"Promo", "1", "trampoline,cyclone,elastic", "0"},
        {"C002", "1", "trampoline,cyclone,elastic", "1"},
    };
    printf("K2_FULL_DEPTH_FUSED_REBENCH_001\nMODEL=%s TOKENS=%u DEPTH=%u\n",
           dir, nTok, depth);
    printf("BASELINE=FULL_DEPTH_PROMO C=FUSED_CONTROL_002\n");
    CombinedArmOut arms[2];
    for (int i = 0; i < 2; ++i) {
        arms[i] = K2_CombinedPolicy_RunArm(kArms[i], dir, nTok, depth, kPrompt);
        LivePath_EmitEffect(stdout, kArms[i].id, arms[i].s);
        fprintf(stdout,
                "DUP=%llu POST_WARM=%llu ACTIVE=%u BYPASS=%u DECISIONS=%u\n",
                (unsigned long long)arms[i].cache.combinedDupAcquires,
                (unsigned long long)arms[i].postWarmAllocs,
                arms[i].liveActiveAfter ? 1u : 0u,
                arms[i].fused.fastBypass, arms[i].fused.decisions);
        fflush(stdout);
    }
    const auto& B = arms[0], &C = arms[1];
    const double need = B.s.decodeTps * 1.03;
    const bool ok = B.s.decodeTps > 0 && C.s.decodeTps > 0;
    const bool parity = B.text == C.text && B.lastTok == C.lastTok;
    const bool active0 = !B.liveActiveAfter && !C.liveActiveAfter;
    const int64_t growth =
        (int64_t)C.cache.bytesPeak - (int64_t)C.cache.bytesAfterWarm;
    const bool growth0 = growth <= 0;
    const bool dup0 = C.cache.combinedDupAcquires == 0;
    const bool hot0 = C.postWarmAllocs == 0;
    const bool fall0 = C.s.fallbackCount == 0;
    const bool trampOk = C.cache.trampOutHits > 0 && C.cache.hits > 0;
    const bool material = C.s.decodeTps + 1e-12 >= need;
    const bool tpsWin = C.s.decodeTps > B.s.decodeTps && C.s.wallMs < B.s.wallMs;
    const bool noRegress = C.s.decodeTps + 1e-12 >= B.s.decodeTps * 0.97;
    const bool inv = ok && parity && active0 && growth0 && dup0 && hot0 && fall0 &&
                     trampOk;
    const bool unfreeze = inv && material && tpsWin;
    const char* decision = unfreeze ? "UNFREEZE_C002" : "KEEP_FROZEN_C002";
    // Gate PASS = invariants hold (decision recorded either way)
    const bool pass = inv && noRegress;
    printf("PROMO_TPS=%.3f C002_TPS=%.3f NEED=%.3f\n",
           B.s.decodeTps, C.s.decodeTps, need);
    printf("MATERIAL=%d TPS_WIN=%d NO_REGRESS=%d\n",
           material ? 1 : 0, tpsWin ? 1 : 0, noRegress ? 1 : 0);
    printf("PARITY=%d ACTIVE0=%d GROWTH0=%d DUP0=%d HOT0=%d FALL0=%d\n",
           parity ? 1 : 0, active0 ? 1 : 0, growth0 ? 1 : 0, dup0 ? 1 : 0,
           hot0 ? 1 : 0, fall0 ? 1 : 0);
    printf("FUSED_BYPASS=%u FUSED_DECISIONS=%u\n",
           C.fused.fastBypass, C.fused.decisions);
    printf("POLICY_DECISION=%s\n", decision);
    printf("K2_FULL_DEPTH_FUSED_REBENCH_001=%s\n", pass ? "PASS" : "FAIL");
    FILE* f = fopen(
        "G:\\~dev\\rawrxd\\evidence\\K2_FULL_DEPTH_FUSED_REBENCH_001\\GATE_STATUS.txt",
        "w");
    if (f) {
        fprintf(f, "PROMO_TPS=%.3f C002_TPS=%.3f NEED=%.3f\n",
                B.s.decodeTps, C.s.decodeTps, need);
        fprintf(f, "FUSED_BYPASS=%u FUSED_DECISIONS=%u\n",
                C.fused.fastBypass, C.fused.decisions);
        fprintf(f, "POLICY_DECISION=%s\n", decision);
        fprintf(f, "K2_FULL_DEPTH_FUSED_REBENCH_001=%s\n",
                pass ? "PASS" : "FAIL");
        fclose(f);
    }
    fflush(stdout);
    _exit(pass ? 0 : 2);
}
