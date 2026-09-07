// deep2_k2_full_depth_combined_policy_cert.cpp — K2_FULL_DEPTH_COMBINED_POLICY_001
// A0 | B2 trampoline | Bbest cyclone+elastic | C002 trampoline+cyclone+elastic+fused002
#include "Deep2LivePath.hpp"
#include "FusedLiveController.hpp"
#include "K2LivePathTensorCache.hpp"
#include "LivePathEffect.hpp"
#include "StreamPathTiming.hpp"
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

static void EmitOwn(FILE* f, const CombinedArmOut& o) {
    fprintf(f, "TRAMP_OUT_HITS=%llu CYCLONE_ACQ=%llu ELASTIC_HITS=%llu DUP=%llu\n",
            (unsigned long long)o.cache.trampOutHits,
            (unsigned long long)o.cache.cycloneLayerAcquires,
            (unsigned long long)o.cache.elasticResidentHits,
            (unsigned long long)o.cache.combinedDupAcquires);
    fprintf(f, "FUSED_FAST_BYPASS=%u FUSED_DECISIONS=%u FUSED_ENABLED_SNAP=%u\n",
            o.fused.fastBypass, o.fused.decisions, Fused_Enabled() ? 1u : 0u);
    StreamPathTiming_Emit(f);
}

int main() {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    _putenv_s("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    _putenv_s("DEEP2_WEIGHT_BUDGET_MIB", "512");
    _putenv_s("DEEP2_LIVE_POLICY", "MANUAL");
    CreateDirectoryA(
        "G:\\~dev\\rawrxd\\evidence\\K2_FULL_DEPTH_COMBINED_POLICY_001", nullptr);
#endif
    const char* dir = std::getenv("DEEP2_K2_SHARD_DIR");
    if (!dir || !dir[0]) dir = "F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M";
    if (!fs::is_directory(dir)) {
        printf("SKIP_NO_MODEL\nK2_FULL_DEPTH_COMBINED_POLICY_001=SKIP\n");
        return 0;
    }
    uint32_t nTok = 4, depth = 61;
    if (const char* t = std::getenv("DEEP2_EFF_TOKENS"))
        nTok = (uint32_t)std::max(2, atoi(t));
    if (const char* d = std::getenv("DEEP2_EFF_LAYER_DEPTH"))
        depth = (uint32_t)std::max(1, atoi(d));
    static const char* kPrompt = "Write one short paragraph on local decode tok/s.";
    static const CombinedArmDef kArms[] = {
        {"A0", "0", "none", "0"},
        {"B2", "1", "trampoline", "0"},
        {"Bbest", "1", "cyclone,elastic", "0"},
        {"C", "1", "trampoline,cyclone,elastic", "1"},
    };
    printf("K2_FULL_DEPTH_COMBINED_POLICY_001\nMODEL=%s TOKENS=%u DEPTH=%u\n",
           dir, nTok, depth);
    printf("C=trampoline+cyclone+elastic (must beat max(B2,Bbest) by >=3%%)\n");
    CombinedArmOut arms[4];
    for (int i = 0; i < 4; ++i) {
        arms[i] = K2_CombinedPolicy_RunArm(kArms[i], dir, nTok, depth, kPrompt);
        LivePath_EmitEffect(stdout, kArms[i].id, arms[i].s);
        EmitOwn(stdout, arms[i]);
        fprintf(stdout, "ACTIVE=%u LAST_TOK=%d\n", arms[i].liveActiveAfter ? 1u : 0u,
                arms[i].lastTok);
        fflush(stdout);
    }
    const auto& A0 = arms[0], &B2 = arms[1], &Bb = arms[2], &C = arms[3];
    const bool ok = A0.s.decodeTps >= 0 && B2.s.decodeTps > 0 && Bb.s.decodeTps > 0 &&
                    C.s.decodeTps > 0;
    const bool parity = A0.text == B2.text && B2.text == Bb.text && Bb.text == C.text &&
                        A0.lastTok == B2.lastTok && B2.lastTok == Bb.lastTok &&
                        Bb.lastTok == C.lastTok;
    const bool active0 = !B2.liveActiveAfter && !Bb.liveActiveAfter && !C.liveActiveAfter;
    const bool fallback0 = C.s.fallbackCount == 0 && B2.s.fallbackCount == 0;
    const int64_t growth =
        (int64_t)C.cache.bytesPeak - (int64_t)C.cache.bytesAfterWarm;
    const bool growth0 = growth <= 0;
    const bool vramOk = C.s.vramPeak <= (512ull << 20) || C.s.vramPeak <= Bb.s.vramPeak;
    const bool qOk = C.s.queuePeak <= 4096u;
    // Champion = best of B2 / Bbest (do not assume cyclone+elastic).
    const bool b2Champ = B2.s.decodeTps >= Bb.s.decodeTps;
    const auto& Champ = b2Champ ? B2 : Bb;
    const char* champId = b2Champ ? "B2" : "Bbest";
    const double target = Champ.s.decodeTps * 1.03;
    const bool bytesOk = C.s.streamBytesRead <= Champ.s.streamBytesRead;
    const bool tpsWin = C.s.decodeTps > Champ.s.decodeTps && C.s.wallMs < Champ.s.wallMs;
    const bool material = C.s.decodeTps + 1e-12 >= target;
    const bool inv = ok && parity && active0 && fallback0 && growth0 && vramOk && qOk;
    const bool cWins = inv && tpsWin && material && bytesOk && C.postWarmAllocs == 0;
    const char* decision = cWins ? "COMBINED" : "SPLIT_FREEZE";
    printf("CHAMPION=%s CHAMPION_TPS=%.3f C_TPS=%.3f C_TARGET=%.3f\n",
           champId, Champ.s.decodeTps, C.s.decodeTps, target);
    printf("C_BEATS_CHAMP=%d MATERIAL=%d GROWTH0=%d BYTES_OK=%d\n",
           tpsWin ? 1 : 0, material ? 1 : 0, growth0 ? 1 : 0, bytesOk ? 1 : 0);
    printf("OUTPUT_PARITY=%d ACTIVE0=%d FALLBACK0=%d\n", parity ? 1 : 0, active0 ? 1 : 0,
           fallback0 ? 1 : 0);
    printf("POLICY_DECISION=%s\n", decision);
    if (!cWins) {
        printf("FREEZE short/shallow=trampoline+cache full-depth=%s\n",
               b2Champ ? "trampoline+output_cache" : "cyclone+elastic");
    }
    const bool pass = inv;
    printf("K2_FULL_DEPTH_COMBINED_POLICY_001=%s\n", pass ? "PASS" : "FAIL");
    FILE* f = fopen(
        "G:\\~dev\\rawrxd\\evidence\\K2_FULL_DEPTH_COMBINED_POLICY_001\\GATE_STATUS.txt",
        "w");
    if (f) {
        for (int i = 0; i < 4; ++i) LivePath_EmitEffect(f, kArms[i].id, arms[i].s);
        fprintf(f, "CHAMPION=%s CHAMPION_TPS=%.3f C_TPS=%.3f C_TARGET=%.3f\n",
                champId, Champ.s.decodeTps, C.s.decodeTps, target);
        fprintf(f, "POLICY_DECISION=%s\n", decision);
        if (!cWins) {
            fprintf(f, "FREEZE short/shallow=trampoline+cache full-depth=%s\n",
                    b2Champ ? "trampoline+output_cache" : "cyclone+elastic");
        }
        fprintf(f, "K2_FULL_DEPTH_COMBINED_POLICY_001=%s\n", pass ? "PASS" : "FAIL");
        fclose(f);
    }
    fflush(stdout);
    _exit(pass ? 0 : 2);
}
