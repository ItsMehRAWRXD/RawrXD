// K2FullDepthCombined_Proof.cpp — emit + score C002 vs Bbest
#include "FusedLiveController.hpp"
#include "K2LivePathTensorCache.hpp"
#include "LivePathEffect.hpp"
#include <cstdio>
#include <string>

namespace Deep2 {

struct CombinedArmOut {
    LivePathEffectSnap s;
    K2LiveCacheStats cache{};
    uint64_t postWarmAllocs = 0;
    std::string text;
    int32_t lastTok = -1;
    bool liveActiveAfter = true;
    FusedCounters fused{};
};

struct CombinedProof {
    bool inv = false;
    bool tpsWin = false;
    bool material = false;
    bool cWins = false;
    double target = 0;
    const char* decision = "SPLIT_FREEZE";
};

CombinedProof K2_CombinedPolicy_Score(const CombinedArmOut& A, const CombinedArmOut& Bb,
                                      const CombinedArmOut& C) {
    CombinedProof p;
    const bool ok = A.s.decodeTps >= 0 && Bb.s.decodeTps > 0 && C.s.decodeTps > 0;
    const bool parity = A.text == Bb.text && Bb.text == C.text &&
                        A.lastTok == Bb.lastTok && Bb.lastTok == C.lastTok;
    const bool active0 = !Bb.liveActiveAfter && !C.liveActiveAfter;
    const bool fallbackOk = C.s.fallbackCount == 0 && Bb.s.fallbackCount == 0;
    const bool qOk = C.s.queuePeak <= 4096u;
    const int64_t cGrowth =
        (int64_t)C.cache.bytesPeak - (int64_t)C.cache.bytesAfterWarm;
    const bool growth0 = cGrowth <= 0;
    const bool vramOk =
        C.s.vramPeak <= (512ull << 20) || C.s.vramPeak <= Bb.s.vramPeak;
    const bool bytesOk =
        C.s.streamBytesPerToken <= Bb.s.streamBytesPerToken * 1.001 + 1.0;
    p.target = Bb.s.decodeTps * 1.03;
    p.tpsWin = C.s.decodeTps > Bb.s.decodeTps;
    p.material = C.s.decodeTps + 1e-12 >= p.target;
    p.inv = ok && parity && active0 && fallbackOk && qOk && growth0 && vramOk &&
            bytesOk;
    p.cWins = p.inv && p.tpsWin && p.material;
    p.decision = p.cWins ? "COMBINED_002" : "SPLIT_FREEZE";
    printf("BBEST_TPS=%.3f C002_TPS=%.3f C_TARGET=%.3f\n", Bb.s.decodeTps,
           C.s.decodeTps, p.target);
    printf("C_BEATS_BBEST=%d MATERIAL_3PCT=%d BYTES_OK=%d GROWTH0=%d\n",
           p.tpsWin ? 1 : 0, p.material ? 1 : 0, bytesOk ? 1 : 0, growth0 ? 1 : 0);
    printf("OUTPUT_PARITY=%d ACTIVE0=%d FALLBACK0=%d QUEUE_PEAK_C=%u\n",
           parity ? 1 : 0, active0 ? 1 : 0, fallbackOk ? 1 : 0, C.s.queuePeak);
    printf("FUSED_FAST_BYPASS_C=%u FUSED_DECISIONS_C=%u\n", C.fused.fastBypass,
           C.fused.decisions);
    printf("POLICY_DECISION=%s\n", p.decision);
    if (!p.cWins)
        printf("FREEZE short/shallow=trampoline+cache full-depth=cyclone+elastic\n");
    return p;
}

} // namespace Deep2
