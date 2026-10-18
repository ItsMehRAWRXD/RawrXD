#include "deep2/Deep2Speculative.hpp"
#include "deep2/MedusaDecoder.hpp"
#include "deep2/KVSpecTransaction.hpp"
#include <cstdio>

int main() {
    Deep2::SpeculativeRoofline r{};
    r.targetModelGB=18.49;
    r.gpu0GBps=640.0;
    r.gpu1GBps=624.0;
    r.efficiency=0.80;
    r.targetOutputTPS=85.0;

    Deep2::MedusaConfig mc{};
    mc.window=4;
    Deep2::MedusaDecoder draft(mc);
    const int prompt[]={1,2,3,4,1,2,3,4,1,2,3};
    draft.observe(prompt,sizeof(prompt)/sizeof(prompt[0]));
    const auto p=draft.propose();

    Deep2::KVCache kv;
    Deep2::KVCacheConfig kc{};
    kc.numLayers=1;kc.numHeads=1;kc.headDim=4;kc.maxSeqLen=32;
    if(!kv.allocate(kc)) {
        std::fprintf(stderr,"DEEP2_QWEN25_32B_85TPS_PREREQ=HOLD kv_alloc\n");
        return 2;
    }
    (void)kv.advanceBy(5);
    {
        Deep2::KVSpecTransaction tx(kv);
        (void)kv.advanceBy(4);
        if(!tx.commitAccepted(2) || kv.currentLength()!=7) {
            std::fprintf(stderr,"DEEP2_QWEN25_32B_85TPS_PREREQ=HOLD kv_tx\n");
            return 3;
        }
    }

    const bool singlePassInsufficient=
        r.rawTargetPassTPS()<r.targetOutputTPS;
    const bool windowEnough=r.physicallyReachableWithWindow(mc.window);
    const bool drafterLive=!p.empty();

    std::fprintf(stdout,
        "GATE=DEEP2_QWEN25_32B_85TPS_PREREQ_001\n"
        "RAW_SINGLE_PASS_TPS=%.6f\n"
        "EFF_SINGLE_PASS_TPS=%.6f\n"
        "MIN_ACCEPTED_PER_PASS=%.6f\n"
        "SPEC_WINDOW=%u\n"
        "DRAFTER_PROPOSALS=%zu\n"
        "KV_TRANSACTION=PASS\n"
        "SINGLE_PASS_INSUFFICIENT=%u\n"
        "WINDOW_PHYSICALLY_SUFFICIENT=%u\n",
        r.rawTargetPassTPS(),r.effectiveTargetPassTPS(),
        r.minimumAcceptedPerPass(),mc.window,p.size(),
        singlePassInsufficient?1u:0u,
        windowEnough?1u:0u);

    const bool pass=
        singlePassInsufficient&&windowEnough&&drafterLive;
    std::fprintf(stdout,
        "DEEP2_QWEN25_32B_85TPS_PREREQ_001=%s\n",
        pass?"PASS":"HOLD");
    return pass?0:1;
}
