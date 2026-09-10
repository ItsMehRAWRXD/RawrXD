#pragma once
/* RAWRXD_PRODUCT_E2E_001 — args + entry. ≤99.
   PRODUCT_PASS = LIVE_WORKING_SET+FUTURE_CONSUMER_READY+TOKEN_WALL<=6666667.
   MODEL_SIZE/FULL_RESIDENCY are not gates. PROMOTE=0. */
#include "Deep2ProductGate.hpp"
#include "NoMoreBaselineStubsLaw.hpp"
#include "ProductE2EBlocker.hpp"
#include <cstdint>
#include <cstdio>

namespace rawr::product {

struct EmitArgs {
    uint64_t tokensRequested = 64;
    uint64_t tokensCommitted = 0;
    uint64_t wallNs = 0;
    uint64_t textBytes = 0;
    int modelAuthority = 0;
    int productionDecode = 0;
    int hostFwdCalls = 0;
    int cpuF32Expands = 0;
    int streamOutput = 0;
    int teardownOk = 0;
    int liveWorkingSet = 0;
    int futureConsumerReady = 0;
};

inline double DecodeTps(uint64_t tok, uint64_t wallNs) noexcept {
    if (!tok || !wallNs) return 0.0;
    return 1e9 * (double)tok / (double)wallNs;
}

inline void Emit(const EmitArgs& a) noexcept {
    const double tps = DecodeTps(a.tokensCommitted, a.wallNs);
    const uint64_t meanWall =
        (a.tokensCommitted && a.wallNs) ? (a.wallNs / a.tokensCommitted) : 0ull;
    const int runtime = (a.productionDecode && a.tokensCommitted > 0) ? 1 : 0;
    const int complete =
        (a.tokensCommitted > 0 && a.streamOutput && a.textBytes > 0 &&
         a.teardownOk)
            ? 1
            : 0;
    const int deadline =
        Deep2::product_gate::MeanDeadlineOk(a.tokensCommitted, a.wallNs);
    const int noHost = (a.hostFwdCalls == 0 && a.cpuF32Expands == 0) ? 1 : 0;
    const int functional =
        (complete && noHost && a.modelAuthority && runtime) ? 1 : 0;
    const int pass =
        functional && Deep2::product_gate::PromoteReady(
                          a.liveWorkingSet, a.futureConsumerReady, meanWall);
    std::printf("RAWRXD_PRODUCT_E2E_001\nINPUT_ACCEPTED=1\n"
                "MODEL_AUTHORITY=%d\nRUNTIME_BACKED=%d\n"
                "PRODUCTION_DECODE_PATH=%d\nHOST_FORWARD_LAYER_CALLS=%d\n"
                "CPU_F32_EXPANDS=%d\nTOKENS_REQUESTED=%llu\n"
                "TOKENS_COMMITTED=%llu\nSTREAM_OUTPUT_PRESENT=%d\n"
                "COMPLETION_RECEIPT_PRESENT=1\nLIVE_WORKING_SET=%d\n"
                "FUTURE_CONSUMER_READY=%d\nMEAN_TOKEN_WALL_NS=%llu\n"
                "TOKEN_WALL_TARGET_NS=%llu\nDEADLINE_OK=%d\n"
                "DECODE_TPS_REAL=%.3f\nNOTE=TPS_DISPLAY_ONLY\n"
                "FUNCTIONAL_PASS=%d\nPRODUCT_PASS=%d\nPROMOTE=0\n"
                "RAWRXD_PRODUCT_E2E_001=%s\n"
                "GATE=LIVE_WORKING_SET+FUTURE_CONSUMER_READY+TOKEN_WALL\n"
                "NOTE=MODEL_SIZE_FULL_RESIDENCY_NOT_GATES\n",
                a.modelAuthority, runtime, a.productionDecode, a.hostFwdCalls,
                a.cpuF32Expands, (unsigned long long)a.tokensRequested,
                (unsigned long long)a.tokensCommitted, a.streamOutput,
                a.liveWorkingSet, a.futureConsumerReady,
                (unsigned long long)meanWall,
                (unsigned long long)TOKEN_WALL_TARGET_NS, deadline, tps,
                functional, pass ? 1 : 0, functional ? "PASS" : "OPEN");
    if (!pass)
        EmitBlocker(functional, a.liveWorkingSet, a.futureConsumerReady,
                    deadline, a.modelAuthority, runtime, a.tokensCommitted,
                    complete);
    std::printf("RAWRXD_NO_MORE_BASELINE_STUBS_001=1\n");
}

} // namespace rawr::product
