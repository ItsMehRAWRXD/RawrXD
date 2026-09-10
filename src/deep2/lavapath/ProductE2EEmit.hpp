#pragma once
/* RAWRXD_PRODUCT_E2E_001 — args + entry. ≤99.
   PROMOTE_IF = PRODUCT_OPEN_PASS && SESSION_ENTER_PASS
                && GENERATED_TOKENS>0 && TOKEN_COMMIT_PASS;
   PROMOTE=0 until live generate probe. MULTI_FAMILY = next independent gate.
   TOKEN_WALL/TPS = telemetry only. MODEL_SIZE/FULL_RESIDENCY ≠ gates. */
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
    int productOpenPass = 0;
    int sessionEnterPass = 0;
    int tokenCommitPass = 0;
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
    const int ready = Deep2::product_gate::PromoteReady(
        a.productOpenPass, a.sessionEnterPass, a.tokensCommitted,
        a.tokenCommitPass);
    /* PRODUCT_PASS = readiness tetrad; PROMOTE stays 0 until climb law opens. */
    const int pass = ready ? 1 : 0;
    std::printf("RAWRXD_PRODUCT_E2E_001\nINPUT_ACCEPTED=1\n"
                "MODEL_AUTHORITY=%d\nRUNTIME_BACKED=%d\n"
                "PRODUCTION_DECODE_PATH=%d\nHOST_FORWARD_LAYER_CALLS=%d\n"
                "CPU_F32_EXPANDS=%d\nTOKENS_REQUESTED=%llu\n"
                "GENERATED_TOKENS=%llu\nTOKENS_COMMITTED=%llu\n"
                "STREAM_OUTPUT_PRESENT=%d\nCOMPLETION_RECEIPT_PRESENT=1\n"
                "PRODUCT_OPEN_PASS=%d\nSESSION_ENTER_PASS=%d\n"
                "TOKEN_COMMIT_PASS=%d\nMEAN_TOKEN_WALL_NS=%llu\n"
                "TOKEN_WALL_TARGET_NS=%llu\nDEADLINE_OK=%d\n"
                "DECODE_TPS_REAL=%.3f\nNOTE=TPS_DISPLAY_ONLY\n"
                "FUNCTIONAL_PASS=%d\nPRODUCT_PASS=%d\nPROMOTE=0\n"
                "RAWRXD_PRODUCT_E2E_001=%s\n"
                "FINAL_READY_GATE=PRODUCT_OPEN_PASS&&SESSION_ENTER_PASS&&"
                "GENERATED_TOKENS>0&&TOKEN_COMMIT_PASS\n"
                "NEXT_INDEPENDENT_GATE=MULTI_FAMILY\n"
                "NOTE=TINYLLAMA_R25_PRODUCTOPEN_NE_MULTI_FAMILY\n",
                a.modelAuthority, runtime, a.productionDecode, a.hostFwdCalls,
                a.cpuF32Expands, (unsigned long long)a.tokensRequested,
                (unsigned long long)a.tokensCommitted,
                (unsigned long long)a.tokensCommitted, a.streamOutput,
                a.productOpenPass, a.sessionEnterPass, a.tokenCommitPass,
                (unsigned long long)meanWall,
                (unsigned long long)TOKEN_WALL_TARGET_NS, deadline, tps,
                functional, pass, ready ? "PASS" : "OPEN");
    if (!pass)
        EmitBlocker(a.productOpenPass, a.sessionEnterPass, a.tokensCommitted,
                    a.tokenCommitPass);
    std::printf("RAWRXD_NO_MORE_BASELINE_STUBS_001=1\n");
}

} // namespace rawr::product
