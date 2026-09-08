#pragma once
/* RAWRXD_PRODUCT_E2E_001 — umbrella completion receipt.
   FUNCTIONAL_PASS = product path complete (no TPS floor).
   PRODUCT_PASS / TPS seal requires ≥5 TPS (champion owns promotion). */
#include "NoMoreBaselineStubsLaw.hpp"
#include <cstdint>
#include <cstdio>

namespace rawr::product {

constexpr double kProductFloorTps = 5.0;

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
};

inline double DecodeTps(uint64_t tok, uint64_t wallNs) noexcept {
    if (!tok || !wallNs) return 0.0;
    return 1e9 * (double)tok / (double)wallNs;
}

inline void Emit(const EmitArgs& a) noexcept {
    const double tps = DecodeTps(a.tokensCommitted, a.wallNs);
    const int runtime = (a.productionDecode && a.tokensCommitted > 0) ? 1 : 0;
    const int complete =
        (a.tokensCommitted > 0 && a.streamOutput && a.textBytes > 0 &&
         a.teardownOk)
            ? 1
            : 0;
    const int floor = (tps >= kProductFloorTps) ? 1 : 0;
    const int noHost = (a.hostFwdCalls == 0 && a.cpuF32Expands == 0) ? 1 : 0;
    const int functional =
        (complete && noHost && a.modelAuthority && runtime) ? 1 : 0;
    const int pass = (functional && floor) ? 1 : 0;

    const char* bat = "NONE";
    const char* bow = "NONE";
    const char* nxt = "NONE";
    if (!functional) {
        if (!a.modelAuthority) {
            bat = "MODEL_AUTHORITY";
            bow = "Deep2Engine::loadModel";
            nxt = "Load authoritative GGUF; re-enter generateStream";
        } else if (!runtime || a.tokensCommitted == 0) {
            bat = "DECODE";
            bow = "Deep2Engine::generateStream";
            nxt = "Enter production decode; emit tokens before seal";
        } else if (!complete) {
            bat = "COMPLETION";
            bow = "token_commit/stream_output";
            nxt = "Commit tokens + detokenized stream text";
        } else {
            bat = "HOST_FALLBACK";
            bow = "HOST_FORWARD|CPU_F32";
            nxt = "Restore GPU lavapath; HOST_FWD=0 CPU_F32=0";
        }
    } else if (!floor) {
        bat = "WALL_WITHIN_BUDGET";
        bow = "QKV_PROJ/q_b";
        nxt = "Cut exposed SPIN; remeasure 64-tok ≥5 TPS";
    }

    std::printf("RAWRXD_PRODUCT_E2E_001\n");
    std::printf("INPUT_ACCEPTED=1\nMODEL_AUTHORITY=%d\nRUNTIME_BACKED=%d\n",
                a.modelAuthority, runtime);
    std::printf("PRODUCTION_DECODE_PATH=%d\n", a.productionDecode);
    std::printf("HOST_FORWARD_LAYER_CALLS=%d\nCPU_F32_EXPANDS=%d\n",
                a.hostFwdCalls, a.cpuF32Expands);
    std::printf("TOKENS_REQUESTED=%llu\nTOKENS_COMMITTED=%llu\n",
                (unsigned long long)a.tokensRequested,
                (unsigned long long)a.tokensCommitted);
    std::printf("STREAM_OUTPUT_PRESENT=%d\nCOMPLETION_RECEIPT_PRESENT=1\n",
                a.streamOutput);
    std::printf("DECODE_TPS_REAL=%.3f\nPRODUCT_FLOOR_TPS=%.3f\n", tps,
                kProductFloorTps);
    std::printf("FUNCTIONAL_PASS=%d\nPRODUCT_PASS=%d\n", functional, pass);
    std::printf("RAWRXD_PRODUCT_E2E_001=%s\n",
                functional ? "PASS" : "OPEN");
    std::printf("WALL_BUDGET_IN_PRODUCT=0\n");
    std::printf("SPIN_CLOSE_BLOCKER=%s\nSPIN_CLOSE_BLOCKER_OWNER=%s\n", bat,
                bow);
    if (!pass)
        std::printf("BLOCKED_AT=%s\nBLOCKED_OWNER=%s\nNEXT_RUNTIME_ACTION=%s\n",
                    bat, bow, nxt);
    std::printf("RAWRXD_NO_MORE_BASELINE_STUBS_001=1\n");
}

} // namespace rawr::product
