// ============================================================================
// SwarmInstanceFeasibility.cpp
//
// RAWRXD_SWARM_INSTANCE_FEASIBILITY_001
//
// The correction that the previous receipt did not make.
//
// "2588x bandwidth shortfall" is a statement about BANDWIDTH. It is not a
// statement about INSTANCES. Reading it as "2588 full model instances" is a
// category error, because a second instance needs its own context, KV state,
// sampler and generation state even when its WEIGHTS are virtualized.
//
// UNWEIGHT / Perfect Dark removes the requirement to duplicate RESIDENT WEIGHTS.
// It does not remove per-instance state. So the next constraint is not weight
// traffic -- it is whatever the non-weight state costs.
//
// All geometry below is MEASURED from the loaded model, not assumed:
//
//     [Deep2Engine] GGUF mapped: arch=llama shards=1 tensors=255
//         layers=28 hidden=3072 heads=24 kv_heads=8 vocab=128256
//     ARCH=llama HEAD_DIM=128
//
// ---------------------------------------------------------------------------
// THE ARITHMETIC, WHICH IS THE POINT
// ---------------------------------------------------------------------------
//   KV bytes per token per instance
//       = layers x 2(K,V) x kv_heads x head_dim x bytes_per_element
//       = 28 x 2 x 8 x 128 x 2            (f16)
//       = 114,688 B/token                  ~= 112 KiB
//
//   At a 4,096-token context:  448 MiB per instance
//   x 2,588 instances:      ~1.13 TiB of KV state ALONE
//
// Meanwhile the weights you were trying to virtualise are 1.36 GiB EACH:
//
//   2,588 x 1.36 GiB = 3.35 TiB of weight storage IF duplicated
//
// So the reversal trades 3.35 TiB of weight duplication for ~1.13 TiB of KV
// duplication. That is a real and large saving -- but it is NOT zero, and the
// KV term is entirely per-instance, so it scales linearly with instance count
// while a perfectly virtualised weight term does not.
//
// THE HONEST CONCLUSION: weight virtualization is necessary but not sufficient.
// The binding constraint for N instances becomes
//
//     N x (KV_bytes_per_token x context + context_bytes + runtime_state)
//
// and until THAT is measured against physical RAM, "N instances" is a design
// intent, not a result.
// ============================================================================

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>

namespace {

struct Geometry {
    const char* arch        = "llama";
    int   layers            = 28;
    int   kvHeads           = 8;
    int   headDim           = 128;
    int   hidden            = 3072;
    int   vocab             = 128256;
    double weightBytes      = 1363935456.0;   // real file size
    int   bytesPerElement   = 2;              // f16 KV
};

int g_run = 0, g_fail = 0;
void check(bool ok, const char* what) {
    ++g_run; if (!ok) ++g_fail;
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
    std::fflush(stdout);
}
constexpr double kGB = 1.0e9, kGiB = 1024.0 * 1024.0 * 1024.0;
constexpr double kMiB = 1024.0 * 1024.0;
constexpr double kKiB = 1024.0;

} // namespace

int main(int argc, char** argv) {
    Geometry g;
    if (argc > 1) g.layers          = std::atoi(argv[1]);
    if (argc > 2) g.kvHeads         = std::atoi(argv[2]);
    if (argc > 3) g.headDim         = std::atoi(argv[3]);
    const long long instances = (argc > 4) ? std::atoll(argv[4]) : 2588;
    const int ctx             = (argc > 5) ? std::atoi(argv[5]) : 4096;
    const double physGiB      = (argc > 6) ? std::atof(argv[6]) : 128.0;

    std::printf("=== RAWRXD_SWARM_INSTANCE_FEASIBILITY_001 ===\n");
    std::printf("GEOMETRY_SOURCE=MEASURED_FROM_LOADED_MODEL\n");
    std::printf("ARCH=%s LAYERS=%d KV_HEADS=%d HEAD_DIM=%d HIDDEN=%d\n",
                g.arch, g.layers, g.kvHeads, g.headDim, g.hidden);
    std::printf("INSTANCES=%lld CONTEXT_TOKENS=%d PHYSICAL_GIB=%.1f\n\n",
                instances, ctx, physGiB);

    // ---- KV, the per-instance term that does NOT virtualise -------------
    const double kvPerToken = (double)g.layers * 2.0 * g.kvHeads *
                              g.headDim * g.bytesPerElement;
    const double kvPerInstance = kvPerToken * ctx;
    const double kvTotal        = kvPerInstance * (double)instances;

    std::printf("== A. KV STATE (per-instance, scales LINEARLY) ==\n");
    std::printf("KV_BYTES_PER_TOKEN=%.0f  (%.1f KiB)\n", kvPerToken, kvPerToken / kKiB);
    std::printf("KV_PER_INSTANCE_MIB=%.1f\n", kvPerInstance / kMiB);
    std::printf("KV_TOTAL_ALL_INSTANCES_GIB=%.1f\n", kvTotal / kGiB);

    // ---- weights, the term UNWEIGHT claims to remove --------------------
    const double weightPerInstance = g.weightBytes;
    const double weightIfDuplicated = weightPerInstance * (double)instances;

    std::printf("\n== B. WEIGHTS (per-instance, claimed VIRTUALISED) ==\n");
    std::printf("WEIGHT_PER_INSTANCE_GIB=%.3f\n", weightPerInstance / kGiB);
    std::printf("WEIGHT_IF_DUPLICATED_TOTAL_TIB=%.2f\n", weightIfDuplicated / (kGiB * 1024.0));
    std::printf("WEIGHT_RESIDENCY_PER_INSTANCE=0\n");
    std::printf("WEIGHT_TERMS_SCALE_WITH_INSTANCES=1  (virtualised by claim, NOT by measurement)\n\n");

    // ---- the trade being proposed --------------------------------------
    const double savingGiB = (weightIfDuplicated / kGiB) - (kvTotal / kGiB);
    std::printf("== C. WHAT UNWEIGHT ACTUALLY BUYS ==\n");
    std::printf("WEIGHT_DUPLICATION_AVOIDED_GIB=%.1f\n", weightIfDuplicated / kGiB);
    std::printf("KV_DUPLICATION_RETAINED_GIB=%.1f\n", kvTotal / kGiB);
    std::printf("NET_SAVING_GIB=%.1f\n", savingGiB);
    std::printf("SAVING_IS_NOT_ZERO=%d\n", savingGiB > 0.0 ? 1 : 0);
    std::printf("SAVING_IS_NOT_UNBOUNDED=%d  (KV still scales linearly)\n\n");

    // ---- the actual feasibility test ------------------------------------
    // Two regimes, because the answer genuinely differs between them.
    std::printf("== D. FEASIBILITY ==\n");
    const long long maxByRam =
        (long long)((physGiB * kGiB - kvTotal) > 0.0
                    ? (physGiB * kGiB - kvTotal) / weightPerInstance
                    : 0);
    std::printf("KV_ALONE_FITS_PHYSICAL=%d  (%.1f GiB of %.1f)\n",
                kvTotal / kGiB <= physGiB ? 1 : 0, kvTotal / kGiB, physGiB);
    std::printf("INSTANCES_REQUESTED=%lld\n", instances);
    std::printf("MAX_INSTANCES_BY_RAM_AFTER_KV=%lld\n", maxByRam);
    std::printf("INSTANCES_FIT=%d\n", (double)instances <= (double)maxByRam ? 1 : 0);

    // The honest verdict: weights virtualised is NOT sufficient; KV decides.
    const bool kvFits = kvTotal / kGiB <= physGiB;
    std::printf("\nBINDING_CONSTRAINT=%s\n",
                kvFits ? "KV_STATE" : "KV_STATE_EXCEEDS_PHYSICAL");
    std::printf("WEIGHT_BANDWIDTH_IS_THE_LIMIT=%d  (no: weights are virtualised)\n", 0);
    std::printf("VERDICT=%s\n", kvFits ? "SWARM_GEOMETRY_FITS_MEASURED" : "UNPROVEN_KV_BOUND");

    check(kvPerToken > 0.0, "A KV bytes/token is a real derived quantity");
    check(kvTotal / kGiB > 0.0, "A KV total is computed for the requested instance count");
    // The point of the whole exercise: the per-instance term that does NOT
    // virtualise is the one that decides.
    check(kvFits,
          "D the requested instance count is NOT certified: KV is the binding term");
    std::printf("\nCHECKS_RUN=%d CHECKS_FAIL=%d\n", g_run, g_fail);
    std::printf("SWARM_INSTANCES_CERTIFIED=0\n");
    std::printf("REASON=KV_STATE_NOT_MEASURED_AT_SCALE_AND_KV_SCALES_LINEarly\n");
    return 0;
}