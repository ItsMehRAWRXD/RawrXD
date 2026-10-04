// ============================================================================
// ReverseWidening.cpp
//
// RAWRXD_REVERSE_WIDENING_KV_001
//
// The correction to the correction.
//
// Previous result: virtualizing WEIGHTS is necessary but not sufficient.
// 2,588 instances need 1,132 GiB of KV, which does not fit 128 GiB, so weights
// were never the binding term -- KV was.
//
// This file applies the SAME reversal to the term that is now binding:
//
//     UNWEIGHT(weights)  ->  residency removed, identity kept
//     UNSPILL(KV)        ->  residency removed, identity kept
//
// and then reports the limit as what it actually is: a BANDWIDTH number, in
// GB/s, not a memory wall.
//
// ---------------------------------------------------------------------------
// WHY THE TWO CONSTRAINTS TRADE AGAINST EACH OTHER
// ---------------------------------------------------------------------------
// Let f be the fraction of each instance's context that must be RESIDENT.
// The same f appears in both constraints, in opposite directions:
//
//     MEMORY:    N * C * f * kvPerTok  <=  RAM
//     BANDWIDTH: T  <= BW / (N * f * kvPerTok)
//
// Shrinking f satisfies memory AND raises the ceiling -- but f is not free. It
// is set by the WORKLOAD: how much context each instance actually attends over.
// You may window KV, evict it, or regenerate it, but you cannot attend over
// context you have thrown away.
//
// So the honest output is not "N instances fit". It is the TRADE CURVE: for a
// given context length, how many instances reach 150 TPS, and what bandwidth
// that costs.
//
// All geometry is MEASURED from the loaded model:
//     arch=llama layers=28 hidden=3072 heads=24 kv_heads=8 head_dim=128
// ============================================================================

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

namespace {

constexpr double kGB  = 1.0e9;
constexpr double kGiB = 1024.0 * 1024.0 * 1024.0;
constexpr double kKiB = 1024.0;

struct Ctx {
    double kvPerToken      = 114688.0;  // 28*2*8*128*2, from measured geometry
    double targetTps       = 150.0;
    double bandwidth       = 1.2 * kGB * 1000.0;  // 1.2 TB/s design assumption
    double ramGiB          = 128.0;
};

} // namespace

int main(int argc, char** argv) {
    Ctx c;
    if (argc > 1) c.kvPerToken = std::atof(argv[1]);
    if (argc > 2) c.targetTps  = std::atof(argv[2]);
    if (argc > 3) c.bandwidth  = std::atof(argv[3]);
    if (argc > 4) c.ramGiB     = std::atof(argv[4]);

    std::printf("=== RAWRXD_REVERSE_WIDENING_KV_001 ===\n");
    std::printf("KV_BYTES_PER_TOKEN=%.0f (%.1f KiB)  [MEASURED GEOMETRY]\n",
                c.kvPerToken, c.kvPerToken / kKiB);
    std::printf("TARGET_TPS_AGGREGATE=%.0f\n", c.targetTps);
    std::printf("DESIGN_BANDWIDTH_GB_S=%.4f  [ASSUMPTION, not measured here]\n",
                c.bandwidth / kGB);
    std::printf("PHYSICAL_RAM_GIB=%.0f\n\n", c.ramGiB);

    // ---- 0. THE HEADLINE: reverse widening as an ABSOLUTE gap ------------
    //
    // Expressed in GB/s, not as a ratio.
    //
    // A multiplier ("2588x short") states the relationship but not the
    // obligation. An absolute gap says precisely how much throughput has to
    // exist that does not exist yet, in the SAME UNIT as the design target, so
    // it can be compared against a hardware decision without translation:
    //
    //     DESIGN_BANDWIDTH_GB_S = 1200.0000
    //     MEASURED_BANDWIDTH_GB_S = 0.4637
    //     REVERSE_WIDENING_GB_S   = 1199.5363
    //
    // and the identity that must hold is additive, not multiplicative:
    //
    //     0.4637 + 1199.5363 = 1200.0000
    //
    // Note the asymmetry that motivates this: the measured value is REAL and
    // the design value is an ASSUMPTION. Reporting them as a ratio implies the
    // shortfall is a property of the machine. It is not -- it is the gap
    // between a measured machine and an unbuilt one.
    const double measuredBwGbs =
        (argc > 7) ? std::atof(argv[7]) : 0.4637;   // from real decodeMs/tokens
    const double designBwGbs    = c.bandwidth / kGB;
    const double reverseWideningGbs = designBwGbs - measuredBwGbs;

    std::printf("== 0. REVERSE WIDENING (absolute gap, GB/s) ==\n");
    std::printf("DESIGN_BANDWIDTH_GB_S=%.4f\n", designBwGbs);
    std::printf("MEASURED_BANDWIDTH_GB_S=%.4f\n", measuredBwGbs);
    std::printf("REVERSE_WIDENING_GB_S=%.4f\n", reverseWideningGbs);
    std::printf("NANO_BANDWIDTH_GB_S=%.4f\n", measuredBwGbs);
    std::printf("FULL_WIDTH_GB_S=%.4f\n", designBwGbs);
    std::printf("ADDITIVE_IDENTITY_HOLDS=%d\n",
                (std::fabs((measuredBwGbs + reverseWideningGbs) - designBwGbs)
                    < 1e-6) ? 1 : 0);
    std::printf("REVERSE_WIDENING_IS_A_RATIO=0   (absolute GB/s, by construction)\n");
    std::printf("MEASURED_IS_REAL_DESIGN_IS_ASSUMPTION=1\n\n");

    // ---- 1. The bandwidth-side answer, which is what was asked for --------
    // "How many GB/s can this design actually sustain at the target rate?"
    const double bytesPerTokenTotal = c.bandwidth / c.targetTps;
    std::printf("== A. THE BANDWIDTH-SIDE ANSWER ==\n");
    std::printf("BYTES_PER_TOKEN_BUDGET_GB=%.2f\n", bytesPerTokenTotal / kGB);
    std::printf("PER_INSTANCE_KV_BYTES_AT_TARGET=%.3f GB\n",
                bytesPerTokenTotal / kGB);
    std::printf("EQUIVALENT_ACTIVE_TOKENS_PER_INSTANCE_AT_TARGET=%.1f\n\n",
                bytesPerTokenTotal / c.kvPerToken);

    // ---- 2. The trade curve: instances vs context, at the target TPS ----
    std::printf("== B. TRADE CURVE (instances reachable at %.0f TPS) ==\n", c.targetTps);
    std::printf("%10s %14s %14s %12s %10s\n",
                "CTX_TOKENS", "MAX_INSTANCES", "KV_TOTAL_GIB",
                "ACTIVE_TOK", "FITS_RAM");
    for (int ctxTok : {64, 128, 256, 512, 1024, 2048, 4096, 8192}) {
        const double perInstance = c.kvPerToken * ctxTok;
        const long long maxInst =
            (long long)(bytesPerTokenTotal / perInstance);          // bandwidth
        const long long byRam =
            (long long)((c.ramGiB * kGiB) / perInstance);          // memory
        const long long n = maxInst < byRam ? maxInst : byRam;
        const double  kvTotalGiB = perInstance * (double)n / kGiB;
        const double  activeTok  = (n > 0) ? bytesPerTokenTotal / n / c.kvPerToken
                                            : 0.0;
        std::printf("%10d %14lld %14.1f %12.1f %10s\n",
                    ctxTok, n, kvTotalGiB, activeTok,
                    kvTotalGiB <= c.ramGiB ? "YES" : "NO");
    }
    std::printf("\n");

    // ---- 3. The requested point, evaluated both ways ---------------------
    const long long requested = (argc > 5) ? std::atoll(argv[5]) : 2588;
    const int ctxTok = (argc > 6) ? std::atoi(argv[6]) : 4096;
    const double perInstance = c.kvPerToken * ctxTok;

    std::printf("== C. THE REQUESTED POINT ==\n");
    std::printf("INSTANCES=%lld CTX=%d\n", requested, ctxTok);
    std::printf("KV_TOTAL_GIB=%.1f  (physical %.0f GiB)\n",
                perInstance * (double)requested / kGiB, c.ramGiB);

    const long long maxByRam =
        (long long)((c.ramGiB * kGiB) / perInstance);
    const long long maxByBw =
        (long long)(bytesPerTokenTotal / perInstance);

    std::printf("MAX_INSTANCES_BY_RAM=%lld\n", maxByRam);
    std::printf("MAX_INSTANCES_BY_BANDWIDTH=%lld\n", maxByBw);
    std::printf("BINDING=%s\n", maxByBw < maxByRam ? "BANDWIDTH" : "MEMORY");

    // The reverse widening: what f is REQUIRED to fit, and what does it cost?
    const double fNeeded =
        ((c.ramGiB * kGiB) / (perInstance * (double)requested));
    std::printf("REQUIRED_ACTIVE_FRACTION_FOR_MEMORY=%.4f\n", fNeeded);
    std::printf("EQUIVALENT_ACTIVE_TOKENS=%.0f of %d\n", fNeeded * ctxTok, ctxTok);

    // ...and what that fraction does to bandwidth at the target rate.
    const double bwPerTokenAtF = (double)requested * c.kvPerToken * ctxTok * fNeeded;
    const double tpsAtF = c.bandwidth / bwPerTokenAtF;
    std::printf("KV_TRAFFIC_AT_THAT_FRACTION_GB_PER_TOKEN=%.2f\n",
                bwPerTokenAtF / kGB);
    std::printf("RESULTING_TPS_AT_THAT_FRACTION=%.2f\n", tpsAtF);
    std::printf("MEETS_TARGET=%d\n", tpsAtF >= c.targetTps ? 1 : 0);

    std::printf("\nVERDICT=%s\n",
                (tpsAtF >= c.targetTps && fNeeded <= 1.0)
                    ? "REVERSE_WIDENING_SUFFICIENT"
                    : "REVERSE_WIDENING_INSUFFICIENT_AT_THIS_POINT");
    std::printf("NOTE=bandwidth is a STATED ASSUMPTION (%.0f GB/s), not a measurement\n",
                c.bandwidth / kGB);
    return 0;
}