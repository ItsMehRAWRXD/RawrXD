// ============================================================================
// residual_overlay_sweep_001.cpp
// RAWRXD_RESIDUAL_OVERLAY_SWEEP_001
//
// Answers the two questions the single-point fusion receipt left open:
//
//   Q1  Is there a base that is BOTH cheap enough AND accurate enough to put the
//       combined payload under break-even (base_bits + delta_bits < 32)?
//   Q2  Is the delta actually COMPRESSIBLE, or only large?
//
// Q2 is the one the previous receipt declared UNMEASURED and explicitly
// warned must not be inferred. DELTA_MAGNITUDE_RATIO=0.787 is an L1 MAGNITUDE
// ratio: a delta with 0.787 magnitude can still be cheap if it is sparse,
// low-rank, or clustered. This file measures the missing quantity directly.
//
// NO ENGINE, NO GPU, NO I/O. The whole point is that these questions are
// answerable without a forward pass.
//
// OWNERSHIP AND CONSISTENCY
//   The single-point harness this sweeps is `rawrxd/tools/residual_overlay_
//   fusion_001.cpp`, owned by another lane and untracked. It is NOT modified
//   here, and this file does not include it -- it re-implements the quantizer
//   so the sweep can vary it.
//
//   Two independent quantizers that disagree would make every sweep number
//   meaningless, so CONTROL 0 reproduces the other lane's published single
//   point (bits=1.5, group=32, threshold=1/3) and REQUIRES an exact match
//   against its measured BASE_ONLY_REL_L2=0.734019 and
//   DELTA_MAGNITUDE_RATIO=0.786882. Agreement is therefore proven, not assumed.
//   If that control ever fails, the sweep is void and says so.
// ============================================================================

#include <cstdio>
#include <cstdint>
#include <cmath>
#include <cstring>
#include <vector>
#include <string>
#include <random>
#include <algorithm>

namespace {

constexpr int    kRows      = 64;
constexpr int    kCols      = 256;
constexpr double kOrigBits  = 32.0;   // fp32 reference the whole comparison is against

// --------------------------------------------------------------- quantizer
//
// Levels are symmetric and uniform: L levels spaced evenly over [-1, 1]. That is
// a deliberately weak base (no per-group k-means, no outlier handling), because a
// sweep whose conclusion depends on a smart quantizer is not measuring the
// architecture -- it is measuring the quantizer. The point here is the SIZE and
// SPARSITY structure of the delta, which a smarter base would only shrink.
struct Base {
    std::vector<int8_t>  code;
    std::vector<float>   scale;     // one per (row, group)
    std::vector<float>   level;     // dequantized level, indexed by code
    int rows = 0, cols = 0, groups = 0, groupSize = 0, levels = 0;
    double deadband = 0.333333333333;

    size_t dequantBytes() const {
        return code.size() * sizeof(int8_t) + scale.size() * sizeof(float);
    }
    // Honest packed cost for the SAME information: ceil(log2(levels)) bits of
    // code plus an fp16 scale amortised over the group.
    double packedBitsPerElem() const {
        const double codeBits = std::ceil(std::log2(double(levels > 1 ? levels : 2)));
        return codeBits + 16.0 / double(groupSize);
    }
};

Base quantize(const std::vector<float>& w, int rows, int cols,
              int groupSize, int levels, double deadband) {
    Base b;
    b.rows = rows; b.cols = cols; b.groupSize = groupSize; b.levels = levels;
    b.deadband = deadband;
    b.groups = cols / groupSize;
    b.code.assign(size_t(rows) * cols, 0);
    b.scale.assign(size_t(rows) * b.groups, 0.0f);

    // Levels and the SELECTION RULE are defined separately, because for the
    // published single point they must be:
    //     decision boundary at |v| = deadband, representative values at +/-1.
    //
    // That is a CLIPPED quantizer, not a uniform one, and conflating the two is
    // what made CONTROL 0 fail twice. Nearest-level assignment over
    // {-deadband, 0, +deadband, ...} puts the boundary at the midpoint between
    // adjacent representatives -- 0.5 for a 3-level set -- regardless of where
    // the representatives sit. The other lane thresholds at 1/3 with
    // representatives at +/-1. Only an explicit decision rule reproduces that.
    b.level.assign(size_t(levels), 0.0f);
    const int mid = levels / 2;
    const int half = (levels - 1) / 2;
    const int lo   = (levels - 1) - half;
    b.level[size_t(mid)] = 0.0f;
    for (int i = 1; i <= half; ++i) {
        b.level[size_t(mid + i)] =
            static_cast<float>(deadband + (double(i) / double(half ? half : 1)) * (1.0 - deadband));
    }
    for (int i = 1; i <= lo; ++i) {
        b.level[size_t(mid - i)] =
            static_cast<float>(-(deadband + (double(i) / double(lo ? lo : 1)) * (1.0 - deadband)));
    }

    for (int r = 0; r < rows; ++r) {
        for (int g = 0; g < b.groups; ++g) {
            const int c0 = g * groupSize;
            float amax = 0.0f;
            for (int k = 0; k < groupSize; ++k)
                amax = std::max(amax, std::fabs(w[size_t(r) * cols + c0 + k]));
            const float s = (amax > 0.0f) ? amax : 1.0f;
            b.scale[size_t(r) * b.groups + g] = s;
            for (int k = 0; k < groupSize; ++k) {
                const size_t i = size_t(r) * cols + c0 + k;
                const double v = double(w[i]) / double(s);        // [-1, 1]
                int code;
                if (v >= deadband) {
                    const double f = (v - deadband) / (1.0 - deadband);
                    int kk = int(f * double(half));
                    if (kk >= half) kk = half - 1;
                    if (kk < 0) kk = 0;
                    code = mid + 1 + kk;
                } else if (v <= -deadband) {
                    const double f = (-deadband - v) / (1.0 - deadband);
                    int kk = int(f * double(lo));
                    if (kk >= lo) kk = lo - 1;
                    if (kk < 0) kk = 0;
                    code = mid - 1 - kk;
                } else {
                    code = mid;
                }
                b.code[i] = static_cast<int8_t>(code);
            }
        }
    }
    return b;
}

float dequantAt(const Base& b, size_t i) {
    const int r = int(i / size_t(b.cols));
    const int c = int(i % size_t(b.cols));
    const int g = c / b.groupSize;
    return float(b.level[size_t(b.code[i])]) * b.scale[size_t(r) * b.groups + g];
}

// ------------------------------------------------------------- measurements
double relL2(const std::vector<float>& a, const std::vector<float>& ref) {
    double n = 0.0, d = 0.0;
    for (size_t i = 0; i < a.size(); ++i) {
        const double t = double(a[i]) - double(ref[i]);
        n += t * t; d += double(ref[i]) * double(ref[i]);
    }
    return d > 0.0 ? std::sqrt(n / d) : 0.0;
}

// Order-0 entropy of the group-normalised delta, in bits per element.
//
// This is the quantity the previous receipt said was missing. It is an UPPER
// BOUND on what any order-0 coder achieves and a LOWER bound is not claimed:
// entropy here is computed over a 256-bin histogram of the int8-normalised
// delta, so it measures symbol-level compressibility and says NOTHING about
// structure a higher-order model could exploit. A high number here therefore
// does not prove the delta is incompressible -- it proves order-0 cannot help.
// That distinction is the whole reason this measurement is reported with its
// method attached.
double deltaEntropyBitsPerElem(const std::vector<float>& dW,
                               const std::vector<float>& groupScale,
                               const std::vector<float>& groupAmax,
                               int rows, int cols, int groupSize, int groups) {
    std::vector<std::uint64_t> hist(256, 0);
    std::uint64_t total = 0;
    for (int r = 0; r < rows; ++r) {
        for (int c = 0; c < cols; ++c) {
            const int g = c / groupSize;
            const float am = groupAmax[size_t(r) * groups + g];
            if (!(am > 0.0f)) { ++total; continue; }
            double v = double(dW[size_t(r) * cols + c]) / double(am);   // ~[-1,1]
            int q = int(std::lround(v * 127.0));
            if (q < -128) q = -128;
            if (q > 127) q = 127;
            ++hist[size_t(q + 128)];
            ++total;
        }
    }
    if (total == 0) return 0.0;
    double h = 0.0;
    for (std::uint64_t c : hist) {
        if (c == 0) continue;
        const double p = double(c) / double(total);
        h -= p * (std::log2(p));
    }
    return h;
}

struct Row {
    int levels, groupSize;
    double deadband;
    double packedBaseBits;
    double baseRelL2;
    double deltaL1Ratio;
    double deltaEntropyBits;
    double sparsity;        // fraction |dW| < 1% of group amax
    double combinedBits;    // packedBaseBits + entropy
    bool  breaksEven;       // combinedBits < 32
};

}  // namespace

int main() {
    std::printf("RAWRXD_RESIDUAL_OVERLAY_SWEEP_001\n");
    std::printf("SCOPE=FIND_PARETO_FRONTIER_AND_MEASURE_DELTA_COMPRESSIBILITY\n");
    std::printf("DOES_NOT_PROVE=MODEL_QUALITY_GPU_RESIDENCY_ANY_IO_BEHAVIOUR\n");
    std::printf("ORIGINAL_BITS_PER_ELEM=%.1f (fp32 reference)\n", kOrigBits);
    std::printf("ROWS=%d COLS=%d\n\n", kRows, kCols);

    // SEED AND DRAW ORDER ARE PART OF THE CONTROL, NOT A STYLE CHOICE.
    //
    // An earlier revision used its own seed and compared its statistics against
    // the other lane's published numbers. DELTA_MAGNITUDE_RATIO agreed to 0.001
    // -- it is a stable aggregate -- while BASE_ONLY_REL_L2 was off by 0.076,
    // because rel_L2 on a SPECIFIC 64x256 draw is sample-specific. The control
    // was comparing two different datasets and nearly passed for the wrong
    // reason. Reproducing the exact seed and draw order is what makes the
    // comparison a test of the QUANTIZER rather than of the RNG.
    std::mt19937 rng(12345u);            // identical to the published harness
    std::normal_distribution<float> gauss(0.0f, 1.0f);

    std::vector<float> W(size_t(kRows) * kCols);
    std::vector<float> x;
    x.resize(size_t(kCols));
    for (auto& v : W) v = gauss(rng);
    for (auto& v : x) v = gauss(rng);

    std::vector<float> yRef(size_t(kRows), 0.0f);
    for (int r = 0; r < kRows; ++r) {
        float acc = 0.0f;
        for (int c = 0; c < kCols; ++c) acc += W[size_t(r) * kCols + c] * x[size_t(c)];
        yRef[size_t(r)] = acc;
    }

    // group amax for the entropy/sparsity metrics, at the FINEST group used in
    // the sweep so metrics are comparable across rows.
    const int refGroup = 32, refGroups = kCols / refGroup;
    std::vector<float> gAmax(size_t(kRows) * refGroups, 0.0f);
    for (int r = 0; r < kRows; ++r)
        for (int g = 0; g < refGroups; ++g)
            for (int k = 0; k < refGroup; ++k)
                gAmax[size_t(r) * refGroups + g] = std::max(
                    gAmax[size_t(r) * refGroups + g],
                    std::fabs(W[size_t(r) * kCols + g * refGroup + k]));

    // ------------------------------------------------------------------
    // CONTROL 0 -- cross-validate against the other lane's published point.
    // If this does not reproduce exactly, every number below is void.
    // ------------------------------------------------------------------
    {
        // Their harness: ternary {+1,0,-1}, int8 code, fp32 scale per 32,
        // threshold 1/3. Reproduced here as a 3-level quantizer whose zero cell
        // has half-width 1/3 -- which IS their rule exactly, given identical
        // nearest-level assignment.
        const Base b3 = quantize(W, kRows, kCols, 32, 3, 1.0 / 3.0);
        std::vector<float> y(size_t(kRows), 0.0f);
        std::vector<float> dW(W.size());
        for (int r = 0; r < kRows; ++r) {
            float acc = 0.0f;
            for (int c = 0; c < kCols; ++c) {
                const float wq = dequantAt(b3, size_t(r) * kCols + c);
                dW[size_t(r) * kCols + c] = W[size_t(r) * kCols + c] - wq;
                acc += wq * x[size_t(c)];
            }
            y[size_t(r)] = acc;
        }
        double num = 0.0, den = 0.0;
        for (size_t i = 0; i < W.size(); ++i) {
            num += std::fabs(double(dW[i]));
            den += std::fabs(double(W[i]));
        }
        const double ratio = den > 0.0 ? num / den : 0.0;
        const double l2 = relL2(y, yRef);

        std::printf("--- CONTROL 0: cross-validation vs published single point ---\n");
        std::printf("PUBLISHED_BASE_ONLY_REL_L2      = 0.734019\n");
        std::printf("MEASURED_BASE_ONLY_REL_L2       = %.6f\n", l2);
        std::printf("PUBLISHED_DELTA_MAGNITUDE_RATIO = 0.786882\n");
        std::printf("MEASURED_DELTA_MAGNITUDE_RATIO  = %.6f\n", ratio);
        const bool okL2    = std::fabs(l2 - 0.734019) < 5e-5;
        const bool okRatio = std::fabs(ratio - 0.786882) < 5e-5;
        std::printf("CROSS_VALIDATION_MATCH=%d\n", (okL2 && okRatio) ? 1 : 0);
        std::printf("\n");
        if (!okL2 || !okRatio) {
            std::printf("VOID: the sweep's quantizer does not reproduce the published\n"
                        "single point, so nothing below is comparable to it.\n"
                        "FINAL_VERDICT=FAIL\n");
            return 1;
        }
    }

    // ------------------------------------------------------------------
    // THE SWEEP
    // ------------------------------------------------------------------
    // levels=2 is EXCLUDED and that exclusion is load-bearing. A 2-level codebook
    // cannot represent zero, so the deadband decision rule has no middle cell to
    // fall into and emits codes outside the level range. The first sweep run
    // included it and reported base_relL2 = 1.17e25 -- not a measurement of a bad
    // quantizer, but an out-of-range index reading past the end of a small
    // vector. A degenerate configuration must be SKIPPED, not reported: an
    // absurd number that looks like a result is worse than no number.
    std::uint64_t g_skipped = 0;
    const int    levelOpts[]   = {3, 4, 5, 8, 16};
    const int    groupOpts[]   = {16, 32, 64, 128, 256};
    const double deadbandOpts[] = {1.0 / 3.0, 0.45, 0.55};
    const double breakEvenBits = kOrigBits;

    std::vector<Row> rows;

    for (int L : levelOpts) {
      for (int G : groupOpts) {
        if (G > kCols) continue;
        for (double db : deadbandOpts) {
            const int _half = (L - 1) / 2, _lo = (L - 1) - _half;
            if (_half == 0 || _lo == 0) continue;   // degenerate codebook
            const Base b = quantize(W, kRows, kCols, G, L, db);

            std::vector<float> y(size_t(kRows), 0.0f);
            std::vector<float> dW(W.size());
            for (int r = 0; r < kRows; ++r) {
                float acc = 0.0f;
                for (int c = 0; c < kCols; ++c) {
                    const float wq = dequantAt(b, size_t(r) * kCols + c);
                    dW[size_t(r) * kCols + c] = W[size_t(r) * kCols + c] - wq;
                    acc += wq * x[size_t(c)];
                }
                y[size_t(r)] = acc;
            }

            double num = 0.0, den = 0.0;
            for (size_t i = 0; i < W.size(); ++i) {
                num += std::fabs(double(dW[i]));
                den += std::fabs(double(W[i]));
            }
            const double l1ratio = den > 0.0 ? num / den : 0.0;

            // sparsity against the reference grouping
            const int groups = kCols / refGroup;
            std::uint64_t nearZero = 0;
            for (int r = 0; r < kRows; ++r)
                for (int c = 0; c < kCols; ++c) {
                    const int g = c / refGroup;
                    const float am = gAmax[size_t(r) * groups + g];
                    if (!(am > 0.0f)) { ++nearZero; continue; }
                    if (std::fabs(double(dW[size_t(r) * kCols + c])) < 0.01 * double(am))
                        ++nearZero;
                }
            const double sparsity = double(nearZero) / double(W.size());

            // entropy with the group scales this row actually used
            const int bGroups = kCols / G;
            std::vector<float> gscale(size_t(kRows) * bGroups, 0.0f);
            std::vector<float> gam(size_t(kRows) * bGroups, 0.0f);
            for (int r = 0; r < kRows; ++r)
                for (int g = 0; g < bGroups; ++g) {
                    float am = 0.0f;
                    for (int k = 0; k < G; ++k)
                        am = std::max(am, std::fabs(W[size_t(r) * kCols + g * G + k]));
                    gam[size_t(r) * bGroups + g] = am;
                    gscale[size_t(r) * bGroups + g] = am;
                }
            const double ent = deltaEntropyBitsPerElem(dW, gscale, gam,
                                                       kRows, kCols, G, bGroups);

            Row row{};
            row.levels = L;
            row.groupSize = G;
            row.deadband = db;
            row.packedBaseBits = b.packedBitsPerElem();
            row.baseRelL2 = relL2(y, yRef);
            row.deltaL1Ratio = l1ratio;
            row.deltaEntropyBits = ent;
            row.sparsity = sparsity;
            row.combinedBits = row.packedBaseBits + ent;
            // A base that produces non-finite output is a broken configuration,
            // not a data point. Reported as skipped rather than averaged in.
            if (!std::isfinite(row.baseRelL2) || row.baseRelL2 > 1e6) {
                ++g_skipped;
                continue;
            }
            row.breaksEven = row.combinedBits < breakEvenBits;
            rows.push_back(row);
        }
    }
    }

    // ------------------------------------------------------------------
    // REPORT
    // ------------------------------------------------------------------
    std::printf("--- Pareto frontier: cheapest COMBINED bits at each accuracy tier ---\n");
    std::printf("%-8s %-7s %-9s %-11s %-12s %-13s %-8s %-8s %s\n",
                "levels", "group", "deadband", "base_bits", "base_relL2",
                "delta_ent_b", "sparse%", "comb_bits", "BREAKS_EVEN");
    for (const Row& r : rows) {
        std::printf("%-8d %-7d %-9.3f %-11.3f %-12.6f %-13.4f %-8.2f %-8.3f %s\n",
                    r.levels, r.groupSize, r.deadband, r.packedBaseBits, r.baseRelL2,
                    r.deltaEntropyBits, r.sparsity * 100.0, r.combinedBits,
                    r.breaksEven ? "YES" : "no");
    }

    // tiers
    struct Tier { const char* name; double maxL2; };
    const Tier tiers[] = {{"relL2<=0.10", 0.10},
                          {"relL2<=0.05", 0.05},
                          {"relL2<=0.02", 0.02}};
    std::printf("\n--- cheapest configuration meeting each accuracy tier ---\n");
    for (const Tier& t : tiers) {
        const Row* best = nullptr;
        for (const Row& r : rows)
            if (r.baseRelL2 <= t.maxL2 && (!best || r.combinedBits < best->combinedBits))
                best = &r;
        if (!best) {
            std::printf("%-12s : NO CONFIGURATION REACHES THIS TIER\n", t.name);
            continue;
        }
        std::printf("%-12s : levels=%-3d group=%-4d db=%.2f base_bits=%.3f "
                    "combined_bits=%.3f delta_entropy=%.4f sparse=%.1f%% "
                    "break_even=%s\n",
                    t.name, best->levels, best->groupSize, best->deadband,
                    best->packedBaseBits,
                    best->combinedBits, best->deltaEntropyBits,
                    best->sparsity * 100.0, best->breaksEven ? "YES" : "no");
    }

    // The question that actually decides low_rank_delta vs sparse_delta.
    std::printf("\n--- is the delta sparse? (sparse_delta viability) ---\n");
    const Row* ternary = nullptr;
    const Row* bestQ4  = nullptr;
    for (const Row& r : rows) {
        if (r.levels == 3 && r.groupSize == 32 && !ternary) ternary = &r;
        if (r.levels == 16 && r.groupSize == 64 && !bestQ4)  bestQ4  = &r;
    }
    if (ternary)
        std::printf("TERNARY(3,32): delta_entropy=%.4f b/elem sparse(<1%% amax)=%.2f%% "
                    "l1_ratio=%.6f\n",
                    ternary->deltaEntropyBits, ternary->sparsity * 100.0,
                    ternary->deltaL1Ratio);
    if (bestQ4)
        std::printf("Q4LIKE(16,64): delta_entropy=%.4f b/elem sparse(<1%% amax)=%.2f%% "
                    "l1_ratio=%.6f\n",
                    bestQ4->deltaEntropyBits, bestQ4->sparsity * 100.0,
                    bestQ4->deltaL1Ratio);

    std::printf("\nENTROPY_METHOD=order0_histogram_of_group_normalised_delta_int8\n");
    std::printf("ENTROPY_LIMITATION=order0_upper_bound;_a_high_value_does_NOT_prove_"
                "incompressibility\n");

    // Verdict computed, never asserted.
    bool anyBreaksEven = false, anyTier02 = false, anyTier05 = false;
    for (const Row& r : rows) {
        if (r.breaksEven) anyBreaksEven = true;
        if (r.baseRelL2 <= 0.02) anyTier02 = true;
        if (r.baseRelL2 <= 0.05) anyTier05 = true;
    }
    std::printf("\n--- SUMMARY (derived) ---\n");
    std::printf("SWEEP_CONFIGS=%zu\n", rows.size());
    std::printf("SWEEP_CONFIGS_SKIPPED=%llu\n", (unsigned long long)g_skipped);
    std::printf("ANY_BREAKS_EVEN=%d\n", anyBreaksEven ? 1 : 0);
    std::printf("REACHES_REL_L2_0.05=%d\n", anyTier05 ? 1 : 0);
    std::printf("REACHES_REL_L2_0.02=%d\n", anyTier02 ? 1 : 0);
    std::printf("CROSS_VALIDATION_MATCH=1\n");   // guarded above by early return
    const bool verdict = anyBreaksEven;
    std::printf("BREAK_EVEN_BASE_EXISTS=%d\n", verdict ? 1 : 0);
    std::printf("FINAL_VERDICT=%s\n", verdict ? "BREAK_EVEN_EXISTS" : "NO_BREAK_EVEN");
    return 0;
}
