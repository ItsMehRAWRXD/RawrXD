// ============================================================================
// residual_overlay_fusion_001.cpp
// RAWRXD_RESIDUAL_OVERLAY_FUSION_001 -- proof kernel for fused base+residual.
//
// SCOPE, STATED UP FRONT SO THE RECEIPT CANNOT OVERCLAIM
//   Proves: that a base-quant matvec and an optional FP16 delta matvec-add
//           compose correctly, and that a missing/deadline-missed residual
//           degrades to base-only WITHOUT stalling or faulting.
//   Does NOT prove: model quality, Kimi viability, that residuals are cheap,
//                   or that the architecture works at any scale.
//
// HONESTY NOTES BAKED INTO THIS FILE (read before trusting any PASS)
//   1. MODE_C and MODE_D are TAUTOLOGIES, not tests.
//      The kernel is `if (resident && data && !deadline_missed) apply; else skip`.
//      Therefore base-only output and missing-residual output are EQUAL BY
//      CONSTRUCTION, with bitwise-identical fp32 results. Reporting
//      BASE_OUTPUT_EQUALS_MISSING_RESIDUAL_OUTPUT=1 as a *pass* would be a
//      self-certifying gate. It is reported as a tautology, always 1, and
//      carries zero evidential weight. The real risk in these modes is a CRASH,
//      which is why CRASH_FREE is the only field that means anything.
//   2. MODE_B's "matches reference" is near-tautological too, BY LINEARITY:
//      y_ref = (dequant(Wb) + dW) * x == dequant(Wb)*x + dW*x exactly, in exact
//      arithmetic. So it tests that the residual was APPLIED and that index
//      mapping is not transposed. That is worth having. It does NOT test the idea.
//   3. The measurement that actually bears on the proposal is BASE_ONLY_REL_L2
//      and DELTA_MAGNITUDE_RATIO. Both are reported below. Both are expected to
//      be bad. That is the point of running it.
//
// WHY THIS EXISTS AT ALL
//   A prior audit measured the real weight distribution and found plane 0 at
//   6.17% ones (49.5% zeros), so a "1.5-bit ternary" base is really a sparse
//   pattern, and measured rel_L2 at the tensor level was ~0.33. That is not a
//   rounding error. This harness quantifies what a full-precision delta must
//   therefore carry to undo it, per element, without any I/O involved. If the
//   delta ratio approaches 1.0, the decomposition relabels bytes rather than
//   saving them, and the architecture is not a compression scheme.
//
// Build (no engine, no Vulkan, no deps):
//   cl /std:c++17 /EHsc /O2 residual_overlay_fusion_001.cpp /Fe:residual_fusion.exe
// ============================================================================

#include <cstdio>
#include <cstdint>
#include <cmath>
#include <cstdlib>
#include <vector>
#include <string>
#include <algorithm>
#include <random>

namespace {

constexpr int    kRows      = 64;
constexpr int    kCols      = 256;
constexpr int    kGroupSize = 32;          // scales per group of elements
constexpr int    kGroups    = kCols / kGroupSize;
constexpr double kBitsBase  = 1.5;         // nominal; ternary levels {-1,0,+1}
// Threshold as a fraction of the per-group max. The density this produces is
// MEASURED at runtime and printed -- it is not assumed to match any real tensor.
constexpr double kTernaryThreshold = 0.3333333;
// Reference only, from the prior RAWRXD bit-plane audit. NOT an assertion about
// this harness: printed so a reader can compare regimes explicitly.
constexpr double kPlane0AuditDensity = 0.061733;

// ---------------------------------------------------------------- metrics
double relL2(const std::vector<float>& a, const std::vector<float>& b) {
    double num = 0.0, den = 0.0;
    for (size_t i = 0; i < a.size(); ++i) {
        const double d = double(a[i]) - double(b[i]);
        num += d * d;
        den += double(b[i]) * double(b[i]);
    }
    if (den == 0.0) return num == 0.0 ? 0.0 : INFINITY;
    return std::sqrt(num / den);
}

double maxAbsDiff(const std::vector<float>& a, const std::vector<float>& b) {
    double m = 0.0;
    for (size_t i = 0; i < a.size(); ++i)
        m = std::max(m, std::fabs(double(a[i]) - double(b[i])));
    return m;
}

bool allFinite(const std::vector<float>& v) {
    for (float x : v) if (!std::isfinite(x)) return false;
    return true;
}

// ---------------------------------------------------------------- base quant
// Ternary {+1,0,-1} with one fp32 scale per group. This mirrors what a real
// low-bit MoE weight quantizer does: group-wise scale, then threshold to levels.
struct BaseQuantTensor {
    std::vector<int8_t>  q;        // ternary levels
    std::vector<float>   scale;    // one per group, per ROW (rows are independent)
    int rows = 0, cols = 0;
    // Measured, not assumed. The density the quantizer ACTUALLY achieved is
    // recorded here and printed. An earlier version of this file carried a
    // comment claiming the 1/3 threshold "matches the measured ~6% nonzero
    // density of a real plane 0" -- that was asserted from the audit and never
    // derived from this code. With Gaussian weights and s = max|w| per 32-sample
    // group, s sits near 2.5 sigma, so P(|w| > s/3) is materially higher than 6%.
    // The realized density is now measured and reported so DELTA_MAGNITUDE_RATIO
    // can be read against what the quantizer actually did.
    double realizedNonzeroDensity = 0.0;
    double realizedPosDensity    = 0.0;
    double threshold             = 0.0;

    size_t bytes() const {
        return q.size() * sizeof(int8_t) + scale.size() * sizeof(float);
    }
};

BaseQuantTensor quantizeTernary(const std::vector<float>& w, int rows, int cols) {
    BaseQuantTensor t; t.rows = rows; t.cols = cols;
    t.q.assign(size_t(rows) * cols, 0);
    t.scale.assign(size_t(rows) * kGroups, 0.0f);
    t.threshold = kTernaryThreshold;

    for (int r = 0; r < rows; ++r) {
        for (int g = 0; g < kGroups; ++g) {
            const int c0 = g * kGroupSize;
            float amax = 0.0f;
            for (int k = 0; k < kGroupSize; ++k)
                amax = std::max(amax, std::fabs(w[size_t(r) * cols + c0 + k]));
            const float s = (amax > 0.0f) ? amax : 1.0f;
            t.scale[size_t(r) * kGroups + g] = s;
            for (int k = 0; k < kGroupSize; ++k) {
                const size_t i = size_t(r) * cols + c0 + k;
                const float v = w[i] / s;                       // in [-1,1]
                // threshold relative to the group max => sparse ternary
                t.q[i] = (v >  kTernaryThreshold) ? int8_t( 1)
                       : (v < -kTernaryThreshold) ? int8_t(-1)
                       :                            int8_t( 0);
            }
        }
    }
    return t;
}

void measureRealizedDensity(BaseQuantTensor& t) {
    size_t nz = 0, pos = 0;
    for (int8_t v : t.q) {
        if (v != 0) ++nz;
        if (v >  0) ++pos;
    }
    const double n = double(t.q.size());
    t.realizedNonzeroDensity = (n > 0.0) ? double(nz) / n : 0.0;
    t.realizedPosDensity    = (n > 0.0) ? double(pos) / n : 0.0;
}

float dequantAt(const BaseQuantTensor& t, size_t i) {
    const int r = int(i / size_t(t.cols));
    const int c = int(i % size_t(t.cols));
    const int g = c / kGroupSize;
    return float(t.q[i]) * t.scale[size_t(r) * kGroups + g];
}

// y[row] = sum_c W[row][c] * x[c]   (fp32, sequential accumulation)
void baseQuantMatVec(const BaseQuantTensor& t, const std::vector<float>& x,
                     std::vector<float>& y) {
    y.assign(size_t(t.rows), 0.0f);
    for (int r = 0; r < t.rows; ++r) {
        float acc = 0.0f;
        for (int c = 0; c < t.cols; ++c)
            acc += dequantAt(t, size_t(r) * t.cols + c) * x[size_t(c)];
        y[size_t(r)] = acc;
    }
}

// y += dW * x   (dW stored row-major fp32 == "FP16 full delta, proof only")
void residualDeltaMatVecAdd(const std::vector<float>& dW,
                            const std::vector<float>& x,
                            std::vector<float>& y) {
    const int cols = int(x.size());
    for (size_t i = 0; i < dW.size(); i += size_t(cols)) {
        const int r = int(i / size_t(cols));
        float acc = 0.0f;
        int c = 0;
        for (c = 0; c < cols; ++c)
            acc += dW[i + size_t(c)] * x[size_t(c)];
        y[size_t(c % kRows)] += acc;                 // <-- CORRUPTED: lands on wrong rows
    }
}

// ------------------------------------------------------------- overlay view
struct ResidualOverlayView {
    const void* data       = nullptr;
    size_t      bytes      = 0;
    bool        resident   = false;
    bool        deadline_missed = false;
    uint64_t    generation = 0;
};

struct FusionReceipt {
    bool     base_executed            = false;
    bool     residual_applied         = false;
    bool     residual_deadline_missed = false;
    uint64_t residual_bytes           = 0;
};

// THE KERNEL UNDER TEST. Base path is mandatory; residual is optional and a
// miss is NOT fatal. This is the whole contract.
void fused_base_residual_matvec(const BaseQuantTensor& base,
                                const ResidualOverlayView& residual,
                                const std::vector<float>& x,
                                std::vector<float>& y,
                                int rows, int cols,
                                FusionReceipt& receipt)
{
    receipt.base_executed = true;

    baseQuantMatVec(base, x, y);                       // always runs

    if (residual.resident && residual.data && !residual.deadline_missed) {
        const float* d = static_cast<const float*>(residual.data);
        residualDeltaMatVecAdd(std::vector<float>(d, d + size_t(rows) * cols), x, y);
        receipt.residual_applied  = true;
        receipt.residual_bytes    = residual.bytes;
    } else {
        receipt.residual_applied         = false;
        receipt.residual_deadline_missed = residual.deadline_missed;
    }
}

// --------------------------------------------------------------- reference
std::vector<float> referenceMatVec(const std::vector<float>& W,
                                   const std::vector<float>& x) {
    std::vector<float> y(size_t(kRows), 0.0f);
    for (int r = 0; r < kRows; ++r) {
        float acc = 0.0f;
        for (int c = 0; c < kCols; ++c)
            acc += W[size_t(r) * kCols + c] * x[size_t(c)];
        y[size_t(r)] = acc;
    }
    return y;
}

int g_crashFree = 1;
std::vector<float> runMode(const BaseQuantTensor& base,
                           const std::vector<float>& dW,
                           const std::vector<float>& x,
                           bool resident, bool deadlineMissed,
                           FusionReceipt& rec)
{
    ResidualOverlayView v;
    v.data            = resident ? static_cast<const void*>(dW.data()) : nullptr;
    v.bytes           = dW.size() * sizeof(float);
    v.resident        = resident;
    v.deadline_missed = deadlineMissed;
    v.generation      = 7;
    std::vector<float> y;
    fused_base_residual_matvec(base, v, x, y, kRows, kCols, rec);
    if (!allFinite(y)) g_crashFree = 0;
    return y;
}

} // namespace

int main() {
    std::mt19937 rng(12345u);                       // fixed seed: reproducibility
    std::normal_distribution<float> gauss(0.0f, 1.0f);

    // --- inputs
    std::vector<float> W(size_t(kRows) * kCols);
    // Most-vexing-parse fix, done correctly.
    //   BAD  : std::vector<float> x(size_t(kCols));   -> declares a FUNCTION
    //   BAD  : std::vector<float> x{size_t(kCols)};   -> initializer_list ctor,
    //                                                      gives ONE element
    //   GOOD : explicit resize(), whose intent cannot be misparsed
    std::vector<float> x;
    x.resize(size_t(kCols));
    // RAWRXD_RESIDUAL_OVERLAY_FUSION_001: size guards.
    // Both failure modes already occurred in this file's history and each looked
    // like a value error rather than a shape error:
    //   (a) x(size_t(kCols))          -> most vexing parse, FUNCTION, no vector
    //   (b) x{size_t(kCols)}         -> initializer_list ctor, ONE element
    // (b) compiles and runs; it just produces a wrong-shaped vector. That is the
    // dangerous one, so the shape is asserted rather than assumed.
    if (x.size() != size_t(kCols)) {
        std::fprintf(stderr, "FATAL: x.size()=%zu expected=%zu\n",
                     x.size(), size_t(kCols));
        return 2;
    }
    for (auto& v : W) v = gauss(rng);
    for (auto& v : x) v = gauss(rng);

    // --- quantize, then build the FULL-PRECISION delta that would be required
    BaseQuantTensor base = quantizeTernary(W, kRows, kCols);
    measureRealizedDensity(base);
    std::vector<float> dW;
    dW.resize(W.size());
    if (dW.size() != W.size()) {
        std::fprintf(stderr, "FATAL: dW.size()=%zu expected=%zu\n",
                     dW.size(), W.size());
        return 2;
    }
    double numMag = 0.0, denMag = 0.0;
    for (size_t i = 0; i < W.size(); ++i) {
        dW[i] = W[i] - dequantAt(base, i);
        numMag += std::fabs(double(dW[i]));
        denMag += std::fabs(double(W[i]));
    }
    const double deltaRatio = denMag > 0.0 ? numMag / denMag : 0.0;

    const std::vector<float> yRef = referenceMatVec(W, x);

    // --- modes
    FusionReceipt rA, rB, rC, rD;
    const std::vector<float> yA = runMode(base, dW, x, false, false, rA);
    const std::vector<float> yB = runMode(base, dW, x, true,  false, rB);
    const std::vector<float> yC = runMode(base, dW, x, false, false, rC);
    const std::vector<float> yD = runMode(base, dW, x, true,  true,  rD);

    const double baseOnlyRelL2 = relL2(yA, yRef);
    const double residRelL2    = relL2(yB, yRef);
    const double residMaxAbs   = maxAbsDiff(yB, yRef);
    // TAUTOLOGY -- equal by construction, carries no evidential weight
    const bool    cEqualsA     = (yC == yA);
    const bool    dEqualsA     = (yD == yA);

    const bool baseFinite      = allFinite(yA);
    const bool residApplied    = rB.residual_applied;
    const bool baseExecutedAll = rA.base_executed && rB.base_executed &&
                                 rC.base_executed && rD.base_executed;
    const bool noFault         = (g_crashFree == 1);
    const bool residMatch      = (residRelL2 < 1e-5);

    // RAWRXD_RESIDUAL_OVERLAY_FUSION_001 -- third negative probe.
    // Blocks the fake-pass where the residual branch never contributes at all:
    // if yB == yA then "matches reference" would be vacuously true whenever the
    // base happened to match, and residRelL2 would be measuring nothing.
    // This asserts the residual path is live BEFORE residMatch is believed.
    const bool residDiffersFromBase = (yB != yA);
    const double residDeltaRelL2    = relL2(yB, yA);   // magnitude of the add
    const bool residContributes     = residDiffersFromBase && residDeltaRelL2 > 0.0;

    std::printf("RAWRXD_RESIDUAL_OVERLAY_FUSION_001\n");
    std::printf("SCOPE=PROVE_FUSION_AND_BOUNDED_DEGRADATION\n");
    std::printf("DOES_NOT_PROVE=MODEL_QUALITY_SCALE_ECONOMICS\n");
    std::printf("\n");
    std::printf("ROWS=%d\nCOLS=%d\nGROUP_SIZE=%d\n", kRows, kCols, kGroupSize);
    std::printf("BASE_QUANT_BITS=%.1f\n", kBitsBase);
    std::printf("BASE_BYTES=%zu\n", base.bytes());
    std::printf("RESIDUAL_FORMAT=FP16_FULL_DELTA_PROOF_ONLY\n");
    std::printf("RESIDUAL_BYTES=%zu\n", dW.size() * sizeof(float));

    // the decisive numbers for the architecture question
    std::printf("\n");
    std::printf("--- architecture-relevant measurements ---\n");
    std::printf("BASE_ONLY_REL_L2=%.6f\n", baseOnlyRelL2);
    std::printf("DELTA_MAGNITUDE_RATIO=%.6f\n", deltaRatio);
    std::printf("DELTA_NOTE=ratio_near_1_means_decomposition_saves_nothing\n");
    std::printf("BASE_OVERHEAD_BYTES_PER_ELEMENT=%.4f\n",
                double(base.bytes()) / double(W.size()));
    std::printf("BASE_EXPECTED_BYTES_PER_ELEMENT=%.4f_1BIT_PLUS_FP32_PER_32\n", 0.25);

    // Density is MEASURED here, not assumed. See BaseQuantTensor's comment: an
    // earlier version claimed the 1/3 threshold reproduced the audit's 6.17%
    // plane-0 density. It does not, and asserting it would have made
    // DELTA_MAGNITUDE_RATIO uninterpretable against the audit it cites.
    std::printf("\n");
    std::printf("--- realized quantization density (measured) ---\n");
    std::printf("BASE_QUANT_THRESHOLD_FRAC_OF_GROUPMAX=%.6f\n", base.threshold);
    std::printf("BASE_REALIZED_NONZERO_DENSITY=%.6f\n", base.realizedNonzeroDensity);
    std::printf("BASE_REALIZED_POSITIVE_DENSITY=%.6f\n", base.realizedPosDensity);
    std::printf("PLANE0_AUDIT_REFERENCE_DENSITY=%.6f_REFERENCE_ONLY\n",
                kPlane0AuditDensity);
    std::printf("DENSITY_REGIME_MATCHES_AUDIT=%d\n",
                (int)(std::fabs(base.realizedNonzeroDensity -
                                kPlane0AuditDensity) < 0.05));
    std::printf("DENSITY_NOTE=synthetic_gaussian_group_max_scaling_differs_from_real_tensor\n");

    std::printf("\n");
    std::printf("--- mode results ---\n");
    std::printf("MODE_A_BASE_EXECUTED=%d\n", (int)rA.base_executed);
    std::printf("MODE_B_RESIDUAL_APPLIED=%d\n", (int)rB.residual_applied);
    std::printf("MODE_C_RESIDUAL_APPLIED=%d\n", (int)rC.residual_applied);
    std::printf("MODE_D_RESIDUAL_APPLIED=%d\n", (int)rD.residual_applied);
    std::printf("MODE_D_DEADLINE_MISS_RECORDED=%d\n", (int)rD.residual_deadline_missed);
    std::printf("BASE_EXECUTED_ALL_MODES=%d\n", (int)baseExecutedAll);
    std::printf("CRASH_FREE_ALL_MODES=%d\n", (int)noFault);

    std::printf("\n");
    std::printf("--- evidence (weighted) ---\n");
    std::printf("BASE_ONLY_FINITE=%d\n", (int)baseFinite);
    std::printf("RESIDENT_RESIDUAL_MATCHES_REFERENCE=%d\n", (int)residMatch);
    std::printf("REFERENCE_MATCH_REL_L2=%.3e\n", residRelL2);
    std::printf("REFERENCE_MATCH_MAX_ABS=%.3e\n", residMaxAbs);

    std::printf("\n");
    std::printf("--- residual-liveness probe (prevents vacuous reference match) ---\n");
    std::printf("MISSING_RESIDUAL_OUTPUT_EQUALS_BASE_ONLY=%d\n", (int)cEqualsA);
    std::printf("RESIDENT_RESIDUAL_OUTPUT_DIFFERS_FROM_BASE_ONLY=%d\n",
                (int)residDiffersFromBase);
    std::printf("RESIDUAL_DELTA_REL_L2=%.6f\n", residDeltaRelL2);
    std::printf("RESIDUAL_PATH_CONTRIBUTES=%d\n", (int)residContributes);

    std::printf("\n");
    std::printf("--- TAUTOLOGIES (reported, NOT scored) ---\n");
    std::printf("MODE_C_EQUALS_MODE_A=%d_TAUTOLOGY_NO_WEIGHT\n", (int)cEqualsA);
    std::printf("MODE_D_EQUALS_MODE_A=%d_TAUTOLOGY_NO_WEIGHT\n", (int)dEqualsA);

    std::printf("\n");
    std::printf("--- vector shape guards ---\n");
    std::printf("VECTOR_X_SIZE=%zu_EXPECTED=%zu\n", x.size(), size_t(kCols));
    std::printf("VECTOR_X_SIZE_CHECK=%d\n", (int)(x.size() == size_t(kCols)));
    std::printf("VECTOR_DW_SIZE=%zu_EXPECTED=%zu\n", dW.size(), W.size());
    std::printf("VECTOR_DW_SIZE_CHECK=%d\n", (int)(dW.size() == W.size()));

    std::printf("\n");
    const bool verdict = (baseFinite && baseExecutedAll && noFault &&
                          residMatch && residContributes);
    std::printf("FUSION_SEMANTICS_VERIFIED=%d\n", (int)verdict);
    std::printf("ARCHITECTURE_ECONOMICS_ESTABLISHED=0\n");
    std::printf("FINAL_VERDICT=%s\n", verdict ? "PASS" : "FAIL");
    return verdict ? 0 : 1;
}