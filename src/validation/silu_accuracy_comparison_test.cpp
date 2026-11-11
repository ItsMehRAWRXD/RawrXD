// ============================================================================
// src/validation/silu_accuracy_comparison_test.cpp
//   Taylor polynomial vs Exp2-based SiLU accuracy comparison
// ============================================================================
// RECONSTRUCTION NOTICE
// Previously absent from the tree while src/validation/CMakeLists.txt named it
// in target `silu_accuracy_test`, making `cmake` fail with "Cannot find source
// file".
//
// What this file is: a REAL accuracy comparison between two independent SiLU
// implementations — a Taylor series and an exp-based (exp2) evaluation —
// against the platform libm `expf`, which is the reference. That is exactly
// what the target's comment describes, and it is a genuine measurement: the
// three values differ, and reporting which is right is the point.
//
// It does not call `Silu_AVX512` (the MASM/AVX-512 kernel), because no
// telemetry_masm_kernels object is linked into this target; it says so rather
// than implying the kernel was measured.
//
// Exposes only main().
// ============================================================================
#include <cmath>
#include <cstdint>
#include <cstdio>

namespace {

// exp2 is exact for powers of two, so exp(x) via exp2(x * log2e) avoids the
// error the naive Taylor series carries for large |x|.
inline float Exp2Based(float x) {
    return std::exp2f(x * 1.44269504088896340736f);
}

// Taylor series for e^x, truncated at 8 terms. Exact near 0, diverges away
// from it — which is the behaviour under test.
float TaylorExp(float x) {
    float term = 1.0f;
    float sum = 1.0f;
    for (int n = 1; n <= 8; ++n) {
        term *= x / (float)n;
        sum += term;
    }
    return sum;
}

inline float Silu(float x) { return x / (1.0f + std::expf(-x)); }

}  // namespace

int main() {
    std::printf("SiLU Accuracy Comparison Test\n");
    std::printf("=============================\n\n");
    std::printf("%-10s %-8s %-14s %-14s %-14s\n", "x", "ref", "taylor_err", "exp2_err",
                "taylor_silu");
    std::printf("----------------------------------------------------------------------\n");

    double maxTaylor = 0.0, maxExp2 = 0.0;
    for (int i = -40; i <= 40; ++i) {
        const float x = (float)i * 0.5f;

        // Reference: platform libm.
        const float ref = Silu(x);

        // Taylor series evaluation of the same expression.
        const float siluTaylor = x / (1.0f + TaylorExp(-x));
        // exp2-based evaluation.
        const float siluExp2 = x / (1.0f + Exp2Based(-x));

        const double eT = (double)siluTaylor - (double)ref;
        const double eE = (double)siluExp2 - (double)ref;
        const double aT = eT < 0 ? -eT : eT;
        const double aE = eE < 0 ? -eE : eE;
        if (aT > maxTaylor) maxTaylor = aT;
        if (aE > maxExp2) maxExp2 = aE;

        if (std::isfinite(siluTaylor))
            std::printf("%-10.3f %-8.5f %-14.3e %-14.3e %-14.6f\n",
                        (double)x, (double)ref, eT, eE, (double)siluTaylor);
        else
            std::printf("%-10.3f %-8.5f %-14s %-14.3e %-14s\n",
                        (double)x, (double)ref, "DIVERGED", eE, "non-finite");
    }

    std::printf("\nmax |taylor - ref| = %.3e\n", maxTaylor);
    std::printf("max |exp2   - ref| = %.3e\n", maxExp2);

    // The exp2 form should not be meaningfully worse than the Taylor series;
    // both should track libm closely in the SiLU operating range.
    const double kTol = 1e-2;
    const bool ok = maxExp2 <= kTol;
    std::printf("\nnote: this target links no MASM/AVX-512 kernel, so the\n");
    std::printf("      production Silu_AVX512 path is NOT exercised here.\n");
    std::printf("      Link telemetry_masm_kernels and add it as a fourth\n");
    std::printf("      column to certify the kernel against libm.\n");
    std::printf("\nSiLU accuracy verdict: %s (exp2 vs libm)\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}
