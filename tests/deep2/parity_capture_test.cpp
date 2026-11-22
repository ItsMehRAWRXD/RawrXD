// ============================================================================
// parity_capture_test.cpp  --  Sprint 9 P0-01 / P0-02 unit test
// ============================================================================
// Dependency-free acceptance test for src/deep2/ParityCapture.hpp.
//
// It verifies the capture CONTRACT and the comparison MATH with synthetic data,
// including an INJECTED numerical mismatch (the "first-divergence detection
// verified with injected numerical mismatch" gate), malformed inputs, and
// non-finite fail-closed behaviour. It links nothing beyond the standard
// library, so it builds and runs without a model or the executor.
// ============================================================================
#include "deep2/ParityCapture.hpp"

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <string>
#include <vector>

namespace PC = RawrXD::Deep2::Parity;

static int g_failures = 0;
static int g_checks = 0;

static void Check(bool cond, const std::string& what) {
    ++g_checks;
    if (!cond) {
        ++g_failures;
        std::printf("FAIL: %s\n", what.c_str());
    } else {
        std::printf("ok  : %s\n", what.c_str());
    }
}

static bool Near(double got, double want, double eps = 1e-12) {
    return std::abs(got - want) <= eps;
}

int main() {
    using PC::Compare;
    using PC::CompareSamples;
    using PC::FirstDivergence;
    using PC::ParityCapture;
    using PC::TensorSample;
    using PC::Tolerance;

    // ---- 1. Identical buffers are equivalent --------------------------------
    {
        std::vector<float> a = {0.5f, -1.25f, 3.0f, 0.0f, 42.0f};
        ParityCapture cap = Compare(a, a, /*layer=*/2, /*position=*/7,
                                    /*operation=*/11);
        Check(cap.valid, "identical: valid");
        Check(cap.Equivalent(), "identical: Equivalent()");
        Check(Near(cap.maxAbsError, 0.0), "identical: maxAbs==0");
        Check(Near(cap.maxRelError, 0.0), "identical: maxRel==0");
        Check(Near(cap.rmsError, 0.0), "identical: rms==0");
        Check(cap.firstMismatchIndex == a.size(),
              "identical: firstMismatchIndex==elementCount");
        Check(cap.layer == 2 && cap.position == 7 && cap.operation == 11,
              "identical: coordinates copied through");
    }

    // ---- 2. Single injected mismatch: exact aggregate math ------------------
    // reference = {1,2,3,4}, candidate = {1,2,3.5,4}
    //   absErr = {0,0,0.5,0}; scale={1,2,3.5,4}; relErr={0,0,0.5/3.5,0}
    //   rms = sqrt(0.5^2 / 4)
    {
        std::vector<float> ref = {1.0f, 2.0f, 3.0f, 4.0f};
        std::vector<float> cand = {1.0f, 2.0f, 3.5f, 4.0f};
        Tolerance tol; // absTol=1e-4, relTol=1e-3 -> index 2 diverges
        ParityCapture cap = Compare(ref, cand, 0, 5, 99, tol);
        Check(cap.valid, "injected: valid");
        Check(cap.hasMismatch, "injected: hasMismatch");
        Check(cap.firstMismatchIndex == 2, "injected: firstMismatchIndex==2");
        Check(Near(cap.maxAbsError, 0.5), "injected: maxAbs==0.5");
        Check(Near(cap.maxRelError, 0.5 / 3.5), "injected: maxRel==0.5/3.5");
        Check(cap.hasWorstRelative && cap.worstRelativeIndex == 2,
              "injected: worst-relative index==2");
        Check(Near(cap.worstReference, 3.0) && Near(cap.worstCandidate, 3.5),
              "injected: worst-relative operands preserved");
        Check(Near(cap.worstAbsoluteError, 0.5) &&
              Near(cap.worstRelativeError, 0.5 / 3.5),
              "injected: worst-relative metrics preserved");
        Check(Near(cap.rmsError, std::sqrt(0.25 / 4.0)),
              "injected: rms==sqrt(0.25/4)");
        Check(!cap.Equivalent(), "injected: not Equivalent");
    }

    // ---- 3. Relative error with a zero reference element --------------------
    // reference 0.0 vs candidate 1.0 -> absErr=1, scale=1, relErr=1.
    {
        std::vector<float> ref = {0.0f};
        std::vector<float> cand = {1.0f};
        ParityCapture cap = Compare(ref, cand, 0, 0, 0);
        Check(cap.valid, "zero-ref: valid");
        Check(Near(cap.maxRelError, 1.0), "zero-ref: maxRel==1");
        Check(cap.firstMismatchIndex == 0, "zero-ref: firstMismatch==0");
    }

    // ---- 4. Both-zero element is NOT a mismatch -----------------------------
    {
        std::vector<float> ref = {0.0f};
        std::vector<float> cand = {0.0f};
        ParityCapture cap = Compare(ref, cand, 0, 0, 0);
        Check(cap.valid && cap.Equivalent(),
              "both-zero: valid and Equivalent (relErr==0)");
    }

    // ---- 5. Tolerance boundary: within tol is OK ----------------------------
    // absErr == absTol exactly must NOT be a mismatch (strictly greater fails).
    // Values exactly representable in float keep the boundary deterministic.
    {
        std::vector<float> r = {2.0f};
        std::vector<float> c = {2.5f};
        Tolerance t2; t2.absTol = 0.5; t2.relTol = 0.0;
        ParityCapture cap = Compare(r, c, 0, 0, 0, t2);
        Check(cap.valid && cap.Equivalent(),
              "boundary: absErr==absTol is within tolerance");
        // Just over the boundary IS a mismatch.
        std::vector<float> c2 = {2.5001f};
        ParityCapture cap2 = Compare(r, c2, 0, 0, 0, t2);
        Check(cap2.valid && cap2.hasMismatch,
              "boundary: absErr>absTol is a mismatch");
    }

    // ---- 6. Size mismatch is invalid, never a pass --------------------------
    {
        std::vector<float> ref = {1.0f, 2.0f};
        std::vector<float> cand = {1.0f};
        ParityCapture cap = Compare(ref, cand, 0, 0, 0);
        Check(!cap.valid, "size-mismatch: invalid");
        Check(!cap.Equivalent(), "size-mismatch: not Equivalent");
    }

    // ---- 7. Empty buffers are invalid ---------------------------------------
    {
        std::vector<float> empty;
        ParityCapture cap = Compare(empty, empty, 0, 0, 0);
        Check(!cap.valid, "empty: invalid");
    }

    // ---- 8. Non-finite operand fails closed ---------------------------------
    {
        const float inf = std::numeric_limits<float>::infinity();
        const float nan = std::numeric_limits<float>::quiet_NaN();
        std::vector<float> ref = {1.0f, inf, 3.0f};
        std::vector<float> cand = {1.0f, 2.0f, 3.0f};
        ParityCapture cap = Compare(ref, cand, 0, 0, 0);
        Check(!cap.valid, "non-finite(inf): invalid");
        Check(!cap.Equivalent(), "non-finite(inf): not Equivalent");
        Check(cap.hasNonFinite && cap.nonFiniteIndex == 1,
              "non-finite(inf): index surfaced");

        std::vector<float> ref2 = {1.0f, nan, 3.0f};
        ParityCapture cap2 = Compare(ref2, cand, 0, 0, 0);
        Check(!cap2.valid, "non-finite(nan): invalid");
    }

    // ---- 9. Invalid tolerance fails closed ----------------------------------
    {
        std::vector<float> r = {1.0f};
        std::vector<float> c = {1.0f};
        Tolerance bad; bad.absTol = -1.0;
        ParityCapture cap = Compare(r, c, 0, 0, 0, bad);
        Check(!cap.valid, "negative absTol: invalid");

        Tolerance bad2; bad2.relTol = std::numeric_limits<double>::infinity();
        ParityCapture cap2 = Compare(r, c, 0, 0, 0, bad2);
        Check(!cap2.valid, "infinite relTol: invalid");
    }

    // ---- 10. FirstDivergence convenience index ------------------------------
    {
        std::vector<float> ref = {1.0f, 2.0f, 3.0f, 4.0f};
        std::vector<float> cand = {1.0f, 2.0f, 9.0f, 4.0f};
        std::uint64_t idx = FirstDivergence(ref.data(), cand.data(), ref.size());
        Check(idx == 2, "FirstDivergence: returns 2");

        std::vector<float> same = ref;
        std::uint64_t idx2 = FirstDivergence(ref.data(), same.data(), ref.size());
        Check(idx2 == ref.size(), "FirstDivergence: returns n when equal");

        std::uint64_t idx3 = FirstDivergence(nullptr, nullptr, 0);
        Check(idx3 == 0, "FirstDivergence: null/0 returns 0 (n)");
    }

    // ---- 11. Op-sequence first divergence across layers ---------------------
    // reference: layer0 ok, layer1 ok, layer2 divergent.
    // candidate: layer0 ok, layer1 ok, layer2 divergent at element 3.
    // The FIRST divergent sample must be reported, with its full record.
    {
        std::vector<TensorSample> ref = {
            {0, 0, 0, "attn_norm", {1.0f, 2.0f}},
            {1, 0, 0, "attn_norm", {1.0f, 2.0f}},
            {2, 0, 0, "ffn_down", {1.0f, 2.0f, 3.0f}},
        };
        std::vector<TensorSample> cand = ref;
        cand[2].values = {1.0f, 2.0f, 3.5f}; // inject at layer2 element2

        PC::Divergence d = CompareSamples(ref, cand);
        Check(d.valid, "samples: structurally valid");
        Check(d.diverged, "samples: diverged");
        Check(d.sampleIndex == 2, "samples: first divergent sample index==2");
        Check(d.capture.layer == 2, "samples: capture.layer==2");
        Check(d.capture.firstMismatchIndex == 2,
              "samples: capture.firstMismatchIndex==2");
    }

    // ---- 12. Equivalent op-sequences report no divergence -------------------
    {
        std::vector<TensorSample> ref = {
            {0, 0, 0, "a", {1.0f, 2.0f}},
            {0, 1, 0, "a", {3.0f, 4.0f}},
        };
        PC::Divergence d = CompareSamples(ref, ref);
        Check(d.valid, "samples-equal: valid");
        Check(!d.diverged, "samples-equal: not diverged");
        Check(d.sampleIndex == ref.size(),
              "samples-equal: sampleIndex==size");
    }

    // ---- 13. Sample count mismatch is invalid but localises prefix ----------
    {
        std::vector<TensorSample> ref = {
            {0, 0, 0, "a", {1.0f}},
            {0, 1, 0, "a", {2.0f}},
        };
        std::vector<TensorSample> cand = {
            {0, 0, 0, "a", {1.0f}},
        };
        PC::Divergence d = CompareSamples(ref, cand);
        Check(!d.valid, "samples-count: invalid");
        Check(d.reason.find("sample count mismatch") != std::string::npos,
              "samples-count: reason names the mismatch");
        Check(d.sampleIndex == 1, "samples-count: sampleIndex==common prefix");
    }

    // ---- 14. Describe() never crashes on invalid capture --------------------
    {
        ParityCapture cap; // default invalid
        std::string s = PC::Describe(cap);
        Check(s.find("valid=false") != std::string::npos,
              "Describe: invalid capture summarized");
    }

    // ---- summary ------------------------------------------------------------
    std::printf("\n==== parity_capture_test: %d checks, %d failures ====\n",
                g_checks, g_failures);
    if (g_failures == 0) {
        std::printf("PARITY_CAPTURE_TEST=PASS\n");
        return 0;
    }
    std::printf("PARITY_CAPTURE_TEST=FAIL\n");
    return 1;
}
