// rawrxd_softmax_stage_trace.cpp  --  RAWRXD_PURE_MASM_SOFTMAX_TRACE_001
//
// Stage-by-stage trace of rawrxd_softmax_inplace for the FIRST FAILING
// varied n=2 case, reproducing the softmax gate's exact RNG stream so the same
// input that fails there fails here.
//
// n=2 is the ideal discriminator: after max subtraction one exponent is
// exactly exp(0) = 1, so a single correct/incorrect value at each stage
// localizes the fault to one side of the exp -> sum -> reciprocal -> multiply
// boundary.
//
// For n=2 with x0 > x1:  d0 = 0, d1 = x1-x0, e0 = 1, e1 = exp(d1),
//   sum = 1 + e1, out0 = 1/sum, out1 = e1/sum.
// With x1 > x0 the roles swap.

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <random>
#include <vector>

extern "C" {
void  rawrxd_softmax_inplace(float* x, int64_t n);
float rawrxd_expf_scalar(float x);
float rawrxd_max_f32(const float* x, int64_t n);
float rawrxd_sum_f32(const float* x, int64_t n);
}

namespace {

// Same generator/sequence as the gate: uniform_real_distribution<float>(-4,4).
std::vector<float> varied_pair() {
    std::mt19937 rng(2u * 6151u + 0u * 29u + 3u);   // n=2, align=0, kind index 3
    std::uniform_real_distribution<float> d(-4.0f, 4.0f);
    std::vector<float> v(2 + 32, 0.0f);
    v[0] = d(rng);
    v[1] = d(rng);
    return v;
}

}  // namespace

int main() {
    std::printf("RAWRXD_PURE_MASM_SOFTMAX_TRACE_001\n");
    std::printf("===================================\n");

    auto v = varied_pair();
    const float x0 = v[0], x1 = v[1];
    std::printf("input      x0=%.9g  x1=%.9g\n", double(x0), double(x1));

    // ---- stage 1: max ----
    const float mx_asm = rawrxd_max_f32(v.data(), 2);
    const float mx_ref = x0 > x1 ? x0 : x1;
    std::printf("max        asm=%.9g  ref=%.9g  %s\n",
                double(mx_asm), double(mx_ref), mx_asm == mx_ref ? "OK" : "*** MISMATCH ***");

    // ---- stage 2: max subtraction ----
    const float d0 = x0 - mx_asm, d1 = x1 - mx_asm;
    const float r0 = x0 - mx_ref, r1 = x1 - mx_ref;
    std::printf("d0=%.9g (ref %.9g)   d1=%.9g (ref %.9g)\n",
                double(d0), double(r0), double(d1), double(r1));
    std::printf("max(d0,d1)=%.9g  -> one exponent must be exactly 1.0f\n",
                double(d0 > d1 ? d0 : d1));

    // ---- stage 3: exp ----
    const float e0 = rawrxd_expf_scalar(d0);
    const float e1 = rawrxd_expf_scalar(d1);
    const double E0 = std::exp(double(r0)), E1 = std::exp(double(r1));
    std::printf("exp(d0) asm=%.9g  ref=%.9g   %s\n", double(e0), E0,
                (e0 == 1.0f) ? "OK (exactly 1)" : "*** NOT 1.0f ***");
    std::printf("exp(d1) asm=%.9g  ref=%.9g   absdiff=%.3g\n", double(e1), E1,
                std::fabs(double(e1) - E1));

    // ---- stage 4: sum ----
    std::vector<float> es = {e0, e1};
    const float sum_asm = rawrxd_sum_f32(es.data(), 2);
    const double sum_ref = E0 + E1;
    std::printf("sum        asm=%.9g  ref=%.9g   %s\n", double(sum_asm), sum_ref,
                sum_asm >= 1.0f ? "OK (>=1)" : "*** < 1 ***");

    // ---- stage 5: full routine ----
    auto w = v;
    rawrxd_softmax_inplace(w.data(), 2);
    const double out0_ref = E0 / sum_ref, out1_ref = E1 / sum_ref;
    std::printf("\nsoftmax_inplace:\n");
    std::printf("  out0 asm=%.9g  ref=%.9g  absdiff=%.4g\n", double(w[0]), out0_ref,
                std::fabs(double(w[0]) - out0_ref));
    std::printf("  out1 asm=%.9g  ref=%.9g  absdiff=%.4g\n", double(w[1]), out1_ref,
                std::fabs(double(w[1]) - out1_ref));
    std::printf("  out0+out1 asm=%.9g  (expect 1)\n", double(w[0]) + double(w[1]));

    // ---- invariant checklist ----
    std::printf("\nINVARIANTS\n");
    int bad = 0;
    #define CHK(cond, label) do { \
        const int ok_ = (cond) ? 1 : 0; \
        if (!ok_) ++bad; \
        std::printf("  %-34s %s\n", label, ok_ ? "PASS" : "FAIL"); \
    } while (0)
    CHK(mx_asm == mx_ref,                     "max selected correctly");
    CHK((d0 == 0.0f) || (d1 == 0.0f),         "one d is exactly 0");
    CHK(e0 == 1.0f || e1 == 1.0f,            "winning exponent is exactly 1.0f");
    CHK(std::isfinite(e0) && std::isfinite(e1), "both exponents finite");
    CHK(e0 >= 0.0f && e1 >= 0.0f,             "exponents non-negative");
    CHK(sum_asm >= 1.0f,                      "sum >= 1");
    CHK(w[0] >= 0.0f && w[0] <= 1.0f,         "out0 in [0,1]");
    CHK(w[1] >= 0.0f && w[1] <= 1.0f,         "out1 in [0,1]");
    CHK(std::fabs((double(w[0]) + double(w[1])) - 1.0) < 1e-5, "out0+out1 == 1");
    #undef CHK

    std::printf("\nSTAGE_FAULT=%s\n",
        bad == 0 ? "NONE (this case passes; fault is elsewhere)"
                 : (mx_asm != mx_ref ? "MAX_SELECTION"
                  : (e0 != 1.0f && e1 != 1.0f ? "EXP_ACCURACY"
                     : (sum_asm < 1.0f ? "SUM" : "NORMALIZE"))));
    return 0;
}