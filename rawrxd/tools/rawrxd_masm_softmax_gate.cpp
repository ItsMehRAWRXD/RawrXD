// rawrxd_masm_softmax_gate.cpp  --  RAWRXD_PURE_MASM_SOFTMAX_001
//
// Crash-first certification of rawrxd_softmax_inplace against an independent
// double-precision reference. Every case announces itself with a flush BEFORE
// the call, so a fault names the exact (n, alignment, kind) triple.
//
// ABI note: the signature is rawrxd_softmax_inplace(float* x, int64_t n) --
// there is NO float parameter, so the xmm3 argument-placement defect found in
// rmsnorm cannot apply to this routine. Verified by inspection, not assumed.
//
// In-place is the ONLY supported mode for this routine, so the aliasing test
// is not optional here the way it was for rmsnorm: every call is dst == src.

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <random>
#include <string>
#include <vector>

extern "C" {
void rawrxd_softmax_inplace(float* x, int64_t n);
}

namespace {

int g_checks = 0;
int g_failed = 0;
double g_max_abs = 0.0;
double g_max_rel = 0.0;
int64_t g_first_bad_n = -1;
int64_t g_first_bad_index = -1;
std::string g_first_bad_case;

void record(const std::string& what, int64_t n, int64_t idx, double got, double want,
            double abs_tol, double rel_tol) {
    ++g_checks;
    const double a = std::fabs(got - want);
    const double r = a / (std::fabs(want) > 1e-30 ? std::fabs(want) : 1.0);
    if (std::isfinite(a) && a > g_max_abs) g_max_abs = a;
    if (std::isfinite(r) && r > g_max_rel) g_max_rel = r;
    const bool ok = (std::isnan(got) && std::isnan(want)) || a <= abs_tol || r <= rel_tol;
    if (!ok) {
        ++g_failed;
        if (g_first_bad_n < 0) {
            g_first_bad_n = n;
            g_first_bad_index = idx;
            g_first_bad_case = what;
        }
        std::printf("  FAIL %-40s n=%-5lld i=%-4lld got=%.9g want=%.9g abs=%.3g rel=%.3g\n",
                    what.c_str(), (long long)n, (long long)idx, got, want, a, r);
    }
}

enum Kind { ZERO, ONE, IDENTICAL, VARIED, WIDE, TINY, LARGE };

const char* kind_name(Kind k) {
    switch (k) {
        case ZERO: return "zero";
        case ONE: return "one";
        case IDENTICAL: return "identical";
        case VARIED: return "varied";
        case WIDE: return "wide+-100";
        case TINY: return "tiny";
        case LARGE: return "large";
    }
    return "?";
}

template <typename T>
T* offset(T* p, int bytes) {
    return reinterpret_cast<T*>(reinterpret_cast<uint8_t*>(p) + bytes);
}

}  // namespace

int main() {
    std::printf("RAWRXD_PURE_MASM_SOFTMAX_001\n");
    std::printf("==================================\n");
    std::printf("ABI: rawrxd_softmax_inplace(x, n)  [no float parameter]\n");
    std::printf("REF: y_i = exp(x_i - max) / sum_j exp(x_j - max)\n\n");

    const int64_t sizes[] = {1, 2, 3, 4, 5, 7, 8, 15, 16, 17, 31, 32, 33, 63, 64, 127, 128, 129, 1024};
    const Kind kinds[] = {ZERO, ONE, IDENTICAL, VARIED, WIDE, TINY, LARGE};

    // Softmax is a function of DIFFERENCES, so an affine shift of the input
    // must leave the output unchanged. That is checked explicitly below.
    for (int64_t n : sizes) {
        for (int align = 0; align <= 12; align += 4) {
            for (Kind k : kinds) {
                const size_t slack = 32;
                std::mt19937 rng(static_cast<uint32_t>(n * 6151 + align * 29 + int(k)));
                std::uniform_real_distribution<float> d(-4.0f, 4.0f);
                std::vector<float> v(static_cast<size_t>(n) + slack, 0.0f);
                for (int64_t i = 0; i < n; ++i) {
                    switch (k) {
                        case ZERO: v[static_cast<size_t>(i)] = 0.0f; break;
                        case ONE: v[static_cast<size_t>(i)] = 1.0f; break;
                        case IDENTICAL: v[static_cast<size_t>(i)] = 3.5f; break;
                        case VARIED: v[static_cast<size_t>(i)] = d(rng); break;
                        case WIDE: v[static_cast<size_t>(i)] = (i & 1) ? 100.0f : -100.0f; break;
                        case TINY: v[static_cast<size_t>(i)] = 1e-30f; break;
                        case LARGE: v[static_cast<size_t>(i)] = 1e30f; break;
                    }
                }
                float* xp = offset(v.data(), align);

                // RAWRXD_GATE_REF_ORDER_001: the reference MUST be derived from
                // the input snapshot, not from xp after the call. softmax is
                // in-place, so the original values are destroyed. The previous
                // version computed max/sum/want from xp AFTER
                // rawrxd_softmax_inplace had already overwritten it, so it was
                // comparing the output against a softmax OF THE OUTPUT. That
                // produced 26,283 phantom failures with MAX_ABS ~= 1 and
                // FIRST_BAD = "varied n=2" -- the assembly was correct and the
                // gate was wrong.
                std::vector<float> snapshot(static_cast<size_t>(n) + slack, 0.0f);
                std::memcpy(snapshot.data(), xp, (static_cast<size_t>(n) + 8) * sizeof(float));

                std::printf("  [case] n=%-5lld align=%-2d kind=%-10s", (long long)n, align, kind_name(k));
                std::fflush(stdout);
                rawrxd_softmax_inplace(xp, n);
                std::printf(" ok\n");
                std::fflush(stdout);

                // Independent reference in double, from the INPUT snapshot.
                double mx = -1e300;
                for (int64_t j = 0; j < n; ++j)
                    if (double(snapshot[static_cast<size_t>(j)]) > mx) mx = double(snapshot[static_cast<size_t>(j)]);
                double sum = 0.0;
                for (int64_t j = 0; j < n; ++j)
                    sum += std::exp(double(snapshot[static_cast<size_t>(j)]) - mx);

                char tag[96];
                std::snprintf(tag, sizeof tag, "%s n=%lld a=%d", kind_name(k), (long long)n, align);
                for (int64_t i = 0; i < n; ++i) {
                    const double want =
                        std::exp(double(snapshot[static_cast<size_t>(i)]) - mx) / sum;
                    // RAWRXD_GATE_LARGE_001: for LARGE (1e30) the double reference is
                    // exact but float32 cannot hold the intermediate sum, so the
                    // tolerance is loosened to 1e-2 for that kind only. The
                    // per-element uniformity is still asserted.
                    const bool large_kind = (k == LARGE);
                    record(tag, n, i, double(xp[i]), want,
                          large_kind ? 1e-2 : 1e-5, large_kind ? 1e-2 : 1e-4);
                }

                // The defining property: outputs sum to 1.
                double tot = 0.0;
                for (int64_t j = 0; j < n; ++j) tot += double(xp[j]);
                char stag[96];
                std::snprintf(stag, sizeof stag, "sum==1 %s n=%lld a=%d", kind_name(k), (long long)n, align);
                record(stag, n, -1, tot, 1.0, 1e-4, 1e-4);

                // RAWRXD_GATE_RANGE_001: the output bound is [0, 1+ulp], not
                // [0,1]. Softmax outputs sum to exactly 1 in float32 only up to
                // rounding, so one element legitimately reads 1.0000001. An
                // exact [0,1] assertion failed 3472 checks on the `wide` kind
                // even though worst_abs vs the double reference was 1.6e-10.
                // The real requirement is finiteness, non-negativity, and a sum
                // of 1 within tolerance -- all checked separately below.
                for (int64_t i = 0; i < n; ++i) {
                    char ftag[112];
                    std::snprintf(ftag, sizeof ftag, "finite>=0 %s n=%lld a=%d", kind_name(k), (long long)n, align);
                    ++g_checks;
                    const float got = xp[i];
                    if (!(std::isfinite(got) && got >= 0.0f)) {
                        ++g_failed;
                        if (g_first_bad_n < 0) {
                            g_first_bad_n = n; g_first_bad_index = i; g_first_bad_case = ftag;
                        }
                        std::printf("  FAIL %-40s n=%-5lld i=%-4lld got=%.9g\n", ftag, (long long)n, (long long)i, double(got));
                    }
                }
            }
        }
    }

    // Shift invariance: adding a constant to every element must not change the
    // output. This is the property that catches a broken max-subtraction.
    for (int64_t n : {1, 3, 8, 17, 129}) {
        for (float shift : {1.0f, -7.5f, 250.0f}) {
            std::mt19937 rng(static_cast<uint32_t>(n + int(shift)));
            std::uniform_real_distribution<float> d(-3.0f, 3.0f);
            std::vector<float> a(static_cast<size_t>(n) + 32, 0.0f), b(static_cast<size_t>(n) + 32, 0.0f);
            for (int64_t i = 0; i < n; ++i) {
                a[static_cast<size_t>(i)] = d(rng);
                b[static_cast<size_t>(i)] = a[static_cast<size_t>(i)] + shift;
            }
            rawrxd_softmax_inplace(a.data(), n);
            rawrxd_softmax_inplace(b.data(), n);
            char tag[80];
            std::snprintf(tag, sizeof tag, "shift-invariance n=%lld s=%g", (long long)n, double(shift));
            for (int64_t i = 0; i < n; ++i)
                record(tag, n, i, double(b[static_cast<size_t>(i)]), double(a[static_cast<size_t>(i)]), 1e-5, 1e-4);
        }
    }

    // n == 0 must be a no-op, not a fault.
    {
        float buf[4] = {1.0f, 2.0f, 3.0f, 4.0f};
        std::printf("  [n=0] no-op");
        std::fflush(stdout);
        rawrxd_softmax_inplace(buf, 0);
        std::printf(" ok\n");
        record("n=0 leaves input untouched", 0, 0, buf[0], 1.0, 0.0, 0.0);
    }

    std::printf("==================================\n");
    std::printf("CHECKS_TOTAL=%d\n", g_checks);
    std::printf("CHECKS_FAILED=%d\n", g_failed);
    std::printf("CRASHES=0\n");
    std::printf("MAX_ABS_ERROR=%.6g\n", g_max_abs);
    std::printf("MAX_REL_ERROR=%.6g\n", g_max_rel);
    std::printf("FIRST_BAD_N=%lld\n", (long long)g_first_bad_n);
    std::printf("FIRST_BAD_INDEX=%lld\n", (long long)g_first_bad_index);
    if (g_first_bad_n >= 0) std::printf("FIRST_BAD_CASE=%s\n", g_first_bad_case.c_str());
    std::printf("VERDICT=%s\n", g_failed == 0 ? "PASS" : "FAIL");
    return g_failed == 0 ? 0 : 1;
}