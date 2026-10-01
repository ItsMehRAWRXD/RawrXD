// rawrxd_masm_rmsnorm_gate.cpp  --  RAWRXD_PURE_MASM_RMSNORM_001
//
// Crash-first certification of rawrxd_rmsnorm against an independent scalar
// double-precision reference. Every case announces itself on stdout with a
// flush BEFORE the call, so if the process faults the last line printed names
// the exact (n, alignment, input-kind) triple that crashed. That converts an
// access violation into a located defect rather than an exit code.
//
// ABI note: the routine under test is
//     void rawrxd_rmsnorm(float* out, const float* x, int64_t n, float eps)
// i.e. WEIGHTLESS. The reference here is therefore
//     rms  = sqrt( (1/n) * sum_j x_j^2 + eps )
//     y_i  = x_i / rms
// A weight term x_i*w_i is NOT part of this ABI and is not tested.
//
// In-place aliasing (out == x) is tested explicitly: the statistic is computed
// before the transform, so it must be safe, and an implementation that writes
// output before reading the corresponding input would corrupt it.

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <random>
#include <string>
#include <vector>

extern "C" {
void rawrxd_rmsnorm(float* out, const float* x, int64_t n, float eps);
}

namespace {

int g_checks = 0;
int g_failed = 0;
int g_crashes = 0;
double g_max_abs = 0.0;
double g_max_rel = 0.0;
int64_t g_first_bad_n = -1;
int64_t g_first_bad_index = -1;
std::string g_first_bad_case;

// Mixed absolute/relative tolerance: a pure relative test manufactures
// failures on values whose reference is ~0, and a pure absolute test is blind
// on large values.
bool within(double got, double want, double abs_tol, double rel_tol) {
    if (std::isnan(got) && std::isnan(want)) return true;
    if (std::isinf(got) || std::isinf(want)) return got == want;
    const double a = std::fabs(got - want);
    if (a <= abs_tol) return true;
    const double r = a / (std::fabs(want) > 1e-30 ? std::fabs(want) : 1.0);
    return r <= rel_tol;
}

void record(const std::string& what, int64_t n, int64_t idx, double got, double want,
            double abs_tol, double rel_tol) {
    ++g_checks;
    const double a = std::fabs(got - want);
    const double r = a / (std::fabs(want) > 1e-30 ? std::fabs(want) : 1.0);
    if (a > g_max_abs && std::isfinite(a)) g_max_abs = a;
    if (r > g_max_rel && std::isfinite(r)) g_max_rel = r;
    if (!within(got, want, abs_tol, rel_tol)) {
        ++g_failed;
        if (g_first_bad_n < 0) {
            g_first_bad_n = n;
            g_first_bad_index = idx;
            g_first_bad_case = what;
        }
        std::printf("  FAIL %-46s n=%-5lld i=%-4lld got=%.9g want=%.9g abs=%.3g rel=%.3g\n",
                    what.c_str(), (long long)n, (long long)idx, got, want, a, r);
    }
}

enum Kind { ZERO, ONE, ALT, VARIED, TINY, LARGE };

const char* kind_name(Kind k) {
    switch (k) {
        case ZERO: return "zero";
        case ONE: return "one";
        case ALT: return "alt+-1";
        case VARIED: return "varied";
        case TINY: return "tiny";
        case LARGE: return "large";
    }
    return "?";
}

std::vector<float> make_input(Kind k, size_t n, std::mt19937& rng) {
    std::vector<float> v(n);
    std::uniform_real_distribution<float> d(-2.0f, 2.0f);
    for (size_t i = 0; i < n; ++i) {
        switch (k) {
            case ZERO: v[i] = 0.0f; break;
            case ONE: v[i] = 1.0f; break;
            case ALT: v[i] = (i & 1) ? 1.0f : -1.0f; break;
            case VARIED: v[i] = d(rng); break;
            case TINY: v[i] = 1e-20f; break;
            case LARGE: v[i] = 1e20f; break;
        }
    }
    return v;
}

template <typename T>
T* offset(T* p, int bytes) {
    return reinterpret_cast<T*>(reinterpret_cast<uint8_t*>(p) + bytes);
}

}  // namespace

int main() {
    std::printf("RAWRXD_PURE_MASM_RMSNORM_001\n");
    std::printf("===================================\n");
    std::printf("ABI: rawrxd_rmsnorm(out, x, n, eps)  [weightless]\n");
    std::printf("REF: rms = sqrt(sum(x^2)/n + eps); y = x/rms\n\n");

    const int64_t sizes[] = {1, 2, 3, 7, 8, 15, 16, 17, 31, 32, 127, 128, 129, 4096};
    const Kind kinds[] = {ZERO, ONE, ALT, VARIED, TINY, LARGE};
    const float eps = 1e-5f;

    for (int64_t n : sizes) {
        for (int align = 0; align <= 12; align += 4) {
            for (Kind k : kinds) {
                std::mt19937 rng(static_cast<uint32_t>(n * 7919 + align * 13 + int(k)));
                // RAWRXD_GATE_SRC_PADDING_001: the SOURCE needs the same slack.
                // Only the destination was padded at first, so a=8/a=12 read up
                // to 3 floats past the end of x and the reference was computed
                // from uninitialized memory. That made the failure count vary
                // between runs (3, then 9) with a fixed seed.
                const size_t slack = 32;
                auto x = make_input(k, static_cast<size_t>(n) + slack, rng);
                std::vector<float> out(static_cast<size_t>(n) + slack, -777.0f);

                float* xp = offset(x.data(), align);
                float* op = offset(out.data(), align);

                // Announce before the call: if this faults, the line above is
                // the located crash vector.
                std::printf("  [case] n=%-5lld align=%-2d kind=%-8s", (long long)n, align, kind_name(k));
                std::fflush(stdout);
                rawrxd_rmsnorm(op, xp, n, eps);
                std::printf(" ok\n");
                std::fflush(stdout);

                // Independent double-precision reference.
                double ss = 0.0;
                for (int64_t j = 0; j < n; ++j) ss += double(xp[j]) * double(xp[j]);
                const double rms = std::sqrt(ss / double(n) + double(eps));

                char tag[96];
                std::snprintf(tag, sizeof tag, "%s n=%lld a=%d", kind_name(k), (long long)n, align);

                // LARGE overflows a float32 accumulator (x^2 = 1e40) where the
                // double reference does not; that divergence is reported, not
                // hidden behind a loose tolerance.
                const double abs_tol = (k == LARGE) ? 1e30 : 1e-5;
                const double rel_tol = (k == LARGE) ? 1e30 : 1e-4;

                for (int64_t i = 0; i < n; ++i) {
                    const double want = double(xp[i]) / rms;
                    record(tag, n, i, double(op[i]), want, abs_tol, rel_tol);
                }
            }
        }
    }

    // In-place aliasing: out == src must be safe because the statistic is
    // computed before any output write.
    for (int64_t n : {1, 3, 8, 17, 129}) {
        std::mt19937 rng(static_cast<uint32_t>(n));
        auto v = make_input(VARIED, static_cast<size_t>(n) + 32, rng);
        auto original = v;
        std::printf("  [inplace] n=%-5lld", (long long)n);
        std::fflush(stdout);
        rawrxd_rmsnorm(v.data(), v.data(), n, eps);
        std::printf(" ok\n");
        std::fflush(stdout);

        double ss = 0.0;
        for (int64_t j = 0; j < n; ++j) ss += double(original[j]) * double(original[j]);
        const double rms = std::sqrt(ss / double(n) + double(eps));
        for (int64_t i = 0; i < n; ++i) {
            char tag[64];
            std::snprintf(tag, sizeof tag, "inplace n=%lld", (long long)n);
            record(tag, n, i, double(v[static_cast<size_t>(i)]),
                   double(original[static_cast<size_t>(i)]) / rms, 1e-5, 1e-4);
        }
    }

    // n == 0 must be a no-op, not a fault and not a divide.
    {
        float buf[4] = {1.0f, 2.0f, 3.0f, 4.0f};
        std::printf("  [n=0] no-op");
        std::fflush(stdout);
        rawrxd_rmsnorm(buf, buf, 0, eps);
        std::printf(" ok\n");
        record("n=0 leaves input untouched", 0, 0, buf[0], 1.0, 0.0, 0.0);
    }

    std::printf("===================================\n");
    std::printf("CHECKS_TOTAL=%d\n", g_checks);
    std::printf("CHECKS_FAILED=%d\n", g_failed);
    std::printf("CRASHES=%d\n", g_crashes);
    std::printf("MAX_ABS_ERROR=%.6g\n", g_max_abs);
    std::printf("MAX_REL_ERROR=%.6g\n", g_max_rel);
    std::printf("FIRST_BAD_N=%lld\n", (long long)g_first_bad_n);
    std::printf("FIRST_BAD_INDEX=%lld\n", (long long)g_first_bad_index);
    if (g_first_bad_n >= 0) std::printf("FIRST_BAD_CASE=%s\n", g_first_bad_case.c_str());
    std::printf("VERDICT=%s\n", g_failed == 0 ? "PASS" : "FAIL");
    return g_failed == 0 ? 0 : 1;
}