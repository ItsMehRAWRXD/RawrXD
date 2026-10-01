// rawrxd_masm_parity_test.cpp  --  RAWRXD_PURE_MASM_PARITY_001
//
// Verifies the hand-written x64 MASM kernels in src/masm/ against scalar C
// references. Every count printed below is MEASURED at runtime: the harness
// computes a max absolute deviation per kernel and derives the verdict from
// those numbers. There is no hardcoded verdict and no simulated counter.
//
// Build (MSVC, x64):
//   ml64 /nologo /c /Fo:math.obj          src\masm\rawrxd_math_masm.asm
//   ml64 /nologo /c /Fo:trans_fixed.obj   src\masm\rawrxd_transformer_masm_fixed.asm
//   ml64 /nologo /c /Fo:trans_full.obj    src\masm\rawrxd_transformer_full.asm
//   cl /nologo /O2 /EHsc /std:c++17 rawrxd_masm_parity_test.cpp *.obj
//
// Or via CMake: cmake --build <dir> --config Release --target rawrxd_masm_parity

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <random>
#include <vector>

extern "C" {
float rawrxd_sum_f32(const float* x, int64_t n);
float rawrxd_dot_f32(const float* a, const float* b, int64_t n);
void  rawrxd_scale_f32(float* x, float s, int64_t n);
void  rawrxd_axpy_f32(float* y, float a, const float* x, int64_t n);
float rawrxd_max_f32(const float* x, int64_t n);
float rawrxd_expf_scalar(float x);
float rawrxd_hsum4_f32(float a, float b, float c, float d);

int   rawrxd_q8_0_dequant(const void* blocks, int64_t nblocks, float* out);
int   rawrxd_q4_0_dequant(const void* blocks, int64_t nblocks, float* out);
float rawrxd_f16_to_f32(uint16_t h);
void  rawrxd_softmax_inplace(float* x, int64_t n);
void  rawrxd_rmsnorm(float* out, const float* x, int64_t n, float eps);
int   rawrxd_is_finite_f32(const float* x, int64_t n);

void  rawrxd_gemv_f32(float* y, const float* w, const float* x, int64_t rows, int64_t cols);
void  rawrxd_gemv_bias_f32(float* y, const float* w, const float* x, const float* bias,
                           int64_t rows, int64_t cols);
void  rawrxd_rope_f32(float* x, int64_t n_heads, int64_t head_dim, float theta, int64_t pos);
float rawrxd_layernorm_f32(float* out, const float* x, int64_t n, float eps,
                           float* mean_out, float* rstd_out);
void  rawrxd_add_f32(float* y, const float* a, const float* b, int64_t n);
}

namespace {

int g_checks = 0;
int g_failed = 0;
double g_worst = 0.0;

// Record one comparison; tolerance is absolute unless the scale demands relative.
void check(const char* name, double got, double want, double tol) {
    ++g_checks;
    const double err = std::fabs(got - want);
    const double rel = err / (std::fabs(want) > 1e-6 ? std::fabs(want) : 1.0);
    if (!(err <= tol) || std::isnan(got)) {
        ++g_failed;
        std::printf("  FAIL %-34s got=%.9g want=%.9g abs=%.3g rel=%.3g\n",
                    name, got, want, err, rel);
    } else if (err > g_worst) {
        g_worst = err;
    }
}

// Deterministic input: a fixed seed keeps the receipt reproducible.
std::vector<float> makeVec(size_t n, std::mt19937& rng, float lo = -2.0f, float hi = 2.0f) {
    std::uniform_real_distribution<float> d(lo, hi);
    std::vector<float> v(n);
    for (auto& f : v) f = d(rng);
    return v;
}

void test_scalars() {
    std::printf("[math] scalar kernels\n");
    std::mt19937 rng(0x5EEDu);

    // Lengths chosen to exercise the 4-wide body, the scalar tail, and both.
    for (int64_t n : {0, 1, 2, 3, 4, 5, 7, 8, 15, 16, 33, 64, 129}) {
        const auto v = makeVec(static_cast<size_t>(n), rng);
        double ref = 0.0;
        for (int64_t i = 0; i < n; ++i) ref += v[static_cast<size_t>(i)];
        check("sum_f32", rawrxd_sum_f32(v.data(), n), ref, 1e-5 * (1.0 + std::fabs(ref)));

        double refmax = (n > 0) ? v[0] : 0.0;
        for (int64_t i = 1; i < n; ++i)
            if (v[static_cast<size_t>(i)] > refmax) refmax = v[static_cast<size_t>(i)];
        check("max_f32", rawrxd_max_f32(v.data(), n), refmax, 0.0);
    }

    for (int64_t n : {1, 3, 4, 8, 17, 64}) {
        const auto a = makeVec(static_cast<size_t>(n), rng);
        const auto b = makeVec(static_cast<size_t>(n), rng);
        double ref = 0.0;
        for (int64_t i = 0; i < n; ++i) ref += a[static_cast<size_t>(i)] * b[static_cast<size_t>(i)];
        check("dot_f32", rawrxd_dot_f32(a.data(), b.data(), n), ref,
              1e-5 * (1.0 + std::fabs(ref)));
    }

    for (int64_t n : {1, 3, 4, 9, 32}) {
        const auto x = makeVec(static_cast<size_t>(n), rng);
        auto got = x, want = x;
        const float s = 3.25f;
        rawrxd_scale_f32(got.data(), s, n);
        for (int64_t i = 0; i < n; ++i) want[static_cast<size_t>(i)] = x[static_cast<size_t>(i)] * s;
        for (int64_t i = 0; i < n; ++i)
            check("scale_f32", got[static_cast<size_t>(i)], want[static_cast<size_t>(i)],
                  1e-6 * (1.0 + std::fabs(want[static_cast<size_t>(i)])));

        auto yg = x, yw = x;
        const auto b = makeVec(static_cast<size_t>(n), rng);
        rawrxd_axpy_f32(yg.data(), s, b.data(), n);
        for (int64_t i = 0; i < n; ++i)
            yw[static_cast<size_t>(i)] = x[static_cast<size_t>(i)] + s * b[static_cast<size_t>(i)];
        for (int64_t i = 0; i < n; ++i)
            check("axpy_f32", yg[static_cast<size_t>(i)], yw[static_cast<size_t>(i)],
                  1e-6 * (1.0 + std::fabs(yw[static_cast<size_t>(i)])));
    }

    check("hsum4_f32", rawrxd_hsum4_f32(1.5f, -2.25f, 3.0f, 0.25f), 2.5, 1e-6);
}

// expf parity across the range reduction breakpoints as well as ordinary values.
void test_expf() {
    std::printf("[math] expf_scalar\n");
    const float xs[] = {0.0f,  1.0f,   -1.0f,  0.5f,   -0.5f,  10.0f,
                        -10.0f, 88.0f,  89.0f, -89.0f, 700.0f, -700.0f,
                        0.6931472f, -0.6931472f, 1.5f, -1.5f, 0.25f, -0.25f};
    for (float x : xs) {
        const float ref = std::exp(x);
        const float got = rawrxd_expf_scalar(x);
        char buf[64];
        std::snprintf(buf, sizeof buf, "expf(%g)", static_cast<double>(x));
        // Near the overflow boundary the library may already be inf; allow the
        // same answer either way.
        if (std::isinf(ref) || std::isinf(got)) {
            ++g_checks;
            if (std::isinf(ref) != std::isinf(got) ||
                (std::isinf(ref) && std::signbit(ref) != std::signbit(got))) {
                ++g_failed;
                std::printf("  FAIL %-34s got=%g want=%g\n", buf, double(got), double(ref));
            }
            continue;
        }
        check(buf, got, ref, 1e-5 * (1.0 + std::fabs(ref)));
    }
}

// f16 -> f32 for the full special-value taxonomy, not just normals.
void test_f16() {
    std::printf("[transformer] f16_to_f32\n");
    const uint16_t cases[] = {0x0000, 0x8000, 0x3C00, 0xC000, 0x3800, 0x4000,
                              0x0001, 0x03FF, 0x0400, 0x7C00, 0xFC00, 0x7E00,
                              0xFE00, 0x7C01, 0x3555, 0xB555};
    for (uint16_t h : cases) {
        const float got = rawrxd_f16_to_f32(h);
        // Reference: exact conversion via double round-trip through _Float16 is
        // not portable, so compare against a hand-written scalar decoder.
        float want;
        {
            const int sign = (h & 0x8000u) ? -1 : 1;
            const int exp = (h >> 10) & 0x1F;
            const int man = h & 0x3FF;
            if (exp == 0) {
                want = (man == 0) ? 0.0f
                      : static_cast<float>(sign) *
                            (static_cast<double>(man) / 1024.0 * std::pow(2.0, -14));
            } else if (exp == 31) {
                want = (man == 0) ? (sign > 0 ? INFINITY : -INFINITY)
                      : std::nanf("");
            } else {
                want = static_cast<float>(sign) *
                       ((1.0 + static_cast<double>(man) / 1024.0) *
                        std::pow(2.0, static_cast<double>(exp - 15)));
            }
        }
        char buf[64];
        std::snprintf(buf, sizeof buf, "f16(0x%04X)", h);
        ++g_checks;
        const bool bothnan = std::isnan(got) && std::isnan(want);
        const bool ok = bothnan || (got == want) ||
                        (std::isinf(got) && std::isinf(want) && std::signbit(got) == std::signbit(want));
        if (!ok) {
            ++g_failed;
            std::printf("  FAIL %-34s got=%.9g want=%.9g\n", buf, double(got), double(want));
        } else if (std::isfinite(got) && std::isfinite(want)) {
            const double err = std::fabs(double(got) - double(want));
            if (err > g_worst) g_worst = err;
        }
    }
}

void test_dequant() {
    std::printf("[transformer] q8_0 / q4_0 dequant\n");
    std::mt19937 rng(0xC0FFEEu);

    // Q8_0: [f16 d][32 int8]
    for (int64_t nb : {1, 2, 5}) {
        std::vector<uint8_t> buf(static_cast<size_t>(nb) * 34);
        const float d = 0.5f;
        std::memcpy(buf.data(), &d, 4);  // f32 copy only for layout; overwritten below
        // write f16 0x3800 (= 0.5) explicitly
        buf[0] = 0x00; buf[1] = 0x38;
        std::vector<float> want(static_cast<size_t>(nb) * 32);
        for (int64_t b = 0; b < nb; ++b) {
            for (int32_t q = 0; q < 32; ++q) {
                const int32_t qi = static_cast<int32_t>(q) - 16;   // signed range
                buf[static_cast<size_t>(b * 34 + 2 + q)] = static_cast<uint8_t>(qi & 0xFF);
                want[static_cast<size_t>(b * 32 + q)] = static_cast<float>(qi) * d;
            }
        }
        std::vector<float> got(want.size(), 0.0f);
        const int n = rawrxd_q8_0_dequant(buf.data(), nb, got.data());
        char buf2[64];
        std::snprintf(buf2, sizeof buf2, "q8_0_dequant(nb=%lld) count", (long long)nb);
        check(buf2, double(n), double(nb * 32), 0.0);
        for (size_t i = 0; i < want.size(); ++i) {
            std::snprintf(buf2, sizeof buf2, "q8_0_dequant(nb=%lld)[%zu]", (long long)nb, i);
            check(buf2, got[i], want[i], 1e-6);
        }
    }

    // Q4_0: [f16 d][16 nibble bytes]; nibble = (element & 7) + 8, so value = (nibble-8)*d
    for (int64_t nb : {1, 3}) {
        std::vector<uint8_t> buf(static_cast<size_t>(nb) * 18);
        buf[0] = 0x00; buf[1] = 0x3C;   // f16 1.0
        const float d = 1.0f;
        std::vector<float> want(static_cast<size_t>(nb) * 32);
        for (int64_t b = 0; b < nb; ++b) {
            for (int j = 0; j < 16; ++j) {
                const int lo = j % 8;            // element 2j   -> low nibble
                const int hi = ((j + 4) % 8);    // element 2j+1 -> high nibble
                buf[static_cast<size_t>(b * 18 + 2 + j)] =
                    static_cast<uint8_t>(((hi + 8) << 4) | (lo + 8));
                want[static_cast<size_t>(b * 32 + 2 * j + 0)] = static_cast<float>(lo);
                want[static_cast<size_t>(b * 32 + 2 * j + 1)] = static_cast<float>(hi);
            }
        }
        std::vector<float> got(want.size(), 0.0f);
        const int n = rawrxd_q4_0_dequant(buf.data(), nb, got.data());
        char buf2[64];
        std::snprintf(buf2, sizeof buf2, "q4_0_dequant(nb=%lld) count", (long long)nb);
        check(buf2, double(n), double(nb * 32), 0.0);
        for (size_t i = 0; i < want.size(); ++i) {
            std::snprintf(buf2, sizeof buf2, "q4_0_dequant(nb=%lld)[%zu]", (long long)nb, i);
            check(buf2, got[i], want[i], 1e-6);
        }
    }
}

void test_softmax() {
    std::printf("[transformer] softmax / rmsnorm / is_finite\n");
    std::mt19937 rng(0x50Fu);

    for (int64_t n : {1, 3, 4, 8, 33, 128}) {
        const auto v = makeVec(static_cast<size_t>(n), rng, -8.0f, 8.0f);
        auto got = v, want = v;
        rawrxd_softmax_inplace(got.data(), n);

        double mx = want[0];
        for (int64_t i = 1; i < n; ++i)
            if (want[static_cast<size_t>(i)] > mx) mx = want[static_cast<size_t>(i)];
        double sum = 0.0;
        for (int64_t i = 0; i < n; ++i) {
            want[static_cast<size_t>(i)] = std::exp(want[static_cast<size_t>(i)] - mx);
            sum += want[static_cast<size_t>(i)];
        }
        for (int64_t i = 0; i < n; ++i) want[static_cast<size_t>(i)] /= sum;
        for (int64_t i = 0; i < n; ++i) {
            char buf[64];
            std::snprintf(buf, sizeof buf, "softmax(n=%lld)[%lld]", (long long)n, (long long)i);
            check(buf, got[static_cast<size_t>(i)], want[static_cast<size_t>(i)], 1e-5);
        }
        double total = 0.0;
        for (int64_t i = 0; i < n; ++i) total += got[static_cast<size_t>(i)];
        char buf[64];
        std::snprintf(buf, sizeof buf, "softmax(n=%lld) sum==1", (long long)n);
        check(buf, total, 1.0, 1e-5);
    }

    for (int64_t n : {1, 4, 17, 64}) {
        const auto v = makeVec(static_cast<size_t>(n), rng, -3.0f, 3.0f);
        std::vector<float> got(static_cast<size_t>(n), 0.0f);
        const float eps = 1e-5f;
        rawrxd_rmsnorm(got.data(), v.data(), n, eps);

        double ss = 0.0;
        for (int64_t i = 0; i < n; ++i) ss += double(v[static_cast<size_t>(i)]) * v[static_cast<size_t>(i)];
        const double rms = std::sqrt(ss / double(n) + double(eps));
        for (int64_t i = 0; i < n; ++i) {
            char buf[64];
            std::snprintf(buf, sizeof buf, "rmsnorm(n=%lld)[%lld]", (long long)n, (long long)i);
            check(buf, got[static_cast<size_t>(i)], float(double(v[static_cast<size_t>(i)]) / rms),
                  1e-5 * (1.0 + std::fabs(double(v[static_cast<size_t>(i)]))));
        }
    }

    {
        const float clean[4] = {1.0f, -2.0f, 0.0f, 3.5f};
        check("is_finite(clean)", double(rawrxd_is_finite_f32(clean, 4)), 1.0, 0.0);
        float dirty[4] = {1.0f, INFINITY, 0.0f, 3.5f};
        check("is_finite(inf)", double(rawrxd_is_finite_f32(dirty, 4)), 0.0, 0.0);
        dirty[1] = NAN;
        check("is_finite(nan)", double(rawrxd_is_finite_f32(dirty, 4)), 0.0, 0.0);
        check("is_finite(n=0)", double(rawrxd_is_finite_f32(clean, 0)), 1.0, 0.0);
    }
}

void test_gemv() {
    std::printf("[transformer] gemv / layernorm / rope / add\n");
    std::mt19937 rng(0x6A17u);

    const int64_t cases[][2] = {{1, 1}, {3, 5}, {8, 8}, {7, 33}, {64, 128}};
    for (const auto& c : cases) {
        const int64_t rows = c[0], cols = c[1];
        const auto w = makeVec(static_cast<size_t>(rows * cols), rng, -1.0f, 1.0f);
        const auto x = makeVec(static_cast<size_t>(cols), rng, -1.0f, 1.0f);
        const auto bias = makeVec(static_cast<size_t>(rows), rng, -0.5f, 0.5f);

        std::vector<float> yg(static_cast<size_t>(rows), 0.0f);
        rawrxd_gemv_f32(yg.data(), w.data(), x.data(), rows, cols);
        std::vector<float> yb(static_cast<size_t>(rows), 0.0f);
        rawrxd_gemv_bias_f32(yb.data(), w.data(), x.data(), bias.data(), rows, cols);

        for (int64_t r = 0; r < rows; ++r) {
            double ref = 0.0;
            for (int64_t k = 0; k < cols; ++k)
                ref += double(w[static_cast<size_t>(r * cols + k)]) * x[static_cast<size_t>(k)];
            char buf[80];
            std::snprintf(buf, sizeof buf, "gemv(%lldx%lld)[%lld]", (long long)rows,
                          (long long)cols, (long long)r);
            check(buf, yg[static_cast<size_t>(r)], ref, 1e-5 * (1.0 + std::fabs(ref)));
            std::snprintf(buf, sizeof buf, "gemv_bias(%lldx%lld)[%lld]", (long long)rows,
                          (long long)cols, (long long)r);
            check(buf, yb[static_cast<size_t>(r)], ref + bias[static_cast<size_t>(r)],
                  1e-5 * (1.0 + std::fabs(ref)));
        }
    }

    for (int64_t n : {1, 3, 4, 16, 33}) {
        const auto v = makeVec(static_cast<size_t>(n), rng, -2.0f, 2.0f);
        std::vector<float> got(static_cast<size_t>(n), 0.0f);
        float mean = 0.0f, rstd = 0.0f;
        const float eps = 1e-5f;
        rawrxd_layernorm_f32(got.data(), v.data(), n, eps, &mean, &rstd);

        double m = 0.0;
        for (int64_t i = 0; i < n; ++i) m += v[static_cast<size_t>(i)];
        m /= double(n);
        double var = 0.0;
        for (int64_t i = 0; i < n; ++i) {
            const double d = v[static_cast<size_t>(i)] - m;
            var += d * d;
        }
        var /= double(n);
        const double sd = std::sqrt(var + double(eps));
        check("layernorm mean", mean, m, 1e-5 * (1.0 + std::fabs(m)));
        check("layernorm rstd", rstd, float(1.0 / sd), 1e-5);
        for (int64_t i = 0; i < n; ++i) {
            char buf[64];
            std::snprintf(buf, sizeof buf, "layernorm(n=%lld)[%lld]", (long long)n, (long long)i);
            check(buf, got[static_cast<size_t>(i)],
                  float((v[static_cast<size_t>(i)] - m) / sd), 1e-5);
        }
    }

    // RoPE must reduce to identity at pos == 0 and must preserve pair norms.
    {
        const int64_t heads = 2, dim = 8;
        auto v = makeVec(static_cast<size_t>(heads * dim), rng, -1.0f, 1.0f);
        auto at0 = v;
        rawrxd_rope_f32(at0.data(), heads, dim, 10000.0f, 0);
        for (size_t i = 0; i < at0.size(); ++i)
            check("rope(pos=0) identity", at0[i], v[i], 1e-5);

        auto at1 = v;
        rawrxd_rope_f32(at1.data(), heads, dim, 10000.0f, 1);
        for (int64_t h = 0; h < heads; ++h) {
            for (int64_t p = 0; p < dim / 2; ++p) {
                const size_t i0 = static_cast<size_t>(h * dim + 2 * p);
                const size_t i1 = i0 + 1;
                const double n0 = v[i0] * v[i0] + v[i1] * v[i1];
                const double n1 = at1[i0] * at1[i0] + at1[i1] * at1[i1];
                char buf[80];
                std::snprintf(buf, sizeof buf, "rope norm h=%lld p=%lld", (long long)h, (long long)p);
                check(buf, n1, n0, 1e-4 * (1.0 + n0));
            }
        }
        // Reference rotation for the first pair at pos=1.
        {
            const double theta = 10000.0;
            const double angle = std::pow(theta, 0.0 / double(dim));  // p=0 -> freq 1
            const double c = std::cos(angle), s = std::sin(angle);
            check("rope p0 x0", at1[0], v[0] * c - v[1] * s, 1e-5);
            check("rope p0 x1", at1[1], v[0] * s + v[1] * c, 1e-5);
        }
    }

    for (int64_t n : {1, 4, 7, 32}) {
        const auto a = makeVec(static_cast<size_t>(n), rng);
        const auto b = makeVec(static_cast<size_t>(n), rng);
        std::vector<float> got(static_cast<size_t>(n), 0.0f);
        rawrxd_add_f32(got.data(), a.data(), b.data(), n);
        for (int64_t i = 0; i < n; ++i)
            check("add_f32", got[static_cast<size_t>(i)],
                  a[static_cast<size_t>(i)] + b[static_cast<size_t>(i)], 1e-6);
    }
}

}  // namespace

int main() {
    std::printf("RAWRXD_PURE_MASM_PARITY_001\n");
    std::printf("===========================\n");

    test_scalars();
    test_expf();
    test_f16();
    test_dequant();
    test_softmax();
    test_gemv();

    std::printf("===========================\n");
    std::printf("CHECKS_TOTAL=%d\n", g_checks);
    std::printf("CHECKS_FAILED=%d\n", g_failed);
    std::printf("WORST_ABS_ERROR=%.6g\n", g_worst);
    std::printf("VERDICT=%s\n", (g_failed == 0) ? "PASS" : "FAIL");
    return g_failed == 0 ? 0 : 1;
}