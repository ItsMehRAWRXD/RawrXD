// rawrxd_masm_all_gate.cpp  --  RAWRXD_PURE_MASM_ALL_PRIMITIVES_001
//
// Step 5: one aggregate differential gate over every exported primitive in the
// three MASM translation units, against independent C references.
//
// Exists so a future edit cannot pass a narrow gate while breaking a primitive
// no narrow gate exercised. add_f32, scale_f32, axpy_f32 and hsum4_f32 had
// exactly that problem: steps 1-4 all passed while those four were broken.
//
// ABI CONTRACT -- MSVC allocates registers by POSITION in the parameter list,
// counting FLOAT parameters when assigning integer registers, and vice versa:
//   scale_f32(x, float s, int64 n)          -> x=rcx  s=xmm1  n=r9   (rdx unused)
//   axpy_f32 (y, float a, const float* x, i64 n)
//                                           -> y=rcx  a=xmm1  x=r8   n=r9
//   add_f32  (y, const float* a, const float* b, i64 n)
//                                           -> y=rcx  a=rdx  b=r8   n=r9
//   rmsnorm  (out, const float* x, i64 n, float eps)
//                                           -> out=rcx x=rdx  n=r8   eps=xmm3
//   gemv     (y, w, x, i64 rows, i64 cols) -> rcx,rdx,r8,r9, [rsp+28h]
//   rope     (x, n_heads, head_dim, float theta, i64 pos)
//                                           -> rcx,rdx,r8, xmm1, [rsp+28h]
// These are MEASURED, not assumed: a probe of the exact four-parameter shape
// showed scale_f32 with n=7 giving rdx=2214801680, r8=0, r9=7.

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

int g_checks = 0, g_failed = 0;
double g_max_abs = 0.0;
const char* g_worst = "-";

void ck(const char* name, double got, double want, double atol, double rtol) {
    ++g_checks;
    if (std::isnan(got) && std::isnan(want)) return;
    const double a = std::fabs(got - want);
    if (std::isfinite(a) && a > g_max_abs) { g_max_abs = a; g_worst = name; }
    const double r = a / (std::fabs(want) > 1e-30 ? std::fabs(want) : 1.0);
    if (!(a <= atol || r <= rtol)) {
        ++g_failed;
        if (g_failed <= 25)
            std::printf("  FAIL %-30s got=%.9g want=%.9g abs=%.3g rel=%.3g\n",
                        name, got, want, a, r);
    }
}

std::vector<float> rnd(size_t n, std::mt19937& rng, float lo = -2.0f, float hi = 2.0f) {
    std::uniform_real_distribution<float> d(lo, hi);
    std::vector<float> v(n);
    for (auto& f : v) f = d(rng);
    return v;
}

float ref_f16(uint16_t h) {
    const int sign = (h & 0x8000u) ? -1 : 1;
    const int e = (h >> 10) & 0x1F, m = h & 0x3FF;
    if (e == 31) return m == 0 ? sign * INFINITY : NAN;
    if (e == 0) return sign * float(double(m) * 5.9604644775390625e-08);
    return sign * float((1.0 + double(m) / 1024.0) * std::pow(2.0, double(e - 15)));
}

}  // namespace

#define STAGE(x)   do { std::printf("[stage] %s\n", x); std::fflush(stdout); } while (0)
#define CALL(x, n) do { std::printf("[call]  %-14s n=%lld\n", x, (long long)(n)); \
                        std::fflush(stdout); } while (0)

int main() {
    std::printf("RAWRXD_PURE_MASM_ALL_PRIMITIVES_001\n");
    std::printf("=====================================\n");
    std::mt19937 rng(0xA11CEu);

    STAGE("sum/dot/max/hsum4");
    for (int64_t n : {0, 1, 2, 3, 4, 5, 7, 8, 15, 16, 17, 31, 32, 33, 64, 127, 128, 129, 1024}) {
        const auto a = rnd((size_t)n + 8, rng);
        double s = 0; for (int64_t i = 0; i < n; ++i) s += a[(size_t)i];
        ck("sum_f32", rawrxd_sum_f32(a.data(), n), s, 1e-4 * (1 + s), 1e-4);
        const auto b = rnd((size_t)n + 8, rng);
        double dt = 0; for (int64_t i = 0; i < n; ++i) dt += double(a[(size_t)i]) * b[(size_t)i];
        ck("dot_f32", rawrxd_dot_f32(a.data(), b.data(), n), dt, 1e-4 * (1 + std::fabs(dt)), 1e-4);
        if (n > 0) {
            double m = a[0];
            for (int64_t i = 1; i < n; ++i) if (a[(size_t)i] > m) m = a[(size_t)i];
            ck("max_f32", rawrxd_max_f32(a.data(), n), m, 0.0, 0.0);
        }
    }
    ck("hsum4_f32", rawrxd_hsum4_f32(1.5f, -2.25f, 3.0f, 0.25f), 2.5, 1e-6, 1e-6);

    STAGE("expf");
    for (int i = 0; i <= 800; ++i) {
        const float x = -0.01f * float(i);
        ck("expf(neg)", rawrxd_expf_scalar(x), float(std::exp(double(x))), 0.0, 2e-5);
    }
    for (float x : {0.5f, 1.0f, 2.0f, 5.0f, 10.0f, 20.0f, 40.0f, 80.0f})
        ck("expf(pos)", rawrxd_expf_scalar(x), float(std::exp(double(x))), 0.0, 2e-5);
    for (float x : {-100.0f, -200.0f, -500.0f, -1000.0f}) {
        ++g_checks;
        if (!(rawrxd_expf_scalar(x) == 0.0f)) {
            ++g_failed;
            std::printf("  FAIL expf underflow not +0 at %g\n", double(x));
        }
    }

    STAGE("f16_exhaustive");
    for (uint32_t h = 0; h < 0x10000u; ++h) {
        const uint16_t bits = (uint16_t)h;
        const float got = rawrxd_f16_to_f32(bits), want = ref_f16(bits);
        ++g_checks;
        bool ok;
        if (std::isnan(want)) ok = std::isnan(got);
        else if (std::isinf(want)) ok = std::isinf(got) && std::signbit(got) == std::signbit(want);
        else if (want == 0.0f) ok = got == 0.0f && std::signbit(got) == std::signbit(want);
        else { int32_t p, q; std::memcpy(&p, &got, 4); std::memcpy(&q, &want, 4);
               ok = std::abs(p - q) <= 1; }
        if (!ok) {
            ++g_failed;
            if (g_failed <= 10) std::printf("  FAIL f16 0x%04X got=%.9g want=%.9g\n", h, double(got), double(want));
        }
    }

    STAGE("scale/axpy/add");
    for (int64_t n : {1, 3, 4, 9, 32, 33}) {
        const auto x = rnd((size_t)n + 16, rng);
        auto g = x;
        CALL("scale_f32", n);
        rawrxd_scale_f32(g.data(), 3.25f, n);
        for (int64_t i = 0; i < n; ++i)
            ck("scale_f32", g[(size_t)i], x[(size_t)i] * 3.25f, 1e-6, 1e-5);

        const auto b = rnd((size_t)n + 16, rng);
        auto y = x;
        CALL("axpy_f32", n);
        rawrxd_axpy_f32(y.data(), 2.0f, b.data(), n);
        for (int64_t i = 0; i < n; ++i)
            ck("axpy_f32", y[(size_t)i], x[(size_t)i] + 2.0f * b[(size_t)i], 1e-6, 1e-5);

        auto s2 = x;
        CALL("add_f32", n);
        rawrxd_add_f32(s2.data(), x.data(), b.data(), n);
        for (int64_t i = 0; i < n; ++i)
            ck("add_f32", s2[(size_t)i], x[(size_t)i] + b[(size_t)i], 1e-6, 1e-5);
    }

    STAGE("rmsnorm/softmax");
    for (int64_t n : {1, 2, 3, 7, 8, 17, 33, 128, 129, 1024}) {
        const auto x = rnd((size_t)n + 32, rng);
        std::vector<float> o((size_t)n + 32, -777.0f);
        rawrxd_rmsnorm(o.data(), x.data(), n, 1e-5f);
        double ss = 0; for (int64_t i = 0; i < n; ++i) ss += double(x[(size_t)i]) * x[(size_t)i];
        const double rms = std::sqrt(ss / double(n) + 1e-5);
        for (int64_t i = 0; i < n; ++i)
            ck("rmsnorm", o[(size_t)i], float(double(x[(size_t)i]) / rms), 1e-5, 1e-4);

        auto sm = x;
        rawrxd_softmax_inplace(sm.data(), n);
        double mx = -1e300;
        for (int64_t i = 0; i < n; ++i) if (x[(size_t)i] > mx) mx = x[(size_t)i];
        double tot = 0; for (int64_t i = 0; i < n; ++i) tot += std::exp(double(x[(size_t)i]) - mx);
        for (int64_t i = 0; i < n; ++i)
            ck("softmax", sm[(size_t)i], std::exp(double(x[(size_t)i]) - mx) / tot, 1e-5, 1e-4);
        double got = 0; for (int64_t i = 0; i < n; ++i) got += sm[(size_t)i];
        ck("softmax sum==1", got, 1.0, 1e-4, 1e-4);
    }

    STAGE("is_finite");
    { const float clean[4] = {1, -2, 0, 3.5f};
      ck("is_finite(clean)", rawrxd_is_finite_f32(clean, 4), 1.0, 0, 0);
      float d[4] = {1, INFINITY, 0, 3.5f};
      ck("is_finite(inf)", rawrxd_is_finite_f32(d, 4), 0.0, 0, 0);
      d[1] = NAN;
      ck("is_finite(nan)", rawrxd_is_finite_f32(d, 4), 0.0, 0, 0); }

    STAGE("dequant");
    {
        std::vector<uint8_t> b8(34 * 3, 0);
        b8[0] = 0x00; b8[1] = 0x38;                       // f16 d = 0.5
        for (int64_t bl = 0; bl < 3; ++bl)
            for (int q = 0; q < 32; ++q)
                b8[(size_t)(bl * 34 + 2 + q)] = (uint8_t)((q - 16) & 0xFF);
        std::vector<float> o8(96, 0.f);
        ck("q8_0 count", rawrxd_q8_0_dequant(b8.data(), 3, o8.data()), 96, 0, 0);
        for (size_t i = 0; i < 96; ++i)
            ck("q8_0_dequant", o8[i], float(int(i % 32) - 16) * 0.5f, 1e-6, 1e-5);

        std::vector<uint8_t> b4(18 * 2, 0);
        b4[0] = 0x00; b4[1] = 0x3C;                       // f16 d = 1.0
        for (int64_t bl = 0; bl < 2; ++bl)
            for (int j = 0; j < 16; ++j) {
                const int lo = j % 8, hi = (j + 4) % 8;
                b4[(size_t)(bl * 18 + 2 + j)] = (uint8_t)(((hi + 8) << 4) | (lo + 8));
            }
        std::vector<float> o4(64, 0.f);
        ck("q4_0 count", rawrxd_q4_0_dequant(b4.data(), 2, o4.data()), 64, 0, 0);
        for (int64_t bl = 0; bl < 2; ++bl)
            for (int j = 0; j < 16; ++j) {
                ck("q4_0 lo", o4[(size_t)(bl * 32 + 2 * j)], float(j % 8), 1e-6, 1e-5);
                ck("q4_0 hi", o4[(size_t)(bl * 32 + 2 * j + 1)], float((j + 4) % 8), 1e-6, 1e-5);
            }
    }

    STAGE("gemv");
    for (int64_t rows : {1, 3, 8, 17, 64}) {
        for (int64_t cols : {1, 5, 8, 33, 128}) {
            const auto w = rnd((size_t)(rows * cols) + 16, rng, -1, 1);
            const auto x = rnd((size_t)cols + 16, rng, -1, 1);
            const auto bi = rnd((size_t)rows + 16, rng, -1, 1);
            std::vector<float> yg((size_t)rows + 16, -1), yb((size_t)rows + 16, -1);
            rawrxd_gemv_f32(yg.data(), w.data(), x.data(), rows, cols);
            rawrxd_gemv_bias_f32(yb.data(), w.data(), x.data(), bi.data(), rows, cols);
            for (int64_t r = 0; r < rows; ++r) {
                double ref = 0;
                for (int64_t k = 0; k < cols; ++k) ref += double(w[(size_t)(r * cols + k)]) * x[(size_t)k];
                ck("gemv", yg[(size_t)r], ref, 1e-4 * (1 + std::fabs(ref)), 1e-4);
                ck("gemv_bias", yb[(size_t)r], ref + bi[(size_t)r], 1e-4 * (1 + std::fabs(ref)), 1e-4);
                ck("gemv identity", yb[(size_t)r] - yg[(size_t)r], bi[(size_t)r], 1e-5, 1e-4);
            }
        }
    }

    STAGE("layernorm");
    for (int64_t n : {1, 4, 17, 64}) {
        const auto x = rnd((size_t)n + 32, rng);
        std::vector<float> o((size_t)n + 32, -777.f);
        float mean = 0, rstd = 0;
        rawrxd_layernorm_f32(o.data(), x.data(), n, 1e-5f, &mean, &rstd);
        double m = 0; for (int64_t i = 0; i < n; ++i) m += x[(size_t)i]; m /= double(n);
        double var = 0; for (int64_t i = 0; i < n; ++i) { const double dd = x[(size_t)i] - m; var += dd * dd; }
        var /= double(n);
        const double sd = std::sqrt(var + 1e-5);
        ck("layernorm mean", mean, m, 1e-5 * (1 + std::fabs(m)), 1e-4);
        ck("layernorm rstd", rstd, float(1.0 / sd), 1e-5, 1e-4);
        for (int64_t i = 0; i < n; ++i)
            ck("layernorm", o[(size_t)i], float((x[(size_t)i] - m) / sd), 1e-5, 1e-4);
    }

    STAGE("rope");
    {
        const int64_t heads = 2, dim = 8;
        const auto v = rnd((size_t)(heads * dim) + 32, rng, -1, 1);
        auto a0 = v;
        rawrxd_rope_f32(a0.data(), heads, dim, 10000.0f, 0);
        for (int64_t i = 0; i < heads * dim; ++i)
            ck("rope pos0 identity", a0[(size_t)i], v[(size_t)i], 1e-5, 1e-4);
        auto a1 = v;
        rawrxd_rope_f32(a1.data(), heads, dim, 10000.0f, 1);
        for (int64_t h = 0; h < heads; ++h)
            for (int64_t p = 0; p < dim / 2; ++p) {
                const size_t i0 = (size_t)(h * dim + 2 * p);
                const double n0 = double(v[i0]) * v[i0] + double(v[i0 + 1]) * v[i0 + 1];
                const double n1 = double(a1[i0]) * a1[i0] + double(a1[i0 + 1]) * a1[i0 + 1];
                ck("rope norm", n1, n0, 1e-4 * (1 + n0), 1e-4);
            }
        const double c1 = std::cos(1.0), s1 = std::sin(1.0);
        ck("rope p0 x0", a1[0], v[0] * c1 - v[1] * s1, 1e-4, 1e-4);
        ck("rope p0 x1", a1[1], v[0] * s1 + v[1] * c1, 1e-4, 1e-4);
    }

    STAGE("done");
    std::printf("=====================================\n");
    std::printf("CHECKS_TOTAL=%d\n", g_checks);
    std::printf("CHECKS_FAILED=%d\n", g_failed);
    std::printf("MAX_ABS_ERROR=%.6g\n", g_max_abs);
    std::printf("WORST_AT=%s\n", g_worst);
    std::printf("VERDICT=%s\n", g_failed == 0 ? "PASS" : "FAIL");
    return g_failed == 0 ? 0 : 1;
}