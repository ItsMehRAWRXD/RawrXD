// rawrxd_masm_gemv_gate.cpp  --  RAWRXD_PURE_MASM_GEMV_BIAS_001
//
// Certifies gemv and gemv_bias by COMPOSITION rather than by debugging
// gemv_bias as an independent kernel:
//
//     y_bias[i] - y_gemv[i] == b[i]
//
// If that identity holds across zero/positive/negative bias, tails not
// divisible by the vector width, and deliberately misaligned buffers, the
// arithmetic and addressing are proven without re-deriving the dot product.
// A direct reference check runs alongside so an identity that holds for two
// equally-wrong kernels cannot pass.

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <random>
#include <vector>

extern "C" {
void rawrxd_gemv_f32(float* y, const float* w, const float* x,
                     int64_t rows, int64_t cols);
void rawrxd_gemv_bias_f32(float* y, const float* w, const float* x,
                          const float* bias, int64_t rows, int64_t cols);
}

namespace {

int g_checks = 0;
int g_failed = 0;

void check(const char* what, double got, double want, double tol) {
    ++g_checks;
    const double err = std::fabs(got - want);
    if (!(err <= tol)) {
        ++g_failed;
        std::printf("  FAIL %-52s got=%.9g want=%.9g abs=%.3g\n", what, got, want, err);
    }
}

// Deliberately offset the base pointer so no routine can rely on 16-byte
// alignment of any of its three buffers.
template <typename T>
T* offset(T* p, size_t elems, int bytes) {
    return reinterpret_cast<T*>(reinterpret_cast<uint8_t*>(p) + bytes);
}

void run_case(int64_t rows, int64_t cols, int align_bytes, float bias_mode,
              const char* label) {
    std::mt19937 rng(static_cast<uint32_t>(rows * 131 + cols * 17 + align_bytes));
    std::uniform_real_distribution<float> d(-1.0f, 1.0f);

    const size_t nw = static_cast<size_t>(rows * cols);
    std::vector<float> w(nw + 8), x(static_cast<size_t>(cols) + 8), b(static_cast<size_t>(rows) + 8);
    for (auto& f : w) f = d(rng);
    for (auto& f : x) f = d(rng);
    for (auto& f : b) {
        // switch on a float is illegal; the mode is an int, so branch on it.
        if (bias_mode == 0) {
            f = 0.0f;
        } else if (bias_mode == 1) {
            f = 0.5f;
        } else {
            f = d(rng);
        }
    }

    float* wp = offset(w.data(), w.size(), align_bytes);
    float* xp = offset(x.data(), x.size(), align_bytes);
    float* bp = offset(b.data(), b.size(), align_bytes);

    std::vector<float> yg(static_cast<size_t>(rows) + 8, -12345.0f);
    std::vector<float> yb(static_cast<size_t>(rows) + 8, -12345.0f);
    float* ygp = offset(yg.data(), yg.size(), align_bytes);
    float* ybp = offset(yb.data(), yb.size(), align_bytes);

    rawrxd_gemv_f32(ygp, wp, xp, rows, cols);
    rawrxd_gemv_bias_f32(ybp, wp, xp, bp, rows, cols);

    char buf[160];
    for (int64_t r = 0; r < rows; ++r) {
        // Independent scalar reference, accumulated in double.
        double ref = 0.0;
        for (int64_t k = 0; k < cols; ++k)
            ref += static_cast<double>(wp[r * cols + k]) * xp[k];

        std::snprintf(buf, sizeof buf, "%s gemv r=%lld", label, (long long)r);
        check(buf, ygp[r], ref, 1e-4 * (1.0 + std::fabs(ref)));

        std::snprintf(buf, sizeof buf, "%s gemv_bias r=%lld", label, (long long)r);
        check(buf, ybp[r], ref + bp[r], 1e-4 * (1.0 + std::fabs(ref + bp[r])));

        // The composition identity itself.
        std::snprintf(buf, sizeof buf, "%s identity y_bias-y_gemv==b r=%lld", label, (long long)r);
        check(buf, static_cast<double>(ybp[r]) - static_cast<double>(ygp[r]),
              static_cast<double>(bp[r]), 1e-5);
    }
}

}  // namespace

int main() {
    std::printf("RAWRXD_PURE_MASM_GEMV_BIAS_001\n");
    std::printf("===================================\n");

    // cols values deliberately include 1, 3, 5, 7 (tail not divisible by 4),
    // exact multiples of 4, and a large odd stride.
    const int64_t shapes[][2] = {{1, 1},  {1, 3},  {3, 5},  {8, 8}, {7, 33},
                                 {64, 128}, {5, 127}, {2, 1024}, {16, 64}};
    const char* mode_name[] = {"bias=0", "bias=+0.5", "bias=random"};

    for (const auto& s : shapes) {
        for (int align = 0; align <= 12; align += 4) {
            for (int mode = 0; mode < 3; ++mode) {
                char label[64];
                std::snprintf(label, sizeof label, "%lldx%lld/a%d/%s",
                              (long long)s[0], (long long)s[1], align, mode_name[mode]);
                run_case(s[0], s[1], align, mode, label);
            }
        }
    }

    // Degenerate shapes must not write anything or fault.
    {
        std::vector<float> y(4, 7.0f), w(4, 1.0f), x(4, 1.0f), b(4, 1.0f);
        rawrxd_gemv_f32(y.data(), w.data(), x.data(), 0, 4);
        rawrxd_gemv_bias_f32(y.data(), w.data(), x.data(), b.data(), 0, 4);
        check("rows=0 leaves y untouched", y[0], 7.0, 0.0);
    }

    std::printf("===================================\n");
    std::printf("CHECKS_TOTAL=%d\n", g_checks);
    std::printf("CHECKS_FAILED=%d\n", g_failed);
    std::printf("VERDICT=%s\n", g_failed == 0 ? "PASS" : "FAIL");
    return g_failed == 0 ? 0 : 1;
}