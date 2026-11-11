// Regression: SiLU must not clamp-then-rescale (BATCH2_L2 FFN_ACT fail).
#include <cmath>
#include <cstdio>
#include <cstdlib>

static float siluStable(float x) {
    if (x > 20.0f) return x;
    if (x < -20.0f) return 0.0f;
    return x / (1.0f + std::exp(-x));
}

static float siluBrokenClamp(float x) {
    const float c = x < -10.f ? -10.f : (x > 10.f ? 10.f : x);
    return x * (1.f / (1.f + std::exp(-c))); // under-scales |x|>10
}

int main() {
    const float gates[] = {16.764139f, -16.f, 0.f, 1.f, -1.f, 25.f, -25.f};
    int fails = 0;
    for (float g : gates) {
        const float s = siluStable(g);
        const float b = siluBrokenClamp(g);
        const float ref = (g > 20.f) ? g : (g < -20.f ? 0.f : g / (1.f + std::exp(-g)));
        const double ds = std::fabs((double)s - (double)ref);
        if (ds > 1e-6) {
            std::printf("FAIL stable vs ref g=%.6g s=%.6g ref=%.6g d=%.3e\n", g, s, ref, ds);
            ++fails;
        }
        if (std::fabs(g) > 10.f && std::fabs(g) < 20.f) {
            // Broken form under-scales by ~gate*(1-sigmoid(10)) ≈ 7.6e-4 @ G=16.76
            // → ACT gap ≈ 7e-3 after *UP (BATCH2_L2 pre-fix).
            const double gap = std::fabs((double)s - (double)b);
            const double actGap = gap * 9.5571442; // oracle UP @ idx5475
            if (gap < 5e-4 || actGap < 5e-3) {
                std::printf("FAIL expected clamp-bug divergence at |g|>10 g=%.6g gap=%.3e actGap=%.3e\n",
                            g, gap, actGap);
                ++fails;
            } else {
                std::printf("OK clamp-bug caught g=%.6g stable=%.6g broken=%.6g gap=%.3e actGap=%.3e\n",
                            g, s, b, gap, actGap);
            }
        }
    }
    // Product identity at oracle hot index scale
    const float g = 16.764139f, u = 9.5571442f;
    const float act = siluStable(g) * u;
    if (std::fabs(act - 160.2173f) > 1e-2f) {
        std::printf("FAIL product scale act=%.8g\n", act);
        ++fails;
    }
    std::printf("test_swiglu_silu %s\n", fails ? "FAIL" : "PASS");
    return fails ? 1 : 0;
}
