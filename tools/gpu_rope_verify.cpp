// gpu_rope_verify.cpp
// RAWRXD_VULKAN_ROPE_CORRECTNESS_001
//
// Verifies VulkanCompute::ExecuteRoPE against a CPU implementation that
// replicates MGRope::Alpha() from ModelGenieExecutor.cpp exactly, including
// the YaRN corr_dim bounds and rope_yarn_ramp mix.

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <cstdint>
#include <vector>
#include <string>
#include <algorithm>
#include "vulkan_compute.h"

namespace {

// Deep2 rope.scaling values, mirrored from MGRope in ModelGenieExecutor.cpp.
constexpr float kFreqBase  = 10000.0f;
constexpr float kFreqScale = 0.025f;
constexpr float kNCtxOrig  = 4096.0f;
constexpr float kYarnLogMul = 0.707f;
constexpr float kBetaFast   = 32.0f;
constexpr float kBetaSlow   = 1.0f;

float CorrDim(float beta, uint32_t n_rot) {
    const float PI = 3.14159265358979323846f;
    return (float)n_rot *
           logf(kNCtxOrig / (beta * 2.0f * PI)) /
           (2.0f * logf(kFreqBase));
}

float RampMix(float k, uint32_t n_rot) {
    float low = floorf(CorrDim(kBetaFast, n_rot));
    if (low < 0.0f) low = 0.0f;
    float high = ceilf(CorrDim(kBetaSlow, n_rot));
    float cap = (float)n_rot - 1.0f;
    if (high > cap) high = cap;
    float span = high - low;
    float denom = (span > 0.001f) ? span : 0.001f;
    float y = (k - low) / denom;
    if (y <= 0.0f) return 1.0f;
    if (y >= 1.0f) return 0.0f;
    return 1.0f - y;
}

float AlphaCpu(uint32_t pos, uint32_t k, uint32_t n_rot) {
    float theta_extrap = (float)pos *
        powf(kFreqBase, -2.0f * (float)k / (float)n_rot);
    float theta_interp = kFreqScale * theta_extrap;
    float ramp = RampMix((float)k, n_rot);
    return theta_interp * (1.0f - ramp) + theta_extrap * ramp;
}

// CPU reference: matches the K_pe application in AttentionFwd.
void ApplyRoPECpu(std::vector<float>& v, uint32_t dim, uint32_t seq_pos, uint32_t rotation_dim) {
    uint32_t n_rot = (rotation_dim ? rotation_dim : dim) & ~1u;
    if (n_rot > dim) n_rot = dim & ~1u;
    for (uint32_t i = 0; i + 1 < n_rot; i += 2) {
        float alpha = AlphaCpu(seq_pos, i / 2, n_rot);
        float ca = cosf(alpha), sa = sinf(alpha);
        float p0 = v[i], p1 = v[i + 1];
        v[i]     = p0 * ca - p1 * sa;
        v[i + 1] = p0 * sa + p1 * ca;
    }
    // Elements beyond n_rot pass through unchanged.
}

struct Metrics { double cosine, rmse, max_abs, rel; bool finite; };

Metrics compare(const std::vector<float>& g, const std::vector<float>& c) {
    Metrics m{};
    m.finite = true;
    double dot=0, ng=0, nc=0, sq=0, mx=0;
    for (size_t i = 0; i < g.size(); ++i) {
        if (!std::isfinite(g[i])) m.finite = false;
        double d = (double)g[i] - (double)c[i];
        sq += d*d;
        mx = std::max(mx, std::fabs(d));
        dot += (double)g[i]*(double)c[i];
        ng += (double)g[i]*(double)g[i];
        nc += (double)c[i]*(double)c[i];
    }
    m.cosine = (ng>0 && nc>0) ? dot/(std::sqrt(ng)*std::sqrt(nc)) : 1.0;
    m.rmse = std::sqrt(sq/(double)g.size());
    m.max_abs = mx;
    double mag = std::sqrt(nc/(double)g.size());
    m.rel = (mag > 1e-12) ? m.rmse/mag : m.rmse;
    return m;
}

} // namespace

int main() {
    printf("=== RAWRXD_VULKAN_ROPE_CORRECTNESS_001 ===\n\n");

    VulkanCompute vc;
    if (!vc.Initialize()) { printf("VULKAN_INIT=FAIL\n"); return 1; }
    printf("VULKAN_DEVICE=%s\n", vc.GetDeviceInfo().device_name.c_str());

    struct Case { uint32_t dim, pos, rot; const char* label; };
    const Case cases[] = {
        {64,  0,  64,  "deep2_k_pe_pos0"},
        {64,  1,  64,  "deep2_k_pe_pos1"},
        {64,  7,  64,  "deep2_k_pe_pos7"},
        {128, 3,  64,  "deep2_partial_rot"},
        {192, 5,  64,  "deep2_full_k_no_tail_touch"},
        {64,  63, 64,  "deep2_late_pos"},
        {66,  2,  64,  "odd_dim_tail"},
    };

    int pass = 0, total = 0;
    for (const Case& c : cases) {
        ++total;
        // Deterministic, non-degenerate input.
        std::vector<float> in(c.dim), gpu(c.dim), cpu(c.dim);
        for (uint32_t i = 0; i < c.dim; ++i)
            in[i] = std::sin((float)(i * 9 + c.pos * 3 + 1)) * 0.7f + 0.05f;
        gpu = in;
        cpu = in;

        bool ok = vc.ExecuteRoPE(gpu.data(), c.dim, c.pos, c.rot);
        ApplyRoPECpu(cpu, c.dim, c.pos, c.rot);

        if (!ok) {
            printf("%-26s dim=%-3u pos=%-2u DISPATCH_FAIL\n", c.label, c.dim, c.pos);
            continue;
        }

        Metrics m = compare(gpu, cpu);
        bool good = m.finite && m.cosine >= 0.999999 && m.rel <= 1e-4;
        if (good) ++pass;

        printf("%-26s dim=%-3u pos=%-2u rot=%-3u cos=%+.10f rel=%.2e max=%.2e finite=%d %s\n",
               c.label, c.dim, c.pos, c.rot, m.cosine, m.rel, m.max_abs,
               m.finite ? 1 : 0, good ? "PASS" : "FAIL");
    }

    printf("\nSHAPES_PASSED=%d/%d\n", pass, total);
    printf("VERDICT=%s\n", (pass == total) ? "PASS" : "FAIL");
    return (pass == total) ? 0 : 1;
}
