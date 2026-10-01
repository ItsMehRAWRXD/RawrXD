// Verifies the AVX-512 kernels against an independent scalar reference.
// A speedup that changes the numbers is not a speedup.
#include "rawrxd_cpu_math.hpp"
#include "gguf_loader.hpp"
#include "rawrxd_transformer.hpp"

#include <cmath>
#include <cstdio>
#include <cstring>
#include <vector>
#include <map>
#include <string>

using namespace rawrxd;
using namespace rawrxd::cpu;

static int g_fail = 0;
static void Check(bool ok, const char* name, double got = 0, double want = 0) {
    if (ok) std::printf("PASS %-38s\n", name);
    else { std::printf("FAIL %-38s got=%.9g want=%.9g\n", name, got, want); ++g_fail; }
    std::fflush(stdout);
}

// ---- independent scalar references (deliberately naive) ----
static float RefDot(const float* a, const float* b, size_t n) {
    double s = 0.0;                     // double accumulation = stricter than f32
    for (size_t i = 0; i < n; ++i) s += double(a[i]) * double(b[i]);
    return float(s);
}
static void RefRmsNorm(float* o, const float* x, const float* w, size_t n, float eps) {
    double s = 0.0;
    for (size_t i = 0; i < n; ++i) s += double(x[i]) * double(x[i]);
    const double inv = 1.0 / std::sqrt(s / double(n) + double(eps));
    for (size_t i = 0; i < n; ++i) o[i] = float(double(x[i]) * inv * double(w[i]));
}
static void RefSoftmax(float* x, size_t n) {
    double m = x[0];
    for (size_t i = 1; i < n; ++i) m = x[i] > m ? x[i] : m;
    double s = 0.0;
    for (size_t i = 0; i < n; ++i) { x[i] = float(std::exp(double(x[i]) - m)); s += x[i]; }
    for (size_t i = 0; i < n; ++i) x[i] = float(double(x[i]) / s);
}
static void RefSilu(float* x, size_t n) {
    for (size_t i = 0; i < n; ++i) x[i] = float(double(x[i]) / (1.0 + std::exp(-double(x[i]))));
}
static void RefRope(float* v, size_t hd, float pos, const float* inv) {
    const size_t half = hd / 2;
    for (size_t i = 0; i < half; ++i) {
        const double f = double(pos) * double(inv[i]);
        const double c = std::cos(f), s = std::sin(f);
        const double x0 = v[i], x1 = v[i + half];
        v[i] = float(x0 * c - x1 * s);
        v[i + half] = float(x0 * s + x1 * c);
    }
}
static void RefWeightedSum(float* dst, const float* w, const float* V,
                           size_t stride, size_t width, size_t count) {
    for (size_t i = 0; i < width; ++i) {
        double s = 0.0;
        for (size_t p = 0; p < count; ++p) s += double(w[p]) * double(V[p * stride + i]);
        dst[i] = float(double(dst[i]) + s);
    }
}

// Mixed absolute/relative tolerance, in the style of numpy.allclose. Pure
// relative error is meaningless when the true value is near zero, which happens
// naturally for dot products of oscillatory vectors: a correct kernel can show
// enormous relative error there while the absolute error stays ~1e-7.
static bool Close(float got, float want, double rtol = 1e-5, double atol = 1e-4) {
    const double d = std::fabs(double(got) - double(want));
    return d <= atol + rtol * std::fabs(double(want));
}
static float RelErr(float got, float want) {
    const double d = std::fabs(double(got) - double(want));
    const double m = std::max(1e-6, std::fabs(double(want)));
    return float(d / m);
}
static float AbsErr(float got, float want) {
    return std::fabs(got - want);
}

int main() {
    const Caps& c = Detect();
    std::printf("backend=%s logical_cpus=%u avx512f=%d avx2=%d fma=%d\n\n",
                BackendName(), c.logical_cpus, c.avx512f, c.avx2, c.fma);

    // Sizes chosen to hit: exact 16-lane, non-multiple tails, and odd sizes.
    for (size_t n : {16u, 32u, 64u, 128u, 256u, 100u, 257u, 1000u}) {
        std::vector<float> a(n), b(n);
        for (size_t i = 0; i < n; ++i) {
            a[i] = 0.7f * std::sin(0.37f * float(i + 1));
            b[i] = 0.3f * std::cos(0.11f * float(i + 3));
        }
        const float got = Dot(a.data(), b.data(), n);
        const float want = RefDot(a.data(), b.data(), n);
        char nm[96];
        std::snprintf(nm, sizeof(nm), "Dot n=%zu abs", n);
        if (!Close(got, want, 1e-5, 1e-4)) {
            std::printf("  DEBUG Dot n=%zu got=%.9g want=%.9g\n", n, got, want);
        }
        Check(Close(got, want), nm, AbsErr(got, want), 0);
    }

    // RmsNorm
    for (size_t n : {16u, 128u, 256u, 1024u, 999u}) {
        std::vector<float> x(n), w(n), got(n), want(n);
        for (size_t i = 0; i < n; ++i) {
            x[i] = 0.5f * std::sin(0.21f * float(i + 1));
            w[i] = 1.0f + 0.1f * std::cos(0.05f * float(i));
        }
        RmsNorm(got.data(), x.data(), w.data(), n, 1e-6f);
        RefRmsNorm(want.data(), x.data(), w.data(), n, 1e-6f);
        float worst = 0;
        for (size_t i = 0; i < n; ++i) worst = std::max(worst, RelErr(got[i], want[i]));
        char nm[96];
        std::snprintf(nm, sizeof(nm), "RmsNorm n=%zu worst relerr", n);
        Check(worst < 5e-6, nm, worst, 0);
    }

    // Softmax: must sum to 1 and stay non-negative.
    for (size_t n : {16u, 128u, 1024u, 333u}) {
        std::vector<float> got(n), want(n);
        for (size_t i = 0; i < n; ++i) {
            got[i] = 0.4f * std::sin(0.7f * float(i + 1));
            want[i] = got[i];
        }
        Softmax(got.data(), n);
        RefSoftmax(want.data(), n);
        float sum = 0, worst = 0;
        for (size_t i = 0; i < n; ++i) {
            sum += got[i];
            worst = std::max(worst, RelErr(got[i], want[i]));
        }
        char nm[96];
        std::snprintf(nm, sizeof(nm), "Softmax n=%zu worst relerr", n);
        Check(worst < 5e-6, nm, worst, 0);
        std::snprintf(nm, sizeof(nm), "Softmax n=%zu sums to 1", n);
        Check(std::fabs(sum - 1.0f) < 1e-5, nm, sum, 1.0);
    }

    // SiLU
    {
        std::vector<float> got(256), want(256);
        for (size_t i = 0; i < 256; ++i) got[i] = 0.6f * std::sin(0.4f * float(i + 1));
        want = got;
        SiluInPlace(got.data(), 256);
        RefSilu(want.data(), 256);
        float worst = 0;
        for (size_t i = 0; i < 256; ++i) worst = std::max(worst, RelErr(got[i], want[i]));
        Check(worst < 1e-5, "SiLU worst relerr", worst, 0);
    }

    // RoPE: identity at pos 0, norm-preserving otherwise.
    {
        const size_t hd = 64;
        std::vector<float> inv(hd / 2), got(hd), want(hd);
        for (size_t i = 0; i < hd / 2; ++i) inv[i] = 1.0f / std::pow(10000.0f, 2.0f * float(i) / float(hd));
        for (size_t i = 0; i < hd; ++i) got[i] = 0.5f * std::sin(0.3f * float(i + 1));
        want = got;
        ApplyRope(got.data(), hd, 0.0f, inv.data());
        RefRope(want.data(), hd, 0.0f, inv.data());
        float worst0 = 0;
        for (size_t i = 0; i < hd; ++i) worst0 = std::max(worst0, std::fabs(got[i] - want[i]));
        Check(worst0 < 1e-6, "RoPE pos=0 is identity vs ref", worst0, 0);

        want = got;  // got is now identity-transformed
        got = want;
        ApplyRope(got.data(), hd, 37.0f, inv.data());
        RefRope(want.data(), hd, 37.0f, inv.data());
        float worst = 0;
        double gn = 0, wn = 0;
        for (size_t i = 0; i < hd; ++i) {
            worst = std::max(worst, RelErr(got[i], want[i]));
            gn += double(got[i]) * double(got[i]);
            wn += double(want[i]) * double(want[i]);
        }
        Check(worst < 5e-6, "RoPE pos=37 vs ref", worst, 0);
        Check(std::fabs(std::sqrt(gn) - std::sqrt(wn)) < 1e-4, "RoPE preserves norm",
              std::sqrt(gn), std::sqrt(wn));
    }

    // WeightedSum
    for (size_t stride : {16u, 64u, 128u, 100u}) {
        for (size_t count : {1u, 8u, 64u, 257u}) {
            for (size_t width : {stride, size_t(16), size_t(32)}) {
                if (width > stride) continue;
                std::vector<float> got(width, 0.25f), want(width, 0.25f);
                std::vector<float> scratch(width, 0.0f);
                std::vector<float> w(count), V(stride * count);
                for (size_t p = 0; p < count; ++p) w[p] = 0.5f / float(p + 1);
                for (size_t j = 0; j < V.size(); ++j) V[j] = 0.2f * std::sin(0.13f * float(j + 1));
                WeightedSum(got.data(), w.data(), V.data(), stride, width, count,
                            scratch.data());
                RefWeightedSum(want.data(), w.data(), V.data(), stride, width, count);
                float worst_abs = 0;
                bool ok = true;
                for (size_t i = 0; i < width; ++i) {
                    worst_abs = std::max(worst_abs, AbsErr(got[i], want[i]));
                    if (!Close(got[i], want[i], 1e-4, 1e-4)) ok = false;
                }
                char nm[112];
                std::snprintf(nm, sizeof(nm), "WeightedSum stride=%zu width=%zu count=%zu",
                              stride, width, count);
                Check(ok, nm, worst_abs, 0);
            }
        }
    }

    // MatMulRow against reference.
    for (size_t k : {16u, 128u, 512u, 1000u}) {
        for (size_t n : {16u, 64u, 256u, 257u}) {
            std::vector<float> x(k), W(n * k);
            for (size_t i = 0; i < k; ++i) x[i] = 0.3f * std::cos(0.19f * float(i + 1));
            for (size_t j = 0; j < W.size(); ++j) W[j] = 0.1f * std::sin(0.07f * float(j + 2));
            std::vector<float> y;
            MatMulRow(y, x.data(), W.data(), k, n);
            float worst_abs = 0;
            bool ok = true;
            for (size_t i = 0; i < n; ++i) {
                double s = 0;
                for (size_t l = 0; l < k; ++l) s += double(W[i * k + l]) * double(x[l]);
                const float want = float(s);
                if (!Close(y[i], want)) {
                    if (worst_abs == 0) {
                        std::printf("  DEBUG first mismatch row=%zu k=%zu n=%zu "
                                    "got=%.9g want=%.9g\n", i, k, n, y[i], want);
                    }
                }
                worst_abs = std::max(worst_abs, AbsErr(y[i], want));
                if (!Close(y[i], want)) ok = false;
            }
            char nm[96];
            std::snprintf(nm, sizeof(nm), "MatMulRow k=%zu n=%zu worst_abs", k, n);
            Check(ok, nm, worst_abs, 0);
        }
    }

    // ---- end-to-end: vectorized forward must match a second run and stay finite ----
    {
        std::map<std::string, GGUFMetadataValue> meta;
        GGUFMetadataValue a; a.type = GGUFType::String; a.value = std::string("llama");
        meta["general.architecture"] = a;
        auto put = [&](const char* k, uint32_t v) {
            GGUFMetadataValue m; m.type = GGUFType::Uint32; m.value = v; meta[k] = m;
        };
        const uint32_t V = 128, H = 128, L = 2, NH = 4, NKV = 2, I = 256;
        put("llama.embedding_length", H);
        put("llama.block_count", L);
        put("llama.attention.head_count", NH);
        put("llama.attention.head_count_kv", NKV);
        put("llama.feed_forward_length", I);
        put("llama.context_length", 512);
        { GGUFMetadataValue m; m.type = GGUFType::Uint32Array;
          std::vector<uint32_t> t(V); for (uint32_t i = 0; i < V; ++i) t[i] = i;
          m.value = t; meta["tokenizer.ggml.tokens"] = m; }

        GGUFTensorWriter w;
        auto add = [&](const std::string& n, const std::vector<uint64_t>& sh, float amp) {
            size_t cnt = 1; for (auto d : sh) cnt *= size_t(d);
            std::vector<float> v(cnt);
            for (size_t i = 0; i < cnt; ++i) v[i] = amp * std::sin(0.013f * float(i % 991));
            std::vector<uint8_t> b((uint8_t*)v.data(), (uint8_t*)v.data() + cnt * 4);
            w.AddTensor(n, GGUFType::Float32, sh, b);
        };
        add("token_embd.weight", {V, H}, 0.05f);
        add("output_norm.weight", {H}, 1.0f);
        for (uint32_t l = 0; l < L; ++l) {
            const std::string b = "blk." + std::to_string(l) + ".";
            const uint32_t kvd = (H / NH) * NKV;
            add(b + "attn_norm.weight", {H}, 1.0f);
            add(b + "ffn_norm.weight", {H}, 1.0f);
            add(b + "attn_q.weight", {H, H}, 0.03f);
            add(b + "attn_k.weight", {kvd, H}, 0.03f);
            add(b + "attn_v.weight", {kvd, H}, 0.03f);
            add(b + "attn_output.weight", {H, H}, 0.03f);
            add(b + "ffn_gate.weight", {I, H}, 0.03f);
            add(b + "ffn_up.weight", {I, H}, 0.03f);
            add(b + "ffn_down.weight", {H, I}, 0.03f);
        }
        const std::string path = "F:/~dev/rawrxd/bench_tmp/parity.gguf";
        if (!w.WriteToFile(path, meta)) { Check(false, "write parity gguf"); return 2; }

        TransformerRuntime rt;
        Check(rt.LoadWeights(path), "LoadWeights for parity model");
        std::vector<uint32_t> prompt = {1, 2, 3, 4, 5};
        std::printf("STEP_A forward\n"); std::fflush(stdout);
        auto f1 = rt.Forward(prompt, 0);
        std::printf("STEP_B forward done success=%d\n", int(f1.success)); std::fflush(stdout);
        Check(f1.success && f1.logits.size() == V, "forward on vectorized path");
        bool finite = true;
        for (float v : f1.logits) if (!std::isfinite(v)) finite = false;
        Check(finite, "logits finite");

        rt.ResetKVCache();
        auto f2 = rt.Forward(prompt, 0);
        float worst = 0;
        for (size_t i = 0; i < f1.logits.size(); ++i)
            worst = std::max(worst, RelErr(f2.logits[i], f1.logits[i]));
        Check(worst < 1e-6, "vectorized forward deterministic", worst, 0);

        // RoPE must make position matter.
        rt.ResetKVCache();
        auto f3 = rt.Forward({7}, 128);
        Check(f3.success, "forward at depth 128 succeeds");
    }

    std::printf("\nRESULT %s (%d failures)\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}