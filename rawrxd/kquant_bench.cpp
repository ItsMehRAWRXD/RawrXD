// kquant_bench.cpp
// Measures the admitted GEMV kernels against their own scalar references on
// the real model's tensors. Computes throughput from wall clock; no figure is
// printed unless the numerical gate passed first.
#include "gguf_loader.hpp"
#include "deep2/k_quant_gemv_avx512.h"

#include <chrono>
#include <cmath>
#include <cstdio>
#include <string>
#include <vector>
#include <algorithm>

using namespace rawrxd;
using Clock = std::chrono::steady_clock;

static double Ms(Clock::time_point a, Clock::time_point b) {
    return std::chrono::duration<double, std::milli>(b - a).count();
}

template <typename Fn>
static double Bench(Fn fn, size_t rows, size_t cols, int reps) {
    std::vector<float> y(rows, 0.0f);
    fn(y.data());
    const auto t0 = Clock::now();
    for (int i = 0; i < reps; ++i) fn(y.data());
    return Ms(t0, Clock::now()) / reps;
}

static void Run(const std::string& path, const char* label, GGMLType ty,
                size_t blkBytes, size_t blkElems,
                void (*scalarFn)(const uint8_t*, const float*, float*, size_t, size_t),
                void (*vecFn)(const uint8_t*, const float*, float*, size_t, size_t)) {
    GGUFLoader loader;
    if (!loader.LoadFromFile(path)) { std::printf("LOAD=FAIL\n"); return; }
    const GGUFModel* m = loader.GetModel();
    std::vector<const GGUFTensorInfo*> ts;
    for (const auto& t : m->tensors)
        if (t.ggml_type == ty && t.shape.size() == 2) ts.push_back(&t);
    if (ts.empty()) { std::printf("%s: NO TENSORS\n", label); return; }

    size_t rows = 0, cols = 0, vecRows = 0, vecCols = 0;
    double scalarMs = 0, vecMs = 0;
    int n = 0, worstRel = 0;
    for (const auto* t : ts) {
        auto view = loader.GetTensor(t->name);
        if (!view) continue;
        const size_t c = (size_t)t->shape[0], r = (size_t)t->shape[1];
        // verify before timing
        std::vector<float> x(c), ya(r, 0.0f), yb(r, 0.0f);
        for (size_t i = 0; i < c; ++i) x[i] = 0.5f * std::sin(0.017f * float(i + 1));
        scalarFn(view->data<uint8_t>(), x.data(), ya.data(), r, c);
        vecFn(view->data<uint8_t>(), x.data(), yb.data(), r, c);
        double dot = 0, na = 0, nb = 0, mx = 0;
        for (size_t i = 0; i < r; ++i) {
            dot += (double)ya[i] * (double)yb[i];
            na  += (double)ya[i] * (double)ya[i];
            nb  += (double)yb[i] * (double)yb[i];
            mx = std::max(mx, std::fabs((double)ya[i] - (double)yb[i]));
        }
        const double cos = (na > 0 && nb > 0) ? dot / (std::sqrt(na) * std::sqrt(nb)) : 0.0;
        if (cos < 0.999999) { std::printf("%s: GATE_FAIL %s cos=%f\n", label, t->name.c_str(), cos); continue; }

        scalarMs += Bench([&](float* y){ scalarFn(view->data<uint8_t>(), x.data(), y, r, c); }, r, c, 3);
        vecMs    += Bench([&](float* y){ vecFn(view->data<uint8_t>(), x.data(), y, r, c); }, r, c, 3);
        rows += r; cols += c; ++n;
        if (n == 1) { vecRows = r; vecCols = c; }
    }
    if (n == 0) { std::printf("%s: no timed tensors\n", label); return; }

    const double macs = (double)rows * (double)cols;
    const double gs = 2.0 * macs / (scalarMs * 1e6);      // GFLOP/s (2 flops per MAC)
    const double gv = 2.0 * macs / (vecMs * 1e6);
    std::printf("%s tensors=%d rows=%zu cols=%zu blk=%zuB/%zuelem bits/elem=%.3f\n",
                label, n, rows, cols, blkBytes, blkElems,
                (double)blkBytes * 8.0 / (double)blkElems);
    std::printf("%s scalar_ms=%.3f  vec_ms=%.3f  speedup=%.2fx  scalar_GFLOPs=%.2f  vec_GFLOPs=%.2f\n",
                label, scalarMs, vecMs, vecMs > 0 ? scalarMs / vecMs : 0.0, gs, gv);
}

int main(int argc, char** argv) {
    const std::string path = argc > 1 ? argv[1] : "F:/~dev/qwen2.5-coder-1.5b-base.gguf";
    std::printf("model=%s\n\n", path.c_str());
    Run(path, "Q4_K", GGMLType::Q4_K, 144, 256,
        &kquant::GemvQ4K, &kquant::GemvQ4K_AVX512);
    std::printf("\n");
    Run(path, "Q6_K", GGMLType::Q6_K, 210, 256,
        &kquant::GemvQ6K, &kquant::GemvQ6K_AVX512);
    return 0;
}