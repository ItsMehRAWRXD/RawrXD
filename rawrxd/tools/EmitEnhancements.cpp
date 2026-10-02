// RAWRXD_EMIT_001
//
// Tests three of the four proposed enhancements against the real Decoda planes
// (read from the real encoder). The fourth needs activations we do not have.
//
//  1. gamma_k centroid adjustment      -- testable, claims 8-14% at zero rate
//  2. hierarchical plane masking       -- testable, claims MSB <0.12 b/w
//  3. Lagrangian per-block allocation  -- testable from plane occupancies
//  4. Hessian-guided traversal         -- NOT testable: needs H = X X^T
//
// "Zero rate cost" is the falsifiable part of (1) and (2), so both are measured
// in bits-per-weight explicitly rather than asserted.

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

#define private public
#include "decoda/decoda.hpp"
#undef private

#include <fstream>

static std::vector<float> load(const std::string& dir) {
    std::ifstream f(dir + "/blk_9_ffn_gate_exps_weight.f32", std::ios::binary | std::ios::ate);
    if (!f) return {};
    const auto n = std::size_t(f.tellg()) / sizeof(float); f.seekg(0);
    std::vector<float> v(n); f.read((char*)v.data(), std::streamsize(n * 4));
    return v;
}

int main(int argc, char** argv) {
    const std::string dir = argc > 1 ? argv[1] : ".";
    auto W = load(dir);
    if (W.empty()) { std::printf("MISSING\n"); return 1; }
    const std::size_t n = W.size();
    const std::size_t bitset = (n + 7) / 8;
    const std::uint32_t R = 256, C = 2048, BLOCK = 64, BITS = 12;

    decoda::BuildOptions o;
    o.block_size = BLOCK; o.residual_bits = BITS; o.outlier_sigma = 3.0f;
    o.store_exact_f32 = false;
    auto T = decoda::Tensor::encode(W.data(), R, C, o);

    const std::uint32_t qmax = (1u << BITS) - 1;
    const std::size_t nblocks = (n + BLOCK - 1) / BLOCK;

    // base reconstruction: ternary + outliers (plane-independent part)
    std::vector<float> base(n);
    for (std::uint32_t r = 0; r < R; ++r)
        for (std::uint32_t c = 0; c < C; ++c)
            base[std::size_t(r) * C + c] = T.reconstructedWeight(r, c, decoda::FidelityState{});

    auto build_prefix = [&](std::uint32_t planes, std::vector<float>& m, std::vector<float>& sg) {
        m.assign(n, 0.0f); sg.assign(n, 1.0f);
        if (!planes) return;
        for (std::uint32_t r = 0; r < R; ++r)
            for (std::uint32_t c = 0; c < C; ++c) {
                const std::size_t i = std::size_t(r) * C + c;
                std::uint32_t q = 0;
                for (std::uint32_t p = 0; p < planes; ++p)
                    if (T.residual_planes_[p * bitset + (i >> 3)] & (1u << (i & 7))) q = (q << 1) | 1u;
                q <<= (BITS - planes);
                const float sc = T.residual_scale_[r];
                const float v = sc * (float(q) / float(qmax));
                m[i] = v;
                sg[i] = (T.residual_sign_[i >> 3] & (1u << (i & 7))) ? -1.0f : 1.0f;
            }
    };
    auto measure = [&](const std::vector<float>& m, const std::vector<float>& sg, double gamma) {
        double num = 0, den = 0;
        for (std::size_t i = 0; i < n; ++i) {
            const double g = base[i] + sg[i] * (double(m[i]) + gamma * double(T.residual_scale_[i / BLOCK]));
            const double d = g - double(W[i]); num += d * d; den += double(W[i]) * double(W[i]);
        }
        return std::sqrt(num / den);
    };

    std::printf("RAWRXD_EMIT_001  testing 3 of 4 proposed enhancements on real Decoda planes\n");
    std::printf("shape %ux%u  block=%u  bits=%u  outliers=%zu\n\n", R, C, BLOCK, BITS,
                T.outlier_value_.size());

    // ================= 1. gamma_k centroid adjustment =================
    std::printf("1. GAMMA_K CENTROID ADJUSTMENT (claim: 8-14%% at zero rate cost)\n");
    std::printf("   planes  gamma=0.5(mid)  best_gamma  gain%%   bits/w  (identical)\n");
    double totalMid = 0, totalBest = 0;
    for (std::uint32_t p = 1; p <= 5; ++p) {
        std::vector<float> m, sg;
        build_prefix(p, m, sg);
        double bestE = 1e300, bestG = 0.5;
        for (int gi = 0; gi <= 100; ++gi) {
            const double g = gi / 200.0;                 // 0 .. 0.5
            const double e = measure(m, sg, g);
            if (e < bestE) { bestE = e; bestG = g; }
        }
        const double mid = measure(m, sg, 0.5);
        totalMid += mid; totalBest += bestE;
        const double bpw = double(T.stats().ternary_bytes)
                         + double(T.outlier_value_.size()) * 4 + T.outlier_col_.size() * 2
                         + double(bitset) + T.residual_scale_.size() * 4 + double(bitset) * p;
        std::printf("   %5u  %14.6f  %11.6f  %6.2f  %7.4f\n", p, mid, bestE,
                    100.0 * (mid - bestE) / mid, bpw * 8.0 / double(n));
    }
    std::printf("   aggregate gain across planes: %.2f%%\n", 100.0 * (totalMid - totalBest) / totalMid);
    std::printf("   -> rate is identical by construction; only the reconstruction point moves.\n");

    // ============ 2. hierarchical plane masking ============
    std::printf("\n2. HIERARCHICAL PLANE MASKING (claim: MSB planes <0.12 b/w)\n");
    std::printf("   plane  frac_ones  dense_bits  best_masked_bits  saving%%  subgroup\n");
    for (std::uint32_t p = 0; p < 3; ++p) {
        const std::uint8_t* pl = T.residual_planes_.data() + p * bitset;
        std::uint64_t ones = 0;
        for (std::size_t i = 0; i < n; ++i) if (pl[i >> 3] & (1u << (i & 7))) ++ones;
        // cost model per 256-element group: 1 header + G mask bits + (#set subgroups)*subgroup_size
        double bestCost = double(n), bestG = 0;
        for (std::uint32_t g : {4u, 8u, 16u, 32u, 64u}) {
            const std::size_t groups = (n + g - 1) / g;
            std::size_t cost = 0, set = 0;
            for (std::size_t gi = 0; gi < groups; ++gi) {
                const std::size_t s = gi * g, e = std::min(s + g, n);
                bool any = false;
                for (std::size_t i = s; i < e; ++i)
                    if (pl[i >> 3] & (1u << (i & 7))) { any = true; break; }
                if (any) ++set;
            }
            cost = (n / 256) * (1 + (256 / g)) + set * g;   // headers+masks per 256-block
            const double bpw = double(cost) * 8.0 / double(n);
            if (bpw < bestCost) { bestCost = bpw; bestG = g; }
        }
        std::printf("   %5u  %10.5f  %11.4f  %17.4f  %7.2f  %u\n", p,
                    double(ones) / double(n), 1.0, bestCost,
                    100.0 * (1.0 - bestCost), unsigned(bestG));
    }
    std::printf("   -> a plane that is 94%% zeros but spread evenly costs the same as dense\n");
    std::printf("      unless subgroups are small enough to actually come out empty.\n");

    // ============ 3. Lagrangian per-block allocation ============
    std::printf("\n3. LAGRANGIAN PER-BLOCK PLANE ALLOCATION\n");
    // marginal distortion reduction of adding plane k, per block
    std::printf("   block   planes_allowed (by marginal gain)\n");
    std::vector<int> allow(nblocks, 0);
    for (std::size_t b = 0; b < nblocks; ++b) {
        double prevSSE = 0;
        int last = 0;
        for (std::uint32_t p = 1; p <= 6; ++p) {
            // SSE of block b using planes 0..p
            double sse = 0.0;
            const std::size_t s = b * BLOCK, e = std::min(s + BLOCK, n);
            for (std::size_t i = s; i < e; ++i) {
                std::uint32_t q = 0;
                for (std::uint32_t pp = 0; pp < p; ++pp)
                    if (T.residual_planes_[pp * bitset + (i >> 3)] & (1u << (i & 7))) q = (q << 1) | 1u;
                q <<= (BITS - p);
                const float sc = T.residual_scale_[i / BLOCK];
                const float v = sc * (float(q) / float(qmax));
                const float sgn = (T.residual_sign_[i >> 3] & (1u << (i & 7))) ? -1.0f : 1.0f;
                const double g = base[i] + sgn * v;
                const double d = g - double(W[i]); sse += d * d;
            }
            const double gain = prevSSE - sse;
            if (gain > 0.0) { allow[b] = int(p); last = int(p); }
            prevSSE = sse;
        }
        (void)last;
    }
    std::vector<int> hist(8, 0);
    for (int a : allow) ++hist[std::min(a, 7)];
    std::size_t bits = 0;
    for (std::size_t b = 0; b < nblocks; ++b) bits += allow[b] * BLOCK;
    std::printf("   distribution of planes per block:\n");
    for (int k = 0; k < 7; ++k) if (hist[k]) std::printf("     %d planes : %d blocks\n", k, hist[k]);
    std::printf("   uniform-6 rate  : %.4f b/w\n", 6.0 + 0.02);
    std::printf("   lagrangian rate : %.4f b/w  (adaptive, error not yet recomputed)\n",
                double(bits) / double(n) + 0.02);
    std::printf("   -> adaptive allocation only pays if the saved planes cost less error\n");
    std::printf("      than they save; that requires recomputing rel_L2 per block, which the\n");
    std::printf("      64-element block size makes statistically noisy.\n");

    // ============ 4. Hessian ============
    std::printf("\n4. HESSIAN-GUIDED TRAVERSAL\n");
    std::printf("   NOT TESTED: requires H = X X^T from real activations.\n");
    std::printf("   Weight-MSE guides nothing about task loss; this is the one enhancement\n");
    std::printf("   in the list that could actually move perplexity, and it is the one\n");
    std::printf("   no measurement on this tensor can speak to.\n");
    return 0;
}
