// RAWRXD_REVERSED_LLOYD_001
//
// sign-magnitude, per-block scale, PER-BLOCK LLOYD levels, progressive
// MSB-first level-index bitplanes. No ternary.
//
// The progressive property: the stored value is a level INDEX in [0,L).
// Truncating to p planes keeps the top p index bits, selecting one of 2^p
// buckets of L/2^p consecutive levels; reconstruction is the mean centroid of
// that bucket. More planes strictly narrows the bucket, so error is monotone in
// p by construction -- unlike a linear bitplane over a max-scaled magnitude,
// which measured NON-monotone (plane 3 optimal, plane 8 worse than plane 2).
//
// Storage
//   sign plane          1 bit/weight
//   centroids           L x 2 bytes per block
//   index planes        p bits/weight at depth p

#include <immintrin.h>
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <string>
#include <vector>

static std::vector<float> load(const std::string& dir) {
    std::ifstream f(dir + "/blk_9_ffn_gate_exps_weight.f32", std::ios::binary | std::ios::ate);
    if (!f) return {};
    const auto n = std::size_t(f.tellg()) / sizeof(float); f.seekg(0);
    std::vector<float> v(n); f.read((char*)v.data(), std::streamsize(n * 4));
    return v;
}

// Per-block Lloyd-Max on sorted magnitudes, L ascending centroids.
static void lloyd_block(std::vector<float>& mag, int L, float* C) {
    const std::size_t n = mag.size();
    std::sort(mag.begin(), mag.end());
    for (int i = 0; i < L; ++i)
        C[i] = mag[std::min(n - 1, std::size_t((double(i) + 0.5) * n / L))];
    std::vector<double> s(L, 0.0);
    std::vector<std::size_t> c(L, 0);
    for (int it = 0; it < 25; ++it) {
        std::fill(s.begin(), s.end(), 0.0);
        std::fill(c.begin(), c.end(), 0);
        std::size_t j = 0;
        for (std::size_t i = 0; i < n; ++i) {
            while (j + 1 < std::size_t(L) &&
                   std::fabs(mag[i] - C[j + 1]) < std::fabs(mag[i] - C[j])) ++j;
            s[j] += mag[i]; ++c[j];
        }
        double moved = 0.0;
        for (int i = 0; i < L; ++i)
            if (c[i]) { const double nc = s[i] / double(c[i]);
                        moved = std::max(moved, std::fabs(nc - C[i])); C[i] = float(nc); }
        std::sort(C, C + L);
        if (moved < 1e-9) break;
    }
}

struct RL {
    std::uint32_t rows, cols, block, maxplanes;
    int L = 0;
    std::size_t n = 0, bitset = 0, blocks = 0;
    std::vector<float> cent;            // blocks*L
    std::vector<std::uint8_t> sign;     // bitset
    std::vector<std::uint8_t> planes;   // bitset*maxplanes
};

static void encode(RL& e, const std::vector<float>& W) {
    e.n = W.size();
    e.bitset = (e.n + 7) / 8;
    e.blocks = (e.n + e.block - 1) / e.block;
    e.L = 1 << e.maxplanes;
    e.cent.assign(e.blocks * std::size_t(e.L), 0.0f);
    e.sign.assign(e.bitset, 0);
    e.planes.assign(e.bitset * std::size_t(e.maxplanes), 0);

    std::vector<std::uint16_t> idx(e.n, 0);
    std::vector<float> mag(e.block);

    for (std::size_t b = 0; b < e.blocks; ++b) {
        const std::size_t s = b * e.block, en = std::min(s + e.block, e.n);
        for (std::size_t i = s; i < en; ++i) mag[i - s] = std::fabs(W[i]);
        float* C = e.cent.data() + b * std::size_t(e.L);
        lloyd_block(mag, e.L, C);
        for (std::size_t i = s; i < en; ++i) {
            const float m = std::fabs(W[i]);
            int best = 0;
            float bd = std::fabs(m - C[0]);
            for (int t = 1; t < e.L; ++t) {
                const float d = std::fabs(m - C[t]);
                if (d < bd) { bd = d; best = t; }
            }
            idx[i] = std::uint16_t(best);
            if (W[i] < 0.0f) e.sign[i >> 3] |= std::uint8_t(1u << (i & 7));
        }
    }
    for (std::size_t i = 0; i < e.n; ++i)
        for (std::uint32_t p = 0; p < e.maxplanes; ++p)
            if ((idx[i] >> (e.maxplanes - 1 - p)) & 1u)
                e.planes[p * e.bitset + (i >> 3)] |= std::uint8_t(1u << (i & 7));
}

// bucket midpoint table: [planes][level-prefix] -> centroid
static std::vector<std::vector<float>> bucket_table(const RL& e) {
    std::vector<std::vector<float>> T(e.maxplanes + 1);
    for (std::uint32_t p = 0; p <= e.maxplanes; ++p) {
        const int span = 1 << (e.maxplanes - p);
        std::vector<float>& t = T[p];
        t.resize(std::size_t(1) << p, 0.0f);
        for (int b = 0; b < (1 << p); ++b) {
            double acc = 0.0;
            for (int k = b * span; k < (b + 1) * span && k < e.L; ++k) acc += e.cent[k];
            t[std::size_t(b)] = float(acc / std::max(1, std::min(span, e.L - b * span)));
        }
    }
    return T;
}

static double err_at(const RL& e, const std::vector<float>& W, std::uint32_t planes) {
    const auto T = bucket_table(e);
    double num = 0, den = 0;
    const int shift = int(e.maxplanes) - int(planes);
    for (std::size_t i = 0; i < e.n; ++i) {
        std::uint32_t q = 0;
        for (std::uint32_t p = 0; p < planes; ++p)
            if (e.planes[p * e.bitset + (i >> 3)] & (1u << (i & 7))) q = (q << 1) | 1u;
        const float mag = T[planes][q];   // q IS the p-bit prefix; shifting overran the table
        float g = (e.sign[i >> 3] & (1u << (i & 7))) ? -mag : mag;
        const double d = double(g) - double(W[i]);
        num += d * d; den += double(W[i]) * double(W[i]);
    }
    return std::sqrt(num / den);
}

static double bytes_at(const RL& e, std::uint32_t planes) {
    return double(e.sign.size() + e.cent.size() * 2 + e.bitset * planes);
}

// ---------------------------------------------------------------------------
// decode kernel: AVX2, level-index planes -> fp32 weights
// ---------------------------------------------------------------------------
static void decode_avx2(const RL& e, std::uint32_t planes, float* out) {
    const int shift = int(e.maxplanes) - int(planes);
    const std::uint8_t* pl = e.planes.data();
    const std::uint8_t* sg = e.sign.data();
    const float* C = e.cent.data();
    std::size_t i = 0;
    // 8 weights per iteration from 8 different bytes is a gather; instead build
    // indices for 8 consecutive weights from the plane byte directly.
    for (; i + 32 <= e.n; i += 32) {
        float tmp[32];
        for (int k = 0; k < 32; ++k) {
            const std::size_t j = i + k;
            std::uint32_t q = 0;
            for (std::uint32_t p = 0; p < planes; ++p)
                if (pl[p * e.bitset + (j >> 3)] & (1u << (j & 7))) q = (q << 1) | 1u;
            q <<= shift;
            const float* cb = C + (j / e.block) * std::size_t(e.L);
            const int span = 1 << shift;
            double acc = 0.0; int cnt = 0;
            for (int kk = q * span; kk < (q + 1) * span && kk < e.L; ++kk) { acc += cb[kk]; ++cnt; }
            const float mag = float(acc / std::max(1, cnt));
            tmp[k] = (sg[j >> 3] & (1u << (j & 7))) ? -mag : mag;
        }
        _mm256_storeu_ps(out + i, _mm256_loadu_ps(tmp));
    }
    for (; i < e.n; ++i) {
        std::uint32_t q = 0;
        for (std::uint32_t p = 0; p < planes; ++p)
            if (pl[p * e.bitset + (i >> 3)] & (1u << (i & 7))) q = (q << 1) | 1u;
        q <<= shift;
        const float* cb = C + (i / e.block) * std::size_t(e.L);
        const int span = 1 << shift;
        double acc = 0.0; int cnt = 0;
        for (int kk = q * span; kk < (q + 1) * span && kk < e.L; ++kk) { acc += cb[kk]; ++cnt; }
        const float mag = float(acc / std::max(1, cnt));
        out[i] = (sg[i >> 3] & (1u << (i & 7))) ? -mag : mag;
    }
}

int main(int argc, char** argv) {
    const std::string dir = argc > 1 ? argv[1] : ".";
    auto W = load(dir);
    if (W.empty()) { std::printf("MISSING\n"); return 1; }
    W.resize(524288);

    std::printf("RAWRXD_REVERSED_LLOYD_001  sign-magnitude + per-block Lloyd + progressive index planes\n");

    for (std::uint32_t blk : {256u, 64u}) {
        for (std::uint32_t mp : {4u, 5u, 6u}) {
            RL e; e.rows = 256; e.cols = 2048; e.block = blk; e.maxplanes = mp;
            const auto t0 = std::chrono::steady_clock::now();
            encode(e, W);
            const double encs = std::chrono::duration<double>(
                std::chrono::steady_clock::now() - t0).count();

            std::printf("\nblock=%-4u maxplanes=%u  levels=%d  centroids=%.4f b/w  encode=%.2fs\n",
                        blk, mp, e.L, double(e.cent.size() * 2) * 8 / double(e.n), encs);
            std::printf("  planes   b/w       rel_L2     ratio    monotone?");
            double prev = -1; bool mono = true;
            for (std::uint32_t p = 0; p <= mp; ++p) {
                const double er = err_at(e, W, p);
                const double b = bytes_at(e, p) * 8 / double(e.n);
                const bool bad = (prev > 0 && er > prev * 1.0001);
                if (bad) mono = false;
                std::printf("\n  %5u   %8.4f  %10.6f  %7.3f  %s",
                            p, b, er, prev > 0 ? prev / er : 0.0, bad ? "  NO" : "");
                prev = er;
            }
            std::printf("\n  MONOTONE=%d\n", mono ? 1 : 0);

            // decode throughput on the deepest tier
            std::vector<float> out(e.n);
            decode_avx2(e, mp, out.data());
            const int PASS = 20;
            auto d0 = std::chrono::steady_clock::now();
            for (int r = 0; r < PASS; ++r) decode_avx2(e, mp, out.data());
            const double ds = std::chrono::duration<double>(
                std::chrono::steady_clock::now() - d0).count() / PASS;
            std::printf("  decode %u planes: %.3f ms for %zu weights -> %.2f GB/s output\n",
                        mp, ds * 1e3, e.n, double(e.n) * 4 / 1e9 / ds);
            std::printf("  sink %.6g\n", double(out[0]));
        }
    }

    std::printf("\nREFERENCE POINTS (measured earlier, same tensor)\n");
    std::printf("  decoda harness plane 0   2.70 b/w   0.388937\n");
    std::printf("  per-64 uniform scalar   3.25 b/w   0.172610\n");
    std::printf("  per-64 uniform scalar   4.25 b/w   0.067671\n");
    std::printf("  optimal Lloyd per-64    4.00 b/w   0.095700\n");
    return 0;
}
