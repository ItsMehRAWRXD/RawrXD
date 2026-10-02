// RAWRXD_REVERSAL_001
//
// The proposed structural reversal, built and measured rate-matched:
//
//   CURRENT   per-block ternary (1.58 b/w) -> sign plane -> PER-ROW residual
//             scale -> 12 MSB bitplanes
//   REVERSED  sign plane -> PER-BLOCK max scale -> MSB-to-LSB magnitude bitplanes
//
// Two defects under test:
//   D1 scale granularity: per-ROW (2048) inflates the peak vs per-BLOCK (256)
//   D2 the trit layer costs 1.58 b/w and under-delivers L2 reduction per bit
//
// The reversed form is progressive: plane k keeps the top k bits of a 12-bit
// block-normalized magnitude, so truncation bounds error by S/2^k exactly.

#include <algorithm>
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

// ---------- REVERSED: sign + per-block scale + MSB bitplanes ----------
struct Rev {
    std::uint32_t rows, cols, block, bits;
    std::vector<std::uint8_t> sign, planes;
    std::vector<float> scale;
    std::size_t bitset, blocks;
};

static void rev_encode(Rev& r, const std::vector<float>& W) {
    const std::size_t n = W.size();
    r.bitset = (n + 7) / 8;
    r.blocks = (n + r.block - 1) / r.block;
    r.scale.assign(r.blocks, 0.0f);
    r.sign.assign(r.bitset, 0);
    r.planes.assign(r.bitset * r.bits, 0);

    for (std::size_t b = 0; b < r.blocks; ++b) {
        const std::size_t s = b * r.block, e = std::min(s + r.block, n);
        double mx = 0.0;
        for (std::size_t idx = s; idx < e; ++idx) mx = std::max(mx, std::fabs(double(W[idx])));
        r.scale[b] = float(mx);
    }
    const std::uint32_t qmax = (1u << r.bits) - 1;
    for (std::size_t idx = 0; idx < n; ++idx) {
        const float S = r.scale[idx / r.block];
        if (S > 0 && W[idx] < 0.0f) r.sign[idx >> 3] |= static_cast<std::uint8_t>(1u << (idx & 7));
        double rv = S > 0 ? std::fabs(double(W[idx])) / double(S) : 0.0;
        long q = std::lround(rv * double(qmax));
        if (q < 0) q = 0;
        if (q > long(qmax)) q = long(qmax);
        const std::uint32_t u = std::uint32_t(q);
        for (std::uint32_t p = 0; p < r.bits; ++p)
            if ((u >> (r.bits - 1 - p)) & 1u)
                r.planes[p * r.bitset + (idx >> 3)] |= static_cast<std::uint8_t>(1u << (idx & 7));
    }
}

static double rev_err(const Rev& r, const std::vector<float>& W, std::uint32_t planes) {
    const std::uint32_t qmax = (1u << r.bits) - 1;
    double num = 0, den = 0;
    for (std::size_t idx = 0; idx < W.size(); ++idx) {
        const float S = r.scale[idx / r.block];
        std::uint32_t q = 0;
        for (std::uint32_t p = 0; p < planes; ++p)
            if (r.planes[p * r.bitset + (idx >> 3)] & (1u << (idx & 7))) q = (q << 1) | 1u;
        q <<= (r.bits - planes);
        double g = double(S) * (double(q) / double(qmax));
        if (r.sign[idx >> 3] & (1u << (idx & 7))) g = -g;
        const double d = g - double(W[idx]); num += d * d; den += double(W[idx]) * double(W[idx]);
    }
    return std::sqrt(num / den);
}

static double rev_bytes(const Rev& r, std::uint32_t planes) {
    return r.sign.size() + r.scale.size() * 2 + r.bitset * planes;
}

// ---------- CURRENT Decoda, read from the real encoder ----------
#include <stdexcept>
#include <type_traits>
#define private public
#include "decoda/decoda.hpp"
#undef private

int main(int argc, char** argv) {
    const std::string dir = argc > 1 ? argv[1] : ".";
    auto W = load(dir);
    if (W.empty()) { std::printf("MISSING\n"); return 1; }
    W.resize(524288);
    const std::size_t n = W.size();
    const std::uint32_t R = 256, C = 2048;

    std::printf("RAWRXD_REVERSAL_001\n");
    std::printf("256x2048 = %zu weights\n\n", n);

    // ---- D1: scale granularity, measured ----
    std::printf("D1 SCALE GRANULARITY\n");
    {
        double gmax = 0, gmin = 1e300;
        for (std::uint32_t blk : {64u, 256u, 2048u}) {
            const std::size_t nb = (n + blk - 1) / blk;
            double mx = 0, mn = 1e300, s1 = 0;
            for (std::size_t b = 0; b < nb; ++b) {
                const std::size_t s = b * blk, e = std::min(s + blk, n);
                double m = 0;
                for (std::size_t idx = s; idx < e; ++idx) m = std::max(m, std::fabs(double(W[idx])));
                mx = std::max(mx, m); mn = std::min(mn, m); s1 += m;
            }
            std::printf("   scale per %4u elems: max=%.5f  mean=%.5f  peak/mean=%.3f\n",
                        blk, mx, s1 / double(nb), mx / (s1 / double(nb)));
        }
        (void)gmax; (void)gmin;
        std::printf("   -> coarser blocks inflate the peak a quantizer must span.\n");
    }

    // ---- CURRENT Decoda curve (real encoder) ----
    decoda::BuildOptions o;
    o.block_size = 64; o.residual_bits = 12; o.outlier_sigma = 3.0f;
    o.store_exact_f32 = false;
    auto T = decoda::Tensor::encode(W.data(), R, C, o);

    auto dec_curve = [&](std::uint32_t planes, double& bpw) {
        decoda::FidelityState s;
        s.include_outliers = true; s.residual_planes = planes;
        std::vector<float> got(n);
        for (std::uint32_t r = 0; r < R; ++r)
            for (std::uint32_t c = 0; c < C; ++c) got[r * C + c] = T.reconstructedWeight(r, c, s);
        double num = 0, den = 0;
        for (std::size_t idx = 0; idx < n; ++idx) {
            const double d = got[idx] - W[idx]; num += d * d; den += double(W[idx]) * W[idx];
        }
        const std::size_t bitset = (n + 7) / 8;
        std::size_t b = (n + 4) / 5 + T.alpha_.size() * 4
                      + T.outlier_value_.size() * 4 + T.outlier_col_.size() * 2;
        if (planes) b += bitset + T.residual_scale_.size() * 4 + bitset * planes;
        bpw = double(b) * 8 / double(n);
        return std::sqrt(num / den);
    };

    // ---- REVERSED curve ----
    Rev rv; rv.rows = R; rv.cols = C; rv.block = 256; rv.bits = 12;
    rev_encode(rv, W);

    std::printf("\nCURVE COMPARISON  (rows: magnitude bitplanes)\n");
    std::printf("   %-6s | %-22s | %-22s | %s\n",
                "planes", "CURRENT decoda", "REVERSED sign-mag", "delta");
    std::printf("   %-6s | %-9s %-11s | %-9s %-11s |\n", "", "b/w", "rel_L2", "b/w", "rel_L2");
    for (std::uint32_t p = 0; p <= 5; ++p) {
        double db = 0;
        const double de = p ? dec_curve(p, db) : dec_curve(0, db);
        const double rb = double(rev_bytes(rv, p)) * 8 / double(n);
        const double re = rev_err(rv, W, p);
        std::printf("   %-6u | %-9.4f %-11.6f | %-9.4f %-11.6f | %.2fx %s\n", p, db, de, rb, re,
                    re > 0 ? de / re : 0.0, re < de ? "reversed wins" : "");
    }

    // ---- the decisive single comparison ----
    std::printf("\nDECISIVE: same rel_L2, what does each cost?\n");
    for (std::uint32_t p = 1; p <= 4; ++p) {
        double db = 0;
        const double de = dec_curve(p, db);
        const double re = rev_err(rv, W, p);
        const double rb = double(rev_bytes(rv, p)) * 8 / double(n);
        std::printf("   planes=%u  current %.6f @ %.4f b/w | reversed %.6f @ %.4f b/w\n",
                    p, de, db, re, rb);
        std::printf("      reversed needs %.2fx the error of current; if reversed err < current err it wins outright\n",
                    re / de);
    }

    // ---- progressive check: does truncation bound error by S/2^k ----
    std::printf("\nPROGRESSIVE BOUND CHECK (reversed, block=256, bits=12)\n");
    double Sbar = 0;
    for (float s : rv.scale) Sbar += s;
    Sbar /= double(rv.scale.size());
    std::printf("   mean block scale S = %.6f\n", Sbar);
    for (std::uint32_t p = 0; p <= 4; ++p)
        std::printf("   planes=%u  measured=%.6f  bound S/2^%u=%.6f  holds=%d\n",
                    p, rev_err(rv, W, p), p, Sbar / std::pow(2.0, p),
                    rev_err(rv, W, p) <= Sbar / std::pow(2.0, p) ? 1 : 0);

    // ---- block size sweep on the reversed form ----
    std::printf("\nREVERSED, block-size sweep\n");
    for (std::uint32_t bs : {64u, 256u, 1024u, 2048u}) {
        Rev t; t.rows = R; t.cols = C; t.block = bs; t.bits = 12;
        rev_encode(t, W);
        std::printf("   block=%4u  planes=1 %.4f b/w err=%.6f | planes=2 %.4f b/w err=%.6f\n",
                    bs, double(rev_bytes(t, 1)) * 8 / double(n), rev_err(t, W, 1),
                    double(rev_bytes(t, 2)) * 8 / double(n), rev_err(t, W, 2));
    }
    return 0;
}
