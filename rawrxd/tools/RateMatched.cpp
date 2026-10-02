// RAWRXD_RATEMATCHED_001
//
// What plane 0 actually is, and the rate-matched comparison.
//
// Verified in the source:
//   decoda.cpp:367  if (!planes) return 0;              -> plane 0 has NO magnitude bits
//   decoda.cpp:588  residual_plane_bytes = bitset*planes -> plane 0 spends 0 bytes on planes
//   decoda.cpp:580  sign/scale bytes are only counted when residual_planes != 0
//
// So "plane 0 = 3.9319 b/w, rel_L2 0.388937" is a TERNARY BASE + OUTLIERS state with
// zero residual magnitude. Comparing it to a 4-bit Lloyd-Max (0.187) compares a
// ternary base against 4 bits of scalar magnitude. That is the rate mismatch.
//
// This builds the same encoder's states and reports, per state:
//   bits actually spent on MAGNITUDE information, and the resulting rel_L2
// then plots both schemes on a common magnitude-information axis.

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

// ---- exact replica of the Decoda encode path, verified against feasibility.exe ----
struct Dec {
    std::uint32_t rows, cols, block, bits;
    std::vector<std::uint8_t> tern, sign, planes;
    std::vector<float> alpha, base, resid, scale;
    std::vector<std::uint8_t> is_out;
    std::vector<std::uint32_t> o_col;
    std::vector<float> o_val;
    std::size_t bitset;
    std::size_t outliers = 0;
};

static const std::uint32_t kPow3[5] = {1u, 3u, 9u, 27u, 81u};

static void dec_encode(Dec& d, const std::vector<float>& W, float sigma) {
    const std::uint32_t R = d.rows, C = d.cols, B = d.block, NB = d.bits;
    const std::size_t n = std::size_t(R) * C;
    d.bitset = (n + 7) / 8;
    const std::uint32_t blocks = (n + B - 1) / B;

    d.alpha.assign(blocks, 0.0f); d.base.assign(n, 0.0f); d.resid.assign(n, 0.0f);
    d.tern.assign((n + 4) / 5, 0); d.is_out.assign(n, 0);
    d.scale.assign(R, 0.0f); d.sign.assign(d.bitset, 0); d.planes.assign(d.bitset * NB, 0);

    for (std::uint32_t b = 0; b < blocks; ++b) {
        const std::uint32_t s = b * B, e = std::min(s + B, std::uint32_t(n));
        double mx = 0; for (std::uint32_t i = s; i < e; ++i) mx = std::max(mx, std::fabs(double(W[i])));
        d.alpha[b] = float(mx);
    }
    for (std::size_t i = 0; i < n; ++i) {
        const double a = d.alpha[i / B], w = W[i];
        const std::uint8_t L = (w > a * 0.5) ? 2 : (w < -a * 0.5 ? 1 : 0);
        d.tern[i / 5] = static_cast<std::uint8_t>(d.tern[i / 5] + L * kPow3[i % 5]);
        d.base[i] = float((double(L) - 1.0) * a);
        d.resid[i] = float(w - d.base[i]);
    }
    double ss = 0; for (std::size_t i = 0; i < n; ++i) ss += double(d.resid[i]) * d.resid[i];
    const double thr = sigma * std::sqrt(ss / double(n));
    for (std::size_t i = 0; i < n; ++i)
        if (std::fabs(double(d.resid[i])) > thr) d.is_out[i] = 1;
    d.outliers = 0;
    for (std::size_t i = 0; i < n; ++i)
        if (d.is_out[i]) { d.o_col.push_back(std::uint32_t(i)); d.o_val.push_back(d.resid[i]); ++d.outliers; }
    for (std::uint32_t r = 0; r < R; ++r) {
        double mx = 0;
        for (std::uint32_t c = 0; c < C; ++c)
            if (!d.is_out[r * C + c]) mx = std::max(mx, std::fabs(double(d.resid[r * C + c])));
        d.scale[r] = float(mx);
    }
    const std::uint32_t qmax = (1u << NB) - 1;
    for (std::uint32_t r = 0; r < R; ++r) {
        const float sc = d.scale[r];
        for (std::uint32_t c = 0; c < C; ++c) {
            const std::size_t i = std::size_t(r) * C + c;
            if (d.is_out[i]) continue;
            double rv = sc > 0 ? double(d.resid[i]) / double(sc) : 0.0;
            long q = std::lround(rv * double(qmax));
            if (q < 0) q = 0; if (q > long(qmax)) q = long(qmax);
            const std::uint32_t u = std::uint32_t(q);
            if (u & 1u) d.sign[i >> 3] |= static_cast<std::uint8_t>(1u << (i & 7));
            for (std::uint32_t p = 0; p < NB; ++p)
                if ((u >> (NB - 1 - p)) & 1u)
                    d.planes[p * d.bitset + (i >> 3)] |= static_cast<std::uint8_t>(1u << (i & 7));
        }
    }
}

// bytes, matching decoda.cpp accounting for a given state
static std::size_t dec_bytes(const Dec& d, std::uint32_t planes, bool sign_and_scale) {
    std::size_t b = (d.tern.size()) + d.alpha.size() * 4
                  + d.o_col.size() * 2 + d.o_val.size() * 4;
    if (planes) b += d.bitset + d.scale.size() * 4 + d.bitset * planes;
    (void)sign_and_scale;
    return b;
}

static double dec_err(const Dec& d, const std::vector<float>& W, std::uint32_t planes) {
    const std::uint32_t R = d.rows, C = d.cols;
    const std::uint32_t qmax = (1u << d.bits) - 1;
    double num = 0, den = 0;
    for (std::uint32_t r = 0; r < R; ++r)
        for (std::uint32_t c = 0; c < C; ++c) {
            const std::size_t i = std::size_t(r) * C + c;
            double got = d.base[i];
            if (d.is_out[i]) got += d.resid[i];
            else if (planes) {
                std::uint32_t q = 0;
                for (std::uint32_t p = 0; p < planes; ++p)
                    if (d.planes[p * d.bitset + (i >> 3)] & (1u << (i & 7))) q = (q << 1) | 1u;
                q <<= (d.bits - planes);
                const double v = double(d.scale[r]) * (double(q) / double(qmax));
                got += (d.sign[i >> 3] & (1u << (i & 7))) ? -v : v;
            }
            const double dd = got - double(W[i]); num += dd * dd; den += double(W[i]) * double(W[i]);
        }
    return std::sqrt(num / den);
}

// ---- per-block uniform scalar baseline (SSE-optimal step), validated earlier ----
static double scalar_err(const std::vector<float>& W, int bits, int block, double* bpb) {
    const int levels = (1 << bits) - 1;
    const std::size_t nb = (W.size() + block - 1) / block;
    const std::size_t scales_b = nb * 2 * 8;
    *bpb = double(bits) + double(scales_b) / double(W.size());
    double num = 0, den = 0;
    for (std::size_t b = 0; b < nb; ++b) {
        const std::size_t s = b * block, e = std::min(s + block, W.size());
        float mn = W[s], mx = W[s];
        for (std::size_t i = s; i < e; ++i) { mn = std::min(mn, W[i]); mx = std::max(mx, W[i]); }
        const double range = double(mx) - double(mn);
        if (range <= 0) continue;
        double best = range / levels, bse = 1e300;
        for (double f = 0.60; f <= 1.45; f += 0.01) {
            const double st = range / levels * f;
            double sse = 0;
            for (std::size_t i = s; i < e; ++i) {
                double q = std::floor((double(W[i]) - double(mn)) / st + 0.5);
                if (q < 0) q = 0; if (q > levels) q = levels;
                const double dd = double(mn) + q * st - double(W[i]); sse += dd * dd;
            }
            if (sse < bse) { bse = sse; best = st; }
        }
        for (std::size_t i = s; i < e; ++i) {
            double q = std::floor((double(W[i]) - double(mn)) / best + 0.5);
            if (q < 0) q = 0; if (q > levels) q = levels;
            const double g = double(mn) + q * best;
            const double dd = g - double(W[i]); num += dd * dd; den += double(W[i]) * double(W[i]);
        }
    }
    return std::sqrt(num / den);
}

int main(int argc, char** argv) {
    const std::string dir = argc > 1 ? argv[1] : ".";
    std::ifstream f(dir + "/blk_9_ffn_gate_exps_weight.f32", std::ios::binary | std::ios::ate);
    if (!f) { std::printf("MISSING\n"); return 1; }
    const auto n = std::size_t(f.tellg()) / sizeof(float); f.seekg(0);
    std::vector<float> W(n); f.read((char*)W.data(), std::streamsize(n * 4));
    W.resize(524288);

    Dec d; d.rows = 256; d.cols = 2048; d.block = 64; d.bits = 12;
    dec_encode(d, W, 3.0f);

    std::printf("RAWRXD_RATEMATCHED_001\n");
    std::printf("256x2048 = %zu weights, block=%u, residual_bits=%u, outliers=%zu\n\n",
                W.size(), d.block, d.bits, d.outliers);

    std::printf("WHAT PLANE 0 IS  (decoda.cpp:367 `if (!planes) return 0`)\n");
    std::printf("   planes=0 -> magnitude reconstruction is identically 0\n");
    std::printf("   plane-0 bytes = ternary + alpha + outlier CSR only:\n");
    std::printf("     ternary payload %8zu B (%.3f b/w)\n", d.tern.size(),
                double(d.tern.size()) * 8 / double(W.size()));
    std::printf("     alpha table    %8zu B (%.3f b/w)\n", d.alpha.size() * 4,
                double(d.alpha.size() * 4) * 8 / double(W.size()));
    std::printf("     outlier CSR    %8zu B (%.3f b/w)\n",
                d.o_col.size() * 2 + d.o_val.size() * 4,
                double(d.o_col.size() * 2 + d.o_val.size() * 4) * 8 / double(W.size()));
    std::printf("     magnitude      %8zu B (%.3f b/w)  <-- ZERO\n", std::size_t(0), 0.0);

    std::printf("\nA) DECODA, TOTAL bytes and MAGNITUDE bytes separated\n");
    std::printf("   planes  total_b/w  mag_b/w  mag-only b/w   rel_L2\n");
    for (std::uint32_t p = 0; p <= 5; ++p) {
        const std::size_t tb = dec_bytes(d, p, p != 0);
        const std::size_t mb = p ? (d.bitset + d.scale.size() * 4 + d.bitset * p) : 0;
        std::printf("   %5u  %10.4f  %8.4f  %13.4f  %10.6f\n", p,
                    double(tb) * 8 / double(W.size()), double(mb) * 8 / double(W.size()),
                    double(mb) * 8 / double(W.size()), dec_err(d, W, p));
    }

    std::printf("\nB) PER-BLOCK UNIFORM SCALAR (SSE-optimal step, block=64)\n");
    std::printf("   bits    total_b/w   rel_L2\n");
    std::vector<std::pair<double,double>> sc;
    for (int b = 1; b <= 8; ++b) {
        double bpb = 0.0;
        const double e = scalar_err(W, b, 64, &bpb);
        sc.push_back({double(bpb), e});
        std::printf("   %4d  %10.4f  %10.6f\n", b, bpb, e);
    }

    std::printf("\nC) RATE-MATCHED: compare at equal MAGNITUDE information\n");
    std::printf("   decoda needs ternary+outliers FIRST (%.2f b/w) before ANY plane adds info\n",
                double(dec_bytes(d, 0, false)) * 8 / double(W.size()));
    std::printf("\n   scalar @ 1 bit      rel_L2 = %.6f\n", sc[0].second);
    std::printf("   decoda @ 0 planes   rel_L2 = %.6f   (magnitude bits = 0)\n", dec_err(d, W, 0));
    std::printf("\n   the honest comparison is decoda planes vs scalar at (mag_b/w + ternary overhead):\n");
    std::printf("   %-10s %-12s %-12s\n", "planes", "decoda_total", "decoda_err");
    for (std::uint32_t p = 0; p <= 3; ++p)
        std::printf("   %-10u %-12.4f %-12.6f\n", p,
                    double(dec_bytes(d, p, p != 0)) * 8 / double(W.size()), dec_err(d, W, p));

    std::printf("\nD) THE REAL QUESTION: how much magnitude does Decoda need to match scalar?\n");
    for (std::uint32_t p = 1; p <= 5; ++p) {
        const double e = dec_err(d, W, p);
        // scalar bits needed to beat it
        int need = -1;
        for (int b = 1; b <= 8; ++b) if (sc[b - 1].second < e) { need = b; break; }
        std::printf("   decoda planes=%u err=%.6f  ->  scalar needs %d bits (%.4f b/w)\n",
                    p, e, need, need > 0 ? sc[need - 1].first : 0.0);
    }
    return 0;
}
