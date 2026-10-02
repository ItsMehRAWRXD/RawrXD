// RAWRXD_RATEMATCH_001  (corrected)
//
// A Lagrange allocator is: per block, emit plane p iff its marginal distortion
// reduction exceeds lambda * (rate of one plane-slot). Sweeping lambda traces the
// adaptive rate-distortion curve, which can then be compared point-for-point
// against the uniform curve at IDENTICAL rate.
//
// The first attempt sorted all (block, plane) candidates by global gain and took
// the top N. That starves every block's deep planes, because a block's highest
// gain is at large p, which the contiguity rule then rejects. Result: the same
// error at every budget and a nonsense 1507 b/w unconstrained rate. Both fixed.

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

#define private public
#include "decoda/decoda.hpp"
#undef private

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
    const std::uint32_t R = 256, C = 2048, BLOCK = 64, BITS = 12, KMAX = 10;
    const std::uint32_t qmax = (1u << BITS) - 1;
    const std::size_t nb = (n + BLOCK - 1) / BLOCK;

    decoda::BuildOptions o;
    o.block_size = BLOCK; o.residual_bits = BITS; o.outlier_sigma = 3.0f;
    o.store_exact_f32 = false;
    auto T = decoda::Tensor::encode(W.data(), R, C, o);

    std::vector<float> base(n);
    for (std::uint32_t r = 0; r < R; ++r)
        for (std::uint32_t c = 0; c < C; ++c)
            base[std::size_t(r) * C + c] = T.reconstructedWeight(r, c, decoda::FidelityState{});

    auto prefix = [&](std::size_t i, std::uint32_t p) {
        std::uint32_t q = 0;
        for (std::uint32_t pp = 0; pp < p; ++pp)
            if (T.residual_planes_[pp * bitset + (i >> 3)] & (1u << (i & 7))) q = (q << 1) | 1u;
        q <<= (BITS - p);
        const float sc = T.residual_scale_[std::uint32_t(i / C)];
        const float v = sc * (float(q) / float(qmax));
        return (T.residual_sign_[i >> 3] & (1u << (i & 7))) ? -v : v;
    };

    // per-block, per-plane marginal SSE reduction, and the per-block prefix SSE
    std::vector<std::vector<double>> dD(nb, std::vector<double>(KMAX + 1, 0.0));
    std::vector<std::vector<double>> sse(nb, std::vector<double>(KMAX + 1, 0.0));
    for (std::size_t b = 0; b < nb; ++b) {
        const std::size_t s = b * BLOCK, e = std::min(s + BLOCK, n);
        for (std::uint32_t p = 0; p <= KMAX; ++p) {
            double acc = 0.0;
            for (std::size_t i = s; i < e; ++i) {
                const double g = double(base[i]) + double(prefix(i, p));
                const double d = g - double(W[i]); acc += d * d;
            }
            sse[b][p] = acc;
        }
        for (std::uint32_t p = 1; p <= KMAX; ++p) dD[b][p] = sse[b][p - 1] - sse[b][p];
    }

    // Lagrange: per block emit planes 1..k_j while dD[b][p] >= lambda * slot
    const double slot = 1.0;                 // one plane-slot per block = 1 plane
    auto alloc = [&](double lambda) {
        std::vector<std::uint32_t> allow(nb, 0);
        for (std::size_t b = 0; b < nb; ++b)
            for (std::uint32_t p = 1; p <= KMAX; ++p) {
                if (dD[b][p] >= lambda * slot) allow[b] = p;
                else break;
            }
        return allow;
    };
    auto slots_of = [&](const std::vector<std::uint32_t>& a) {
        std::size_t s = 0; for (std::uint32_t x : a) s += x; return s;
    };
    auto err_of = [&](const std::vector<std::uint32_t>& a) {
        double num = 0, den = 0;
        for (std::size_t b = 0; b < nb; ++b) {
            const std::uint32_t p = a[b];
            const std::size_t s = b * BLOCK, e = std::min(s + BLOCK, n);
            for (std::size_t i = s; i < e; ++i) {
                const double g = double(base[i]) + double(prefix(i, p));
                const double d = g - double(W[i]); num += d * d; den += double(W[i]) * double(W[i]);
            }
        }
        return std::sqrt(num / den);
    };

    const double base_bytes = double(bitset) + T.residual_scale_.size() * 4
                            + T.stats().ternary_bytes
                            + T.outlier_value_.size() * 4 + T.outlier_col_.size() * 2;
    // slots is already a tensor-wide BIT count (sum of per-block plane emissions,
    // each covering BLOCK elements). Do NOT multiply by bitset again -- that was
    // an 8x-1024x units bug that made uniform-3 print 1027 b/w instead of 3.76.
    auto rate_of = [&](std::size_t slots) {
        return (base_bytes + double(slots) / 8.0) * 8 / double(n);
    };

    std::printf("RAWRXD_RATEMATCH_001  corrected: per-block monotonic Lagrange\n");
    std::printf("block=%u bits=%u base=%.4f b/w  blocks=%zu\n\n",
                BLOCK, BITS, base_bytes * 8 / double(n), nb);

    // uniform curve
    std::printf("UNIFORM CURVE\n%-6s %-10s %-12s\n", "k", "b/w", "rel_L2");
    std::vector<std::pair<double,double>> uni;
    for (std::uint32_t k = 1; k <= KMAX; ++k) {
        std::vector<std::uint32_t> a(nb, k);
        const double r = rate_of(nb * k), e = err_of(a);
        uni.push_back({r, e});
        std::printf("%-6u %-10.4f %-12.6f\n", k, r, e);
    }

    // adaptive curve via lambda sweep
    std::printf("\nADAPTIVE CURVE (lambda sweep)\n%-12s %-8s %-10s %-12s\n",
                "lambda", "slots", "b/w", "rel_L2");
    struct P { double r, e; };
    std::vector<P> ad;
    std::vector<double> lambdas;
    for (double l = 1e-12; l <= 1e-3; l *= 3.0) lambdas.push_back(l);   // must start > 0: 0.0 *= 2.0 loops forever
    std::sort(lambdas.begin(), lambdas.end());
    for (double l : lambdas) {
        auto a = alloc(l);
        const std::size_t sl = slots_of(a);
        if (sl == 0) continue;
        const double r = rate_of(sl), e = err_of(a);
        ad.push_back({r, e});
        std::printf("%-12.4g %-8zu %-10.4f %-12.6f\n", l, sl, r, e);
    }

    // SAME-RATE comparison: interpolate uniform error at each adaptive rate
    std::printf("\nSAME-RATE COMPARISON (uniform interpolated to adaptive's rate)\n");
    std::printf("%-10s %-14s %-14s %-10s\n", "b/w", "adaptive err", "uniform err", "gain%");
    std::sort(ad.begin(), ad.end(), [](const P& x, const P& y) { return x.r < y.r; });
    std::sort(uni.begin(), uni.end(),
              [](const std::pair<double,double>& x, const std::pair<double,double>& y) {
                  return x.first < y.first; });
    auto interp = [&](double r) {
        if (r <= uni.front().first) return uni.front().second;
        if (r >= uni.back().first) return uni.back().second;
        for (std::size_t i = 1; i < uni.size(); ++i)
            if (r <= uni[i].first) {
                const double t = (r - uni[i - 1].first) / (uni[i].first - uni[i - 1].first);
                return uni[i - 1].second + t * (uni[i].second - uni[i - 1].second);
            }
        return uni.back().second;
    };
    double best = -1e9;
    for (const auto& p : ad) {
        const double ue = interp(p.r);
        const double gain = 100.0 * (ue - p.e) / ue;
        best = std::max(best, gain);
        std::printf("%-10.4f %-14.6f %-14.6f %+9.2f\n", p.r, p.e, ue, gain);
    }
    std::printf("\nBEST SAME-RATE GAIN: %+.2f%%\n", best);
    std::printf("the earlier '30%%' compared adaptive at 0.2578 against uniform-8 at 0.3674,\n");
    std::printf("which is a different rate. this is the same rate.\n");
    return 0;
}
