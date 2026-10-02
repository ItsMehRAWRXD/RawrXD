// RAWRXD_MSB_INJECTION_001
//
// Rung 3. Both reversals failed for one measured reason: the code is 12 bits
// wide but only ~102 of 4096 codes are occupied per 256-element block. Every
// plane above the occupancy depth is a bit of a constant, which is why error
// ROSE past plane 2 instead of falling.
//
// "Force MSB-first structure injection" = match the code width to the occupancy
// and make the levels match the value density, so each retained plane actually
// halves the error. Concretely:
//   - per-block scale S_b (unchanged, that part was never the problem)
//   - a GLOBAL monotone companding curve fitted to the empirical distribution of
//     u = |w|/S_b  (Lloyd-style, not log1p)
//   - quantize u through that curve into 2^bits levels, bits <= occupancy depth
//   - emit MSB-first planes of the LEVEL INDEX
//   - the level table is global and shared, so it costs 2^bits * 2 bytes once
//
// The question: does the curve become monotone, and where does it land
// against the per-64-block uniform scalar and against current Decoda?

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

struct Inj {
    std::uint32_t block, bits;
    std::vector<float> scale;      // per block
    std::vector<float> levels;     // GLOBAL companding table: bits_per_weight 2^bits entries
    std::vector<std::uint8_t> sign, planes;
    std::size_t bitset, blocks;
    std::uint32_t qmax;
};

// Fit a global monotone table T[0..L-1] mapping level index -> normalized
// magnitude, minimising squared error over the pooled u distribution.
static void fit_levels(const std::vector<float>& u, int L, std::vector<float>& T) {
    std::vector<float> s(u);
    std::sort(s.begin(), s.end());
    T.assign(L, 0.0f);
    for (int i = 0; i < L; ++i)
        T[i] = s[std::min(s.size() - 1, std::size_t(double(i) * s.size() / L))];
    for (int it = 0; it < 40; ++it) {
        std::vector<double> sum(L, 0.0);
        std::vector<std::size_t> cnt(L, 0);
        for (float x : u) {
            // nearest level
            int best = 0; double bd = std::fabs(double(x) - T[0]);
            for (int i = 1; i < L; ++i) {
                const double d = std::fabs(double(x) - T[i]);
                if (d < bd) { bd = d; best = i; }
            }
            sum[best] += x; ++cnt[best];
        }
        for (int i = 0; i < L; ++i) if (cnt[i]) T[i] = float(sum[i] / double(cnt[i]));
        for (int i = 1; i < L; ++i) if (T[i] < T[i - 1]) T[i] = T[i - 1];
    }
}

static void enc(Inj& c, const std::vector<float>& W) {
    const std::size_t n = W.size();
    c.bitset = (n + 7) / 8;
    c.blocks = (n + c.block - 1) / c.block;
    c.scale.assign(c.blocks, 0.0f);
    c.sign.assign(c.bitset, 0);
    c.planes.assign(c.bitset * c.bits, 0);
    c.qmax = (1u << c.bits) - 1;

    for (std::size_t b = 0; b < c.blocks; ++b) {
        const std::size_t s = b * c.block, e = std::min(s + c.block, n);
        double mx = 0;
        for (std::size_t idx = s; idx < e; ++idx) mx = std::max(mx, std::fabs(double(W[idx])));
        c.scale[b] = float(mx);
    }
    // pooled u distribution -> global level table
    std::vector<float> u;
    u.reserve(n);
    for (std::size_t idx = 0; idx < n; ++idx) {
        const float S = c.scale[idx / c.block];
        u.push_back(S > 0 ? float(std::min(1.0f, std::fabs(W[idx]) / S)) : 0.0f);
    }
    fit_levels(u, int(c.qmax) + 1, c.levels);

    for (std::size_t idx = 0; idx < n; ++idx) {
        if (c.scale[idx / c.block] > 0 && W[idx] < 0.0f)
            c.sign[idx >> 3] |= static_cast<std::uint8_t>(1u << (idx & 7));
        int best = 0; double bd = std::fabs(double(u[idx]) - double(c.levels[0]));
        for (int i = 1; i <= int(c.qmax); ++i) {
            const double d = std::fabs(double(u[idx]) - double(c.levels[i]));
            if (d < bd) { bd = d; best = i; }
        }
        const std::uint32_t q = std::uint32_t(best);
        for (std::uint32_t p = 0; p < c.bits; ++p)
            if ((q >> (c.bits - 1 - p)) & 1u)
                c.planes[p * c.bitset + (idx >> 3)] |= static_cast<std::uint8_t>(1u << (idx & 7));
    }
}

static double err(const Inj& c, const std::vector<float>& W, std::uint32_t planes) {
    double num = 0, den = 0;
    for (std::size_t idx = 0; idx < W.size(); ++idx) {
        std::uint32_t q = 0;
        for (std::uint32_t p = 0; p < planes; ++p)
            if (c.planes[p * c.bitset + (idx >> 3)] & (1u << (idx & 7))) q = (q << 1) | 1u;
        q <<= (c.bits - planes);
        const double u = double(c.levels[q]);
        double g = double(c.scale[idx / c.block]) * u;
        if (c.sign[idx >> 3] & (1u << (idx & 7))) g = -g;
        const double d = g - double(W[idx]); num += d * d; den += double(W[idx]) * double(W[idx]);
    }
    return std::sqrt(num / den);
}

static double bytes(const Inj& c, std::uint32_t planes) {
    return double(c.sign.size() + c.scale.size() * 2 + c.bitset * planes);
}

int main(int argc, char** argv) {
    const std::string dir = argc > 1 ? argv[1] : ".";
    auto W = load(dir);
    if (W.empty()) { std::printf("MISSING\n"); return 1; }
    W.resize(524288);

    std::printf("RAWRXD_MSB_INJECTION_001  sign + per-block scale + Lloyd-shaped levels, MSB planes\n");
    std::printf("reference: decoda plane0 0.388937@2.70  plane2 0.170473@5.72\n");
    std::printf("           scalar per-64: 2.25->0.368743  3.25->0.172610  4.25->0.067671\n\n");

    std::printf("   bits   levels   table_B   curve at best b/w    monotone?\n");
    double bestErr = 1e300; unsigned bestB = 0, bestP = 0; double bestRate = 0;
    for (unsigned bits = 4; bits <= 10; ++bits) {
        Inj c; c.block = 256; c.bits = bits; enc(c, W);
        // find the b/w at which this config beats the scalar 3-bit point
        double prev = -1; bool mono = true; double atBest = 0;
        for (std::uint32_t p = 0; p <= bits; ++p) {
            const double e = err(c, W, p);
            if (prev > 0 && e > prev * 1.0001) mono = false;
            if (bytes(c, p) * 8 / double(W.size()) <= 3.25 && e < atBest) atBest = e;
            if (e < bestErr) { bestErr = e; bestB = bits; bestP = p; bestRate = bytes(c, p) * 8 / double(W.size()); }
            prev = e;
        }
        std::printf("   %4u   %6u   %7.1f   %-22.6f %s\n", bits, (1u << bits),
                    double((1u << bits)) * 2.0, atBest, mono ? "yes" : "NO");
    }
    std::printf("\n   BEST: bits=%u planes=%u  err=%.6f @ %.4f b/w\n", bestB, bestP, bestErr, bestRate);
    std::printf("   scalar 3-bit reference: 0.172610 @ 3.2500 b/w\n");
    std::printf("   decoda  plane-2        : 0.170473 @ 5.7200 b/w\n");
    std::printf("   VERDICT: %s\n", bestErr < 0.172610 ? "MSB INJECTION BEATS SCALAR"
                        : (bestErr < 0.170473 ? "beats decoda plane-2" : "still loses"));

    {
        Inj c; c.block = 256; c.bits = bestB; enc(c, W);
        std::printf("\nFULL CURVE at bits=%u\n   planes   b/w       rel_L2     ratio\n", bestB);
        double prev = -1;
        for (std::uint32_t p = 0; p <= bestB; ++p) {
            const double e = err(c, W, p);
            std::printf("   %5u   %8.4f  %10.6f  %8.3f\n", p,
                        bytes(c, p) * 8 / double(W.size()), e, prev > 0 ? prev / e : 0.0);
            prev = e;
        }
    }
    return 0;
}
