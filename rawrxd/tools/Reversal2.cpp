// RAWRXD_REVERSAL2_001
//
// Reversal rung 2. Rung 1 (sign + per-block max scale + MSB bitplanes) failed
// because max/rms = 8.74, so ~3 bits of every block's code range are empty and
// the planes refine bin edges instead of occupied bins. Measured error ROSE
// from plane 3 onward and the S/2^k bound missed by 14x-90x.
//
// Rung 2 keeps the sign-magnitude + progressive bitplane shape and reverses the
// MAPPING: quantize a companded magnitude instead of a linear one, so the code
// domain is uniformly occupied before the bits are sliced.
//
//   w  ->  u = |w| / S_block  ->  c = log1p(K*u)/log1p(K)  ->  12-bit code
//   ->  MSB-first bitplanes  ->  top-k retained, mid-bin reconstructed
//
// K is the clip ratio and is swept. Small K = aggressive companding.

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

struct Cmp {
    std::uint32_t block, bits;
    double K;
    std::vector<float> scale;              // per block, fp16-equivalent
    std::vector<std::uint8_t> sign, planes;
    std::size_t bitset, blocks;
    std::uint32_t qmax;
};

static void enc(Cmp& c, const std::vector<float>& W) {
    const std::size_t n = W.size();
    c.bitset = (n + 7) / 8;
    c.blocks = (n + c.block - 1) / c.block;
    c.scale.assign(c.blocks, 0.0f);
    c.sign.assign(c.bitset, 0);
    c.planes.assign(c.bitset * c.bits, 0);
    c.qmax = (1u << c.bits) - 1;
    const double lk = std::log1p(c.K);

    for (std::size_t b = 0; b < c.blocks; ++b) {
        const std::size_t s = b * c.block, e = std::min(s + c.block, n);
        double mx = 0.0;
        for (std::size_t idx = s; idx < e; ++idx) mx = std::max(mx, std::fabs(double(W[idx])));
        c.scale[b] = float(mx);
    }
    for (std::size_t idx = 0; idx < n; ++idx) {
        const float S = c.scale[idx / c.block];
        if (S > 0 && W[idx] < 0.0f) c.sign[idx >> 3] |= static_cast<std::uint8_t>(1u << (idx & 7));
        const double u = S > 0 ? std::min(1.0, std::fabs(double(W[idx])) / double(S)) : 0.0;
        const double comp = std::log1p(c.K * u) / lk;          // 0..1, occupied
        const std::uint32_t q = std::uint32_t(std::lround(comp * double(c.qmax)));
        for (std::uint32_t p = 0; p < c.bits; ++p)
            if ((q >> (c.bits - 1 - p)) & 1u)
                c.planes[p * c.bitset + (idx >> 3)] |= static_cast<std::uint8_t>(1u << (idx & 7));
    }
}

static double err(const Cmp& c, const std::vector<float>& W, std::uint32_t planes) {
    const double lk = std::log1p(c.K);
    double num = 0, den = 0;
    for (std::size_t idx = 0; idx < W.size(); ++idx) {
        std::uint32_t q = 0;
        for (std::uint32_t p = 0; p < planes; ++p)
            if (c.planes[p * c.bitset + (idx >> 3)] & (1u << (idx & 7))) q = (q << 1) | 1u;
        q <<= (c.bits - planes);
        const double cc = double(q) / double(c.qmax);
        const double u = std::expm1(cc * lk) / c.K;           // inverse companding
        double g = double(c.scale[idx / c.block]) * u;
        if (c.sign[idx >> 3] & (1u << (idx & 7))) g = -g;
        const double d = g - double(W[idx]); num += d * d; den += double(W[idx]) * double(W[idx]);
    }
    return std::sqrt(num / den);
}

static double bytes(const Cmp& c, std::uint32_t planes) {
    return double(c.sign.size() + c.scale.size() * 2 + c.bitset * planes);
}

int main(int argc, char** argv) {
    const std::string dir = argc > 1 ? argv[1] : ".";
    auto W = load(dir);
    if (W.empty()) { std::printf("MISSING\n"); return 1; }
    W.resize(524288);

    std::printf("RAWRXD_REVERSAL2_001   sign + per-block scale + COMPANDED magnitude bitplanes\n");
    std::printf("reference: current decoda plane0 = 0.388937 @ 2.70 b/w, plane2 = 0.170473 @ 5.72 b/w\n\n");

    // occupancy check: how uniform is the code domain under each K?
    {
        std::printf("CODE OCCUPANCY (fraction of 12-bit codes used, per block avg)\n");
        std::printf("   K        occupancy   plane0_err  plane3_err\n");
        for (double K : {1.0, 3.0, 7.0, 15.0, 31.0, 63.0, 255.0, 1023.0}) {
            Cmp c; c.block = 256; c.bits = 12; c.K = K; enc(c, W);
            // count distinct codes per block
            double occ = 0.0;
            const double lk = std::log1p(K);
            for (std::size_t b = 0; b < c.blocks; ++b) {
                const std::size_t s = b * c.block, e = std::min(s + c.block, W.size());
                std::vector<std::uint8_t> seen(4096, 0); std::size_t d = 0;
                for (std::size_t idx = s; idx < e; ++idx) {
                    const double u = c.scale[b] > 0
                        ? std::min(1.0, std::fabs(double(W[idx])) / double(c.scale[b])) : 0.0;
                    const std::uint32_t q = std::uint32_t(std::lround(std::log1p(K * u) / lk * double(c.qmax)));
                    if (!seen[q]) { seen[q] = 1; ++d; }
                }
                occ += double(d);
            }
            occ /= double(c.blocks);
            std::printf("   %-8.0f %8.1f    %10.6f  %10.6f\n", K, occ, err(c, W, 0), err(c, W, 3));
        }
    }

    // best K, full curve
    double bestK = 0, bestE = 1e300;
    for (double K = 1.0; K <= 1023.0; K *= 1.5) {
        Cmp c; c.block = 256; c.bits = 12; c.K = K; enc(c, W);
        const double e3 = err(c, W, 3);
        if (e3 < bestE) { bestE = e3; bestK = K; }
    }
    {
        Cmp c; c.block = 256; c.bits = 12; c.K = bestK; enc(c, W);
        std::printf("\nBEST K = %.0f  (plane-3 err %.6f)\n", bestK, bestE);
        std::printf("\n   planes   b/w       rel_L2     monotone?\n");
        double prev = -1; bool mono = true;
        for (std::uint32_t p = 0; p <= 6; ++p) {
            const double e = err(c, W, p);
            std::printf("   %5u   %8.4f  %10.6f   %s\n", p, bytes(c, p) * 8 / double(W.size()), e,
                        (prev > 0 && e > prev * 1.0001) ? "NO -- not progressive" : "yes");
            if (prev > 0 && e > prev * 1.0001) mono = false;
            prev = e;
        }
        std::printf("   MONOTONE_DECREASING=%d\n", mono ? 1 : 0);
        std::printf("   vs current decoda: plane2 %.6f@5.72 | this %.6f@%.4f\n",
                    0.170473, err(c, W, 2), bytes(c, 2) * 8 / double(W.size()));
    }

    // does it ever beat the scalar baseline at matched rate?
    std::printf("\nMATCHED-RATE vs per-64-block uniform scalar\n");
    {
        Cmp c; c.block = 256; c.bits = 12; c.K = bestK; enc(c, W);
        struct S { double b, e; };
        const S sc[] = {{1.25,0.838383},{2.25,0.368743},{3.25,0.172610},
                        {4.25,0.067671},{5.25,0.033964},{6.25,0.016365}};
        std::printf("   target_err   scalar_b/w   companded_b/w  verdict\n");
        for (const auto& t : sc) {
            double bb = 0, be = 1e300;
            for (std::uint32_t p = 0; p <= 12; ++p) {
                const double b = bytes(c, p) * 8 / double(W.size());
                if (b <= t.b + 1e-9 && err(c, W, p) < be) { be = err(c, W, p); bb = b; }
            }
            std::printf("   %-11.6f %-12.4f %-14.4f %s\n", t.e, t.b, bb,
                        (be < t.e) ? "companded wins" : "scalar wins");
        }
    }
    return 0;
}
