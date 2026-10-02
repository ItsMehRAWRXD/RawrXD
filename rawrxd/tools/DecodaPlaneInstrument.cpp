// RAWRXD_OPTIMIZATION_NEXT_001 -- instrumented against the REAL Decoda encoder.
//
// The first two attempts replicated decoda.cpp by hand and produced invalid
// numbers (rel_L2 2.52 at plane 0 instead of 0.389, and error RISING with
// plane count, which is impossible for a progressive scheme). Cause: the hand
// copy used a crude +/-alpha threshold for the ternary base where Decoda uses an
// SSE-optimal support, and a different outlier threshold. Replicating the
// encoder was the wrong instrument.
//
// This compiles the real src/decoda.cpp and reads its members directly via the
// `private -> public` diagnostic redefinition. Nothing in the drop is modified.
//
// Three numbers, as requested:
//   1. var(S) across blocks  (residual_scale_, granularity from the source)
//   2. H[plane p] for p = 0..3, MSB-first
//   3. block size in use

// Pull in every standard header BEFORE redefining `private`, otherwise the
// C++ standard library headers trip C1189 ("forbids macroizing private").
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

// Now expose Decoda's internals without modifying the drop.
#define private public
#include "decoda/decoda.hpp"
#undef private

static std::vector<float> load(const std::string& p) {
    std::ifstream f(p, std::ios::binary | std::ios::ate);
    if (!f) return {};
    const auto n = std::size_t(f.tellg()) / sizeof(float);
    f.seekg(0);
    std::vector<float> v(n);
    f.read(reinterpret_cast<char*>(v.data()), std::streamsize(n * sizeof(float)));
    return v;
}

static double binH(std::uint64_t ones, std::uint64_t tot) {
    if (!tot) return 0.0;
    const double p = double(ones) / double(tot);
    if (p <= 0.0 || p >= 1.0) return 0.0;
    return -(p * std::log2(p) + (1.0 - p) * std::log2(1.0 - p));
}

int main(int argc, char** argv) {
    const std::string dir = argc > 1 ? argv[1] : ".";
    auto W = load(dir + "/blk_9_ffn_gate_exps_weight.f32");
    if (W.empty()) { std::printf("MISSING\n"); return 1; }
    const std::uint32_t R = 256, C = 2048;
    W.resize(std::size_t(R) * C);

    decoda::BuildOptions o;
    o.block_size = 64; o.residual_bits = 12; o.outlier_sigma = 3.0f;
    o.store_exact_f32 = false;
    auto T = decoda::Tensor::encode(W.data(), R, C, o);
    const std::size_t n = W.size();
    const std::size_t bitset = (n + 7) / 8;
    const std::size_t NB = T.residual_bits_;

    std::printf("RAWRXD_OPTIMIZATION_NEXT_001  (real decoda.cpp, internals read directly)\n");
    std::printf("shape=%ux%u  block_size=%u  residual_bits=%u  outliers=%llu (%.4f%%)\n\n",
                R, C, T.block_size_, unsigned(NB),
                (unsigned long long)T.outlier_value_.size(),
                100.0 * double(T.outlier_value_.size()) / double(n));

    // ---------- 1. scale dispersion ----------
    {
        std::printf("1. SCALE DISPERSION\n");
        // ternary alpha: per block of block_size_
        const std::size_t blocks = T.alpha_.size();
        double amn = 1e300, amx = 0, a1 = 0, a2 = 0;
        for (float a : T.alpha_) { amn = std::min(amn, double(a)); amx = std::max(amx, double(a));
                                   a1 += a; a2 += double(a) * a; }
        const double am = a1 / double(blocks);
        std::printf("   ternary alpha  per-%u-block : max/min=%9.4g  stddev/mean=%.4f  n=%zu\n",
                    T.block_size_, amx / amn,
                    std::sqrt(std::max(0.0, a2 / double(blocks) - am * am)) / (am > 0 ? am : 1), blocks);
        // residual scale: find its granularity from the source
        std::printf("   residual_scale_ size = %zu  -> granularity = %s\n",
                    T.residual_scale_.size(),
                    T.residual_scale_.size() == T.rows_ ? "per ROW" :
                    (T.residual_scale_.size() == blocks ? "per BLOCK" : "other"));
        double smn = 1e300, smx = 0, s1 = 0, s2 = 0;
        for (float s : T.residual_scale_) { smn = std::min(smn, double(s)); smx = std::max(smx, double(s));
                                              s1 += s; s2 += double(s) * s; }
        const double sn = double(T.residual_scale_.size()), sm = s1 / sn;
        std::printf("   residual scale  per ROW      : max/min=%9.4g  stddev/mean=%.4f\n",
                    smx / smn, std::sqrt(std::max(0.0, s2 / sn - sm * sm)) / (sm > 0 ? sm : 1));
        std::printf("   verdict: %s\n", (smx / smn) < 5.0
            ? "residual scale is TIGHT -> candidate 1 (scale contamination) is NOT supported"
            : "scale is dispersed -> candidate 1 is live");
    }

    // ---------- 2. per-plane entropy, MSB-first ----------
    {
        std::printf("\n2. PER-PLANE ENTROPY (plane p = bit %zu-1-p, as decoda.cpp:250 stores it)\n",
                    NB);
        std::printf("   plane     H        frac_ones   reading\n");
        for (std::size_t p = 0; p < 6; ++p) {
            std::uint64_t ones = 0;
            const std::uint8_t* pl = T.residual_planes_.data() + p * bitset;
            for (std::size_t i = 0; i < n; ++i)
                if (pl[i >> 3] & (1u << (i & 7))) ++ones;
            const double H = binH(ones, n);
            std::printf("   %4zu   %.6f   %.5f     %s\n", p, H, double(ones) / double(n),
                        H < 0.2  ? "near-constant: carries almost nothing"
                                  : (H > 0.85 ? "near-random: full entropy" : "informative"));
        }
        // is the MSB of the top plane near-constant?
        std::printf("   (sign plane entropy for comparison)\n");
        std::uint64_t s1o = 0;
        for (std::size_t i = 0; i < n; ++i) if (T.residual_sign_[i >> 3] & (1u << (i & 7))) ++s1o;
        std::printf("   sign   %.6f   %.5f\n", binH(s1o, n), double(s1o) / double(n));
    }

    // ---------- 3. block size + the real curve ----------
    {
        std::printf("\n3. BLOCK SIZE AND THE REAL CURVE\n");
        std::printf("   block_size in use = %u\n", T.block_size_);
        std::printf("\n   planes  bits/w     rel_L2     d/dplane   reference D_min@~4b/w=0.0969\n");
        double prev = -1;
        for (std::uint32_t p = 0; p <= 6; ++p) {
            decoda::FidelityState s;
            s.include_outliers = true;
            s.residual_planes = p;
            std::vector<float> got(n);
            for (std::uint32_t r = 0; r < R; ++r)
                for (std::uint32_t c = 0; c < C; ++c)
                    got[r * C + c] = T.reconstructedWeight(r, c, s);
            double num = 0, den = 0;
            for (std::size_t i = 0; i < n; ++i) {
                const double d = got[i] - W[i]; num += d * d; den += double(W[i]) * W[i];
            }
            const double e = std::sqrt(num / den);
            const double b = double(T.stats().ternary_bytes)
                           + double(T.outlier_value_.size()) * 8 + (double(R) + 1) * 4
                           + double(bitset) + double(T.residual_scale_.size()) * 4
                           + double(bitset) * p;
            std::printf("   %5u  %7.4f  %10.6f  %8.4f\n", p, b * 8.0 / double(n), e,
                        prev > 0 ? prev / e : 0.0);
            prev = e;
        }
    }

    // ---------- 4. the proposed fix, measured on the real encoder ----------
    {
        std::printf("\n4. TESTING THE PROPOSED FIX\n");
        std::printf("   (a) per-block plane emission: NOT a code change available -- planes are\n");
        std::printf("       already plane-major [p*bitset + i/8], and the scale is read\n");
        std::printf("       from residual_scale_[row] of the SAME element, so there is no\n");
        std::printf("       cross-block mixing to fix.\n");
        // what CAN be varied without touching decoda.cpp: block_size and sigma
        std::printf("\n   (b) block_size sweep, real encoder, plane 0\n");
        std::printf("       block  bits/w     rel_L2@0   rel_L2@2\n");
        for (std::uint32_t bs : {32u, 64u, 128u, 256u, 512u}) {
            decoda::BuildOptions bo;
            bo.block_size = bs; bo.residual_bits = 12; bo.outlier_sigma = 3.0f;
            bo.store_exact_f32 = false;
            auto TT = decoda::Tensor::encode(W.data(), R, C, bo);
            std::printf("       %5u  %7.4f  %10.6f  %10.6f\n", bs,
                        double(TT.stats().ternary_bytes) * 8.0 / double(n),
                        TT.maxRowL1WeightError(decoda::FidelityState{}) * 0 +
                            [&]{ decoda::FidelityState s0; s0.include_outliers = true;
                                 std::vector<float> g(n);
                                 for (std::uint32_t r = 0; r < R; ++r)
                                     for (std::uint32_t c = 0; c < C; ++c) g[r*C+c] = TT.reconstructedWeight(r,c,s0);
                                 double a=0,b2=0; for (std::size_t i=0;i<n;++i){double d=g[i]-W[i];a+=d*d;b2+=double(W[i])*W[i];}
                                 return std::sqrt(a/b2); }(),
                        [&]{ decoda::FidelityState s2; s2.include_outliers = true; s2.residual_planes = 2;
                             std::vector<float> g(n);
                             for (std::uint32_t r = 0; r < R; ++r)
                                 for (std::uint32_t c = 0; c < C; ++c) g[r*C+c] = TT.reconstructedWeight(r,c,s2);
                             double a=0,b2=0; for (std::size_t i=0;i<n;++i){double d=g[i]-W[i];a+=d*d;b2+=double(W[i])*W[i];}
                             return std::sqrt(a/b2); }());
        }
    }
    return 0;
}
