// q2k_layout_discriminator.cpp
// RAWRXD_Q2K_LAYOUT_DISCRIMINATOR_001
//
// WHY THIS EXISTS
// ---------------
// src/deep2/QuantKernelRegistry.hpp:72 asserts (RAWRXD_Q2K_FIELD_ORDER_002) that
// the GGUF Q2_K super-block fp16 words d/dmin live at offsets 80/82, with
// scales@0 and qs@16.  tools/q2k_block_parity_probe.cpp then "verifies" that by
// decoding the same block with the same offsets by hand and comparing against
// production.  Production and the reference therefore cannot disagree, so the
// gate reports PARITY no matter which layout is right.  That is a gate with no
// information in it.
//
// This probe does not consult production and does not consult that header's
// claim.  It reads the real bytes of a real trained tensor and applies the SAME
// canonical decode arithmetic to two candidate field layouts, then asks which
// one produces weights that could have come out of a trained language model.
//
// THE DISCRIMINATOR (physics, not authority)
// ------------------------------------------
// Q2_K stores a 256-value block as 2-bit indices q in {0,1,2,3} scaled by
// six-bit sub-scales, wrapped in one fp16 super-scale d and one fp16 dmin:
//
//     w = d * sc * q  -  dmin * m
//
// Because q <= 3 and sc <= 63, the block's peak magnitude is bounded by
// 3 * 63 * d  =  189 * d.  So for any correctly-read block:
//
//   (1) d MUST be positive.          fp16 read out of 2-bit quant bytes is not.
//   (2) d MUST be small.             Real Q2_K d is ~1e-3..1e-1.  Garbage is not.
//   (3) max|w| / d MUST land in (0, 189].  Read the wrong way it cannot, because
//                                      the same d multiplies a different sub-scale
//                                      set and the ratio blows out.
//   (4) per-block w must be roughly zero-mean. Trained weight matrices are.
//
// None of these consults a layout authority.  Run it and the numbers say which
// offset set is real.
//
// Usage: q2k_layout_discriminator <model.gguf> <tensor_name> [blocks]

#include "QuantKernelRegistry.hpp"
#include "GGUFLoader.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <string>
#include <vector>
#include <algorithm>

static float f16(uint16_t h) {
    uint32_t sign = static_cast<uint32_t>(h & 0x8000u) << 16;
    uint32_t exp  = (h >> 10) & 0x1Fu;
    uint32_t frac = h & 0x3FFu;
    if (exp == 0) {
        if (frac == 0) { uint32_t b = sign; float f; std::memcpy(&f, &b, 4); return f; }
        uint32_t e = 1, f = frac;
        while ((f & 0x400u) == 0) { f <<= 1; ++e; }
        f &= 0x3FFu;
        uint32_t b = sign | ((127 - 15 + 2 - e) << 23) | (f << 13);
        float out; std::memcpy(&out, &b, 4); return out;
    }
    if (exp == 31) { uint32_t b = sign | 0x7F800000u | (frac << 13); float o; std::memcpy(&o, &b, 4); return o; }
    uint32_t b = sign | ((exp + 127 - 15) << 23) | (frac << 13);
    float out; std::memcpy(&out, &b, 4); return out;
}

// Canonical Q2_K scale/min unpack, per ggml dequantize_row_q2_K (QK_K==256):
// scales are 4-bit, low nibble = scale, high nibble = min, consumed
// sequentially as `is++`.  This is NOT get_scale_min_k2 -- that 6-bit packing
// belongs to Q3_K/Q4_K/Q5_K.  Confirmed against three independent sources:
//   * llama.cpp ggml-quants.c  -> sc = scales[is++] & 0xF ; m = scales[is++] >> 4
//   * whisper.cpp ggml-quants.h-> "scales and mins, quantized with 4 bits"
//   * ggml dequantize_block_q2_K (CUDA) -> x[i].scales[is+0] & 0xF / >> 4
static void scaleMin(int j, const uint8_t* q, int& d, int& m) {
    d = q[j] & 0x0F;
    m = (q[j] >> 4) & 0x0F;
}

struct Layout {
    const char* name;
    int scalesOff;
    int qsOff;
    int dOff;
    int dminOff;
};

// Canonical llama.cpp / ggml-common.h block_q2_K is d-first.  The layout this
// repository currently ships is the second row.  Both are 84 bytes, which is
// precisely why a size check cannot separate them.
static const Layout LAYOUTS[] = {
    { "A_d_first_canonical", 4, 20,  0,  2 },
    { "B_d_last_current",    0, 16, 80, 82 },
};

struct Stats {
    size_t blocks = 0;
    size_t dNonPositive = 0;
    size_t dNonFinite   = 0;
    size_t dAboveOne    = 0;   // a 2-bit block cannot need super-scale > 1
    size_t ratioBad     = 0;   // max|w|/d outside (0, 189]
    double dMin = 0, dMax = 0, dSum = 0;
    double absMeanSum = 0;
    double wAbsMaxAll = 0;
    std::vector<double> blockStd;
    // Intra-block sub-group RMS spread. The quantizer allocates one scale per
    // 16-weight sub-group precisely so those groups come out comparable, so a
    // correct unpack gives a tight spread inside a block. Scrambled scale bits
    // blow it out. This is the axis that catches a wrong scale UNPACK, which
    // the d/dmin test above cannot see.
    std::vector<double> groupRmsRatio;
};

static bool decodeBlock(const uint8_t* src, const Layout& L, float* w, float& dOut) {
    const uint8_t* scales = src + L.scalesOff;
    const uint8_t* qs     = src + L.qsOff;
    uint16_t dRaw, dmRaw;
    std::memcpy(&dRaw,  src + L.dOff,  2);
    std::memcpy(&dmRaw, src + L.dminOff, 2);
    const float d    = f16(dRaw);
    const float dmin = f16(dmRaw);
    dOut = d;
    if (!std::isfinite(d) || !std::isfinite(dmin)) return false;

    int y = 0;
    for (int n = 0; n < 256; n += 128) {
        const uint8_t* q = qs + (n / 128) * 32;
        int shift = 0;
        for (int j = 0; j < 4; ++j) {
            for (int half = 0; half < 2; ++half) {
                int sc, m;
                scaleMin(2 * j + half, scales, sc, m);
                const float dl = d * static_cast<float>(sc);
                const float ml = dmin * static_cast<float>(m);
                for (int l = 0; l < 16; ++l) {
                    const int qv = static_cast<int>((q[l + half * 16] >> shift) & 3);
                    w[y++] = dl * static_cast<float>(qv) - ml;
                }
            }
            shift += 2;
        }
    }
    return true;
}

static void accumulate(const uint8_t* data, size_t numBlocks, const Layout& L, Stats& s) {
    std::vector<float> w(256);
    bool first = true;
    for (size_t b = 0; b < numBlocks; ++b) {
        float d = 0.0f;
        if (!decodeBlock(data + b * 84, L, w.data(), d)) { ++s.dNonFinite; continue; }

        ++s.blocks;
        if (!(d > 0.0f)) ++s.dNonPositive;
        if (d > 1.0f) ++s.dAboveOne;
        double dd = d;
        if (first) { s.dMin = s.dMax = dd; first = false; }
        s.dMin = std::min(s.dMin, dd);
        s.dMax = std::max(s.dMax, dd);
        s.dSum += dd;

        double sum = 0, sumSq = 0, absMax = 0;
        for (float v : w) {
            if (!std::isfinite(v)) { absMax = HUGE_VAL; break; }
            sum += v; sumSq += static_cast<double>(v) * v;
            absMax = std::max(absMax, std::fabs(static_cast<double>(v)));
        }
        if (!std::isfinite(absMax)) { ++s.ratioBad; continue; }

        // Physics bound: max|w| <= 3 * 63 * d
        if (!(absMax > 0.0) || absMax > 189.0 * static_cast<double>(d) * 1.0001) ++s.ratioBad;

        s.absMeanSum += absMax;
        s.wAbsMaxAll = std::max(s.wAbsMaxAll, absMax);
        const double mean = sum / 256.0;
        const double var  = sumSq / 256.0 - mean * mean;
        s.blockStd.push_back(std::sqrt(std::max(0.0, var)));

        // per-16-group RMS inside this block
        double gMin = HUGE_VAL, gMax = 0.0;
        for (int g = 0; g < 16; ++g) {
            double gs = 0;
            for (int p = 0; p < 16; ++p) { const double v = w[g * 16 + p]; gs += v * v; }
            const double rms = std::sqrt(gs / 16.0);
            gMin = std::min(gMin, rms);
            gMax = std::max(gMax, rms);
        }
        if (gMin > 1e-12 && std::isfinite(gMax)) s.groupRmsRatio.push_back(gMax / gMin);
    }
}

static void report(const Layout& L, const Stats& s) {
    std::fprintf(stderr, "\n--- LAYOUT %s (scales@%d qs@%d d@%d dmin@%d) ---\n",
                 L.name, L.scalesOff, L.qsOff, L.dOff, L.dminOff);
    std::fprintf(stderr, "BLOCKS_DECODED=%zu\n",   s.blocks);
    std::fprintf(stderr, "D_NONPOSITIVE=%zu\n",     s.dNonPositive);
    std::fprintf(stderr, "D_NONFINITE=%zu\n",       s.dNonFinite);
    std::fprintf(stderr, "D_ABOVE_ONE=%zu\n",       s.dAboveOne);
    std::fprintf(stderr, "RATIO_VIOLATIONS=%zu\n",  s.ratioBad);
    if (s.blocks) {
        std::fprintf(stderr, "D_MIN=%.6g\n", s.dMin);
        std::fprintf(stderr, "D_MAX=%.6g\n", s.dMax);
        std::fprintf(stderr, "D_MEAN=%.6g\n", s.dSum / static_cast<double>(s.blocks));
        std::fprintf(stderr, "D_SPAN_DECADES=%.2f\n",
            std::log10(std::max(1e-30, s.dMax)) - std::log10(std::max(1e-30, s.dMin)));
        std::fprintf(stderr, "BLOCK_MAXABS_MEAN=%.6g\n", s.absMeanSum / static_cast<double>(s.blocks));
        std::fprintf(stderr, "GLOBAL_MAXABS=%.6g\n", s.wAbsMaxAll);
        std::vector<double> ss = s.blockStd;
        std::sort(ss.begin(), ss.end());
        std::fprintf(stderr, "BLOCK_STD_P05=%.6g\n", ss.empty() ? 0 : ss[ss.size() / 20]);
        std::fprintf(stderr, "BLOCK_STD_MEDIAN=%.6g\n", ss.empty() ? 0 : ss[ss.size() / 2]);
        std::fprintf(stderr, "BLOCK_STD_P95=%.6g\n", ss.empty() ? 0 : ss[(ss.size() * 95) / 100]);

        std::vector<double> gr = s.groupRmsRatio;
        std::sort(gr.begin(), gr.end());
        if (!gr.empty()) {
            std::fprintf(stderr, "GROUP_RMS_RATIO_P50=%.4g\n", gr[gr.size() / 2]);
            std::fprintf(stderr, "GROUP_RMS_RATIO_P95=%.4g\n", gr[(gr.size() * 95) / 100]);
            std::fprintf(stderr, "GROUP_RMS_RATIO_MAX=%.4g\n", gr.back());
            std::fprintf(stderr, "GROUPS_OVER_8X=%zu/%zu\n",
                (size_t)std::count_if(gr.begin(), gr.end(), [](double r){ return r > 8.0; }),
                gr.size());
        }
    }

    // A layout is physically admissible only if every bound holds.
    const bool ok = s.blocks > 0
                 && s.dNonFinite == 0
                 && s.dNonPositive == 0
                 && s.dAboveOne == 0
                 && s.ratioBad == 0;
    std::fprintf(stderr, "LAYOUT_ADMISSIBLE=%s\n", ok ? "YES" : "NO");
}

int main(int argc, char** argv) {
    if (argc < 3) {
        std::fprintf(stderr, "Usage: %s <model.gguf> <tensor_name> [blocks]\n", argv[0]);
        return 64;
    }
    const char* modelPath = argv[1];
    const char* tensorName = argv[2];
    const size_t wantBlocks = (argc > 3) ? static_cast<size_t>(std::atoll(argv[3])) : 256;

    std::fprintf(stderr, "=== RAWRXD_Q2K_LAYOUT_DISCRIMINATOR_001 ===\n");
    std::fprintf(stderr, "MODEL=%s\n",   modelPath);
    std::fprintf(stderr, "TENSOR=%s\n",  tensorName);

    Deep2::GGUFLoader loader;
    if (!loader.load(modelPath)) {
        std::fprintf(stderr, "FAIL=load %s\n", loader.error().c_str());
        return 1;
    }
    const Deep2::GGUFTensor* t = loader.getTensor(tensorName);
    if (!t || !t->data) { std::fprintf(stderr, "FAIL=tensor_not_found\n"); return 1; }
    if (t->type != Deep2::GGMLType::GGML_TYPE_Q2_K) {
        std::fprintf(stderr, "FAIL=not_q2_k type=%d\n", static_cast<int>(t->type));
        return 1;
    }
    const size_t numBlocks = t->sizeBytes / 84;
    const size_t n = std::min(numBlocks, wantBlocks);
    std::fprintf(stderr, "TENSOR_TYPE=Q2_K TENSOR_BLOCKS=%zu PROBING=%zu BLOCK_BYTES=84\n",
                 numBlocks, n);

    bool admissible[2];
    for (int i = 0; i < 2; ++i) {
        Stats s;
        accumulate(t->data, n, LAYOUTS[i], s);
        report(LAYOUTS[i], s);
        admissible[i] = (s.blocks > 0 && s.dNonFinite == 0 && s.dNonPositive == 0
                         && s.dAboveOne == 0 && s.ratioBad == 0);
    }

    std::fprintf(stderr, "\n=== DISCRIMINATION ===\n");
    std::fprintf(stderr, "A_d_first_canonical_ADMISSIBLE=%s\n", admissible[0] ? "YES" : "NO");
    std::fprintf(stderr, "B_d_last_current_ADMISSIBLE=%s\n",    admissible[1] ? "YES" : "NO");

    if (admissible[0] == admissible[1]) {
        std::fprintf(stderr, "VERDICT=INCONCLUSIVE both layouts agree (%s) — "
                             "the discriminator has no discriminating power on this tensor\n",
                     admissible[0] ? "admissible" : "inadmissible");
        return 3;
    }
    std::fprintf(stderr, "VERDICT=%s\n", admissible[0] ? "LAYOUT_A_CANONICAL"
                                                      : "LAYOUT_B_CURRENT");
    return admissible[0] ? 0 : 4;
}
