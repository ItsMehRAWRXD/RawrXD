// kquant_parity_check.cpp
// Differential oracle for the fused K-quant GEMV kernels.
//
// The vectorized kernel is admitted ONLY if it agrees with an independent
// scalar reference across shapes that exercise exact block multiples, partial
// tails, and multi-row accumulation into a pre-existing y (the GEMV contract is
// y[r] += ..., not y[r] = ...).
//
// The reference here is deliberately written independently of the production
// scalar routine so a shared indexing mistake cannot hide.
#include "deep2/k_quant_gemv_avx512.h"
#include "gguf_loader.hpp"

#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <vector>

using namespace rawrxd::kquant;

static int g_fail = 0;
static void Check(bool ok, const char* name, double got = 0, double want = 0) {
    if (ok) std::printf("PASS %-44s\n", name);
    else { std::printf("FAIL %-44s got=%.9g want=%.9g\n", name, got, want); ++g_fail; }
    std::fflush(stdout);
}

// ---- independent reference: byte-at-a-time, no shared helper ----
static float RefFP16(uint16_t h) {
    const uint32_t sign = (uint32_t)(h & 0x8000u) << 16;
    uint32_t e = (h >> 10) & 0x1Fu, m = h & 0x3FFu, bits;
    if (e == 0) {
        if (m == 0) bits = sign;
        else { int sh = 0; while (!(m & 0x400u)) { m <<= 1; ++sh; }
               m &= 0x3FFu; bits = sign | ((127 - 15 - sh) << 23) | (m << 13); }
    } else if (e == 31) bits = sign | 0x7F800000u | (m << 13);
    else bits = sign | ((e + 112) << 23) | (m << 13);
    float f; std::memcpy(&f, &bits, 4); return f;
}

static void RefScales(const uint8_t* s, uint8_t* sc, uint8_t* mn) {
    for (int i = 0; i < 4; ++i) { sc[i] = s[i] & 63; mn[i] = s[4 + i] & 63; }
    for (int i = 0; i < 4; ++i) {
        sc[4 + i] = (s[8 + i] & 0x0F) | ((s[i]     >> 6) << 4);
        mn[4 + i] = (s[8 + i] >> 4)    | ((s[4 + i] >> 6) << 4);
    }
}

// Reference walks the 128 qs bytes exactly as ggml defines them:
//   group g (32 weights) <- nibble parity (g&1) of bytes qs[(g/2)*32 .. +32)
static void RefGemvQ4K(const uint8_t* w, const float* x, float* y,
                       size_t rows, size_t cols) {
    const size_t bpr = (cols + 255) / 256;
    for (size_t r = 0; r < rows; ++r) {
        double acc = 0.0;
        const uint8_t* base = w + r * bpr * 144;
        for (size_t b = 0; b < bpr; ++b) {
            const uint8_t* blk = base + b * 144;
            const float d = RefFP16((uint16_t)(blk[0] | (blk[1] << 8)));
            const float dmin = RefFP16((uint16_t)(blk[2] | (blk[3] << 8)));
            uint8_t sc[8], mn[8];
            RefScales(blk + 4, sc, mn);
            const uint8_t* qs = blk + 16;
            for (unsigned g = 0; g < 8; ++g) {
                const uint8_t* q = qs + (g / 2) * 32;
                const int shift = (g & 1) ? 4 : 0;
                const double ds = (double)d * sc[g];
                const double mm = (double)dmin * mn[g];
                const size_t ebase = b * 256 + g * 32;
                const size_t avail = ebase < cols
                    ? ((cols - ebase) < 32 ? (cols - ebase) : 32) : 0;
                for (size_t l = 0; l < avail; ++l) {
                    const int nib = (q[l] >> shift) & 0x0F;
                    acc += (ds * nib - mm) * (double)x[ebase + l];
                }
            }
        }
        y[r] += (float)acc;
    }
}

// ---- ggml-transcribed reference -------------------------------------------
// RAWRXD_GATE_INTEGRITY_001
// The cross-check's first reference used the SAME (g/2)*32 / (g&1)?4:0 rule as
// the fixed loader, in the same shape. That is a valid two-translation-unit
// cross-check but NOT a structurally independent derivation: one wrong belief
// about the layout would be replicated in both and agree with itself.
//
// This reference is transcribed from ggml's dequantize_row_q4_K
// (ggml-quants.c) shape instead: it walks y in groups of 32 and indexes
// x[i] = qs[j] with j running 0..63 for the low half and the mirrored high half
// offset by 64 -- no "group" abstraction at all. If the loader's group rule were
// wrong, this one would not be wrong the same way.
static void RefGemvQ4K_ggml(const uint8_t* w, const float* x, float* y,
                            size_t rows, size_t cols) {
    const size_t bpr = (cols + 255) / 256;
    for (size_t r = 0; r < rows; ++r) {
        double acc = 0.0;
        const uint8_t* row = w + r * bpr * 144;
        for (size_t b = 0; b < bpr; ++b) {
            const uint8_t* blk = row + b * 144;
            const float d    = RefFP16((uint16_t)(blk[0] | (blk[1] << 8)));
            const float dmin = RefFP16((uint16_t)(blk[2] | (blk[3] << 8)));
            uint8_t sc[8], mn[8];
            RefScales(blk + 4, sc, mn);
            const uint8_t* qs = blk + 16;
            const uint8_t* q = qs;
            // ggml: for each of 8 groups of 32, take 32 low nibbles from q[0..32)
            // then 32 high nibbles from q[0..32), advancing q by 32 per pair.
            for (int is = 0; is < 8; is += 2) {
                const float d1 = d * sc[is], m1 = dmin * mn[is];
                const float d2 = d * sc[is + 1], m2 = dmin * mn[is + 1];
                for (int l = 0; l < 32; ++l) {
                    const size_t i0 = b * 256 + (size_t)is * 32 + l;
                    const size_t i1 = i0 + 32;
                    if (i0 < cols) acc += (d1 * (q[l] & 0x0F) - m1) * (double)x[i0];
                    if (i1 < cols) acc += (d2 * (q[l] >> 4)    - m2) * (double)x[i1];
                }
                q += 32;
            }
        }
        y[r] += (float)acc;
    }
}

// Cross-check: loader must agree with BOTH references.
static void CrossCheckLoader(const char* label, const std::vector<uint8_t>& blk,
                             const std::vector<float>& want) {
    rawrxd::GGUFTensorInfo info;
    info.ggml_type = rawrxd::GGMLType::Q4_K;
    info.block_size = 256;
    info.element_size = 144;
    info.byte_size = 144;
    info.element_count = 256;
    rawrxd::GGUFTensorView view(blk.data(), info);
    std::vector<float> loaded;
    const bool got = view.ToFloat32(loaded);
    Check(got && loaded.size() == 256,
          (std::string("loader decoded Q4_K super-block (") + label + ")").c_str());
    float worst = 0.0f;
    int firstbad = -1;
    for (size_t i = 0; i < 256 && i < want.size(); ++i) {
        const double mag = std::max(1.0, std::fabs((double)want[i]));
        const double e = std::fabs((double)loaded[i] - (double)want[i]) / mag;
        if (e > worst) worst = (float)e;
        if (e > 1e-4 && firstbad < 0) firstbad = (int)i;
    }
    if (firstbad >= 0) {
        std::printf("  INFO [%s] first mismatch at weight %d: loader=%.6f ref=%.6f\n",
                    label, firstbad, loaded[firstbad], want[firstbad]);
    }
    Check(worst < 1e-4,
          (std::string("gguf_loader Q4_K == ") + label).c_str(), worst, 0.0);
}

static std::vector<float> ReferenceFromGroups(const std::vector<uint8_t>& blk) {
    uint8_t sc[8], mn[8];
    RefScales(blk.data() + 4, sc, mn);
    const float d = RefFP16((uint16_t)(blk[0] | (blk[1] << 8)));
    const float dmin = RefFP16((uint16_t)(blk[2] | (blk[3] << 8)));
    std::vector<float> want(256);
    for (unsigned g = 0; g < 8; ++g) {
        const uint8_t* q = blk.data() + 16 + (g / 2) * 32;
        const int shift = (g & 1) ? 4 : 0;
        for (size_t l = 0; l < 32; ++l) {
            const int nib = (q[l] >> shift) & 0x0F;
            want[g * 32 + l] =
                (float)((double)d * sc[g] * nib - (double)dmin * mn[g]);
        }
    }
    return want;
}

// Independent transcription of upstream get_scale_min_k4, used as the Q5_K
// reference. Written separately from kquant::GetScaleMinK4 so a shared belief
// about the layout cannot hide a defect.
static void RefScaleMinK4(int j, const uint8_t* q, uint8_t& d, uint8_t& m) {
    if (j < 4) { d = (uint8_t)(q[j] & 63); m = (uint8_t)(q[j + 4] & 63); }
    else {
        d = (uint8_t)((q[j + 4] & 0x0F) | (((q[j - 4] >> 6) & 0x03) << 4));
        m = (uint8_t)((q[j + 4] >> 4)   | (((q[j - 0] >> 6) & 0x03) << 4));
    }
}

int main() {
    std::printf("avx512_compiled=%d\n\n", HaveAvx512() ? 1 : 0);

    // Deterministic pseudo-random weights.
    auto rnd = [](uint32_t& s) { s ^= s << 13; s ^= s >> 17; s ^= s << 5; return s; };

    for (size_t cols : {256u, 512u, 1024u, 4096u, 300u, 700u}) {
        for (size_t rows : {1u, 3u, 8u}) {
            const size_t bpr = (cols + 255) / 256;
            std::vector<uint8_t> w(rows * bpr * 144);
            uint32_t s = 12345u + static_cast<uint32_t>(cols) * 7u + static_cast<uint32_t>(rows);
            for (auto& b : w) b = static_cast<uint8_t>(rnd(s) & 0xFF);
            // Random bytes make arbitrary fp16 scales, and fp16 exponent 0x1F
            // is Inf/NaN -- which poisons the accumulator and fails every
            // numeric comparison for reasons that have nothing to do with the
            // kernel. Real GGUF scales are finite and small, so overwrite the
            // d/dmin fields of every block with well-formed fp16 values and
            // leave the quantized payload random.
            auto put_f16 = [](std::vector<uint8_t>& buf, size_t off, float v) {
                // round-to-nearest fp32 -> fp16 for a finite, in-range value
                uint32_t bits; std::memcpy(&bits, &v, 4);
                uint16_t h = static_cast<uint16_t>(
                    ((bits >> 16) & 0x8000u) |
                    ((((bits >> 23) & 0xFFu) - 127 + 15) << 10) |
                    ((bits >> 13) & 0x3FFu));
                buf[off] = static_cast<uint8_t>(h & 0xFF);
                buf[off + 1] = static_cast<uint8_t>(h >> 8);
            };
            for (size_t i = 0; i < rows * bpr; ++i) {
                const size_t off = i * 144;
                const float dv = 0.01f + 0.002f * float(i % 37);
                const float mv = 0.005f + 0.001f * float(i % 23);
                put_f16(w, off, dv);
                put_f16(w, off + 2, mv);
            }
            std::vector<float> x(cols);
            for (size_t i = 0; i < cols; ++i) x[i] = 0.5f * std::sin(0.017f * float(i));

            // GEMV accumulates into y, so seed both with the same bias.
            std::vector<float> ygot(rows, 0.75f), yref(rows, 0.75f);
            GemvQ4KDispatch(w.data(), x.data(), ygot.data(), rows, cols);
            RefGemvQ4K(w.data(), x.data(), yref.data(), rows, cols);

            float worst = 0.0f;
            bool finite = true;
            for (size_t r = 0; r < rows; ++r) {
                if (!std::isfinite(ygot[r])) finite = false;
                // Q4_K products accumulate over `cols` terms in float32; the
                // tolerance is scaled by the magnitude of the accumulator.
                const double mag = std::max(1.0, std::fabs((double)yref[r]));
                const double err = std::fabs((double)ygot[r] - (double)yref[r]) / mag;
                if (err > worst) worst = (float)err;
            }
            char nm[96];
            std::snprintf(nm, sizeof(nm), "Q4_K GEMV cols=%zu rows=%zu relerr", cols, rows);
            Check(finite && worst < 1e-4, nm, worst, 0.0);
        }
    }

    // Accumulation contract: y must be += , not = .
    {
        const size_t cols = 256, rows = 1;
        std::vector<uint8_t> w(144, 0x5A);
        w[0] = 0x11; w[1] = 0x21;      // finite fp16 d
        w[2] = 0x11; w[3] = 0x18;      // finite fp16 dmin
        std::vector<float> x(cols, 0.25f);
        // One call into a fresh buffer yields acc. TWO calls into the SAME
        // buffer must yield 2*acc -- that is the GEMV contract (y[r] += ...).
        // The earlier version of this test called each buffer exactly once, so
        // it compared acc against acc and could never detect a y[r] = acc bug.
        std::vector<float> y1(1, 0.0f), y2(1, 0.0f);
        GemvQ4KDispatch(w.data(), x.data(), y1.data(), rows, cols);
        GemvQ4KDispatch(w.data(), x.data(), y2.data(), rows, cols);
        GemvQ4KDispatch(w.data(), x.data(), y2.data(), rows, cols);
        const double twice = 2.0 * (double)y1[0];
        const double delta = std::fabs((double)y2[0] - twice);
        const double tol = 1e-3 * std::max(1.0, std::fabs(twice));
        std::printf("  INFO y1=%.6f y2=%.6f twice=%.6f delta=%.6g tol=%.6g\n",
                    y1[0], y2[0], twice, delta, tol);
        Check(delta < tol, "GEMV accumulates (y += acc, twice == 2x)",
              delta, tol);
    }

    // Scalar and AVX-512 paths must agree with each other directly.
#if defined(__AVX512F__)
    {
        const size_t cols = 2048, rows = 4;
        const size_t bpr = cols / 256;
        std::vector<uint8_t> w(rows * bpr * 144);
        uint32_t s = 999u;
        for (auto& b : w) b = static_cast<uint8_t>(rnd(s) & 0xFF);
        for (size_t i = 0; i < rows * bpr; ++i) {
            const size_t off = i * 144;
            auto put = [&w](size_t o, uint16_t h) {
                w[o] = static_cast<uint8_t>(h & 0xFF);
                w[o + 1] = static_cast<uint8_t>(h >> 8);
            };
            put(off, 0x2111);   // finite small fp16
            put(off + 2, 0x1A2B);
        }
        std::vector<float> x(cols);
        for (size_t i = 0; i < cols; ++i) x[i] = 0.3f * std::cos(0.011f * float(i));
        std::vector<float> ya(rows, 0.0f), yb(rows, 0.0f);
        GemvQ4K(w.data(), x.data(), ya.data(), rows, cols);            // scalar
        GemvQ4K_AVX512(w.data(), x.data(), yb.data(), rows, cols);    // vector
        float worst = 0.0f;
        for (size_t r = 0; r < rows; ++r) {
            const double mag = std::max(1.0, std::fabs((double)ya[r]));
            const double err = std::fabs((double)ya[r] - (double)yb[r]) / mag;
            if (err > worst) worst = (float)err;
        }
        Check(worst < 1e-5, "AVX512 vs scalar direct agreement", worst, 0.0);
    }
#endif

    // ---- CROSS-CHECK: gguf_loader's Q4_K decoder vs the GEMV kernel ---------
    // RAWRXD_Q4K_NIBBLE_MAP_001
    // These two decoders were written independently and disagreed. gguf_loader
    // used a low/high-to-front/back permutation that scrambled 7 of 8 weight
    // groups, and it is the decoder the INFERENCE path actually calls
    // (LoadAllWeights -> rawrxd::GGUFTensorView::ToFloat32). The GEMV parity above
    // could never catch that because it compared the GEMV against its own local
    // reference, never against the loader. This closes that gap: decode the same
    // synthetic super-block through both and require agreement.
    {
        auto rnd2 = [](uint32_t& s) { s ^= s << 13; s ^= s >> 17; s ^= s << 5; return s; };
        const size_t kBlk = 256;
        std::vector<uint8_t> blk(kBlk / 32 * 144, 0);
        uint32_t s = 4242u;
        for (auto& b : blk) b = static_cast<uint8_t>(rnd2(s) & 0xFF);
        // well-formed finite fp16 scales
        auto putf16 = [](std::vector<uint8_t>& v, size_t o, uint16_t h) {
            v[o] = static_cast<uint8_t>(h & 0xFF); v[o + 1] = static_cast<uint8_t>(h >> 8);
        };
        putf16(blk, 0, 0x2111);   // d
        putf16(blk, 2, 0x1911);   // dmin

        // loader path
        CrossCheckLoader("group-rule reference", blk, ReferenceFromGroups(blk));

        // Second, structurally independent reference transcribed from ggml.
        // Compare the two REFERENCES to each other on a full GEMV; if the group
        // rule and the ggml transcription disagree, one of them is wrong even
        // though the loader happens to match.
        {
            std::vector<float> xw(256);
            for (size_t i = 0; i < 256; ++i) xw[i] = 0.01f * std::sin(0.021f * float(i));
            std::vector<float> ya(1, 0.0f), yb(1, 0.0f);
            RefGemvQ4K(blk.data(), xw.data(), ya.data(), 1, 256);
            RefGemvQ4K_ggml(blk.data(), xw.data(), yb.data(), 1, 256);
            const double mag = std::max(1.0, std::fabs((double)ya[0]));
            const double e = std::fabs((double)ya[0] - (double)yb[0]) / mag;
            Check(e < 1e-5, "group-rule and ggml-transcribed references agree",
                  e, 0.0);
        }
    }

    // ---- Q5_K synthetic differential -------------------------------------
    // The bundled model contains only F32/Q4_K/Q6_K, so Q5_K cannot be proven
    // on real weights here. It is proven instead against an independent
    // reference transcribed from upstream dequantize_row_q5_K
    // (ggml-quants.c:1731) rather than from the kernel under test.
    {
        auto rnd5 = [](uint32_t& s) { s ^= s << 13; s ^= s >> 17; s ^= s << 5; return s; };
        for (size_t cols : {256u, 768u, 2048u}) {
            for (size_t rows : {1u, 5u}) {
                const size_t bpr = cols / 256;
                std::vector<uint8_t> w(rows * bpr * 176);
                uint32_t s = 0xABCDEF01u + (uint32_t)(cols * 31 + rows);
                for (auto& b : w) b = (uint8_t)(rnd5(s) & 0xFF);
                // well-formed finite fp16 d / dmin
                for (size_t i = 0; i < rows * bpr; ++i) {
                    uint16_t d16 = 0x2E66;    // ~0.1
                    uint16_t m16 = 0x3126;    // ~0.09
                    const size_t o = i * 176;
                    w[o + 172] = (uint8_t)(d16 & 0xFF); w[o + 173] = (uint8_t)(d16 >> 8);
                    w[o + 174] = (uint8_t)(m16 & 0xFF); w[o + 175] = (uint8_t)(m16 >> 8);
                }
                std::vector<float> x(cols);
                for (size_t i = 0; i < cols; ++i) x[i] = 0.5f * std::sin(0.017f * float(i + 1));

                // Independent reference (upstream shape).
                std::vector<float> yRef(rows, 0.0f);
                for (size_t r = 0; r < rows; ++r) {
                    const uint8_t* base = w.data() + r * bpr * 176;
                    double acc = 0.0;
                    for (size_t bb = 0; bb < bpr; ++bb) {
                        const uint8_t* blk = base + bb * 176;
                        const uint8_t* ql = blk;
                        const uint8_t* qh = blk + 128;
                        const uint8_t* sc = blk + 160;
                        const float dd = RefFP16((uint16_t)(blk[172] | (blk[173] << 8)));
                        const float mn = RefFP16((uint16_t)(blk[174] | (blk[175] << 8)));
                        int is = 0; uint8_t u1 = 1, u2 = 2; size_t n = 0;
                        for (; n < 256; n += 64) {
                            uint8_t s0, m0, s1, m1;
                            RefScaleMinK4(is + 0, sc, s0, m0);
                            RefScaleMinK4(is + 1, sc, s1, m1);
                            const float d1 = dd * (float)s0, e1 = mn * (float)m0;
                            const float d2 = dd * (float)s1, e2 = mn * (float)m1;
                            for (size_t l = 0; l < 32; ++l) {
                                const size_t i0 = bb * 256 + n + l;
                                const size_t i1 = bb * 256 + n + 32 + l;
                                acc += (d1 * (float)((ql[l] & 0x0F) + ((qh[l] & u1) ? 16 : 0)) - e1) * (double)x[i0];
                                acc += (d2 * (float)((ql[l] >> 4)  + ((qh[l] & u2) ? 16 : 0)) - e2) * (double)x[i1];
                            }
                            ql += 32; is += 2; u1 = (uint8_t)(u1 << 2); u2 = (uint8_t)(u2 << 2);
                        }
                    }
                    yRef[r] = (float)acc;
                }

                std::vector<float> yFast(rows, 0.0f);
                rawrxd::kquant::GemvQ5KDispatch(w.data(), x.data(), yFast.data(), rows, cols);
                std::vector<float> yScalar(rows, 0.0f);
                rawrxd::kquant::GemvQ5K(w.data(), x.data(), yScalar.data(), rows, cols);

                auto chk = [&](const char* what, const std::vector<float>& a) {
                    float worst = 0.0f; int nf = 0;
                    for (size_t i = 0; i < rows; ++i) {
                        if (!std::isfinite(a[i])) { ++nf; continue; }
                        const double den = std::max(1.0, std::fabs((double)yRef[i]));
                        const double e = std::fabs((double)a[i] - (double)yRef[i]) / den;
                        if (e > worst) worst = (float)e;
                    }
                    char nm[96];
                    std::snprintf(nm, sizeof(nm), "Q5_K %s cols=%zu rows=%zu rel", what, cols, rows);
                    Check(nf == 0 && worst < 1e-4, nm, worst, 0.0);
                };
                chk("scalar", yScalar);
                chk("dispatch", yFast);
#if defined(__AVX512F__)
                // The AVX-512 form is compiled but not dispatched
                // (RAWRXD_Q5K_VECTOR_WITHHELD_001): it does not reproduce the
                // scalar reference. Asserted here so it cannot silently ship.
                {
                    std::vector<float> yV(rows, 0.0f);
                    rawrxd::kquant::GemvQ5K_AVX512(w.data(), x.data(), yV.data(), rows, cols);
                    float worst = 0.0f;
                    for (size_t i = 0; i < rows; ++i) {
                        const double den = std::max(1.0, std::fabs((double)yRef[i]));
                        const double e = std::fabs((double)yV[i] - (double)yRef[i]) / den;
                        if (e > worst) worst = (float)e;
                    }
                    char nm[96];
                    std::snprintf(nm, sizeof(nm), "Q5_K avx512 WITHHELD (rel>tol) cols=%zu rows=%zu", cols, rows);
                    Check(worst >= 1e-4, nm, worst, 0.0);
                }
#endif
            }
        }
    }

    std::printf("\nRESULT %s (%d failures)\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}

