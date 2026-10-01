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

    std::printf("\nRESULT %s (%d failures)\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}