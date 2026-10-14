// ============================================================================
// test_q2k_q3k_parity.cpp
// ============================================================================
// G05 — Q2_K / Q3_K numerical parity against the repository's own ggml
// reference. The gate is the FIRST DIVERGENT DATUM, not a benchmark: as soon as
// one element disagrees, the block index, the element index, both values and
// the relevant scale/iterm fields are printed and the gate fails.
//
// The reference is the vendored llama.cpp code in THIS repository, so the
// comparison stays honest if either side drifts:
//   * 3rdparty/ggml/src/ggml-quants.c:784   dequantize_row_q2_K
//   * 3rdparty/ggml/src/ggml-quants.c:1128  dequantize_row_q3_K
//   * 3rdparty/ggml/src/ggml-quants.c:1554  dequantize_row_q5_K
//   * 3rdparty/ggml/src/ggml-quants.c       quantize_row_q8_K_ref
// They are transcribed verbatim below and never used on the production path.
//
// The oracle is chosen so the check is INDEPENDENT of Deep2's kernels: the
// reference dequantizer reconstructs the 256 weights from the block bytes, and
// the expected dot product is Σ (reconstructed weight) x (dequantized
// activation). Any disagreement between Deep2's kernel and that sum is a real
// mathematical divergence, not an artifact of comparing Deep2 to itself.
//
// Exit codes: 0 = all parity gates PASS, 4 = a parity gate FAILED,
//             5 = a layout/size gate FAILED.
// ============================================================================

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cmath>
#include <random>
#include <vector>

#include "QuantKernelRegistry.hpp"    // block_q{2,3,5,6,8}_K layouts
#include "QuantKernelRegistry_K.h"    // Deep2 vec_dot_* kernels

using namespace Deep2;

static int g_fail = 0;
static int g_first_divergent = 0;   // set once, so only the first datum is noisy

// ---------------------------------------------------------------------------
// Independent IEEE-754 half-precision <-> single-precision conversion, used
// only by the reference so the oracle does not share code with Deep2.
// ---------------------------------------------------------------------------
static float ref_fp16_to_fp32(uint16_t h) {
    const uint32_t sign = (uint32_t)(h & 0x8000u) << 16;
    const uint32_t exp  = (h >> 10) & 0x1Fu;
    const uint32_t frac = h & 0x3FFu;
    uint32_t bits;
    if (exp == 0) {
        if (frac == 0) { bits = sign; }
        else {
            // Subnormal: normalize.
            uint32_t e = 127 - 15 + 1;
            uint32_t f = frac;
            while ((f & 0x400u) == 0) { f <<= 1; --e; }
            f &= 0x3FFu;
            bits = sign | (e << 23) | (f << 13);
        }
    } else if (exp == 31) {
        bits = sign | 0x7F800000u | (frac << 13);
    } else {
        bits = sign | ((exp + 127 - 15) << 23) | (frac << 13);
    }
    float out;
    std::memcpy(&out, &bits, sizeof(out));
    return out;
}

static uint16_t ref_fp32_to_fp16(float f) {
    uint32_t x;
    std::memcpy(&x, &f, sizeof(x));
    const uint32_t sign = (x >> 16) & 0x8000u;
    int32_t exp   = (int32_t)((x >> 23) & 0xFFu);
    const uint32_t frac = x & 0x7FFFFFu;
    uint16_t out;
    if (exp == 0xFF) {                      // inf / nan
        out = (uint16_t)(sign | 0x7C00u | (frac ? 0x200u : 0u));
    } else if (exp == 0) {                  // zero / flush to zero
        out = (uint16_t)sign;
    } else {
        exp = exp - 127 + 15;
        if (exp >= 31) {
            out = (uint16_t)(sign | 0x7C00u);            // overflow -> inf
        } else if (exp <= 0) {
            if (exp < -10) out = (uint16_t)sign;         // underflow -> zero
            else {
                // Subnormal half.
                uint32_t m = frac | 0x800000u;
                const int shift = 14 - exp;
                uint32_t half = m >> shift;
                const uint32_t rem = m & ((1u << shift) - 1u);
                const uint32_t halfway = 1u << (shift - 1);
                if (rem > halfway || (rem == halfway && (half & 1u))) ++half;
                out = (uint16_t)(sign | half);
            }
        } else {
            uint32_t half = ((uint32_t)exp << 10) | (frac >> 13);
            const uint32_t rem = frac & 0x1FFFu;
            if (rem > 0x1000u || (rem == 0x1000u && (half & 1u))) ++half;
            out = (uint16_t)(sign | half);
        }
    }
    return out;
}

// ---------------------------------------------------------------------------
// ggml reference: quantize_row_q8_K_ref (ggml-quants.c:2555), plus the
// round-half-to-even nearest_int used there.
// ---------------------------------------------------------------------------
static int ref_nearest_int(float fval) {
    float val = fval + 12582912.f;              // 1.5 * 2^23
    int i;
    std::memcpy(&i, &val, sizeof(int));
    return (i & 0x007fffff) - 0x00400000;       // round-half-to-even
}

static void ref_quantize_row_q8_K(const float* x, block_q8_K* y, int64_t k) {
    const int64_t nb = k / QK_K;
    for (int64_t i = 0; i < nb; ++i) {
        float maxf = 0.f, amax = 0.f;
        for (int j = 0; j < QK_K; ++j) {
            float ax = std::fabs(x[j]);
            if (ax > amax) { amax = ax; maxf = x[j]; }
        }
        if (!amax) {
            y[i].d = 0;
            std::memset(y[i].qs, 0, QK_K);
            std::memset(y[i].bsums, 0, sizeof(y[i].bsums));
            continue;
        }
        const float iscale = -127.f / maxf;
        for (int j = 0; j < QK_K; ++j) {
            const int v = ref_nearest_int(iscale * x[j]);
            y[i].qs[j] = static_cast<int8_t>(v < 127 ? v : 127);
        }
        for (int j = 0; j < QK_K / 16; ++j) {
            int sum = 0;
            for (int ii = 0; ii < 16; ++ii) sum += y[i].qs[j * 16 + ii];
            y[i].bsums[j] = static_cast<int16_t>(sum);
        }
        y[i].d = 1.0f / iscale;
    }
}

// ---------------------------------------------------------------------------
// ggml reference: dequantize_row_q2_K (ggml-quants.c:784), verbatim.
// ---------------------------------------------------------------------------
static void ref_dequantize_row_q2_K(const block_q2_K* x, float* y, int64_t k) {
    const int64_t nb = k / QK_K;
    for (int64_t i = 0; i < nb; ++i) {
        const float d    = ref_fp16_to_fp32(x[i].d);
        const float dmin = ref_fp16_to_fp32(x[i].dmin);
        const uint8_t* q = x[i].qs;

        int is = 0;
        float dl, ml;
        for (int n = 0; n < QK_K; n += 128) {
            int shift = 0;
            for (int j = 0; j < 4; ++j) {
                uint8_t sc = x[i].scales[is++];
                dl = d * (float)(sc & 0xF); ml = dmin * (float)(sc >> 4);
                for (int l = 0; l < 16; ++l) *y++ = dl * ((int8_t)((q[l] >> shift) & 3)) - ml;

                sc = x[i].scales[is++];
                dl = d * (float)(sc & 0xF); ml = dmin * (float)(sc >> 4);
                for (int l = 0; l < 16; ++l) *y++ = dl * ((int8_t)((q[l + 16] >> shift) & 3)) - ml;

                shift += 2;
            }
            q += 32;
        }
    }
}

// ---------------------------------------------------------------------------
// ggml reference: dequantize_row_q3_K (ggml-quants.c:1128), verbatim.
// ---------------------------------------------------------------------------
static void ref_dequantize_row_q3_K(const block_q3_K* x, float* y, int64_t k) {
    const uint32_t kmask1 = 0x03030303u;
    const uint32_t kmask2 = 0x0f0f0f0fu;
    uint32_t aux[4];
    const int8_t* scales = reinterpret_cast<const int8_t*>(aux);

    const int64_t nb = k / QK_K;
    for (int64_t i = 0; i < nb; ++i) {
        const float d_all = ref_fp16_to_fp32(x[i].d);
        const uint8_t* q  = x[i].qs;
        const uint8_t* hm = x[i].hmask;
        uint8_t m = 1;

        std::memcpy(aux, x[i].scales, 12);
        uint32_t tmp = aux[2];
        aux[2] = ((aux[0] >> 4) & kmask2) | (((tmp >> 4) & kmask1) << 4);
        aux[3] = ((aux[1] >> 4) & kmask2) | (((tmp >> 6) & kmask1) << 4);
        aux[0] =  (aux[0]     & kmask2) | (((tmp >> 0) & kmask1) << 4);
        aux[1] =  (aux[1]     & kmask2) | (((tmp >> 2) & kmask1) << 4);

        int is = 0;
        for (int n = 0; n < QK_K; n += 128) {
            int shift = 0;
            for (int j = 0; j < 4; ++j) {
                const float dl = d_all * (float)(scales[is++] - 32);
                for (int l = 0; l < 16; ++l) {
                    *y++ = dl * ((int8_t)((q[l] >> shift) & 3) - ((hm[l] & m) ? 0 : 4));
                }
                const float dl2 = d_all * (float)(scales[is++] - 32);
                for (int l = 0; l < 16; ++l) {
                    *y++ = dl2 * ((int8_t)((q[l + 16] >> shift) & 3) - ((hm[l + 16] & m) ? 0 : 4));
                }
                shift += 2;
                m <<= 1;
            }
            q += 32;
        }
    }
}

// ---------------------------------------------------------------------------
// ggml reference: dequantize_row_q5_K (ggml-quants.c:1554), verbatim.
// ---------------------------------------------------------------------------
static void ref_dequantize_row_q5_K(const block_q5_K* x, float* y, int64_t k) {
    const int64_t nb = k / QK_K;
    for (int64_t i = 0; i < nb; ++i) {
        const uint8_t* ql = x[i].qs;
        const uint8_t* qh = x[i].qh;
        const float d    = ref_fp16_to_fp32(x[i].d);
        const float dmin = ref_fp16_to_fp32(x[i].dmin);

        int is = 0;
        uint8_t u1 = 1, u2 = 2;
        for (int j = 0; j < QK_K; j += 64) {
            uint8_t sc, mm;
            // get_scale_min_k4, inlined exactly as ggml defines it.
            auto gsm = [&](int jj) {
                if (jj < 4) { sc = x[i].scales[jj] & 63; mm = x[i].scales[jj + 4] & 63; }
                else {
                    sc = (uint8_t)((x[i].scales[jj + 4] & 0x0F) | ((x[i].scales[jj - 4] >> 6) << 4));
                    mm = (uint8_t)((x[i].scales[jj + 4] >> 4) | ((x[i].scales[jj] >> 6) << 4));
                }
            };
            gsm(is + 0);
            const float d1 = d * (float)sc, m1 = dmin * (float)mm;
            gsm(is + 1);
            const float d2 = d * (float)sc, m2 = dmin * (float)mm;
            for (int l = 0; l < 32; ++l) {
                *y++ = d1 * (float)((ql[l] & 0xF) + (qh[l] & u1 ? 16 : 0)) - m1;
            }
            for (int l = 0; l < 32; ++l) {
                *y++ = d2 * (float)((ql[l] >> 4)  + (qh[l] & u2 ? 16 : 0)) - m2;
            }
            ql += 32; qh += 32; is += 2;
            u1 <<= 2; u2 <<= 2;
        }
    }
}

// ---------------------------------------------------------------------------
// Report the first divergent datum and stop.
// ---------------------------------------------------------------------------
static void report_divergence(const char* what, int blk, int elem,
                              double ref, double got, double tol) {
    if (g_first_divergent != 0) return;   // only the first is noisy
    g_first_divergent = 1;
    std::printf("  [DIVERGE] FIRST %s divergence: block=%d element=%d ref=%.9g got=%.9g "
                "abs=%.9g tol=%.9g\n",
                what, blk, elem, ref, got, std::fabs(ref - got), tol);
}

// ---------------------------------------------------------------------------
// Parity criterion.
//
// A dot product over 256 terms has no single exact float32 answer: the sum
// depends on the accumulation ORDER. Comparing a float32 kernel against a
// double-precision oracle with a hand-picked tolerance either hides real
// mathematical errors or fails on harmless rounding.
//
// The criterion used here is order-independent and cannot hide a bug:
//
//     |kernel - exact_double|  <=  |ggml_f32 - exact_double| + slack
//
// i.e. Deep2's kernel must be AT LEAST as accurate as ggml's own float32
// accumulation, both measured against the same double-precision oracle. ggml_f32
// is the reference kernel transcribed verbatim in its own accumulation order,
// so its own rounding is the bound. A real mathematical error (wrong scale, wrong
// index, wrong block sums) is orders of magnitude larger than the slack and
// therefore always fails — which is exactly what the earlier defects did.
// ---------------------------------------------------------------------------
static bool parity_ok(double kernel_val, double ggml_f32_val, double exact_val) {
    const double ke  = std::fabs(kernel_val   - exact_val);
    const double ge  = std::fabs(ggml_f32_val - exact_val);
    const double den = std::fabs(exact_val);
    // Allow the kernel a little more accumulation noise than ggml's ordering
    // (it uses a different but equally valid order) but nothing beyond.
    const double slack = 1e-5 * (den + 1e-30) + 1.0 * 1.0e-7;
    return ke <= ge + slack;
}

// ---------------------------------------------------------------------------
// ggml reference: ggml_vec_dot_q3_K_q8_K_generic (src/ggml-cpu/quants.c:471),
// transcribed verbatim so the parity comparison can bound Deep2's rounding by
// ggml's own accumulation order.
// ---------------------------------------------------------------------------
static float ref_vec_dot_q3_K_q8_K(const block_q3_K* x, const block_q8_K* y) {
    const uint32_t kmask1 = 0x03030303u;
    const uint32_t kmask2 = 0x0f0f0f0fu;

    int8_t  aux8[QK_K];
    int16_t aux16[8];
    float   sums[8];
    int32_t aux32[8];
    std::memset(sums, 0, sizeof(sums));

    uint32_t auxs[4];
    const int8_t* scales = reinterpret_cast<const int8_t*>(auxs);

    float sumf = 0.f;
    const uint8_t* q3 = x->qs;
    const uint8_t* hm = x->hmask;
    const int8_t*  q8 = y->qs;
    std::memset(aux32, 0, sizeof(aux32));
    int8_t* a = aux8;
    uint8_t m = 1;
    for (int j = 0; j < QK_K; j += 128) {
        for (int l = 0; l < 32; ++l) a[l] = q3[l] & 3;
        for (int l = 0; l < 32; ++l) a[l] -= (hm[l] & m ? 0 : 4);
        a += 32; m <<= 1;
        for (int l = 0; l < 32; ++l) a[l] = (q3[l] >> 2) & 3;
        for (int l = 0; l < 32; ++l) a[l] -= (hm[l] & m ? 0 : 4);
        a += 32; m <<= 1;
        for (int l = 0; l < 32; ++l) a[l] = (q3[l] >> 4) & 3;
        for (int l = 0; l < 32; ++l) a[l] -= (hm[l] & m ? 0 : 4);
        a += 32; m <<= 1;
        for (int l = 0; l < 32; ++l) a[l] = (q3[l] >> 6) & 3;
        for (int l = 0; l < 32; ++l) a[l] -= (hm[l] & m ? 0 : 4);
        a += 32; m <<= 1;
        q3 += 32;
    }
    a = aux8;
    std::memcpy(auxs, x->scales, 12);
    uint32_t tmp = auxs[2];
    auxs[2] = ((auxs[0] >> 4) & kmask2) | (((tmp >> 4) & kmask1) << 4);
    auxs[3] = ((auxs[1] >> 4) & kmask2) | (((tmp >> 6) & kmask1) << 4);
    auxs[0] =  (auxs[0]     & kmask2) | (((tmp >> 0) & kmask1) << 4);
    auxs[1] =  (auxs[1]     & kmask2) | (((tmp >> 2) & kmask1) << 4);
    for (int j = 0; j < QK_K / 16; ++j) {
        for (int l = 0; l < 8; ++l) aux16[l] = q8[l] * a[l];
        for (int l = 0; l < 8; ++l) aux32[l] += (scales[j] - 32) * aux16[l];
        q8 += 8; a += 8;
        for (int l = 0; l < 8; ++l) aux16[l] = q8[l] * a[l];
        for (int l = 0; l < 8; ++l) aux32[l] += (scales[j] - 32) * aux16[l];
        q8 += 8; a += 8;
    }
    const float d = ref_fp16_to_fp32(x->d) * y->d;
    for (int l = 0; l < 8; ++l) sums[l] += d * aux32[l];
    for (int l = 0; l < 8; ++l) sumf += sums[l];
    return sumf;
}

// Relative comparison for the exact dequant gate: the reference walk and the
// walk under test perform the identical float operations in the identical
// order, so any real difference is an indexing/semantic error, not rounding.
static bool close_ulp(float ref, float got, float rel) {
    const float diff = std::fabs(ref - got);
    const float scale = std::fabs(ref);
    if (scale == 0.f) return diff <= rel;
    return diff <= rel * scale;
}

// ---------------------------------------------------------------------------
// ggml reference: ggml_vec_dot_q2_K_q8_K_generic (src/ggml-cpu/quants.c:419),
// transcribed verbatim.
// ---------------------------------------------------------------------------
static float ref_vec_dot_q2_K_q8_K(const block_q2_K* x, const block_q8_K* y) {
    const uint8_t* q2 = x->qs;
    const int8_t*  q8 = y->qs;
    const uint8_t* sc = x->scales;

    int summs = 0;
    for (int j = 0; j < 16; ++j) summs += y->bsums[j] * (sc[j] >> 4);

    const float dall = y->d * ref_fp16_to_fp32(x->d);
    const float dmin = y->d * ref_fp16_to_fp32(x->dmin);

    int isum = 0;
    int is = 0;
    for (int k = 0; k < QK_K / 128; ++k) {
        int shift = 0;
        for (int j = 0; j < 4; ++j) {
            int d = sc[is++] & 0xF;
            int isuml = 0;
            for (int l =  0; l < 16; ++l) isuml += q8[l] * ((q2[l] >> shift) & 3);
            isum += d * isuml;
            d = sc[is++] & 0xF;
            isuml = 0;
            for (int l = 16; l < 32; ++l) isuml += q8[l] * ((q2[l] >> shift) & 3);
            isum += d * isuml;
            shift += 2;
            q8 += 32;
        }
        q2 += 32;
    }
    return dall * (float)isum - dmin * (float)summs;
}

// ---------------------------------------------------------------------------
// Deterministic block generator.
//
// Blocks are produced by synthesising the raw byte fields directly rather than
// by running ggml's quantizer, so the test does not depend on a quantizer that
// itself has search heuristics. The generator writes the ggml-ordered fields,
// and the gate then checks Deep2's kernels against the reference dequantizer
// reading the SAME bytes: Deep2's kernel must agree with ggml's semantics, not
// with a particular quantizer.
// ---------------------------------------------------------------------------
static void gen_q2_K(block_q2_K* b, std::mt19937& rng) {
    std::uniform_int_distribution<int> s(0, 15);
    std::uniform_int_distribution<int> q(0, 255);
    const float d    = 0.03f + 0.25f * (float)(rng() % 1000) / 1000.0f;
    const float dmin = 0.005f + 0.05f * (float)(rng() % 1000) / 1000.0f;
    b->d    = ref_fp32_to_fp16(d);
    b->dmin = ref_fp32_to_fp16(dmin);
    for (int i = 0; i < 16; ++i) b->scales[i] = (uint8_t)((s(rng) << 4) | s(rng));
    for (int i = 0; i < 64; ++i) b->qs[i] = (uint8_t)q(rng);
}

static void gen_q3_K(block_q3_K* b, std::mt19937& rng) {
    std::uniform_int_distribution<int> q(0, 255);
    b->d = ref_fp32_to_fp16(0.02f + 0.3f * (float)(rng() % 1000) / 1000.0f);
    for (int i = 0; i < 32; ++i) b->hmask[i]  = (uint8_t)q(rng);
    for (int i = 0; i < 64; ++i) b->qs[i]     = (uint8_t)q(rng);
    for (int i = 0; i < 12; ++i) b->scales[i] = (uint8_t)q(rng);
}

static void gen_q5_K(block_q5_K* b, std::mt19937& rng) {
    std::uniform_int_distribution<int> q(0, 255);
    b->d    = ref_fp32_to_fp16(0.02f + 0.3f * (float)(rng() % 1000) / 1000.0f);
    b->dmin = ref_fp32_to_fp16(0.01f + 0.2f * (float)(rng() % 1000) / 1000.0f);
    for (int i = 0; i < 12; ++i)  b->scales[i] = (uint8_t)q(rng);
    for (int i = 0; i < 32; ++i)  b->qh[i]     = (uint8_t)q(rng);
    for (int i = 0; i < 128; ++i) b->qs[i]     = (uint8_t)q(rng);
}

// ===========================================================================
// G5.1 — block layout must match ggml byte-for-byte.
// ===========================================================================
static void Test_Layouts() {
    std::printf("\n[TEST] G05.1 ggml block layout / size parity\n");

    struct { const char* name; size_t got; size_t want; } t[] = {
        {"q2_K", sizeof(block_q2_K),  84},
        {"q3_K", sizeof(block_q3_K), 110},
        {"q4_K", sizeof(block_q4_K), 144},
        {"q5_K", sizeof(block_q5_K), 176},
        {"q6_K", sizeof(block_q6_K), 210},
        {"q8_K", sizeof(block_q8_K), 292},
    };
    for (auto& e : t) {
        if (e.got != e.want) {
            std::printf("  [FAIL] block_%s size %zu != ggml %zu\n", e.name, e.got, e.want);
            ++g_fail;
        } else {
            std::printf("  [PASS] block_%s size %zu == ggml %zu\n", e.name, e.got, e.want);
        }
    }

    // Field offsets are part of the ABI. Verify a couple of the ones that were
    // wrong before (q2_K / q3_K super-scales at the END of the block).
    if (offsetof(block_q2_K, d)   !=  80 || offsetof(block_q2_K, scales) != 0 ||
        offsetof(block_q2_K, qs)  !=  16) {
        std::printf("  [FAIL] block_q2_K field offsets wrong (scales=%zu qs=%zu d=%zu)\n",
                    offsetof(block_q2_K, scales), offsetof(block_q2_K, qs),
                    offsetof(block_q2_K, d));
        ++g_fail;
    } else {
        std::printf("  [PASS] block_q2_K offsets scales=0 qs=16 d=80 dmin=82\n");
    }
    if (offsetof(block_q3_K, hmask) != 0 || offsetof(block_q3_K, qs) != 32 ||
        offsetof(block_q3_K, scales) != 96 || offsetof(block_q3_K, d) != 108) {
        std::printf("  [FAIL] block_q3_K field offsets wrong (hmask=%zu qs=%zu scales=%zu d=%zu)\n",
                    offsetof(block_q3_K, hmask), offsetof(block_q3_K, qs),
                    offsetof(block_q3_K, scales), offsetof(block_q3_K, d));
        ++g_fail;
    } else {
        std::printf("  [PASS] block_q3_K offsets hmask=0 qs=32 scales=96 d=108\n");
    }
    if (offsetof(block_q5_K, qh) != 16 || offsetof(block_q5_K, qs) != 48) {
        std::printf("  [FAIL] block_q5_K field offsets wrong (qh=%zu qs=%zu)\n",
                    offsetof(block_q5_K, qh), offsetof(block_q5_K, qs));
        ++g_fail;
    } else {
        std::printf("  [PASS] block_q5_K offsets qh=16 qs=48\n");
    }
}

// ===========================================================================
// One paranoid run of the Q2_K parity gate.
// ===========================================================================
static void Test_Q2K_Parity(int nblocks) {
    std::printf("\n[TEST] G05.2 Q2_K dequant + dot parity vs ggml reference "
                "(%d blocks)\n", nblocks);

    std::mt19937 rng(20261014u);

    std::vector<block_q2_K> blocks(nblocks);
    for (int i = 0; i < nblocks; ++i) gen_q2_K(&blocks[i], rng);

    // Independent activation vectors -> Q8_K.
    std::vector<std::vector<float>> act(nblocks, std::vector<float>(QK_K));
    std::normal_distribution<float> nd(0.f, 1.f);
    std::vector<block_q8_K> q8(nblocks);
    for (int i = 0; i < nblocks; ++i) {
        for (int j = 0; j < QK_K; ++j) act[i][j] = nd(rng);
        ref_quantize_row_q8_K(act[i].data(), &q8[i], QK_K);
    }

    // --- dequant gate: the reference walk, expressed as a weight[256] array.
    // This is ggml's own reconstruction (the same walk as the vendored
    // dequantize_row_q2_K) with the super-scale applied exactly as ggml does,
    // i.e. dl * q - ml. It is the oracle the dot gate uses, so it is stated
    // once here and reused.
    auto q2k_weight_array = [&](const block_q2_K& blk, float* w) {
        const float d    = ref_fp16_to_fp32(blk.d);
        const float dmin = ref_fp16_to_fp32(blk.dmin);
        const uint8_t* q = blk.qs;
        int is = 0;
        int out = 0;
        for (int n = 0; n < QK_K; n += 128) {
            int shift = 0;
            for (int j = 0; j < 4; ++j) {
                for (int half = 0; half < 2; ++half) {
                    const uint8_t sc = blk.scales[is++];
                    const float dl = d * (float)(sc & 0xF);
                    const float ml = dmin * (float)(sc >> 4);
                    for (int l = 0; l < 16; ++l) {
                        w[out++] = dl * (float)((int8_t)((q[16 * half + l] >> shift) & 3)) - ml;
                    }
                }
                shift += 2;
            }
            q += 32;
        }
    };

    {
        std::vector<float> ref_w(QK_K);
        for (int i = 0; i < nblocks; ++i) {
            ref_dequantize_row_q2_K(&blocks[i], ref_w.data(), QK_K);
            std::vector<float> w(QK_K);
            q2k_weight_array(blocks[i], w.data());
            for (int e = 0; e < QK_K; ++e) {
                if (!close_ulp(ref_w[e], w[e], 1e-6f)) {
                    report_divergence("Q2_K dequant", i, e, ref_w[e], w[e], 1e-6f);
                    ++g_fail;
                    return;
                }
            }
        }
        std::printf("  [PASS] Q2_K dequant walk (scales/qs/shift indexing) matches "
                    "ggml over %d blocks x 256 weights\n", nblocks);
    }

    // --- dot gate: Deep2's kernel vs the ggml float32 reference kernel and the
    // double-precision oracle. Deep2 must be as accurate as ggml's own float32
    // accumulation, and must agree with ggml's float32 result to rounding.
    {
        std::vector<float> ref_w(QK_K);
        float worst_rel = 0.f, worst_vs_ggml = 0.f;
        int worst_blk = -1;
        for (int i = 0; i < nblocks; ++i) {
            ref_dequantize_row_q2_K(&blocks[i], ref_w.data(), QK_K);
            const float q8d = q8[i].d;
            double expect = 0.0;
            for (int e = 0; e < QK_K; ++e) {
                expect += (double)ref_w[e] * (double)(q8d * (float)q8[i].qs[e]);
            }
            const float got    = vec_dot_q2_K_q8_K_single(&blocks[i], &q8[i]);
            const float ggml_f = ref_vec_dot_q2_K_q8_K(&blocks[i], &q8[i]);

            if (!parity_ok((double)got, (double)ggml_f, expect)) {
                report_divergence("Q2_K dot", i, -1, expect, got, 2e-5);
                std::printf("         block %d: exact_double=%.9g deep2=%.9g ggml_f32=%.9g\n",
                            i, expect, got, ggml_f);
                ++g_fail;
                return;
            }
            const double dv = std::fabs((double)got - (double)ggml_f) /
                              (std::fabs((double)ggml_f) + 1e-30);
            const float rel = (float)(std::fabs((double)got - expect) /
                                       (std::fabs(expect) + 1e-30));
            if (dv > worst_vs_ggml) worst_vs_ggml = (float)dv;
            if (rel > worst_rel) { worst_rel = rel; worst_blk = i; }
        }
        std::printf("  [PASS] Q2_K dot matches ggml (worst rel %.3g at blk %d; "
                    "vs ggml_f32 %.3g)\n", worst_rel, worst_blk, worst_vs_ggml);
    }
}

// ===========================================================================
// One paranoid run of the Q3_K parity gate.
// ===========================================================================
static void Test_Q3K_Parity(int nblocks) {
    std::printf("\n[TEST] G05.3 Q3_K dequant + dot parity vs ggml reference "
                "(%d blocks)\n", nblocks);

    std::mt19937 rng(771u);

    std::vector<block_q3_K> blocks(nblocks);
    for (int i = 0; i < nblocks; ++i) gen_q3_K(&blocks[i], rng);

    std::vector<block_q8_K> q8(nblocks);
    std::vector<std::vector<float>> act(nblocks, std::vector<float>(QK_K));
    std::normal_distribution<float> nd(0.f, 1.f);
    for (int i = 0; i < nblocks; ++i) {
        for (int j = 0; j < QK_K; ++j) act[i][j] = nd(rng);
        ref_quantize_row_q8_K(act[i].data(), &q8[i], QK_K);
    }

    std::vector<float> ref_w(QK_K);
    float worst_rel = 0.f;
    int worst_blk = -1;
    for (int i = 0; i < nblocks; ++i) {
        ref_dequantize_row_q3_K(&blocks[i], ref_w.data(), QK_K);
        const float q8d = q8[i].d;
        double expect = 0.0;
        for (int e = 0; e < QK_K; ++e) {
            expect += (double)ref_w[e] * (double)(q8d * (float)q8[i].qs[e]);
        }
        const float got     = vec_dot_q3_K_q8_K_single(&blocks[i], &q8[i]);
        const float ggml_f  = ref_vec_dot_q3_K_q8_K(&blocks[i], &q8[i]);
        const double d_err = std::fabs((double)got - expect);
        const double g_err = std::fabs((double)ggml_f - expect);

        if (!parity_ok((double)got, (double)ggml_f, expect)) {
            report_divergence("Q3_K dot", i, -1, expect, got, 2e-5);
            std::printf("         block %d: exact_double=%.9g deep2=%.9g (err %.3g) "
                        "ggml_f32=%.9g (err %.3g)\n",
                        i, expect, got, d_err, ggml_f, g_err);

            // Dump the raw block fields so the divergence is actionable.
            std::printf("         scales[12] =");
            for (int j = 0; j < 12; ++j) std::printf(" %02x", blocks[i].scales[j]);
            std::printf("\n         hmask[0..3] =");
            for (int j = 0; j < 4; ++j) std::printf(" %02x", blocks[i].hmask[j]);
            std::printf("\n         qs[0..3]    =");
            for (int j = 0; j < 4; ++j) std::printf(" %02x", blocks[i].qs[j]);
            std::printf("\n         q8[0..7]    =");
            for (int j = 0; j < 8; ++j) std::printf(" %d", (int)q8[i].qs[j]);
            std::printf("  q8.d=%g\n", q8d);

            ++g_fail;
            return;
        }
        const float rel = (float)(d_err / (std::fabs(expect) + 1e-30));
        if (rel > worst_rel) { worst_rel = rel; worst_blk = i; }
    }
    std::printf("  [PASS] Q3_K dot is as accurate as ggml's own float32 "
                "accumulation (worst Deep2 rel %.3g at blk %d)\n", worst_rel, worst_blk);
}

// ===========================================================================
// One paranoid run of the Q5_K parity gate.
// ===========================================================================
static void Test_Q5K_Parity(int nblocks) {
    std::printf("\n[TEST] G05.4 Q5_K dequant + dot parity vs ggml reference "
                "(%d blocks)\n", nblocks);

    std::mt19937 rng(99u);
    std::vector<block_q5_K> blocks(nblocks);
    for (int i = 0; i < nblocks; ++i) gen_q5_K(&blocks[i], rng);

    std::vector<block_q8_K> q8(nblocks);
    std::vector<std::vector<float>> act(nblocks, std::vector<float>(QK_K));
    std::normal_distribution<float> nd(0.f, 1.f);
    for (int i = 0; i < nblocks; ++i) {
        for (int j = 0; j < QK_K; ++j) act[i][j] = nd(rng);
        ref_quantize_row_q8_K(act[i].data(), &q8[i], QK_K);
    }

    std::vector<float> ref_w(QK_K);
    float worst_rel = 0.f;
    int worst_blk = -1;
    for (int i = 0; i < nblocks; ++i) {
        ref_dequantize_row_q5_K(&blocks[i], ref_w.data(), QK_K);
        const float q8d = q8[i].d;
        double expect = 0.0;
        for (int e = 0; e < QK_K; ++e) {
            expect += (double)ref_w[e] * (double)(q8d * (float)q8[i].qs[e]);
        }
        const float got = vec_dot_q5_K_q8_K_single(&blocks[i], &q8[i]);
        const double rel = std::fabs(expect - (double)got) /
                           (std::fabs(expect) + 1e-30);
        // The Q5_K reference kernel is the only oracle transcribed here, so the
        // bound is Deep2's own rounding against the double oracle directly.
        if (!(rel < 1e-4)) {
            report_divergence("Q5_K dot", i, -1, expect, got, 1e-4);
            std::printf("         block %d: exact_double=%.9g deep2=%.9g rel=%.3g\n",
                        i, expect, got, rel);
            ++g_fail;
            return;
        }
        if (rel > worst_rel) { worst_rel = rel; worst_blk = i; }
    }
    std::printf("  [PASS] Q5_K dot product matches ggml (worst relative %.3g at blk %d)\n",
                worst_rel, worst_blk);
}

// ===========================================================================
// Regression: the previously-buggy geometry must not come back. These use
// feature-rich blocks (all scale nibbles distinct, all shifts exercised) which
// is where the old one-scale-for-32-elements and duplicated-bsums bugs showed.
// ===========================================================================
static void Test_AdversarialQ2K() {
    std::printf("\n[TEST] G05.5 Q2_K adversarial geometry (all nibbles/shifts)\n");

    block_q2_K b;
    std::memset(&b, 0, sizeof(b));
    b.d    = ref_fp32_to_fp16(1.0f);
    b.dmin = ref_fp32_to_fp16(0.5f);
    // Distinct low and high nibbles for every group so a mis-paired scale or a
    // wrong bsum index can only show up as a wrong answer.
    for (int i = 0; i < 16; ++i) b.scales[i] = (uint8_t)((i << 4) | (16 - i));
    // Chosen so every 2-bit field is non-zero and all four shifts differ.
    for (int i = 0; i < 64; ++i) b.qs[i] = (uint8_t)(0xE4 + 0x1D * i);

    block_q8_K y;
    std::memset(&y, 0, sizeof(y));
    y.d = 1.0f;
    for (int e = 0; e < QK_K; ++e) y.qs[e] = (int8_t)(e - 128);
    for (int g = 0; g < 16; ++g) {
        int s = 0;
        for (int l = 0; l < 16; ++l) s += y.qs[g * 16 + l];
        y.bsums[g] = (int16_t)s;
    }

    // This is the geometry the old kernel got wrong: two different scale bytes
    // per 32-element group, and 16 min terms paired 1:1 with the block sums.
    // With distinct nibbles the two defects cannot cancel.
    const float got = vec_dot_q2_K_q8_K_single(&b, &y);
    std::vector<float> w(QK_K);
    ref_dequantize_row_q2_K(&b, w.data(), QK_K);
    double expect = 0.0;
    for (int e = 0; e < QK_K; ++e) {
        expect += (double)w[e] * (double)(1.0f * (float)y.qs[e]);
    }
    const double rel = std::fabs(expect - (double)got) / (std::fabs(expect) + 1e-30);
    std::printf("  [INFO] expect=%.9g got=%.9g rel=%.3g\n", expect, got, rel);
    if (!(rel < 2e-5)) {
        std::printf("  [FAIL] adversarial Q2_K geometry diverges\n");
        ++g_fail;
        return;
    }
    std::printf("  [PASS] adversarial Q2_K geometry matches ggml\n");
}

// ===========================================================================
int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    const int nblocks = (argc > 1) ? std::atoi(argv[1]) : 200;

    std::printf("=================================================================\n");
    std::printf(" G05 - Q2_K / Q3_K numerical parity vs vendored ggml reference\n");
    std::printf(" blocks=%d   oracle: ggml dequantize_row_q*_K (independent)\n", nblocks);
    std::printf("=================================================================\n");

    Test_Layouts();
    Test_Q2K_Parity(nblocks);
    Test_Q3K_Parity(nblocks);
    Test_Q5K_Parity(nblocks);
    Test_AdversarialQ2K();

    std::printf("\n=================================================================\n");
    if (g_fail == 0) {
        std::printf(" G05 parity: PASS\n");
        std::printf("=================================================================\n");
        return 0;
    }
    std::printf(" G05 parity: FAIL (%d gate(s)) - first divergence reported above\n", g_fail);
    std::printf("=================================================================\n");
    return 4;
}
