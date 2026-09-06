/*
 * BATCH2_O_PROJ_ROW_002 — worst-row block/dot localization for blk.0.attn_output
 *
 * Freezes row with max |prod-llama|, dumps:
 *   x_fp32, x_q8k, w_q4k blocks, per-block dots, running acc, final y
 * A/B: production GEMV vs ggml-faithful Q4_K×Q8_K scalar vs llama Y[row]
 *
 * Does NOT reopen Q/K/V / tokenizer / Track A.
 */
#include "GGUFLoader.hpp"
#include "QuantKernelRegistry.hpp"

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>

#ifdef _WIN32
#include <direct.h>
#define MKDIR(p) _mkdir(p)
#else
#include <sys/stat.h>
#define MKDIR(p) mkdir(p, 0755)
#endif

using Deep2::GGUFLoader;
using Deep2::QuantKernelRegistry;
using Deep2::block_q8_K;

#pragma pack(push, 1)
struct BlockQ4K {
    uint16_t d, dmin;
    uint8_t scales[12];
    uint8_t qs[128];
};
#pragma pack(pop)
static_assert(sizeof(BlockQ4K) == 144, "Q4_K");

static float f16(uint16_t h) {
    uint32_t sign = (uint32_t)(h & 0x8000) << 16;
    uint32_t exp = (h >> 10) & 0x1F;
    uint32_t frac = h & 0x3FF;
    uint32_t bits;
    if (exp == 0) {
        if (frac == 0) {
            bits = sign;
            float r;
            std::memcpy(&r, &bits, 4);
            return r;
        }
        exp = 1;
        while ((frac & 0x400) == 0) {
            frac <<= 1;
            ++exp;
        }
        frac &= 0x3FF;
        bits = sign | ((127 - 15 - exp + 2) << 23) | (frac << 13);
    } else if (exp == 31) {
        bits = sign | 0x7F800000 | (frac << 13);
    } else {
        bits = sign | ((exp + 127 - 15) << 23) | (frac << 13);
    }
    float r;
    std::memcpy(&r, &bits, 4);
    return r;
}

// ggml / QuantKernelRegistry unpack_q4_k_scales
static void unpack_scales_ggml(const uint8_t s[12], uint8_t scales[8], uint8_t mins[8]) {
    scales[0] = s[0] & 0x3F;
    scales[1] = s[1] & 0x3F;
    scales[2] = s[2] & 0x3F;
    scales[3] = s[3] & 0x3F;
    mins[0] = s[4] & 0x3F;
    mins[1] = s[5] & 0x3F;
    mins[2] = s[6] & 0x3F;
    mins[3] = s[7] & 0x3F;
    scales[4] = (s[8] & 0x0F) | ((s[0] >> 6) << 4);
    scales[5] = (s[9] & 0x0F) | ((s[1] >> 6) << 4);
    scales[6] = (s[10] & 0x0F) | ((s[2] >> 6) << 4);
    scales[7] = (s[11] & 0x0F) | ((s[3] >> 6) << 4);
    mins[4] = (s[8] >> 4) | ((s[4] >> 6) << 4);
    mins[5] = (s[9] >> 4) | ((s[5] >> 6) << 4);
    mins[6] = (s[10] >> 4) | ((s[6] >> 6) << 4);
    mins[7] = (s[11] >> 4) | ((s[7] >> 6) << 4);
}

static inline int nearest_int_q8k(float fval) {
    float val = fval + 12582912.f;
    int i;
    std::memcpy(&i, &val, sizeof(int));
    return (i & 0x007fffff) - 0x00400000;
}

static void quantize_row_q8_K(const float* x, block_q8_K* y, size_t k) {
    const size_t nb = k / 256;
    for (size_t i = 0; i < nb; ++i) {
        float max = 0.f, amax = 0.f;
        for (int j = 0; j < 256; ++j) {
            float ax = std::fabs(x[j]);
            if (ax > amax) {
                amax = ax;
                max = x[j];
            }
        }
        if (!amax) {
            y[i].d = 0.f;
            std::memset(y[i].qs, 0, 256);
            std::memset(y[i].bsums, 0, sizeof(y[i].bsums));
            x += 256;
            continue;
        }
        const float iscale = -127.f / max;
        for (int j = 0; j < 256; ++j) {
            int v = nearest_int_q8k(iscale * x[j]);
            y[i].qs[j] = static_cast<int8_t>(v > 127 ? 127 : v);
        }
        for (int j = 0; j < 16; ++j) {
            int sum = 0;
            for (int ii = 0; ii < 16; ++ii)
                sum += y[i].qs[j * 16 + ii];
            y[i].bsums[j] = static_cast<int16_t>(sum);
        }
        y[i].d = 1.f / iscale;
        x += 256;
    }
}

// Single-block ggml vec_dot_q4_K_q8_K (nb=1)
static float vec_dot_one_block(const BlockQ4K& x, const block_q8_K& y) {
    static const uint32_t kmask1 = 0x3f3f3f3f;
    static const uint32_t kmask2 = 0x0f0f0f0f;
    static const uint32_t kmask3 = 0x03030303;
    uint32_t utmp[4];
    const uint8_t* scales = reinterpret_cast<const uint8_t*>(&utmp[0]);
    const uint8_t* mins = reinterpret_cast<const uint8_t*>(&utmp[2]);
    int8_t aux8[256];
    int16_t aux16[8];
    float sums[8];
    int32_t aux32[8];
    std::memset(sums, 0, sizeof(sums));
    float sumf = 0.f;

    const uint8_t* q4 = x.qs;
    const int8_t* q8 = y.qs;
    std::memset(aux32, 0, sizeof(aux32));
    int8_t* a = aux8;
    for (int j = 0; j < 4; ++j) {
        for (int l = 0; l < 32; ++l)
            a[l] = static_cast<int8_t>(q4[l] & 0xF);
        a += 32;
        for (int l = 0; l < 32; ++l)
            a[l] = static_cast<int8_t>(q4[l] >> 4);
        a += 32;
        q4 += 32;
    }
    std::memcpy(utmp, x.scales, 12);
    utmp[3] = ((utmp[2] >> 4) & kmask2) | (((utmp[1] >> 6) & kmask3) << 4);
    const uint32_t uaux = utmp[1] & kmask1;
    utmp[1] = (utmp[2] & kmask2) | (((utmp[0] >> 6) & kmask3) << 4);
    utmp[2] = uaux;
    utmp[0] &= kmask1;

    int sumi = 0;
    for (int j = 0; j < 16; ++j)
        sumi += y.bsums[j] * mins[j / 2];
    a = aux8;
    int is = 0;
    for (int j = 0; j < 8; ++j) {
        const int32_t scale = scales[is++];
        for (int r = 0; r < 4; ++r) {
            for (int l = 0; l < 8; ++l)
                aux16[l] = static_cast<int16_t>(q8[l] * a[l]);
            for (int l = 0; l < 8; ++l)
                aux32[l] += scale * aux16[l];
            q8 += 8;
            a += 8;
        }
    }
    const float d = f16(x.d) * y.d;
    for (int l = 0; l < 8; ++l)
        sums[l] += d * static_cast<float>(aux32[l]);
    const float dmin = f16(x.dmin) * y.d;
    sumf -= dmin * static_cast<float>(sumi);
    for (int l = 0; l < 8; ++l)
        sumf += sums[l];
    return sumf;
}

static bool loadF32(const char* p, size_t n, std::vector<float>& o) {
    FILE* f = std::fopen(p, "rb");
    if (!f)
        return false;
    o.resize(n);
    bool ok = std::fread(o.data(), 4, n, f) == n;
    std::fclose(f);
    return ok;
}

static void hexDump(FILE* f, const char* tag, const uint8_t* p, size_t n) {
    std::fprintf(f, "%s=", tag);
    for (size_t i = 0; i < n; ++i)
        std::fprintf(f, "%02x", p[i]);
    std::fprintf(f, "\n");
}

int main() {
    const char* model = R"(F:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf)";
    const char* loc = R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_ATTN_OUT_LOC)";
    const char* outDir =
        R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_O_PROJ_ROW_002)";
    MKDIR(R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001)");
    MKDIR(outDir);

    std::vector<float> Xd, Xl, Yllama, Ydeep2;
    if (!loadF32((std::string(loc) + "\\deep2_ATTN_PRE_O_0_pos0_layer0_full_n2048_seq008.bin").c_str(),
                 2048, Xd) ||
        !loadF32((std::string(loc) + "\\llama_ATTN_PRE_O_0_pos0_layer0_full_n2048_seq102.bin").c_str(),
                 2048, Xl) ||
        !loadF32((std::string(loc) + "\\llama_ATTN_OUT_0_pos0_layer0_full_n2048_seq105.bin").c_str(),
                 2048, Yllama) ||
        !loadF32((std::string(loc) + "\\deep2_ATTN_OUT_0_pos0_layer0_full_n2048_seq009.bin").c_str(),
                 2048, Ydeep2)) {
        std::fprintf(stderr, "LOAD_FAIL\n");
        return 2;
    }

    auto lr = GGUFLoader::Load(model, {true, true, false});
    if (!lr.success || !lr.GetTensor("blk.0.attn_output.weight")) {
        std::fprintf(stderr, "GGUF_FAIL\n");
        return 2;
    }
    const auto* wo = lr.GetTensor("blk.0.attn_output.weight");
    const size_t cols = (size_t)wo->dimensions[0];
    const size_t rows = (size_t)wo->dimensions[1];
    const size_t bpr = cols / 256;
    const BlockQ4K* W = reinterpret_cast<const BlockQ4K*>(wo->data);

    auto& reg = QuantKernelRegistry::Instance();
    reg.Initialize();
    auto ker = reg.GetGEMV((int)wo->type);

    std::vector<float> Yprod(rows, 0.f), YprodLlamaX(rows, 0.f);
    ker((const uint8_t*)wo->data, Xd.data(), Yprod.data(), rows, cols);
    ker((const uint8_t*)wo->data, Xl.data(), YprodLlamaX.data(), rows, cols);

    // Find worst row vs llama using deep2 X
    int worst = -1;
    double worstAbs = 0;
    int rowsGt1e5 = 0;
    for (size_t r = 0; r < rows; ++r) {
        double d = std::fabs((double)Yprod[r] - (double)Yllama[r]);
        if (d > 1e-5)
            ++rowsGt1e5;
        if (d > worstAbs) {
            worstAbs = d;
            worst = (int)r;
        }
    }

    const size_t row = (size_t)worst;
    const BlockQ4K* rowW = W + row * bpr;

    std::vector<block_q8_K> xQ8(bpr), xQ8l(bpr);
    quantize_row_q8_K(Xd.data(), xQ8.data(), cols);
    quantize_row_q8_K(Xl.data(), xQ8l.data(), cols);

    double acc = 0.0;
    std::vector<float> blockDots(bpr);
    for (size_t b = 0; b < bpr; ++b) {
        blockDots[b] = vec_dot_one_block(rowW[b], xQ8[b]);
        acc += (double)blockDots[b];
    }
    const float yRef = (float)acc;

    // PRE_O gap contribution at this row (same W, different X)
    double accL = 0.0;
    for (size_t b = 0; b < bpr; ++b)
        accL += (double)vec_dot_one_block(rowW[b], xQ8l[b]);

    FILE* rf = std::fopen((std::string(outDir) + "\\row_dump.txt").c_str(), "w");
    FILE* vf = std::fopen((std::string(outDir) + "\\VERDICT.txt").c_str(), "w");
    if (!rf) {
        std::fprintf(stderr, "ROW_DUMP_OPEN_FAIL\n");
        return 2;
    }

    std::fprintf(rf,
                 "BATCH2_O_PROJ_ROW_002\n"
                 "row=%d worst_abs_prod_vs_llama=%.17g\n"
                 "rows_gt_1e-5=%d/%zu\n\n",
                 worst, worstAbs, rowsGt1e5, rows);

    // X stats
    double xmax = 0, xdiff = 0;
    int xFirst = -1;
    for (size_t i = 0; i < cols; ++i) {
        double d = std::fabs((double)Xd[i] - (double)Xl[i]);
        if (d > xdiff) {
            xdiff = d;
            if (xFirst < 0 && d > 1e-6)
                xFirst = (int)i;
        }
        xmax = std::max(xmax, std::fabs((double)Xd[i]));
    }

    std::fprintf(rf,
                 "X=deep2_ATTN_PRE_O_0\n"
                 "X_llama=llama_ATTN_PRE_O_0\n"
                 "X_max_abs=%.9e\n"
                 "X_deep2_vs_llama max_abs=%.17g first_gt_1e-6=%d\n"
                 "Y_deep2[row]=%.17g\n"
                 "Y_prod[row]=%.17g\n"
                 "Y_ref_blocksum[row]=%.17g\n"
                 "Y_llama[row]=%.17g\n"
                 "Y_prod_llamaX[row]=%.17g\n"
                 "Y_ref_llamaX_blocksum[row]=%.17g\n\n",
                 xmax, xdiff, xFirst, Ydeep2[row], Yprod[row], yRef, Yllama[row],
                 YprodLlamaX[row], (float)accL);

    std::fprintf(rf, "prod_vs_deep2_out abs=%.17g\n",
                 std::fabs((double)Yprod[row] - (double)Ydeep2[row]));
    std::fprintf(rf, "ref_vs_prod abs=%.17g\n",
                 std::fabs((double)yRef - (double)Yprod[row]));
    std::fprintf(rf, "prod_vs_llama abs=%.17g\n",
                 std::fabs((double)Yprod[row] - (double)Yllama[row]));
    std::fprintf(rf, "prod_llamaX_vs_llama abs=%.17g\n",
                 std::fabs((double)YprodLlamaX[row] - (double)Yllama[row]));
    std::fprintf(rf, "ref_llamaX_vs_llama abs=%.17g\n\n",
                 std::fabs(accL - (double)Yllama[row]));

    // Per-block dump
    double run = 0;
    for (size_t b = 0; b < bpr; ++b) {
        const BlockQ4K& blk = rowW[b];
        uint8_t scales[8], mins[8];
        unpack_scales_ggml(blk.scales, scales, mins);
        run += blockDots[b];
        std::fprintf(rf, "--- block %zu ---\n", b);
        std::fprintf(rf, "d_f16=0x%04x d=%g dmin_f16=0x%04x dmin=%g\n", blk.d, f16(blk.d),
                     blk.dmin, f16(blk.dmin));
        std::fprintf(rf, "scales=");
        for (int i = 0; i < 8; ++i)
            std::fprintf(rf, "%u%s", scales[i], i == 7 ? "\n" : ",");
        std::fprintf(rf, "mins=");
        for (int i = 0; i < 8; ++i)
            std::fprintf(rf, "%u%s", mins[i], i == 7 ? "\n" : ",");
        hexDump(rf, "scales12", blk.scales, 12);
        hexDump(rf, "qs_head32", blk.qs, 32);
        std::fprintf(rf, "x_q8k.d=%g bsums0_3=%d,%d,%d,%d\n", xQ8[b].d, (int)xQ8[b].bsums[0],
                     (int)xQ8[b].bsums[1], (int)xQ8[b].bsums[2], (int)xQ8[b].bsums[3]);
        hexDump(rf, "x_q8k.qs_head32", reinterpret_cast<const uint8_t*>(xQ8[b].qs), 32);
        std::fprintf(rf, "dot_block=%.17g running_acc=%.17g\n\n", blockDots[b], run);
    }

    // Full-vector gates for VERDICT
    auto maxAbs = [](const float* a, const float* b, size_t n) {
        double m = 0;
        for (size_t i = 0; i < n; ++i)
            m = std::max(m, std::fabs((double)a[i] - (double)b[i]));
        return m;
    };
    const double preO = maxAbs(Xd.data(), Xl.data(), cols);
    const double prodDeep = maxAbs(Yprod.data(), Ydeep2.data(), rows);
    const double prodLlama = maxAbs(Yprod.data(), Yllama.data(), rows);
    const double prodLlamaXLlama = maxAbs(YprodLlamaX.data(), Yllama.data(), rows);

    // Classify first divergence for this row
    const char* root = "UNKNOWN";
    if (preO > 1e-5)
        root = "ATTN_PRE_O_0 (upstream — unexpected)";
    else if (std::fabs((double)Yprod[row] - (double)Ydeep2[row]) > 1e-7)
        root = "production path != engine ATTN_OUT (instrument bug)";
    else if (std::fabs((double)yRef - (double)Yprod[row]) > 1e-7)
        root = "block-dot sum != production GEMV (kernel split)";
    else if (std::fabs((double)YprodLlamaX[row] - (double)Yllama[row]) <= 1e-6)
        root = "X_PRE_O gap alone explained O error (use llama X)";
    else if (std::fabs(accL - (double)Yllama[row]) > 1e-5 &&
             std::fabs((double)Yprod[row] - (double)Yllama[row]) > 1e-5)
        root = "Q4_K×Q8_K vs llama (same-ish on deep2/llama X) — kernel/repack/accum";
    else
        root = "Q4_K×Q8_K residual (MANY_TINY_FP) — accum/order/repack class";

    if (vf) {
        std::fprintf(vf,
                     "BATCH2_O_PROJ_ROW_002\n"
                     "authority=CPU llama ATTN_OUT_0 + Deep2 ATTN_PRE_O_0\n"
                     "W=blk.0.attn_output.weight Q4_K rows=%zu cols=%zu bpr=%zu\n\n"
                     "ATTN_PRE_O deep2_vs_llama max_abs=%.17g gate=%s\n"
                     "prod_Q8K vs deep2_ATTN_OUT max_abs=%.17g\n"
                     "prod_Q8K(deep2X) vs llama_ATTN_OUT max_abs=%.17g\n"
                     "prod_Q8K(llamaX) vs llama_ATTN_OUT max_abs=%.17g\n\n"
                     "worst_row=%d\n"
                     "worst_abs=%.17g\n"
                     "rows_gt_1e-5=%d/%zu\n"
                     "y_prod=%.17g y_ref=%.17g y_llama=%.17g y_prod_llamaX=%.17g\n"
                     "ref_vs_prod=%.17g\n\n"
                     "FIRST_DIVERGENCE_CLASS=%s\n"
                     "pattern=MANY_TINY_FP_DIFFS (none >=1e-4)\n"
                     "do_not_reopen=Q/K/V tokenizer Track_A\n"
                     "next=if kernel/repack: compare llama CPU_REPACK q4_K_8x8 vs file Q4_K on this row\n",
                     rows, cols, bpr, preO, preO <= 1e-5 ? "PASS/INSPECT" : "FAIL", prodDeep,
                     prodLlama, prodLlamaXLlama, worst, worstAbs, rowsGt1e5, rows, Yprod[row],
                     yRef, Yllama[row], YprodLlamaX[row],
                     std::fabs((double)yRef - (double)Yprod[row]), root);
        std::fclose(vf);
    }
    if (rf)
        std::fclose(rf);

    std::printf("BATCH2_O_PROJ_ROW_002 worst_row=%d worst_abs=%.6e root=%s\n", worst, worstAbs,
                root);
    std::printf("PRE_O max_abs=%.6e prod_vs_deep2=%.6e prod_vs_llama=%.6e prod(llamaX)_vs_llama=%.6e\n",
                preO, prodDeep, prodLlama, prodLlamaXLlama);
    std::printf("row y_prod=%.9g y_ref=%.9g y_llama=%.9g ref-prod=%.3g\n", Yprod[row], yRef,
                Yllama[row], std::fabs((double)yRef - (double)Yprod[row]));
    return 0;
}
