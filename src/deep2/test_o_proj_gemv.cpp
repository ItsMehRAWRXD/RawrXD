/*
 * BATCH2_O_PROJ_GEMV_001 — A/B discriminator for blk.0.attn_output
 * Frozen X = Deep2 ATTN_PRE_O_0 (== GQA_expand(V) exact)
 * Compare: production Q4_K×Q8_K GEMV vs FP32 dequant·x vs llama Y
 */
#include "GGUFLoader.hpp"
#include "QuantKernelRegistry.hpp"

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#ifdef _WIN32
#include <direct.h>
#define MKDIR(p) _mkdir(p)
#else
#include <sys/stat.h>
#define MKDIR(p) mkdir(p, 0755)
#endif

using Deep2::GGUFLoader;
using Deep2::QuantKernelRegistry;
using Deep2::GGMLType;

// Mirror ggml dequantize_row_q4_K (from test_q4k / registry)
#pragma pack(push, 1)
struct BlockQ4K {
    uint16_t d, dmin;
    uint8_t scales[12];
    uint8_t qs[128];
};
#pragma pack(pop)
static_assert(sizeof(BlockQ4K) == 144, "Q4_K block");

static float f16(uint16_t h) {
    uint32_t sign = (uint32_t)(h & 0x8000) << 16;
    uint32_t exp = (h >> 10) & 0x1F;
    uint32_t frac = h & 0x3FF;
    uint32_t bits;
    if (exp == 0) {
        if (frac == 0) { bits = sign; return reinterpret_cast<float&>(bits); }
        exp = 1; while ((frac & 0x400) == 0) { frac <<= 1; ++exp; }
        frac &= 0x3FF;
        bits = sign | ((127 - 15 - exp + 2) << 23) | (frac << 13);
    } else if (exp == 31) {
        bits = sign | 0x7F800000 | (frac << 13);
    } else {
        bits = sign | ((exp + 127 - 15) << 23) | (frac << 13);
    }
    return reinterpret_cast<float&>(bits);
}

static void unpack_scales(const uint8_t s[12], uint8_t scales[8], uint8_t mins[8]) {
    scales[0] = s[0] & 63; scales[1] = s[1] & 63; scales[2] = s[2] & 63; scales[3] = s[3] & 63;
    scales[4] = s[4] & 63; scales[5] = s[5] & 63; scales[6] = s[6] & 63; scales[7] = s[7] & 63;
    mins[0] = (s[8] & 15) | ((s[0] >> 6) << 4);
    mins[1] = (s[8] >> 4) | ((s[1] >> 6) << 4);
    mins[2] = (s[9] & 15) | ((s[2] >> 6) << 4);
    mins[3] = (s[9] >> 4) | ((s[3] >> 6) << 4);
    mins[4] = (s[10] & 15) | ((s[4] >> 6) << 4);
    mins[5] = (s[10] >> 4) | ((s[5] >> 6) << 4);
    mins[6] = (s[11] & 15) | ((s[6] >> 6) << 4);
    mins[7] = (s[11] >> 4) | ((s[7] >> 6) << 4);
}

static void dequant_row_q4_K(const BlockQ4K* blocks, size_t bpr, float* out) {
    for (size_t b = 0; b < bpr; ++b) {
        const BlockQ4K& blk = blocks[b];
        float d = f16(blk.d), dmin = f16(blk.dmin);
        uint8_t scales[8], mins[8];
        unpack_scales(blk.scales, scales, mins);
        const uint8_t* q = blk.qs;
        float* y = out + b * 256;
        for (int is = 0; is < 8; is += 2) {
            float d1 = d * scales[is], m1 = dmin * mins[is];
            float d2 = d * scales[is + 1], m2 = dmin * mins[is + 1];
            for (int l = 0; l < 32; ++l) {
                y[is * 32 + l] = d1 * (q[l] & 0xF) - m1;
                y[(is + 1) * 32 + l] = d2 * (q[l] >> 4) - m2;
            }
            q += 32;
        }
    }
}

static void gemv_fp32_dequant(const BlockQ4K* w, const float* x, float* y, size_t rows, size_t cols) {
    const size_t bpr = cols / 256;
    std::vector<float> row(cols);
    for (size_t r = 0; r < rows; ++r) {
        dequant_row_q4_K(w + r * bpr, bpr, row.data());
        double acc = 0;
        for (size_t c = 0; c < cols; ++c) acc += (double)row[c] * (double)x[c];
        y[r] = (float)acc;
    }
}

static bool loadF32(const char* p, size_t n, std::vector<float>& o) {
    FILE* f = std::fopen(p, "rb");
    if (!f) return false;
    o.resize(n);
    bool ok = std::fread(o.data(), 4, n, f) == n;
    std::fclose(f);
    return ok;
}

static void cmp(const char* tag, const float* a, const float* b, size_t n, FILE* vf) {
    double maxa = 0, maxr = 0, ss = 0;
    int first = -1, larg = -1, exact = 0;
    for (size_t i = 0; i < n; ++i) {
        double d = std::fabs((double)a[i] - (double)b[i]);
        ss += d * d;
        if (d > maxa) { maxa = d; larg = (int)i; }
        float den = std::max(std::fabs(a[i]), std::fabs(b[i]));
        double r = den > 0 ? d / den : 0;
        if (r > maxr) maxr = r;
        if (d <= 1e-6) ++exact;
        else if (first < 0) first = (int)i;
    }
    const char* gate = maxa <= 1e-6 ? "PASS" : (maxa <= 1e-5 ? "INSPECT" : "FAIL");
    std::printf("%s gate=%s max_abs=%.6e max_rel=%.6e rms=%.6e exact=%d first_bad=%d largest=%d\n",
                tag, gate, maxa, maxr, std::sqrt(ss / n), exact, first, larg);
    if (vf) {
        std::fprintf(vf, "%s\n  max_abs=%.17g\n  max_rel=%.17g\n  first_bad=%d\n  PASS/FAIL=%s\n",
                     tag, maxa, maxr, first, gate);
    }
}

int main() {
    const char* model = R"(F:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf)";
    const char* loc = R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_ATTN_OUT_LOC)";
    const char* outDir = R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_O_PROJ_GEMV_001)";
    MKDIR(R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001)");
    MKDIR(outDir);

    std::vector<float> X, Yllama, Ydeep2;
    if (!loadF32((std::string(loc) + "\\deep2_ATTN_PRE_O_0_pos0_layer0_full_n2048_seq008.bin").c_str(), 2048, X) ||
        !loadF32((std::string(loc) + "\\llama_ATTN_OUT_0_pos0_layer0_full_n2048_seq105.bin").c_str(), 2048, Yllama) ||
        !loadF32((std::string(loc) + "\\deep2_ATTN_OUT_0_pos0_layer0_full_n2048_seq009.bin").c_str(), 2048, Ydeep2)) {
        std::fprintf(stderr, "LOAD_FAIL\n");
        return 2;
    }

    auto lr = GGUFLoader::Load(model, {true, true, false});
    if (!lr.success) { std::fprintf(stderr, "GGUF_FAIL\n"); return 2; }
    const auto* wo = lr.GetTensor("blk.0.attn_output.weight");
    if (!wo || !wo->data) { std::fprintf(stderr, "NO_WO\n"); return 2; }
    const size_t cols = (size_t)wo->dimensions[0];
    const size_t rows = (size_t)wo->dimensions[1];
    const size_t bpr = cols / 256;
    const size_t rowBytes = bpr * sizeof(BlockQ4K);

    FILE* vf = std::fopen((std::string(outDir) + "\\verdict.txt").c_str(), "w");
    if (vf) {
        std::fprintf(vf,
            "BATCH2_O_PROJ_GEMV_001\n"
            "X=deep2_ATTN_PRE_O_0 (GQA_expand(V) exact)\n"
            "W=blk.0.attn_output.weight type=%d rows=%zu cols=%zu size=%llu rowBytes=%zu bpr=%zu\n"
            "PRE_O_vs_llama=INSPECT max_abs~6.14e-6 (not FAIL; concat layout OK)\n"
            "ATTN_OUT_vs_llama=FAIL max_abs~8.45e-5 -> O_PROJ domain\n\n",
            (int)wo->type, rows, cols, (unsigned long long)wo->size, rowBytes, bpr);
    }
    std::printf("W type=%d rows=%zu cols=%zu size=%llu data=%p\n",
                (int)wo->type, rows, cols, (unsigned long long)wo->size, wo->data);

    // Raw byte fingerprint of first block
    const uint8_t* w0 = (const uint8_t*)wo->data;
    std::printf("W_hdr first16=");
    for (int i = 0; i < 16; ++i) std::printf("%02x", w0[i]);
    std::printf("\n");

    auto& reg = QuantKernelRegistry::Instance();
    reg.Initialize();
    auto ker = reg.GetGEMV((int)wo->type);

    std::vector<float> Yprod(rows, 0.f), Yscalar(rows, 0.f);
    ker((const uint8_t*)wo->data, X.data(), Yprod.data(), rows, cols);
    gemv_fp32_dequant((const BlockQ4K*)wo->data, X.data(), Yscalar.data(), rows, cols);

    cmp("prod_Q8K vs deep2_ATTN_OUT", Yprod.data(), Ydeep2.data(), rows, vf);
    cmp("prod_Q8K vs llama_ATTN_OUT", Yprod.data(), Yllama.data(), rows, vf);
    cmp("scalar_FP32 vs llama_ATTN_OUT", Yscalar.data(), Yllama.data(), rows, vf);
    cmp("scalar_FP32 vs prod_Q8K", Yscalar.data(), Yprod.data(), rows, vf);

    // Row-wise: count rows where |prod-llama| > 1e-5
    int badRows = 0, worstRow = -1;
    double worst = 0;
    for (size_t r = 0; r < rows; ++r) {
        double d = std::fabs((double)Yprod[r] - (double)Yllama[r]);
        if (d > 1e-5) ++badRows;
        if (d > worst) { worst = d; worstRow = (int)r; }
    }
    std::printf("rows_gt_1e-5=%d/%zu worst_row=%d worst_abs=%.6e\n", badRows, rows, worstRow, worst);
    if (vf) {
        std::fprintf(vf, "\nrows_gt_1e-5=%d/%zu\nworst_row=%d\nworst_abs=%.17g\n",
                     badRows, rows, worstRow, worst);
        std::fprintf(vf,
            "\nINTERPRETATION\n"
            "scalar~llama, prod differs => optimized GEMV/Q8_K/accum\n"
            "scalar~prod, both~diff llama => decode or llama arith convention (repack q4_K_8x8)\n"
            "scalar closer than prod => accumulation order/precision\n"
            "sparse bad rows => row index/tail\n");
        std::fclose(vf);
    }
    return 0;
}
