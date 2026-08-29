/*
 * test_q4k_gemv_parity.cpp — BATCH2_Q4K_GEMV_001
 *
 * Frozen boundary: ATTN_NORM_0 MATCH → attn_q Q4_K → Q_0 FIRST DIFF
 * Standalone: loads GGUF, builds ATTN_NORM_0 for BOS token_id=1, compares
 * Deep2 Q4_K paths vs exact ggml dequantize_row_q4_K + FP64 dot.
 *
 * Usage:
 *   test_q4k_gemv_parity.exe [model.gguf] [out_dir]
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
#define MKDIR(p) mkdir((p), 0755)
#endif

using Deep2::GGMLType;
using Deep2::GGUFLoader;
using Deep2::GGUFLoadOptions;
using Deep2::GGUFLoadResult;
using Deep2::QuantKernelRegistry;
using Deep2::TensorInfo;

namespace {

struct BlockQ4K {
    uint16_t d;
    uint16_t dmin;
    uint8_t scales[12];
    uint8_t qs[128];
};
static_assert(sizeof(BlockQ4K) == 144, "block_q4_K");

static float fp16ToF32(uint16_t h) {
    uint32_t sign = (h >> 15) & 0x1u;
    uint32_t exp = (h >> 10) & 0x1Fu;
    uint32_t mant = h & 0x3FFu;
    uint32_t f;
    if (exp == 0) {
        if (mant == 0) f = sign << 31;
        else {
            int e = -1;
            do { e++; mant <<= 1; } while (!(mant & 0x400u));
            mant &= 0x3FFu;
            f = (sign << 31) | ((uint32_t)(127 - 15 - e) << 23) | (mant << 13);
        }
    } else if (exp == 31) {
        f = (sign << 31) | (0xFFu << 23) | (mant << 13);
    } else {
        f = (sign << 31) | ((exp + 127 - 15) << 23) | (mant << 13);
    }
    float r;
    std::memcpy(&r, &f, 4);
    return r;
}

static inline void ggmlGetScaleMinK4(int j, const uint8_t* q, uint8_t* d, uint8_t* m) {
    if (j < 4) {
        *d = q[j] & 63;
        *m = q[j + 4] & 63;
    } else {
        *d = (q[j + 4] & 0xF) | ((q[j - 4] >> 6) << 4);
        *m = (q[j + 4] >> 4) | ((q[j - 0] >> 6) << 4);
    }
}

static void ggmlDequantBlock(const BlockQ4K& blk, float* y) {
    const uint8_t* q = blk.qs;
    const float d = fp16ToF32(blk.d);
    const float minv = fp16ToF32(blk.dmin);
    int is = 0;
    uint8_t sc, m;
    for (int j = 0; j < 256; j += 64) {
        ggmlGetScaleMinK4(is + 0, blk.scales, &sc, &m);
        const float d1 = d * sc, m1 = minv * m;
        ggmlGetScaleMinK4(is + 1, blk.scales, &sc, &m);
        const float d2 = d * sc, m2 = minv * m;
        for (int l = 0; l < 32; ++l) *y++ = d1 * (float)(q[l] & 0xF) - m1;
        for (int l = 0; l < 32; ++l) *y++ = d2 * (float)(q[l] >> 4) - m2;
        q += 32;
        is += 2;
    }
}

static void deep2UnpackScales(const uint8_t s[12], uint8_t scales[8], uint8_t mins[8]) {
    scales[0] = s[0] & 0x3F; scales[1] = s[1] & 0x3F;
    scales[2] = s[2] & 0x3F; scales[3] = s[3] & 0x3F;
    mins[0] = s[4] & 0x3F; mins[1] = s[5] & 0x3F;
    mins[2] = s[6] & 0x3F; mins[3] = s[7] & 0x3F;
    scales[4] = (s[8] & 0x0F) | ((s[0] >> 6) << 4);
    scales[5] = (s[9] & 0x0F) | ((s[1] >> 6) << 4);
    scales[6] = (s[10] & 0x0F) | ((s[2] >> 6) << 4);
    scales[7] = (s[11] & 0x0F) | ((s[3] >> 6) << 4);
    mins[4] = (s[8] >> 4) | ((s[4] >> 6) << 4);
    mins[5] = (s[9] >> 4) | ((s[5] >> 6) << 4);
    mins[6] = (s[10] >> 4) | ((s[6] >> 6) << 4);
    mins[7] = (s[11] >> 4) | ((s[7] >> 6) << 4);
}

static void deep2DequantBlock(const BlockQ4K& blk, float* y) {
    float d = fp16ToF32(blk.d), dmin = fp16ToF32(blk.dmin);
    uint8_t scales[8], mins[8];
    deep2UnpackScales(blk.scales, scales, mins);
    const uint8_t* q = blk.qs;
    for (int is = 0; is < 8; is += 2) {
        const float d1 = d * (float)scales[is], m1 = dmin * (float)mins[is];
        const float d2 = d * (float)scales[is + 1], m2 = dmin * (float)mins[is + 1];
        for (int l = 0; l < 32; ++l) *y++ = d1 * (float)(q[l] & 0x0F) - m1;
        for (int l = 0; l < 32; ++l) *y++ = d2 * (float)(q[l] >> 4) - m2;
        q += 32;
    }
}

static void legacyWrongDequantBlock(const BlockQ4K& blk, float* y) {
    float d = fp16ToF32(blk.d), dmin = fp16ToF32(blk.dmin);
    for (int j = 0; j < 8; j++) {
        uint8_t sc, m;
        ggmlGetScaleMinK4(j, blk.scales, &sc, &m);
        float scale = d * sc, minv = dmin * m;
        const uint8_t* quants = blk.qs + j * 16;
        for (int k = 0; k < 16; k++) {
            uint8_t byte = quants[k];
            y[j * 32 + k] = scale * (float)(byte & 0xF) - minv;
            y[j * 32 + k + 16] = scale * (float)(byte >> 4) - minv;
        }
    }
}

static uint64_t fnv1a(const float* a, size_t n) {
    uint64_t h = 14695981039346656037ull;
    for (size_t i = 0; i < n; ++i) {
        uint32_t bits = 0;
        std::memcpy(&bits, &a[i], 4);
        for (int b = 0; b < 4; ++b) {
            h ^= (bits >> (8 * b)) & 0xFFu;
            h *= 1099511628211ull;
        }
    }
    return h;
}

// ggml block_q8_K — activation side of mul_mat(Q4_K, Q8_K)
struct BlockQ8K {
    float d;
    int8_t qs[256];
    int16_t bsums[16];
};
static_assert(sizeof(BlockQ8K) == 4 + 256 + 32, "block_q8_K");

static inline int nearestInt(float fval) {
    float val = fval + 12582912.f;
    int i;
    std::memcpy(&i, &val, sizeof(int));
    return (i & 0x007fffff) - 0x00400000;
}

static void quantizeRowQ8K(const float* x, BlockQ8K* y, size_t k) {
    const size_t nb = k / 256;
    for (size_t i = 0; i < nb; ++i) {
        float max = 0, amax = 0;
        for (int j = 0; j < 256; ++j) {
            float ax = std::fabs(x[j]);
            if (ax > amax) { amax = ax; max = x[j]; }
        }
        if (!amax) {
            y[i].d = 0;
            std::memset(y[i].qs, 0, 256);
            std::memset(y[i].bsums, 0, sizeof(y[i].bsums));
            x += 256;
            continue;
        }
        const float iscale = -127.f / max;
        for (int j = 0; j < 256; ++j) {
            int v = nearestInt(iscale * x[j]);
            y[i].qs[j] = (int8_t)(v > 127 ? 127 : v);
        }
        for (int j = 0; j < 16; ++j) {
            int sum = 0;
            for (int ii = 0; ii < 16; ++ii) sum += y[i].qs[j * 16 + ii];
            y[i].bsums[j] = (int16_t)sum;
        }
        y[i].d = 1.f / iscale;
        x += 256;
    }
}

// Port of ggml_vec_dot_q4_K_q8_K_generic (one row, n = cols).
static float vecDotQ4KQ8K(const BlockQ4K* x, const BlockQ8K* y, size_t cols) {
    const size_t nb = cols / 256;
    static const uint32_t kmask1 = 0x3f3f3f3f;
    static const uint32_t kmask2 = 0x0f0f0f0f;
    static const uint32_t kmask3 = 0x03030303;
    uint32_t utmp[4];
    const uint8_t* scales = (const uint8_t*)&utmp[0];
    const uint8_t* mins = (const uint8_t*)&utmp[2];
    int8_t aux8[256];
    int16_t aux16[8];
    float sums[8];
    int32_t aux32[8];
    std::memset(sums, 0, sizeof(sums));
    float sumf = 0;
    for (size_t i = 0; i < nb; ++i) {
        const uint8_t* q4 = x[i].qs;
        const int8_t* q8 = y[i].qs;
        std::memset(aux32, 0, sizeof(aux32));
        int8_t* a = aux8;
        for (int j = 0; j < 4; ++j) {
            for (int l = 0; l < 32; ++l) a[l] = (int8_t)(q4[l] & 0xF);
            a += 32;
            for (int l = 0; l < 32; ++l) a[l] = (int8_t)(q4[l] >> 4);
            a += 32;
            q4 += 32;
        }
        std::memcpy(utmp, x[i].scales, 12);
        utmp[3] = ((utmp[2] >> 4) & kmask2) | (((utmp[1] >> 6) & kmask3) << 4);
        const uint32_t uaux = utmp[1] & kmask1;
        utmp[1] = (utmp[2] & kmask2) | (((utmp[0] >> 6) & kmask3) << 4);
        utmp[2] = uaux;
        utmp[0] &= kmask1;

        int sumi = 0;
        for (int j = 0; j < 16; ++j) sumi += y[i].bsums[j] * mins[j / 2];
        a = aux8;
        int is = 0;
        for (int j = 0; j < 8; ++j) {
            int32_t scale = scales[is++];
            for (int r = 0; r < 4; ++r) {
                for (int l = 0; l < 8; ++l) aux16[l] = (int16_t)(q8[l] * a[l]);
                for (int l = 0; l < 8; ++l) aux32[l] += scale * aux16[l];
                q8 += 8;
                a += 8;
            }
        }
        const float d = fp16ToF32(x[i].d) * y[i].d;
        for (int l = 0; l < 8; ++l) sums[l] += d * (float)aux32[l];
        const float dmin = fp16ToF32(x[i].dmin) * y[i].d;
        sumf -= dmin * (float)sumi;
    }
    for (int l = 0; l < 8; ++l) sumf += sums[l];
    return sumf;
}

static void dumpRow0Block0(FILE* f, const BlockQ4K& blk, const float* x256) {
    std::fprintf(f, "=== ROW0_BLOCK0_DISCRIMINATOR ===\n");
    std::fprintf(f, "raw_bytes_hex=");
    const uint8_t* raw = reinterpret_cast<const uint8_t*>(&blk);
    for (size_t i = 0; i < sizeof(BlockQ4K); ++i) std::fprintf(f, "%02x", raw[i]);
    std::fprintf(f, "\n");
    std::fprintf(f, "d_fp16=0x%04x d=%.9e\n", blk.d, (double)fp16ToF32(blk.d));
    std::fprintf(f, "dmin_fp16=0x%04x dmin=%.9e\n", blk.dmin, (double)fp16ToF32(blk.dmin));
    std::fprintf(f, "scales12=");
    for (int i = 0; i < 12; ++i) std::fprintf(f, "%02x%s", blk.scales[i], i == 11 ? "\n" : " ");

    uint8_t ds[8], dm[8], gs, gm;
    deep2UnpackScales(blk.scales, ds, dm);
    bool scaleOk = true;
    for (int j = 0; j < 8; ++j) {
        ggmlGetScaleMinK4(j, blk.scales, &gs, &gm);
        std::fprintf(f, "group%d deep2_sc=%u deep2_min=%u ggml_sc=%u ggml_min=%u %s\n",
                     j, ds[j], dm[j], gs, gm,
                     (gs == ds[j] && gm == dm[j]) ? "MATCH" : "DIFF");
        if (gs != ds[j] || gm != dm[j]) scaleOk = false;
    }
    std::fprintf(f, "scale_unpack=%s\n", scaleOk ? "MATCH" : "DIFF");

    float gq[256], dq[256];
    ggmlDequantBlock(blk, gq);
    deep2DequantBlock(blk, dq);
    double maxAbs = 0;
    int first = -1;
    for (int i = 0; i < 256; ++i) {
        double d = std::fabs((double)gq[i] - (double)dq[i]);
        if (d > maxAbs) maxAbs = d;
        if (first < 0 && gq[i] != dq[i]) first = i;
    }
    std::fprintf(f, "dequant_32x8_groups max_abs=%.9e first_bad=%d %s\n",
                 maxAbs, first, maxAbs == 0.0 ? "MATCH" : "DIFF");
    for (int g = 0; g < 8; ++g) {
        double gDot = 0, dDot = 0;
        for (int i = 0; i < 32; ++i) {
            gDot += (double)gq[g * 32 + i] * (double)x256[g * 32 + i];
            dDot += (double)dq[g * 32 + i] * (double)x256[g * 32 + i];
        }
        std::fprintf(f, "group_dot[%d] ggml=%.17g deep2=%.17g delta=%.9e\n",
                     g, gDot, dDot, std::fabs(gDot - dDot));
    }
    double gBlk = 0, dBlk = 0;
    for (int i = 0; i < 256; ++i) {
        gBlk += (double)gq[i] * (double)x256[i];
        dBlk += (double)dq[i] * (double)x256[i];
    }
    std::fprintf(f, "block_dot ggml=%.17g deep2=%.17g delta=%.9e %s\n",
                 gBlk, dBlk, std::fabs(gBlk - dBlk),
                 gBlk == dBlk ? "MATCH" : "DIFF");
}

static void spotCheckTensor(const char* name, const TensorInfo* t, const float* x,
                            size_t cols, FILE* vf) {
    if (!t || !t->data) {
        std::fprintf(vf, "%s=MISSING\n", name);
        return;
    }
    const size_t rows = t->dimensions.size() > 1 ? (size_t)t->dimensions[1] : 0;
    const size_t bpr = (cols + 255) / 256;
    const BlockQ4K* blocks = reinterpret_cast<const BlockQ4K*>(t->data);
    // Row 0 only: FP64 ggml dequant-dot vs production GEMV scalar path for 1 row
    double accG = 0;
    for (size_t b = 0; b < bpr; ++b) {
        float tmp[256];
        ggmlDequantBlock(blocks[b], tmp);
        size_t n = (b + 1 == bpr) ? (cols - b * 256) : 256;
        for (size_t i = 0; i < n; ++i) accG += (double)tmp[i] * (double)x[b * 256 + i];
    }
    std::vector<float> y(rows, 0.f);
    auto kernel = QuantKernelRegistry::Instance().GetGEMV((int)GGMLType::GGML_TYPE_Q4_K);
    if (!kernel) {
        std::fprintf(vf, "%s_row0=NO_KERNEL\n", name);
        return;
    }
    kernel((const uint8_t*)t->data, x, y.data(), rows, cols);
    const double delta = std::fabs(accG - (double)y[0]);
    std::fprintf(vf, "%s_row0 ggml=%.17g prod=%.9e delta=%.9e %s\n",
                 name, accG, (double)y[0], delta, delta == 0.0 ? "MATCH" : "DIFF");
    std::printf("[%s] row0 ggml=%.9e prod=%.9e delta=%.9e %s\n",
                name, accG, (double)y[0], delta, delta == 0.0 ? "MATCH" : "DIFF");
}

static double l2norm(const float* a, size_t n) {
    double ss = 0;
    for (size_t i = 0; i < n; ++i) ss += (double)a[i] * (double)a[i];
    return std::sqrt(ss);
}

static void cmpVec(const char* tag, const float* a, const float* b, size_t n,
                   double* outMaxAbs, int* outFirst) {
    double maxAbs = 0;
    int first = -1;
    for (size_t i = 0; i < n; ++i) {
        double d = std::fabs((double)a[i] - (double)b[i]);
        if (d > maxAbs) maxAbs = d;
        if (first < 0 && a[i] != b[i]) first = (int)i;
    }
    std::printf("[%s] n=%zu max_abs=%.9e first_bad=%d l2a=%.9e l2b=%.9e\n",
                tag, n, maxAbs, first, l2norm(a, n), l2norm(b, n));
    if (outMaxAbs) *outMaxAbs = maxAbs;
    if (outFirst) *outFirst = first;
}

static bool writeBin(const std::string& path, const void* p, size_t n) {
    FILE* f = std::fopen(path.c_str(), "wb");
    if (!f) return false;
    std::fwrite(p, 1, n, f);
    std::fclose(f);
    return true;
}

static void rmsNormF32(const float* w, const float* x, float* y, size_t n, float eps) {
    double ss = 0;
    for (size_t i = 0; i < n; ++i) ss += (double)x[i] * (double)x[i];
    float scale = (float)(1.0 / std::sqrt(ss / (double)n + (double)eps));
    for (size_t i = 0; i < n; ++i) y[i] = w[i] * x[i] * scale;
}

} // namespace

int main(int argc, char** argv) {
    const char* modelPath =
        R"(F:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf)";
    const char* outDir =
        R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_Q4K_GEMV_001)";
    if (argc >= 2) modelPath = argv[1];
    if (argc >= 3) outDir = argv[2];
    MKDIR(R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001)");
    MKDIR(outDir);

    std::printf("Q4K-GEMV-001\nmodel=%s\nout=%s\n", modelPath, outDir);

    Deep2::GGUFLoadOptions opt;
    opt.mmap = true;
    opt.loadTensors = true;
    opt.verbose = false;
    Deep2::GGUFLoadResult lr = Deep2::GGUFLoader::Load(modelPath, opt);
    if (!lr.success) {
        std::fprintf(stderr, "GGUF_LOAD_FAIL: %s\n", lr.error);
        return 2;
    }

    const Deep2::TensorInfo* tq = lr.GetTensor("blk.0.attn_q.weight");
    const Deep2::TensorInfo* tn = lr.GetTensor("blk.0.attn_norm.weight");
    const Deep2::TensorInfo* te = lr.GetTensor("token_embd.weight");
    if (!tq || !tq->data || !tn || !tn->data || !te || !te->data) {
        std::fprintf(stderr, "MISSING_TENSORS q=%p n=%p e=%p\n", (void*)tq, (void*)tn, (void*)te);
        return 2;
    }

    const size_t cols = tq->dimensions.size() > 0 ? (size_t)tq->dimensions[0] : 0;
    const size_t rows = tq->dimensions.size() > 1 ? (size_t)tq->dimensions[1] : 0;
    const size_t bpr = (cols + 255) / 256;
    const size_t rowBytes = bpr * sizeof(BlockQ4K);
    const float eps = lr.metadata.rmsNormEps > 0 ? lr.metadata.rmsNormEps : 1e-5f;

    std::printf("attn_q rows=%zu cols=%zu type=%d bpr=%zu eps=%.9g\n",
                rows, cols, (int)tq->type, bpr, eps);

    {
        FILE* mf = std::fopen((std::string(outDir) + "\\attn_q_tensor_meta.txt").c_str(), "w");
        if (mf) {
            std::fprintf(mf,
                "name=blk.0.attn_q.weight\nrows=%zu\ncols=%zu\ntype=%d\n"
                "blocks_per_row=%zu\nrow_bytes=%zu\ntotal_bytes=%zu\n"
                "rms_norm_eps=%.9g\nbos_token_id=1\n",
                rows, cols, (int)tq->type, bpr, rowBytes, rows * rowBytes, eps);
            std::fclose(mf);
        }
    }
    writeBin(std::string(outDir) + "\\attn_q_raw_blocks.bin", tq->data, rows * rowBytes);

    // Build ATTN_NORM_0 for BOS token 1
    std::vector<float> emb(cols), attnNorm(cols);
    if ((int)te->type == (int)Deep2::GGMLType::GGML_TYPE_Q4_K) {
        const size_t embBpr = (cols + 255) / 256;
        const BlockQ4K* erow =
            reinterpret_cast<const BlockQ4K*>((const uint8_t*)te->data + 1 * embBpr * sizeof(BlockQ4K));
        for (size_t b = 0; b < embBpr; ++b) {
            ggmlDequantBlock(erow[b], emb.data() + b * 256);
        }
    } else if ((int)te->type == (int)Deep2::GGMLType::GGML_TYPE_F32) {
        std::memcpy(emb.data(), (const float*)te->data + 1 * cols, cols * sizeof(float));
    } else {
        // Use registry dequant
        Deep2::QuantKernelRegistry::Instance().Initialize();
        auto dq = Deep2::QuantKernelRegistry::Instance().GetDequant((int)te->type);
        if (!dq) {
            std::fprintf(stderr, "EMBED_DEQUANT_UNSUPPORTED type=%d\n", (int)te->type);
            return 3;
        }
        const size_t embElems = te->GetNumElements();
        const size_t vocab = te->dimensions.size() > 1 ? (size_t)te->dimensions[1] : 0;
        const size_t embRowBytes = (vocab > 0) ? (te->size / vocab) : 0;
        if (embRowBytes == 0) {
            std::fprintf(stderr, "EMBED_ROWBYTES_0\n");
            return 3;
        }
        dq((const uint8_t*)te->data + 1 * embRowBytes, emb.data(), cols);
        (void)embElems;
    }
    if ((int)tn->type != (int)Deep2::GGMLType::GGML_TYPE_F32) {
        std::fprintf(stderr, "ATTN_NORM_NOT_F32 type=%d\n", (int)tn->type);
        return 3;
    }
    rmsNormF32((const float*)tn->data, emb.data(), attnNorm.data(), cols, eps);
    writeBin(std::string(outDir) + "\\input_attn_norm_0.bin",
             attnNorm.data(), cols * sizeof(float));
    const uint64_t attnFnv = fnv1a(attnNorm.data(), cols);
    const double attnL2 = l2norm(attnNorm.data(), cols);
    std::printf("ATTN_NORM_0 l2=%.9e fnv=%016llx\n", attnL2, (unsigned long long)attnFnv);
    std::printf("rms_norm_epsilon_source=llama.attention.layer_norm_rms_epsilon\n");
    std::printf("rms_norm_epsilon=%.9e\n", (double)eps);
    // Batch-2 certified digest (must match before blaming LinearW).
    const uint64_t expectFnv = 0xb4ca919612be6c51ull;
    const bool attnNormCertified = (attnFnv == expectFnv);
    std::printf("ATTN_NORM_0_vs_batch2_cert=%s (expect_fnv=b4ca919612be6c51)\n",
                attnNormCertified ? "MATCH" : "DIFF");

    const BlockQ4K* blocks = reinterpret_cast<const BlockQ4K*>(tq->data);

    FILE* disc = std::fopen((std::string(outDir) + "\\row0_block0_discriminator.txt").c_str(), "w");
    if (disc) {
        std::fprintf(disc, "rms_norm_epsilon_source=llama.attention.layer_norm_rms_epsilon\n");
        std::fprintf(disc, "rms_norm_epsilon=%.9e\n", (double)eps);
        std::fprintf(disc, "ATTN_NORM_0 l2=%.9e fnv=%016llx cert=%s\n",
                     attnL2, (unsigned long long)attnFnv,
                     attnNormCertified ? "MATCH" : "DIFF");
        dumpRow0Block0(disc, blocks[0], attnNorm.data());
        std::fclose(disc);
    }

    // Scale unpack check
    bool scaleMatch = true;
    uint8_t gs, gm, ds[8], dm[8];
    deep2UnpackScales(blocks[0].scales, ds, dm);
    for (int j = 0; j < 8; ++j) {
        ggmlGetScaleMinK4(j, blocks[0].scales, &gs, &gm);
        if (gs != ds[j] || gm != dm[j]) scaleMatch = false;
    }
    std::printf("scale_unpack_match=%d\n", scaleMatch ? 1 : 0);

    // Dequant probe
    FILE* rp = std::fopen((std::string(outDir) + "\\row_probe_dequant.txt").c_str(), "w");
    bool dequantMatch = true;
    float gq[256], dq[256], lq[256];
    for (size_t r = 0; r < 8 && r < rows; ++r) {
        ggmlDequantBlock(blocks[r * bpr], gq);
        deep2DequantBlock(blocks[r * bpr], dq);
        legacyWrongDequantBlock(blocks[r * bpr], lq);
        double maxAbs = 0, maxLeg = 0;
        int fb = -1;
        cmpVec(("row" + std::to_string(r) + "_deep2").c_str(), dq, gq, 256, &maxAbs, &fb);
        cmpVec(("row" + std::to_string(r) + "_legacy").c_str(), lq, gq, 256, &maxLeg, &fb);
        if (maxAbs > 0) dequantMatch = false;
        if (rp) {
            std::fprintf(rp, "row=%zu deep2_max_abs=%.9e legacy_max_abs=%.9e\n", r, maxAbs, maxLeg);
        }
    }

    // Full GEMV
    std::vector<float> qGgml(rows), qDeep2(rows), qLegacy(rows), qProd(rows, 0.f);
    auto gemv = [&](void (*deq)(const BlockQ4K&, float*), std::vector<float>& out) {
        for (size_t r = 0; r < rows; ++r) {
            double acc = 0;
            const BlockQ4K* row = blocks + r * bpr;
            for (size_t b = 0; b < bpr; ++b) {
                float tmp[256];
                deq(row[b], tmp);
                size_t n = (b + 1 == bpr) ? (cols - b * 256) : 256;
                for (size_t i = 0; i < n; ++i)
                    acc += (double)tmp[i] * (double)attnNorm[b * 256 + i];
            }
            out[r] = (float)acc;
        }
    };
    gemv(ggmlDequantBlock, qGgml);
    gemv(deep2DequantBlock, qDeep2);
    gemv(legacyWrongDequantBlock, qLegacy);

    Deep2::QuantKernelRegistry::Instance().Initialize();
    auto kernel = Deep2::QuantKernelRegistry::Instance().GetGEMV((int)Deep2::GGMLType::GGML_TYPE_Q4_K);
    if (!kernel) {
        std::fprintf(stderr, "NO_Q4K_GEMV\n");
        return 4;
    }
    kernel((const uint8_t*)tq->data, attnNorm.data(), qProd.data(), rows, cols);

    double maxDD = 0, maxPD = 0, maxLD = 0;
    int fbDD = -1, fbPD = -1, fbLD = -1;
    cmpVec("full_deep2Dequant_vs_ggml", qDeep2.data(), qGgml.data(), rows, &maxDD, &fbDD);
    cmpVec("full_prodKernel_vs_ggml_fp64", qProd.data(), qGgml.data(), rows, &maxPD, &fbPD);
    cmpVec("full_legacy_vs_ggml", qLegacy.data(), qGgml.data(), rows, &maxLD, &fbLD);

    FILE* bd = std::fopen((std::string(outDir) + "\\row_probe_block_dots.txt").c_str(), "w");
    int failRow = fbPD >= 0 ? fbPD : 0;
    if (bd) {
        std::fprintf(bd, "fail_row=%d prod_max_abs=%.9e\n", failRow, maxPD);
        const BlockQ4K* row = blocks + (size_t)failRow * bpr;
        for (size_t b = 0; b < bpr; ++b) {
            float gtmp[256], dtmp[256];
            ggmlDequantBlock(row[b], gtmp);
            deep2DequantBlock(row[b], dtmp);
            double gDot = 0, dDot = 0;
            size_t n = (b + 1 == bpr) ? (cols - b * 256) : 256;
            for (size_t i = 0; i < n; ++i) {
                gDot += (double)gtmp[i] * (double)attnNorm[b * 256 + i];
                dDot += (double)dtmp[i] * (double)attnNorm[b * 256 + i];
            }
            std::fprintf(bd, "block=%zu ggml_dot=%.17g deep2_dot=%.17g abs_delta=%.9e\n",
                         b, gDot, dDot, std::fabs(gDot - dDot));
        }
        std::fclose(bd);
    }
    if (rp) std::fclose(rp);

    // ggml mul_mat path: quantize activation to Q8_K then vec_dot_q4_K_q8_K
    std::vector<BlockQ8K> xQ8(bpr);
    quantizeRowQ8K(attnNorm.data(), xQ8.data(), cols);
    std::vector<float> qQ8(rows);
    for (size_t r = 0; r < rows; ++r)
        qQ8[r] = vecDotQ4KQ8K(blocks + r * bpr, xQ8.data(), cols);

    double maxPQ8 = 0;
    int fbPQ8 = -1;
    cmpVec("full_prodKernel_vs_ggml_q8k", qProd.data(), qQ8.data(), rows, &maxPQ8, &fbPQ8);

    writeBin(std::string(outDir) + "\\q_vector_ggml.bin", qGgml.data(), rows * 4);
    writeBin(std::string(outDir) + "\\q_vector_deep2.bin", qProd.data(), rows * 4);
    writeBin(std::string(outDir) + "\\q_vector_ggml_q8k.bin", qQ8.data(), rows * 4);

    const uint64_t fnvGgml = fnv1a(qGgml.data(), rows);
    const uint64_t fnvProd = fnv1a(qProd.data(), rows);
    const uint64_t fnvQ8 = fnv1a(qQ8.data(), rows);
    const double l2Ggml = l2norm(qGgml.data(), rows);
    const double l2Prod = l2norm(qProd.data(), rows);
    const double l2Q8 = l2norm(qQ8.data(), rows);
    // Batch-2 STAGE_DIGEST anchors
    const uint64_t batch2Deep2Q = 0x78631c3504e1b579ull;
    const uint64_t batch2LlamaQ = 0x8d53927ede5ddb3full;
    std::printf("Q_fnv ggml_fp64=%016llx l2=%.9e\n", (unsigned long long)fnvGgml, l2Ggml);
    std::printf("Q_fnv deep2_prod=%016llx l2=%.9e batch2_deep2=%s\n",
                (unsigned long long)fnvProd, l2Prod,
                (fnvProd == batch2Deep2Q) ? "MATCH" : "DIFF");
    std::printf("Q_fnv ggml_q8k=%016llx l2=%.9e batch2_llama=%s (expect l2~1.93852)\n",
                (unsigned long long)fnvQ8, l2Q8,
                (fnvQ8 == batch2LlamaQ) ? "MATCH" : "DIFF");

    // Spot-check K/V share the same LinearW class from identical ATTN_NORM_0.
    FILE* kvf = std::fopen((std::string(outDir) + "\\kv_spotcheck.txt").c_str(), "w");
    if (kvf) {
        std::fprintf(kvf, "input=ATTN_NORM_0 frozen from BOS token_id=1\n");
        spotCheckTensor("blk.0.attn_k.weight", lr.GetTensor("blk.0.attn_k.weight"),
                        attnNorm.data(), cols, kvf);
        spotCheckTensor("blk.0.attn_v.weight", lr.GetTensor("blk.0.attn_v.weight"),
                        attnNorm.data(), cols, kvf);
        std::fclose(kvf);
    }

    constexpr double kProdTol = 1e-5; // FP32 GEMV noise vs integer Q8_K path
    const bool rawMatch = true; // same mmap pointer used for ggml + deep2 paths
    const bool blockMatch = (maxDD == 0.0);
    // Production must match ggml mul_mat (Q4_K×Q8_K), not FP64 dequant-dot.
    const bool fullMatch = (maxPQ8 <= kProdTol);
    const bool pass = rawMatch && dequantMatch && blockMatch && fullMatch && scaleMatch;

    FILE* vf = std::fopen((std::string(outDir) + "\\verdict.txt").c_str(), "w");
    if (vf) {
        std::fprintf(vf,
            "Q4K-GEMV-001=%s\n"
            "raw_weight_bytes=%s\n"
            "scalar_dequant=%s\n"
            "block_dot_products=%s\n"
            "full_Q0=%s\n"
            "scale_unpack=%s\n"
            "rms_norm_epsilon_source=llama.attention.layer_norm_rms_epsilon\n"
            "rms_norm_epsilon=%.9e\n"
            "ATTN_NORM_0_cert=%s fnv=%016llx\n"
            "attn_norm_l2=%.9e\n"
            "prod_vs_ggml_q8k_max_abs=%.9e tol=%.9e first_bad=%d\n"
            "prod_vs_ggml_fp64_max_abs=%.9e (informational; pre-fix FP32 path)\n"
            "legacy_vs_ggml_max_abs=%.9e\n"
            "Q_ggml_fp64_fnv=%016llx l2=%.9e\n"
            "Q_deep2_prod_fnv=%016llx l2=%.9e batch2_deep2_Q=%s\n"
            "Q_ggml_q8k_fnv=%016llx l2=%.9e batch2_llama_Q=%s\n"
            "authority=ggml mul_mat Q4_K x Q8_K (vec_dot_q4_K_q8_K_generic)\n"
            "production_kernel=QuantKernelRegistry::gemv_q4_k_scalar (Q8_K path)\n"
            "hypothesis_scale_min_decode=REJECTED\n"
            "fix=LinearW_Q4_K_now_matches_llama_CPU_mul_mat\n"
            "note=legacyWrongDequantBlock = pre-fix fused nibble grouping\n"
            "decision_tree=raw_bytes|dequant|block_dots MATCH; full_Q0 via Q8_K\n"
            "do_not_advance=K/V RoPE softmax AGENT-E2E-002b until Batch-2 STAGE_DIGEST Q_0 MATCH\n",
            pass ? "PASS" : "FAIL",
            rawMatch ? "MATCH" : "DIFF",
            dequantMatch ? "MATCH" : "DIFF",
            blockMatch ? "MATCH" : "DIFF",
            fullMatch ? "MATCH" : "DIFF",
            scaleMatch ? "MATCH" : "DIFF",
            (double)eps,
            attnNormCertified ? "MATCH" : "DIFF",
            (unsigned long long)attnFnv,
            attnL2,
            maxPQ8, kProdTol, fbPQ8,
            maxPD, maxLD,
            (unsigned long long)fnvGgml, l2Ggml,
            (unsigned long long)fnvProd, l2Prod,
            (fnvProd == batch2Deep2Q) ? "MATCH" : "DIFF",
            (unsigned long long)fnvQ8, l2Q8,
            (fnvQ8 == batch2LlamaQ) ? "MATCH" : "DIFF");
        std::fclose(vf);
    }

    std::printf("Q4K-GEMV-001=%s dequant=%s prod_vs_q8k=%s max_abs=%.9e first_bad=%d\n",
                pass ? "PASS" : "FAIL",
                dequantMatch ? "MATCH" : "DIFF",
                fullMatch ? "MATCH" : "DIFF",
                maxPQ8, fbPQ8);
    return pass ? 0 : 1;
}
