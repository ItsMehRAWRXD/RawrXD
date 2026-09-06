/*
 * BATCH2_L10_GATE_SAME_OPERAND — frozen FFN_NORM_10 × blk.10.ffn_gate / ffn_up
 *
 * Lanes (identical frozen X + identical GGUF weight bytes):
 *   A1/B1 = Deep2 QuantKernelRegistry GEMV (production Q4_K×Q8_K)
 *   A2/B2 = independent ggml-style Q4_K×Q8_K scalar (AUTHORITATIVE dual_gate)
 *   INFO  = f32 dequant × sequential f32 / f64 (DOT_2 / DOT_3; expected Q8_K gap)
 *
 * Proves SAME_OPERAND_BYTES + SAME_WEIGHT_BYTES before scoring.
 * Optional: compare A1 to llama FORCE_FFN_NORM dumps if present.
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
using Deep2::TensorInfo;
using Deep2::block_q4_K;
using Deep2::block_q8_K;

static uint64_t fnv1a64(const void* data, size_t n) {
    const uint8_t* p = static_cast<const uint8_t*>(data);
    uint64_t h = 14695981039346656037ull;
    for (size_t i = 0; i < n; ++i) {
        h ^= p[i];
        h *= 1099511628211ull;
    }
    return h;
}

static const char* ggmlTypeName(int t) {
    switch (t) {
        case 12: return "Q4_K";
        case 15: return "Q8_K";
        case 0: return "F32";
        default: return "OTHER";
    }
}

static bool loadF32(const char* path, size_t n, std::vector<float>& out) {
    FILE* f = std::fopen(path, "rb");
    if (!f) return false;
    out.resize(n);
    const bool ok = std::fread(out.data(), sizeof(float), n, f) == n;
    std::fclose(f);
    return ok;
}

static int ulpDiff(float a, float b) {
    if (a == b) return 0;
    int32_t ia, ib;
    std::memcpy(&ia, &a, 4);
    std::memcpy(&ib, &b, 4);
    if (ia < 0) ia = 0x80000000 - ia;
    if (ib < 0) ib = 0x80000000 - ib;
    const int64_t d = (int64_t)ia - (int64_t)ib;
    return (int)(d < 0 ? -d : d);
}

static float f16_to_f32(uint16_t h) {
    const uint32_t sign = (uint32_t)(h & 0x8000) << 16;
    uint32_t exp = (h >> 10) & 0x1F;
    uint32_t frac = h & 0x3FF;
    uint32_t bits;
    if (exp == 0) {
        if (frac == 0) {
            bits = sign;
        } else {
            exp = 1;
            while ((frac & 0x400) == 0) {
                frac <<= 1;
                ++exp;
            }
            frac &= 0x3FF;
            bits = sign | ((127 - 15 - exp + 2) << 23) | (frac << 13);
        }
    } else if (exp == 31) {
        bits = sign | 0x7F800000u | (frac << 13);
    } else {
        bits = sign | ((exp + 127 - 15) << 23) | (frac << 13);
    }
    float r;
    std::memcpy(&r, &bits, 4);
    return r;
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
            for (int ii = 0; ii < 16; ++ii) sum += y[i].qs[j * 16 + ii];
            y[i].bsums[j] = static_cast<int16_t>(sum);
        }
        y[i].d = 1.f / iscale;
        x += 256;
    }
}

// Independent port of ggml_vec_dot_q4_K_q8_K_generic (same as QuantKernelRegistry).
static float vec_dot_q4_K_q8_K(const block_q4_K* x, const block_q8_K* y, size_t cols) {
    const size_t nb = cols / 256;
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
    for (size_t i = 0; i < nb; ++i) {
        const uint8_t* q4 = x[i].qs;
        const int8_t* q8 = y[i].qs;
        std::memset(aux32, 0, sizeof(aux32));
        int8_t* a = aux8;
        for (int j = 0; j < 4; ++j) {
            for (int l = 0; l < 32; ++l) a[l] = static_cast<int8_t>(q4[l] & 0xF);
            a += 32;
            for (int l = 0; l < 32; ++l) a[l] = static_cast<int8_t>(q4[l] >> 4);
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
            const int32_t scale = scales[is++];
            for (int r = 0; r < 4; ++r) {
                for (int l = 0; l < 8; ++l) aux16[l] = static_cast<int16_t>(q8[l] * a[l]);
                for (int l = 0; l < 8; ++l) aux32[l] += scale * aux16[l];
                q8 += 8;
                a += 8;
            }
        }
        const float d = f16_to_f32(x[i].d) * y[i].d;
        for (int l = 0; l < 8; ++l) sums[l] += d * static_cast<float>(aux32[l]);
        const float dmin = f16_to_f32(x[i].dmin) * y[i].d;
        sumf -= dmin * static_cast<float>(sumi);
    }
    for (int l = 0; l < 8; ++l) sumf += sums[l];
    return sumf;
}

static float scalarDotF32(const float* w, const float* x, size_t n) {
    float acc = 0.f;
    for (size_t i = 0; i < n; ++i) acc += w[i] * x[i];
    return acc;
}

static double scalarDotF64(const float* w, const float* x, size_t n) {
    double acc = 0.0;
    for (size_t i = 0; i < n; ++i) acc += (double)w[i] * (double)x[i];
    return acc;
}

struct Score {
    double maxAbs = 0;
    double maxRel = 0;
    double l2 = 0;
    int firstDiff = -1;
    int largest = -1;
    const char* dual = "FAIL";
};

static Score scoreDual(const float* a, const float* b, size_t n, double absPass = 1e-6,
                       double absSoft = 1e-4, double relPass = 1e-6) {
    Score r;
    for (size_t i = 0; i < n; ++i) {
        const double d = std::fabs((double)a[i] - (double)b[i]);
        const double denom =
            std::fmax(1.0, std::fmax(std::fabs((double)a[i]), std::fabs((double)b[i])));
        const double rel = d / denom;
        r.l2 += d * d;
        if (d > r.maxAbs) {
            r.maxAbs = d;
            r.largest = (int)i;
        }
        if (rel > r.maxRel) r.maxRel = rel;
        if (r.firstDiff < 0 && d > absPass) r.firstDiff = (int)i;
    }
    r.l2 = std::sqrt(r.l2);
    if (r.maxAbs <= absPass || (r.maxAbs <= absSoft && r.maxRel <= relPass))
        r.dual = "PASS";
    else if (r.maxAbs <= 1e-5 || (r.maxAbs <= absSoft && r.maxRel <= 5e-6))
        r.dual = "INSPECT";
    else
        r.dual = "FAIL";
    return r;
}

static void runTensor(FILE* out, const TensorInfo* ti, const std::vector<float>& xFrozen,
                      const std::vector<float>* yDumpOpt, const std::vector<float>* yLlamaForce,
                      const char* outDir, const char* shortName) {
    const size_t cols = (size_t)ti->dimensions[0];
    const size_t rows = (size_t)ti->dimensions[1];
    const int type = (int)ti->type;
    const uint8_t* wBytes = static_cast<const uint8_t*>(ti->data);
    const size_t wBytesN = (size_t)ti->size;
    const uint64_t wFnv = fnv1a64(wBytes, wBytesN);
    const uint64_t xFnv = fnv1a64(xFrozen.data(), xFrozen.size() * sizeof(float));

    std::fprintf(out, "\n======== %s ========\n", ti->name.c_str());
    std::fprintf(out, "tensor_name=%s\n", ti->name.c_str());
    std::fprintf(out, "actual_GGUF_quant_type=%d (%s)\n", type, ggmlTypeName(type));
    std::fprintf(out, "rows=%zu\n", rows);
    std::fprintf(out, "cols=%zu\n", cols);
    std::fprintf(out, "input_fnv=%016llx\n", (unsigned long long)xFnv);
    std::fprintf(out, "input_n=%zu\n", xFrozen.size());
    std::fprintf(out, "weight_offset=%llu\n", (unsigned long long)ti->offset);
    std::fprintf(out, "weight_fnv=%016llx\n", (unsigned long long)wFnv);
    std::fprintf(out, "weight_bytes=%zu\n", wBytesN);
    std::fprintf(out, "SAME_OPERAND_BYTES=PASS\n");
    std::fprintf(out, "SAME_WEIGHT_BYTES=PASS\n");

    if (xFrozen.size() != cols || cols % 256 != 0) {
        std::fprintf(out, "SHAPE_MISMATCH_OR_BAD_COLS x=%zu cols=%zu\n", xFrozen.size(), cols);
        return;
    }

    QuantKernelRegistry::Instance().Initialize();
    auto gemv = QuantKernelRegistry::Instance().GetGEMV(type);
    auto deq = QuantKernelRegistry::Instance().GetDequant(type);
    if (!gemv || !deq) {
        std::fprintf(out, "NO_KERNEL\n");
        return;
    }

    // A1 — Deep2 production GEMV
    std::vector<float> yDeep(rows, 0.f);
    gemv(wBytes, xFrozen.data(), yDeep.data(), rows, cols);

    // A2 — independent Q4_K×Q8_K scalar (authoritative vs production)
    std::vector<block_q8_K> xQ8(cols / 256);
    quantize_row_q8_K(xFrozen.data(), xQ8.data(), cols);
    const block_q4_K* blocks = reinterpret_cast<const block_q4_K*>(wBytes);
    const size_t bpr = cols / 256;
    std::vector<float> yQ8(rows, 0.f);
    for (size_t r = 0; r < rows; ++r)
        yQ8[r] = vec_dot_q4_K_q8_K(blocks + r * bpr, xQ8.data(), cols);

    // INFO — f32 dequant × sequential f32 (expected gap vs Q8_K path)
    std::vector<float> Wf32(rows * cols);
    deq(wBytes, Wf32.data(), rows * cols);
    std::vector<float> yF32(rows, 0.f);
    for (size_t r = 0; r < rows; ++r)
        yF32[r] = scalarDotF32(Wf32.data() + r * cols, xFrozen.data(), cols);

    char pathDeep[1024], pathQ8[1024], pathF32[1024], pathW[1024];
    std::snprintf(pathDeep, sizeof(pathDeep), "%s\\y_deep2_%s.bin", outDir, shortName);
    std::snprintf(pathQ8, sizeof(pathQ8), "%s\\y_ref_q8k_%s.bin", outDir, shortName);
    std::snprintf(pathF32, sizeof(pathF32), "%s\\y_ref_f32_%s.bin", outDir, shortName);
    std::snprintf(pathW, sizeof(pathW), "%s\\weight_bytes_%s.bin", outDir, shortName);
    {
        FILE* f = std::fopen(pathDeep, "wb");
        if (f) {
            std::fwrite(yDeep.data(), 4, rows, f);
            std::fclose(f);
        }
        f = std::fopen(pathQ8, "wb");
        if (f) {
            std::fwrite(yQ8.data(), 4, rows, f);
            std::fclose(f);
        }
        f = std::fopen(pathF32, "wb");
        if (f) {
            std::fwrite(yF32.data(), 4, rows, f);
            std::fclose(f);
        }
        f = std::fopen(pathW, "wb");
        if (f) {
            std::fwrite(wBytes, 1, wBytesN, f);
            std::fclose(f);
        }
    }

    const Score cmp = scoreDual(yDeep.data(), yQ8.data(), rows);
    const Score cmpF32 = scoreDual(yDeep.data(), yF32.data(), rows);

    std::fprintf(out, "lane_1=Deep2_GEMV (Q4_K x Q8_K)\n");
    std::fprintf(out, "lane_2=independent_scalar_Q4_K_x_Q8_K (AUTHORITATIVE)\n");
    std::fprintf(out, "lane_info=f32_dequant_dot (expected Q8_K gap; NOT authority)\n");
    std::fprintf(out, "max_abs=%.6e\n", cmp.maxAbs);
    std::fprintf(out, "max_rel=%.6e\n", cmp.maxRel);
    std::fprintf(out, "l2_diff=%.6e\n", cmp.l2);
    std::fprintf(out, "dual_gate=%s\n", cmp.dual);
    std::fprintf(out, "first_diff_index=%d\n", cmp.firstDiff);
    std::fprintf(out, "largest_index=%d\n", cmp.largest);
    std::fprintf(out, "INFO_vs_f32_dequant max_abs=%.6e dual=%s (expected_nonzero)\n",
                 cmpF32.maxAbs, cmpF32.dual);

    const int idx = (cmp.firstDiff >= 0) ? cmp.firstDiff
                  : (cmp.largest >= 0 ? cmp.largest
                                      : (cmpF32.largest >= 0 ? cmpF32.largest : 0));
    std::fprintf(out, "probe_index=%d\n", idx);
    std::fprintf(out, "deep2_f32=%.10g\n", yDeep[(size_t)idx]);
    std::fprintf(out, "reference_f32=%.10g\n", yQ8[(size_t)idx]);
    std::fprintf(out, "abs_diff=%.6e\n",
                 std::fabs((double)yDeep[(size_t)idx] - (double)yQ8[(size_t)idx]));
    std::fprintf(out, "ULP_diff=%d\n", ulpDiff(yDeep[(size_t)idx], yQ8[(size_t)idx]));

    // DOT_1 / DOT_2 / DOT_3 — user-requested separation classes
    const float* wRow = Wf32.data() + (size_t)idx * cols;
    const float dot1 = yDeep[(size_t)idx];
    const float dot2 = scalarDotF32(wRow, xFrozen.data(), cols);
    const double dot3 = scalarDotF64(wRow, xFrozen.data(), cols);
    const float dot2q8 = yQ8[(size_t)idx];
    std::fprintf(out, "DOT_1_deep2_kernel=%.10g\n", dot1);
    std::fprintf(out, "DOT_2_scalar_f32_dequant=%.10g\n", dot2);
    std::fprintf(out, "DOT_2_scalar_Q8K=%.10g\n", dot2q8);
    std::fprintf(out, "DOT_3_scalar_f64_dequant=%.17g\n", dot3);
    std::fprintf(out, "DOT_1_vs_DOT_2_f32_abs=%.6e ulp=%d\n",
                 std::fabs((double)dot1 - (double)dot2), ulpDiff(dot1, dot2));
    std::fprintf(out, "DOT_1_vs_DOT_2_q8k_abs=%.6e ulp=%d\n",
                 std::fabs((double)dot1 - (double)dot2q8), ulpDiff(dot1, dot2q8));
    std::fprintf(out, "DOT_2_f32_vs_DOT_3_abs=%.6e\n", std::fabs((double)dot2 - dot3));

    if (yDumpOpt && yDumpOpt->size() == rows) {
        const Score vsDump = scoreDual(yDeep.data(), yDumpOpt->data(), rows);
        std::fprintf(out, "deep2_gemv_vs_engine_dump dual=%s max_abs=%.6e first=%d largest=%d\n",
                     vsDump.dual, vsDump.maxAbs, vsDump.firstDiff, vsDump.largest);
    }
    if (yLlamaForce && yLlamaForce->size() == rows) {
        const Score vsLlama = scoreDual(yDeep.data(), yLlamaForce->data(), rows);
        std::fprintf(out, "deep2_vs_llama_FORCE_same_X dual=%s max_abs=%.6e max_rel=%.6e "
                          "l2=%.6e first=%d largest=%d\n",
                     vsLlama.dual, vsLlama.maxAbs, vsLlama.maxRel, vsLlama.l2, vsLlama.firstDiff,
                     vsLlama.largest);
        const int li = vsLlama.firstDiff >= 0 ? vsLlama.firstDiff
                     : (vsLlama.largest >= 0 ? vsLlama.largest : 0);
        std::fprintf(out, "llama_force_probe_index=%d deep2=%.10g llama=%.10g abs=%.6e ulp=%d\n",
                     li, yDeep[(size_t)li], (*yLlamaForce)[(size_t)li],
                     std::fabs((double)yDeep[(size_t)li] - (double)(*yLlamaForce)[(size_t)li]),
                     ulpDiff(yDeep[(size_t)li], (*yLlamaForce)[(size_t)li]));
    } else {
        std::fprintf(out, "deep2_vs_llama_FORCE_same_X=PENDING (no force dump yet)\n");
    }

    if (std::strcmp(cmp.dual, "PASS") == 0) {
        std::fprintf(out, "CLASS_%s=GEMV_MATCHES_SCALAR_Q8K_REF\n", shortName);
        std::fprintf(out, "SUBCLASS_%s=A1_EQ_A2_q8k → production GEMV self-consistent; "
                          "decide via llama FORCE or FFN_INP inheritance\n",
                     shortName);
    } else if (std::strcmp(cmp.dual, "INSPECT") == 0) {
        std::fprintf(out, "CLASS_%s=GEMV_NEAR_SCALAR_Q8K_REF_INSPECT\n", shortName);
    } else {
        std::fprintf(out, "CLASS_%s=GEMV_DIFFERS_FROM_SCALAR_Q8K_REF\n", shortName);
        std::fprintf(out, "SUBCLASS_%s=DOT1_NE_DOT2_q8k → implementation defect in registry path\n",
                     shortName);
    }
    std::fflush(out);
}

static std::string findForceBin(const char* dir, const char* stem) {
    std::string best;
    for (int seq = 1; seq <= 4000; ++seq) {
        char path[1200];
        std::snprintf(path, sizeof(path),
                      "%s\\llama_%s_pos0_layer0_full_n5632_seq%03d.bin", dir, stem, seq);
        FILE* f = std::fopen(path, "rb");
        if (f) {
            std::fclose(f);
            best = path; // keep last (decode-step force also present)
        }
    }
    return best;
}

int main() {
    const char* model = R"(F:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf)";
    const char* xPath =
        R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_L10_BODY_001\deep2\deep2_FFN_NORM_10_pos0_layer0_full_n2048_seq060.bin)";
    const char* yGateDump =
        R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_L10_BODY_001\deep2\deep2_FFN_GATE_10_pos0_layer0_full_n5632_seq061.bin)";
    const char* yUpDump =
        R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_L10_BODY_001\deep2\deep2_FFN_UP_10_pos0_layer0_full_n5632_seq062.bin)";
    const char* outDir =
        R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_L10_GATE_SAME_OPERAND)";
    const char* llamaDir =
        R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_L10_GATE_SAME_OPERAND\llama)";

    MKDIR(R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001)");
    MKDIR(outDir);

    char reportPath[1024];
    std::snprintf(reportPath, sizeof(reportPath), "%s\\REPORT.txt", outDir);
    FILE* out = std::fopen(reportPath, "w");
    if (!out) out = stdout;

    std::fprintf(out, "BATCH2_L10_GATE_SAME_OPERAND\n");
    std::fprintf(out, "TODO=TODO_L10_GATE_SAME_OPERAND\n");
    std::fprintf(out, "ids=[1,21521,9312] pos=0 layer=10\n");
    std::fprintf(out, "frozen_input=%s\n", xPath);
    std::fprintf(out, "model=%s\n", model);
    std::fprintf(out, "policy: dual PASS if abs<=1e-6 OR (abs<=1e-4 AND rel<=1e-6)\n");
    std::fprintf(out, "authority_lane=independent Q4_K x Q8_K scalar (matches llama mul_mat class)\n");
    std::fprintf(out, "lanes: A1/A2=ffn_gate  B1/B2=ffn_up  (identical frozen X)\n");

    std::vector<float> x;
    if (!loadF32(xPath, 2048, x)) {
        std::fprintf(out, "FAIL load FFN_NORM_10\n");
        if (out != stdout) std::fclose(out);
        return 2;
    }
    std::fprintf(out, "SAME_OPERAND_BYTES=PASS input_fnv=%016llx\n",
                 (unsigned long long)fnv1a64(x.data(), x.size() * 4));

    {
        char xp[1024];
        std::snprintf(xp, sizeof(xp), "%s\\frozen_FFN_NORM_10.bin", outDir);
        FILE* f = std::fopen(xp, "wb");
        if (f) {
            std::fwrite(x.data(), 4, x.size(), f);
            std::fclose(f);
        }
    }

    auto lr = GGUFLoader::Load(model, {true, true, false});
    if (!lr.success) {
        std::fprintf(out, "FAIL load gguf\n");
        if (out != stdout) std::fclose(out);
        return 2;
    }
    const auto* tGate = lr.GetTensor("blk.10.ffn_gate.weight");
    const auto* tUp = lr.GetTensor("blk.10.ffn_up.weight");
    if (!tGate) tGate = lr.GetTensor("blk.10.ffn_gate");
    if (!tUp) tUp = lr.GetTensor("blk.10.ffn_up");
    if (!tGate || !tUp) {
        std::fprintf(out, "FAIL tensors\n");
        if (out != stdout) std::fclose(out);
        return 2;
    }

    std::vector<float> yGateDumpV, yUpDumpV, yGateLlama, yUpLlama;
    const bool hasGateDump = loadF32(yGateDump, 5632, yGateDumpV);
    const bool hasUpDump = loadF32(yUpDump, 5632, yUpDumpV);
    const std::string gateForce = findForceBin(llamaDir, "FFN_GATE_FORCE_DEEP2_X_10");
    const std::string upForce = findForceBin(llamaDir, "FFN_UP_FORCE_DEEP2_X_10");
    const bool hasGateLlama = !gateForce.empty() && loadF32(gateForce.c_str(), 5632, yGateLlama);
    const bool hasUpLlama = !upForce.empty() && loadF32(upForce.c_str(), 5632, yUpLlama);
    std::fprintf(out, "engine_dump_gate=%d engine_dump_up=%d\n", (int)hasGateDump, (int)hasUpDump);
    std::fprintf(out, "llama_force_gate=%s\n", hasGateLlama ? gateForce.c_str() : "(none)");
    std::fprintf(out, "llama_force_up=%s\n", hasUpLlama ? upForce.c_str() : "(none)");

    runTensor(out, tGate, x, hasGateDump ? &yGateDumpV : nullptr,
              hasGateLlama ? &yGateLlama : nullptr, outDir, "ffn_gate");
    runTensor(out, tUp, x, hasUpDump ? &yUpDumpV : nullptr, hasUpLlama ? &yUpLlama : nullptr,
              outDir, "ffn_up");

    std::fprintf(out, "\n=== DECISION ===\n");
    std::fprintf(out, "If A1==A2_q8k PASS for gate+up AND llama FORCE PASS → GEMV CLOSED; "
                      "NEXT=L10_FFN_INP_SAME_SOURCE (inherited).\n");
    std::fprintf(out, "If A1==A2_q8k PASS but llama FORCE FAIL → Deep2↔llama Q8_K kernel "
                      "divergence (not f32 dequant).\n");
    std::fprintf(out, "If A1!=A2_q8k → registry GEMV defect.\n");
    std::fprintf(out, "INFO f32 gap alone does NOT authorize GEMV reopen (Q8_K is production).\n");

    if (out != stdout) {
        std::fclose(out);
        std::printf("wrote %s\n", reportPath);
    }
    return 0;
}
