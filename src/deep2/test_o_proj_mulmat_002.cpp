/*
 * O_PROJ_MULMAT_PARITY_002 — same-operands wo mul_mat (Gate A, then Gate B)
 *
 * Gate A: identical FP32 X = frozen Deep2 ATTN_PRE_O_0 + same W Q4_K bytes
 *   Deep2:  X → Q8_K → Q4_K×Q8_K → Y
 *   llama:  forced kqv_out-0=X → its Q8_K → Q4_K×Q8_K → Y  (ATTN_OUT_FORCE_DEEP2_X)
 *
 * Gate B (only if A fails): identical frozen Q8_K blocks + same Q4_K →
 *   per-block integer products / scales / contributions / running acc on worst row.
 *
 * Does NOT reopen PRE_O layout / QKV / tokenizer.
 *
 * Usage:
 *   test_o_proj_mulmat_002.exe [llama_force_y.bin]
 * Env defaults point at BATCH2_ATTN_OUT_LOC + O_PROJ_MULMAT_PARITY_002.
 */
#include "GGUFLoader.hpp"
#include "QuantKernelRegistry.hpp"

#include <algorithm>
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

static void unpack_scales_ggml(const uint8_t s[12], uint8_t scales[8], uint8_t mins[8]) {
    scales[0] = s[0] & 63;
    scales[1] = s[1] & 63;
    scales[2] = s[2] & 63;
    scales[3] = s[3] & 63;
    mins[0] = s[4] & 63;
    mins[1] = s[5] & 63;
    mins[2] = s[6] & 63;
    mins[3] = s[7] & 63;
    scales[4] = (s[8] & 0xF) | ((s[0] >> 6) << 4);
    scales[5] = (s[8] >> 4) | ((s[1] >> 6) << 4);
    scales[6] = (s[9] & 0xF) | ((s[2] >> 6) << 4);
    scales[7] = (s[9] >> 4) | ((s[3] >> 6) << 4);
    mins[4] = (s[10] & 0xF) | ((s[4] >> 6) << 4);
    mins[5] = (s[10] >> 4) | ((s[5] >> 6) << 4);
    mins[6] = (s[11] & 0xF) | ((s[6] >> 6) << 4);
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

static double maxAbsDiff(const float* a, const float* b, size_t n, int* worstIdx) {
    double m = 0;
    int wi = -1;
    for (size_t i = 0; i < n; ++i) {
        double d = std::fabs((double)a[i] - (double)b[i]);
        if (d > m) {
            m = d;
            wi = (int)i;
        }
    }
    if (worstIdx)
        *worstIdx = wi;
    return m;
}

static const char* gateLabel(double maxAbs) {
    if (maxAbs <= 1e-6)
        return "PASS";
    if (maxAbs <= 1e-5)
        return "INSPECT";
    return "FAIL";
}

static std::string findLatestForceBin(const char* dir) {
    // Prefer explicit ATTN_OUT_FORCE_DEEP2_X dumps; fall back to newest matching glob via argv.
    std::string best;
    // Simple: look for known stem patterns by probing seq 001..200
    for (int seq = 1; seq <= 200; ++seq) {
        char path[1024];
        std::snprintf(path, sizeof(path),
                      "%s\\llama_ATTN_OUT_FORCE_DEEP2_X_pos0_layer0_full_n2048_seq%03d.bin", dir, seq);
        FILE* f = std::fopen(path, "rb");
        if (f) {
            std::fclose(f);
            best = path;
        }
    }
    return best;
}

int main(int argc, char** argv) {
    const char* model = R"(F:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf)";
    const char* loc = R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_ATTN_OUT_LOC)";
    const char* outDir =
        R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\O_PROJ_MULMAT_PARITY_002)";
    MKDIR(R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001)");
    MKDIR(outDir);

    const std::string xPathS =
        std::string(loc) + "\\deep2_ATTN_PRE_O_0_pos0_layer0_full_n2048_seq008.bin";
    const std::string yDeepS =
        std::string(loc) + "\\deep2_ATTN_OUT_0_pos0_layer0_full_n2048_seq009.bin";
    const std::string yLlamaNativeS =
        std::string(loc) + "\\llama_ATTN_OUT_0_pos0_layer0_full_n2048_seq105.bin";

    std::string yLlamaForceS;
    if (argc >= 2 && argv[1] && argv[1][0])
        yLlamaForceS = argv[1];
    else
        yLlamaForceS = findLatestForceBin(outDir);
    if (yLlamaForceS.empty())
        yLlamaForceS = findLatestForceBin(loc);

    std::vector<float> X, Ydeep2, YllamaNative, YllamaForce;
    if (!loadF32(xPathS.c_str(), 2048, X) || !loadF32(yDeepS.c_str(), 2048, Ydeep2) ||
        !loadF32(yLlamaNativeS.c_str(), 2048, YllamaNative)) {
        std::fprintf(stderr, "LOAD_FAIL frozen X/Y\n");
        return 2;
    }
    if (yLlamaForceS.empty() || !loadF32(yLlamaForceS.c_str(), 2048, YllamaForce)) {
        std::fprintf(stderr,
                     "LOAD_FAIL llama force Y — run probe with RAWRXD_FORCE_PRE_O_BIN first\n"
                     "  expected under %s\\llama_ATTN_OUT_FORCE_DEEP2_X_*.bin\n",
                     outDir);
        return 3;
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
    std::vector<float> Yprod(rows, 0.f);
    ker((const uint8_t*)wo->data, X.data(), Yprod.data(), rows, cols);

    int wA = -1, wNat = -1, wProdDeep = -1;
    const double gateA = maxAbsDiff(Yprod.data(), YllamaForce.data(), rows, &wA);
    const double natGap = maxAbsDiff(Yprod.data(), YllamaNative.data(), rows, &wNat);
    const double prodDeep = maxAbsDiff(Yprod.data(), Ydeep2.data(), rows, &wProdDeep);

    FILE* vf = std::fopen((std::string(outDir) + "\\VERDICT.txt").c_str(), "w");
#define EMIT(...)                 \
    do {                          \
        std::printf(__VA_ARGS__); \
        if (vf)                   \
            std::fprintf(vf, __VA_ARGS__); \
    } while (0)

    EMIT("O_PROJ_MULMAT_PARITY_002\n"
         "authority=CPU llama mul_mat (forced identical X) vs Deep2 Q4_K×Q8_K\n"
         "W=blk.0.attn_output.weight Q4_K rows=%zu cols=%zu bpr=%zu\n"
         "X=deep2_ATTN_PRE_O_0 (%s)\n"
         "Y_llama_force=%s\n\n",
         rows, cols, bpr, xPathS.c_str(), yLlamaForceS.c_str());

    EMIT("CONTROL prod_vs_deep2_ATTN_OUT max_abs=%.17g gate=%s\n", prodDeep,
         gateLabel(prodDeep));
    EMIT("CONTROL prod_vs_llama_native_ATTN_OUT max_abs=%.17g (PRE_O-induced gap)\n", natGap);
    EMIT("\nGATE_A same_FP32_X+same_W\n");
    EMIT("  Deep2_Q8K_path vs llama_mul_mat(force_X) max_abs=%.17g worst_row=%d gate=%s\n",
         gateA, wA, gateLabel(gateA));

    const char* authority = "UNKNOWN";
    bool needGateB = false;
    if (prodDeep > 1e-7) {
        authority = "instrument_bug: prod != deep2 ATTN_OUT";
        needGateB = true;
    } else if (gateA <= 1e-6) {
        authority = "same_FP32_X_makes_Deep2_llama_match — PRE_O delta amplified; wo kernel CLOSED";
    } else if (gateA <= 1e-5) {
        authority = "INSPECT: same X within 1e-5 — treat as near-closed; optional Gate B";
        needGateB = true;
    } else {
        authority = "GATE_A_FAIL — proceed Gate B (same Q8_K)";
        needGateB = true;
    }
    EMIT("\nAUTHORITY=%s\n", authority);

    EMIT("\nPRIOR_ROW_002: prod(llama_PRE_O) vs llama_ATTN_OUT max_abs~9.3e-9\n"
         "  (Deep2 kernel matches llama when X is llama's PRE_O)\n");

    if (!needGateB || gateA <= 1e-6) {
        EMIT("\nGATE_B=SKIPPED (Gate A closed kernel)\n"
             "LIVE_STATUS=wo Q4_K×Q8_K CLOSED under identical operands\n"
             "REMAINING=quantizer/input sensitivity of tiny PRE_O delta (6.14e-6) only\n"
             "do_not_reopen=TOKENIZER EMBED NORM QKV SOFTMAX AV GQA PRE_O_LAYOUT\n");
        if (vf)
            std::fclose(vf);
        return gateA <= 1e-5 ? 0 : 1;
    }

    // -------- Gate B: freeze Q8_K, worst-row block trace --------
    EMIT("\nGATE_B same_Q8_K + same_Q4_K (Deep2 scalar block path vs prod)\n");
    std::vector<block_q8_K> xQ8(bpr);
    quantize_row_q8_K(X.data(), xQ8.data(), cols);

    {
        FILE* qf = std::fopen((std::string(outDir) + "\\frozen_X_Q8K.bin").c_str(), "wb");
        if (qf) {
            std::fwrite(xQ8.data(), sizeof(block_q8_K), bpr, qf);
            std::fclose(qf);
        }
    }

    std::vector<float> Yref(rows, 0.f);
    for (size_t r = 0; r < rows; ++r) {
        double acc = 0;
        const BlockQ4K* rowW = W + r * bpr;
        for (size_t b = 0; b < bpr; ++b)
            acc += (double)vec_dot_one_block(rowW[b], xQ8[b]);
        Yref[r] = (float)acc;
    }
    int wRef = -1;
    const double refVsProd = maxAbsDiff(Yref.data(), Yprod.data(), rows, &wRef);
    const double refVsLlama = maxAbsDiff(Yref.data(), YllamaForce.data(), rows, &wA);
    EMIT("  frozen_Q8K_blocksum vs prod max_abs=%.17g\n", refVsProd);
    EMIT("  frozen_Q8K_blocksum vs llama_force max_abs=%.17g worst=%d\n", refVsLlama, wA);

    const int row = wA >= 0 ? wA : 0;
    const BlockQ4K* rowW = W + (size_t)row * bpr;
    FILE* rf = std::fopen((std::string(outDir) + "\\row_trace.txt").c_str(), "w");
    if (rf) {
        std::fprintf(rf,
                     "GATE_B_ROW_TRACE\n"
                     "row_index=%d\n"
                     "y_prod=%.17g\n"
                     "y_ref=%.17g\n"
                     "y_llama_force=%.17g\n\n",
                     row, Yprod[(size_t)row], Yref[(size_t)row], YllamaForce[(size_t)row]);
        double run = 0;
        for (size_t b = 0; b < bpr; ++b) {
            const BlockQ4K& blk = rowW[b];
            uint8_t scales[8], mins[8];
            unpack_scales_ggml(blk.scales, scales, mins);
            const float contrib = vec_dot_one_block(blk, xQ8[b]);
            run += (double)contrib;
            std::fprintf(rf, "--- block %zu ---\n", b);
            std::fprintf(rf, "d=%g dmin=%g\n", f16(blk.d), f16(blk.dmin));
            std::fprintf(rf, "scales=");
            for (int i = 0; i < 8; ++i)
                std::fprintf(rf, "%u%s", scales[i], i == 7 ? "\n" : ",");
            std::fprintf(rf, "mins=");
            for (int i = 0; i < 8; ++i)
                std::fprintf(rf, "%u%s", mins[i], i == 7 ? "\n" : ",");
            hexDump(rf, "Q4_K_block", reinterpret_cast<const uint8_t*>(&blk), sizeof(blk));
            hexDump(rf, "Q8_K_qs_head64", reinterpret_cast<const uint8_t*>(xQ8[b].qs), 64);
            std::fprintf(rf, "Q8_K_d=%g\n", xQ8[b].d);
            std::fprintf(rf, "block_float_contribution=%.17g\n", contrib);
            std::fprintf(rf, "running_row_accumulator=%.17g\n\n", run);
        }
        std::fprintf(rf, "final_y_ref=%.17g\n", Yref[(size_t)row]);
        std::fclose(rf);
    }

    if (refVsProd <= 1e-7 && refVsLlama > 1e-5) {
        EMIT("\nGATE_B_CLASS=Q8_K_match_Deep2_internal but llama_force still differs\n"
             "  => llama Q8_K quantizer and/or q4_K_8x8 accum differs under same FP32 X\n"
             "  => first differing quantity is outside Deep2 generic vec_dot (see row_trace)\n");
    } else if (refVsProd > 1e-7) {
        EMIT("\nGATE_B_CLASS=Deep2 prod vs frozen blocksum diverge — kernel split\n");
    } else {
        EMIT("\nGATE_B_CLASS=unexpected near-match on ref vs llama_force\n");
    }

    EMIT("\ndo_not_reopen=TOKENIZER EMBED NORM QKV SOFTMAX AV GQA PRE_O_LAYOUT\n");
    if (vf)
        std::fclose(vf);
#undef EMIT
    return 1;
}
