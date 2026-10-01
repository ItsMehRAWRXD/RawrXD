// test_embed_parity.cpp -- EMBED_PARITY_001
// Compares canonical float dequantization vs Deep2Engine::embedToken output
// for token_embd.weight tensor.
//
// The include block comes first. It used to sit below the first two local
// copies, which use uint8_t / uint16_t; with no header above them the compiler
// reported "missing type specifier" on the first field and then produced a
// ~22-error syntax cascade from the broken declarations.
#include "Deep2Engine.h"
#include "QuantKernelRegistry.hpp"
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cmath>
#include <vector>
#include <limits>
#include <string>
#include <algorithm>

// Local copy of unpack_q4_k_scales from QuantKernelRegistry.cpp
static inline void unpack_q4_k_scales(const uint8_t s[12], uint8_t scales[8], uint8_t mins[8]) {
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

// Local copy of block_q4_K from QuantKernelRegistry.hpp
struct block_q4_K_local {
    uint16_t d;
    uint16_t dmin;
    uint8_t  scales[12];
    uint8_t  qs[128];
};

// Local copy of fp16->fp32 conversion (same as QuantKernelRegistry.cpp)
static inline float f16_to_f32(uint16_t h) {
    uint32_t sign = (static_cast<uint32_t>(h & 0x8000)) << 16;
    uint32_t exp  = (h >> 10) & 0x1F;
    uint32_t frac = h & 0x03FF;
    if (exp == 0) {
        if (frac == 0) return reinterpret_cast<const float&>(sign);
        uint32_t e = 1;
        uint32_t f = frac;
        while ((f & 0x0400) == 0) { f <<= 1; e++; }
        f &= 0x03FF;
        uint32_t bits = sign | ((127 - 15 + 2 - e) << 23) | (f << 13);
        return reinterpret_cast<float&>(bits);
    }
    if (exp == 31) {
        uint32_t bits = sign | 0x7F800000 | (frac << 13);
        return reinterpret_cast<float&>(bits);
    }
    uint32_t bits = sign | ((exp + 127 - 15) << 23) | (frac << 13);
    return reinterpret_cast<float&>(bits);
}

// Exact copy of dequant_q4_k from QuantKernelRegistry.cpp (canonical reference)
static void dequant_q4_k_ref(const uint8_t* src, float* dst, size_t n) {
    using Deep2::block_q4_K;
    
    const block_q4_K* blocks = reinterpret_cast<const block_q4_K*>(src);
    size_t numBlocks = (n + 255) / 256;
    for (size_t b = 0; b < numBlocks; ++b) {
        float d = f16_to_f32(blocks[b].d);
        float dmin = f16_to_f32(blocks[b].dmin);
        if (!std::isfinite(d))    d    = 0.0f;
        if (!std::isfinite(dmin)) dmin = 0.0f;
        uint8_t scales[8], mins[8];
        unpack_q4_k_scales(blocks[b].scales, scales, mins);
        const uint8_t* q = blocks[b].qs;
        float* y = dst + b * 256;
        for (int is = 0; is < 8; is += 2) {
            const float d1 = d * static_cast<float>(scales[is]);
            const float m1 = dmin * static_cast<float>(mins[is]);
            const float d2 = d * static_cast<float>(scales[is + 1]);
            const float m2 = dmin * static_cast<float>(mins[is + 1]);
            for (int l = 0; l < 32; ++l) {
                size_t g0 = b * 256 + static_cast<size_t>(is) * 32 + static_cast<size_t>(l);
                size_t g1 = g0 + 32;
                if (g0 < n) y[static_cast<size_t>(is) * 32 + static_cast<size_t>(l)] =
                    d1 * static_cast<float>(q[l] & 0x0F) - m1;
                if (g1 < n) y[static_cast<size_t>(is) * 32 + 32 + static_cast<size_t>(l)] =
                    d2 * static_cast<float>(q[l] >> 4) - m2;
            }
            q += 32;
        }
    }
}

// F32 dequant (identity)
static void dequant_f32_ref(const uint8_t* src, float* dst, size_t n) {
    const float* s = reinterpret_cast<const float*>(src);
    for (size_t i = 0; i < n; ++i) dst[i] = s[i];
}

// F16 dequant
static void dequant_f16_ref(const uint8_t* src, float* dst, size_t n) {
    const uint16_t* s = reinterpret_cast<const uint16_t*>(src);
    for (size_t i = 0; i < n; ++i) dst[i] = f16_to_f32(s[i]);
}

// Q8_0 block: an fp16 scale followed by 32 int8 weights. This used to be an
// anonymous struct declared inline inside the reinterpret_cast below, which
// MSVC rejects with C2226 / C2143 / C2059 and which therefore did not compile
// at all. Hoisting it to a named type also makes the layout assertable.
struct q8_0_ref_block {
    uint16_t d;
    int8_t  qs[32];
};
static_assert(sizeof(q8_0_ref_block) == 34, "Q8_0 block must be 2 + 32 bytes");

// Q8_0 dequant (from QuantKernelRegistry.cpp)
static void dequant_q8_0_ref(const uint8_t* src, float* dst, size_t n) {
    constexpr size_t kBlk = 34;
    const size_t numBlocks = (n + 31) / 32;
    for (size_t b = 0; b < numBlocks; ++b) {
        const q8_0_ref_block* blk =
            reinterpret_cast<const q8_0_ref_block*>(src + b * kBlk);
        float d = f16_to_f32(blk->d);
        const size_t base = b * 32;
        const size_t elems = (b == numBlocks - 1 && (n % 32) != 0) ? (n % 32) : 32;
        for (size_t i = 0; i < elems; ++i) {
            dst[base + i] = d * static_cast<float>(blk->qs[i]);
        }
    }
}

using namespace Deep2;

int main(int argc, char** argv) {
    const char* modelPath = (argc > 1) ? argv[1]
        : "F:\\\\~dev\\\\qwen2.5-coder-1.5b-base.gguf";

    const char* ggufSha256 = "6a77366395772462c84f0c4d226ac404674327cbe78c01e4391cc7e0c698851e";
    const char* refCommit = "c7e6049f9987f5efcee7fdd80f09af67ee43009e";

    std::fprintf(stderr, "GATE=EMBED_PARITY_001\n");
    std::fprintf(stderr, "GGUF_SHA256=%s\n", ggufSha256);
    std::fprintf(stderr, "REFERENCE_COMMIT=%s\n", refCommit);

    Deep2Engine engine;
    EngineConfig cfg{};
    cfg.maxSeqLen   = 4096;
    cfg.useKVCache  = true;
    cfg.useThreadPool = true;
    cfg.numThreads  = 1;

    if (!engine.initialize(cfg)) { std::fprintf(stderr, "FAIL=initialize\n"); return 1; }
    std::fprintf(stderr, "PASS=initialize\n");

    if (!engine.loadModel(modelPath)) { std::fprintf(stderr, "FAIL=loadModel\n"); return 1; }
    std::fprintf(stderr, "PASS=loadModel\n");

    const auto& mw = engine.getModelWeights();
    const WeightTensor& embed = mw.tokenEmbed;
    if (!embed.data || embed.rows == 0 || embed.cols == 0) {
        std::fprintf(stderr, "FAIL=token_embd_not_loaded\n");
        return 1;
    }

    const size_t V = embed.rows;
    const size_t H = embed.cols;
    const int quantType = embed.type;
    const size_t numElements = V * H;

    std::fprintf(stderr, "TENSOR=token_embd.weight type=%d rows=%zu cols=%zu elements=%zu\n",
                 quantType, V, H, numElements);

    // Select reference dequant function based on quant type
    using DequantFn = void(*)(const uint8_t*, float*, size_t);
    DequantFn refDequant = nullptr;
    const char* typeName = "UNKNOWN";

    switch (static_cast<GGMLType>(quantType)) {
        case GGMLType::GGML_TYPE_F32:
            refDequant = dequant_f32_ref;
            typeName = "F32";
            break;
        case GGMLType::GGML_TYPE_F16:
            refDequant = dequant_f16_ref;
            typeName = "F16";
            break;
        case GGMLType::GGML_TYPE_Q4_K:
            refDequant = dequant_q4_k_ref;
            typeName = "Q4_K";
            break;
        case GGMLType::GGML_TYPE_Q8_0:
            refDequant = dequant_q8_0_ref;
            typeName = "Q8_0";
            break;
        default:
            std::fprintf(stderr, "FAIL=unsupported_quant_type=%d\n", quantType);
            return 1;
    }

    // Canonical reference dequantization
    std::vector<float> refEmbed(numElements);
    refDequant(static_cast<const uint8_t*>(embed.data), refEmbed.data(), numElements);

    bool refAllFinite = true;
    for (size_t i = 0; i < numElements; ++i) {
        if (!std::isfinite(refEmbed[i])) { refAllFinite = false; break; }
    }
    std::fprintf(stderr, "REF_DEQUANT_FINITE=%s\n", refAllFinite ? "PASS" : "FAIL");
    if (!refAllFinite) return 1;

    // Deep2Engine embedToken for each token
    std::vector<float> engineEmbed(H);
    size_t tokensTested = 0;
    size_t maxTokensToTest = std::min<size_t>(V, 1000);

    double maxAbsError = 0.0;
    double meanAbsError = 0.0;
    double maxRelError = 0.0;
    size_t firstMismatchIndex = static_cast<size_t>(-1);
    double absErrorSum = 0.0;
    size_t validComparisons = 0;

    for (size_t tokenId = 0; tokenId < maxTokensToTest; ++tokenId) {
        const float* refRow = &refEmbed[tokenId * H];

        if (!engine.embedToken(static_cast<int>(tokenId), engineEmbed.data())) {
            std::fprintf(stderr, "FAIL=embedToken_failed tokenId=%zu\n", tokenId);
            return 1;
        }

        for (size_t i = 0; i < H; ++i) {
            double refVal = static_cast<double>(refRow[i]);
            double engVal = static_cast<double>(engineEmbed[i]);
            double absErr = std::abs(refVal - engVal);
            double relErr = absErr / std::max(1e-12, std::max(std::abs(refVal), std::abs(engVal)));

            absErrorSum += absErr;
            validComparisons++;

            if (absErr > maxAbsError) maxAbsError = absErr;
            if (relErr > maxRelError) maxRelError = relErr;

            if (firstMismatchIndex == static_cast<size_t>(-1) && absErr > 1e-5) {
                firstMismatchIndex = tokenId * H + i;
            }
        }
        tokensTested++;
    }

    if (validComparisons > 0) {
        meanAbsError = absErrorSum / validComparisons;
    }

    std::fprintf(stderr, "TOKEN_IDS_TESTED=%zu\n", tokensTested);
    std::fprintf(stderr, "MAX_ABS_ERROR=%.12e\n", maxAbsError);
    std::fprintf(stderr, "MEAN_ABS_ERROR=%.12e\n", meanAbsError);
    std::fprintf(stderr, "RELATIVE_ERROR=%.12e\n", maxRelError);
    std::fprintf(stderr, "FIRST_MISMATCH_INDEX=%lld\n",
                 static_cast<long long>(firstMismatchIndex == static_cast<size_t>(-1) ? -1 : firstMismatchIndex));

    const double ABS_TOL = 1e-5;
    const double REL_TOL = 1e-4;
    bool verdict = (maxAbsError <= ABS_TOL) && (maxRelError <= REL_TOL);

    std::fprintf(stderr, "VERDICT=%s\n", verdict ? "PASS" : "FAIL");
    return verdict ? 0 : 1;
}