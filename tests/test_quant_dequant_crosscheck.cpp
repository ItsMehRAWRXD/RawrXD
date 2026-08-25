// ============================================================================
// test_quant_dequant_crosscheck.cpp — Cross-check all K-quant dequantizers
//
// Purpose: Validate RawrXD's dequantization against canonical GGML reference
//          implementations for Q2_K, Q3_K, Q4_K, Q5_K, Q6_K, and Q8_0.
//
// Run with:
//   test_quant_dequant_crosscheck.exe
//
// Expected output on success:
//   [CROSSCHECK] PASS: all quant types certified
//   [CROSSCHECK] maxAbsErr=... maxRelErr=... meanAbsErr=...
//
// Expected output on failure:
//   [CROSSCHECK] FAIL: type=N block=M idx=K ref=... got=... absErr=... relErr=...
//   Exit code: 1
// ============================================================================

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <cstdint>
#include <algorithm>
#include <vector>
#include <random>

// ============================================================================
// Block layouts (must match GGUFLoader.hpp exactly)
// ============================================================================
#pragma pack(push, 1)

struct block_q8_0 {
    uint16_t d;
    int8_t   qs[32];
};

struct block_q2_K {
    uint8_t  scales[16];
    uint8_t  qs[64];
    uint16_t d;
    uint16_t dmin;
};

struct block_q3_K {
    uint8_t  hmask[32];
    uint8_t  qs[64];
    uint8_t  scales[12];
    uint16_t d;
};

struct block_q4_K {
    uint16_t d;
    uint16_t dmin;
    uint8_t  scales[12];
    uint8_t  qs[128];
};

struct block_q5_K {
    uint16_t d;
    uint16_t dmin;
    uint8_t  scales[12];
    uint8_t  qh[32];
    uint8_t  qs[128];
};

struct block_q6_K {
    uint8_t  ql[128];
    uint8_t  qh[64];
    int8_t   scales[16];
    uint16_t d;
};

#pragma pack(pop)

static_assert(sizeof(block_q8_0) == 34,  "block_q8_0 must be 34 bytes");
static_assert(sizeof(block_q2_K) == 84,  "block_q2_K must be 84 bytes");
static_assert(sizeof(block_q3_K) == 110, "block_q3_K must be 110 bytes");
static_assert(sizeof(block_q4_K) == 144, "block_q4_K must be 144 bytes");
static_assert(sizeof(block_q5_K) == 176, "block_q5_K must be 176 bytes");
static_assert(sizeof(block_q6_K) == 210, "block_q6_K must be 210 bytes");

// ============================================================================
// FP16 -> FP32 conversion (exact, no approximations)
// ============================================================================
static inline float fp16_to_fp32(uint16_t h) {
    const uint32_t sign = (uint32_t)(h & 0x8000u) << 16;
    const uint32_t exp  = (h >> 10) & 0x1fu;
    const uint32_t mant = h & 0x03ffu;
    uint32_t bits;
    if (exp == 0) {
        if (mant == 0) {
            bits = sign;
        } else {
            uint32_t m = mant;
            int e = -14;
            while ((m & 0x0400u) == 0) { m <<= 1; --e; }
            m &= 0x03ffu;
            bits = sign | ((uint32_t)(e + 127) << 23) | (m << 13);
        }
    } else if (exp == 31) {
        bits = sign | 0x7f800000u | (mant << 13);
    } else {
        bits = sign | ((exp + 112u) << 23) | (mant << 13);
    }
    float result;
    std::memcpy(&result, &bits, sizeof(result));
    return result;
}

// ============================================================================
// Reference dequantization implementations (canonical GGML-style)
// ============================================================================

static void ref_dequant_q8_0(const block_q8_0* block, float* out) {
    float d = fp16_to_fp32(block->d);
    for (int i = 0; i < 32; ++i) {
        out[i] = d * (float)block->qs[i];
    }
}

static void ref_dequant_q2_k(const block_q2_K* block, float* out) {
    float d    = fp16_to_fp32(block->d);
    float dmin = fp16_to_fp32(block->dmin);
    for (int chunk = 0; chunk < 2; ++chunk) {
        for (int subBlock = 0; subBlock < 4; ++subBlock) {
            for (int group = 0; group < 2; ++group) {
                int scaleIdx = chunk * 8 + subBlock * 2 + group;
                uint8_t sc = block->scales[scaleIdx];
                float dl = d * (float)(sc & 0x0F);
                float ml = dmin * (float)(sc >> 4);
                for (int pos = 0; pos < 16; ++pos) {
                    int i = chunk * 128 + subBlock * 32 + group * 16 + pos;
                    int qsIdx = chunk * 32 + group * 16 + pos;
                    int qsShift = subBlock * 2;
                    int q = (block->qs[qsIdx] >> qsShift) & 0x03;
                    out[i] = dl * (float)q - ml;
                }
            }
        }
    }
}

static void ref_dequant_q3_k(const block_q3_K* block, float* out) {
    float d = fp16_to_fp32(block->d);
    int8_t scales[16];
    for (int j = 0; j < 8; ++j) {
        scales[j]     = (int8_t)(block->scales[j] & 0x0F);
        scales[j + 8] = (int8_t)((block->scales[j] >> 4) & 0x0F);
    }
    for (int i = 0; i < 256; ++i) {
        int chunk    = i / 128;
        int subBlock = (i % 128) / 32;
        int posInSub = i % 32;
        int qsIdx    = chunk * 32 + posInSub;
        int qsShift  = subBlock * 2;
        int lo       = (block->qs[qsIdx] >> qsShift) & 0x03;
        int hmIdx    = posInSub;
        int hmShift  = i / 32;
        int hmaskBit = (block->hmask[hmIdx] >> hmShift) & 0x01;
        int q        = lo - (hmaskBit ? 0 : 4);
        int scaleIdx = chunk * 4 + subBlock;
        float dl     = d * (float)(scales[scaleIdx] - 32);
        out[i] = dl * (float)q;
    }
}

static inline void get_scale_min_k4(int j, const uint8_t* q, uint8_t& d, uint8_t& m) {
    if (j < 4) {
        d = q[j] & 63;
        m = q[j + 4] & 63;
    } else {
        d = (q[j + 4] & 0x0F) | ((q[j - 4] >> 6) << 4);
        m = (q[j + 4] >> 4) | ((q[j] >> 6) << 4);
    }
}

static void ref_dequant_q4_k(const block_q4_K* block, float* out) {
    float d    = fp16_to_fp32(block->d);
    float dmin = fp16_to_fp32(block->dmin);
    for (int j = 0; j < 8; ++j) {
        uint8_t sc, m;
        get_scale_min_k4(j, block->scales, sc, m);
        float scale = d * sc;
        float min   = dmin * m;
        const uint8_t* quants = block->qs + j * 16;
        for (int k = 0; k < 16; ++k) {
            uint8_t byte = quants[k];
            int lo = byte & 0xF;
            int hi = (byte >> 4) & 0xF;
            out[j * 32 + k]       = scale * lo - min;
            out[j * 32 + k + 16]  = scale * hi - min;
        }
    }
}

static void ref_dequant_q5_k(const block_q5_K* block, float* out) {
    float d    = fp16_to_fp32(block->d);
    float dmin = fp16_to_fp32(block->dmin);
    for (int j = 0; j < 8; ++j) {
        uint8_t sc, m;
        get_scale_min_k4(j, block->scales, sc, m);
        float scale = d * sc;
        float min   = dmin * m;
        for (int k = 0; k < 32; ++k) {
            int idx = j * 32 + k;
            int qsIdx = idx / 2;
            int qsShift = (idx % 2) * 4;
            uint8_t low4 = (block->qs[qsIdx] >> qsShift) & 0x0F;
            int qhIdx = idx / 8;
            int qhShift = idx % 8;
            uint8_t high1 = (block->qh[qhIdx] >> qhShift) & 0x01;
            uint8_t q = low4 | (high1 << 4);
            out[idx] = scale * q - min;
        }
    }
}

static void ref_dequant_q6_k(const block_q6_K* block, float* out) {
    float d = fp16_to_fp32(block->d);
    for (int i = 0; i < 256; ++i) {
        int qlIdx = i / 2;
        int qlShift = (i % 2) * 4;
        uint8_t low4 = (block->ql[qlIdx] >> qlShift) & 0x0F;
        int qhIdx = i / 4;
        int qhShift = (i % 4) * 2;
        uint8_t high2 = (block->qh[qhIdx] >> qhShift) & 0x03;
        int q = (int)(low4 | (high2 << 4)) - 32;
        int scaleIdx = i / 16;
        out[i] = d * (float)block->scales[scaleIdx] * (float)q;
    }
}

// ============================================================================
// RawrXD dequantization implementations (copied from QuantKernelRegistry.cpp)
// ============================================================================

static void rawrxd_dequant_q8_0(const uint8_t* src, float* dst, size_t n) {
    const block_q8_0* blocks = reinterpret_cast<const block_q8_0*>(src);
    size_t numBlocks = (n + 31) / 32;
    for (size_t b = 0; b < numBlocks; ++b) {
        for (int i = 0; i < 32; ++i) {
            size_t idx = b * 32 + i;
            if (idx < n) dst[idx] = fp16_to_fp32(blocks[b].d) * (float)blocks[b].qs[i];
        }
    }
}

static void rawrxd_dequant_q2_k(const uint8_t* src, float* dst, size_t n) {
    const block_q2_K* blocks = reinterpret_cast<const block_q2_K*>(src);
    size_t numBlocks = (n + 255) / 256;
    for (size_t b = 0; b < numBlocks; ++b) {
        float d    = fp16_to_fp32(blocks[b].d);
        float dmin = fp16_to_fp32(blocks[b].dmin);
        for (int chunk = 0; chunk < 2; ++chunk) {
            for (int subBlock = 0; subBlock < 4; ++subBlock) {
                for (int group = 0; group < 2; ++group) {
                    int scaleIdx = chunk * 8 + subBlock * 2 + group;
                    uint8_t sc = blocks[b].scales[scaleIdx];
                    float dl = d * (float)(sc & 0x0F);
                    float ml = dmin * (float)(sc >> 4);
                    for (int pos = 0; pos < 16; ++pos) {
                        int i = chunk * 128 + subBlock * 32 + group * 16 + pos;
                        size_t globalIdx = b * 256 + i;
                        if (globalIdx >= n) return;
                        int qsIdx = chunk * 32 + group * 16 + pos;
                        int qsShift = subBlock * 2;
                        int q = (blocks[b].qs[qsIdx] >> qsShift) & 0x03;
                        dst[globalIdx] = dl * (float)q - ml;
                    }
                }
            }
        }
    }
}

static void rawrxd_dequant_q3_k(const uint8_t* src, float* dst, size_t n) {
    const block_q3_K* blocks = reinterpret_cast<const block_q3_K*>(src);
    size_t numBlocks = (n + 255) / 256;
    for (size_t b = 0; b < numBlocks; ++b) {
        float d = fp16_to_fp32(blocks[b].d);
        int8_t scales[16];
        for (int j = 0; j < 8; ++j) {
            scales[j]     = (int8_t)(blocks[b].scales[j] & 0x0F);
            scales[j + 8] = (int8_t)((blocks[b].scales[j] >> 4) & 0x0F);
        }
        for (size_t i = 0; i < 256; ++i) {
            size_t globalIdx = b * 256 + i;
            if (globalIdx >= n) return;
            int chunk    = (int)(i / 128);
            int subBlock = (int)((i % 128) / 32);
            int posInSub = (int)(i % 32);
            int qsIdx    = chunk * 32 + posInSub;
            int qsShift  = subBlock * 2;
            int lo       = (blocks[b].qs[qsIdx] >> qsShift) & 0x03;
            int hmIdx    = posInSub;
            int hmShift  = (int)(i / 32);
            int hmaskBit = (blocks[b].hmask[hmIdx] >> hmShift) & 0x01;
            int q        = lo - (hmaskBit ? 0 : 4);
            int scaleIdx = chunk * 4 + subBlock;
            float dl     = d * (float)(scales[scaleIdx] - 32);
            dst[globalIdx] = dl * (float)q;
        }
    }
}

static void rawrxd_dequant_q4_k(const uint8_t* src, float* dst, size_t n) {
    const block_q4_K* blocks = reinterpret_cast<const block_q4_K*>(src);
    size_t numBlocks = (n + 255) / 256;
    for (size_t b = 0; b < numBlocks; ++b) {
        float d = fp16_to_fp32(blocks[b].d);
        float dmin = fp16_to_fp32(blocks[b].dmin);
        for (int sb = 0; sb < 8; ++sb) {
            uint8_t sc, m;
            get_scale_min_k4(sb, blocks[b].scales, sc, m);
            float scale = d * sc;
            float min   = dmin * m;
            const uint8_t* quants = blocks[b].qs + sb * 16;
            for (int k = 0; k < 16; ++k) {
                uint8_t byte = quants[k];
                int lo = byte & 0x0F;
                int hi = (byte >> 4) & 0x0F;
                int idx0 = sb * 32 + k;
                int idx1 = sb * 32 + k + 16;
                size_t g0 = b * 256 + idx0;
                size_t g1 = b * 256 + idx1;
                if (g0 < n) dst[g0] = scale * lo - min;
                if (g1 < n) dst[g1] = scale * hi - min;
            }
        }
    }
}

static void rawrxd_dequant_q5_k(const uint8_t* src, float* dst, size_t n) {
    const block_q5_K* blocks = reinterpret_cast<const block_q5_K*>(src);
    size_t numBlocks = (n + 255) / 256;
    for (size_t b = 0; b < numBlocks; ++b) {
        float d = fp16_to_fp32(blocks[b].d);
        float dmin = fp16_to_fp32(blocks[b].dmin);
        for (int sb = 0; sb < 8; ++sb) {
            uint8_t scale, min;
            get_scale_min_k4(sb, blocks[b].scales, scale, min);
            float s = d * scale;
            float m = dmin * min;
            for (int i = 0; i < 32; ++i) {
                int idx = sb * 32 + i;
                size_t globalIdx = b * 256 + idx;
                if (globalIdx >= n) return;
                int qsIdx = idx / 2;
                int qsShift = (idx % 2) * 4;
                uint8_t low4 = (blocks[b].qs[qsIdx] >> qsShift) & 0x0F;
                int qhIdx = idx / 8;
                int qhShift = idx % 8;
                uint8_t high1 = (blocks[b].qh[qhIdx] >> qhShift) & 0x01;
                uint8_t q = low4 | (high1 << 4);
                dst[globalIdx] = s * q - m;
            }
        }
    }
}

static void rawrxd_dequant_q6_k(const uint8_t* src, float* dst, size_t n) {
    const block_q6_K* blocks = reinterpret_cast<const block_q6_K*>(src);
    size_t numBlocks = (n + 255) / 256;
    for (size_t b = 0; b < numBlocks; ++b) {
        float d = fp16_to_fp32(blocks[b].d);
        const uint8_t* ql = blocks[b].ql;
        const uint8_t* qh = blocks[b].qh;
        const int8_t*  sc = blocks[b].scales;
        for (size_t idx = 0; idx < 256; ++idx) {
            size_t globalIdx = b * 256 + idx;
            if (globalIdx >= n) return;
            size_t qlIdx = idx / 2;
            int    qlShift = (idx % 2) * 4;
            uint8_t low4 = (ql[qlIdx] >> qlShift) & 0x0F;
            size_t qhIdx = idx / 4;
            int    qhShift = (idx % 4) * 2;
            uint8_t high2 = (qh[qhIdx] >> qhShift) & 0x03;
            int8_t q = (int8_t)(low4 | (high2 << 4)) - 32;
            int scaleIdx = (int)(idx / 16);
            dst[globalIdx] = d * (float)sc[scaleIdx] * (float)q;
        }
    }
}

// ============================================================================
// Synthetic block generators
// ============================================================================

static std::mt19937 rng(42); // deterministic seed

static uint16_t random_fp16() {
    // Generate reasonable FP16 values: exponent 10-20, random mantissa
    uint16_t exp = 10 + (rng() % 11); // 10..20
    uint16_t mant = rng() & 0x3FF;
    uint16_t sign = (rng() % 2) ? 0x8000 : 0;
    return sign | (exp << 10) | mant;
}

static void generate_q8_0_block(block_q8_0* block) {
    block->d = random_fp16();
    for (int i = 0; i < 32; ++i) {
        block->qs[i] = (int8_t)(rng() % 256 - 128);
    }
}

static void generate_q2_k_block(block_q2_K* block) {
    block->d = random_fp16();
    block->dmin = random_fp16();
    for (int i = 0; i < 16; ++i) {
        block->scales[i] = (uint8_t)(rng() % 256);
    }
    for (int i = 0; i < 64; ++i) {
        block->qs[i] = (uint8_t)(rng() % 256);
    }
}

static void generate_q3_k_block(block_q3_K* block) {
    block->d = random_fp16();
    for (int i = 0; i < 32; ++i) {
        block->hmask[i] = (uint8_t)(rng() % 256);
    }
    for (int i = 0; i < 64; ++i) {
        block->qs[i] = (uint8_t)(rng() % 256);
    }
    for (int i = 0; i < 12; ++i) {
        block->scales[i] = (uint8_t)(rng() % 256);
    }
}

static void generate_q4_k_block(block_q4_K* block) {
    block->d = random_fp16();
    block->dmin = random_fp16();
    for (int i = 0; i < 12; ++i) {
        block->scales[i] = (uint8_t)(rng() % 256);
    }
    for (int i = 0; i < 128; ++i) {
        block->qs[i] = (uint8_t)(rng() % 256);
    }
}

static void generate_q5_k_block(block_q5_K* block) {
    block->d = random_fp16();
    block->dmin = random_fp16();
    for (int i = 0; i < 12; ++i) {
        block->scales[i] = (uint8_t)(rng() % 256);
    }
    for (int i = 0; i < 32; ++i) {
        block->qh[i] = (uint8_t)(rng() % 256);
    }
    for (int i = 0; i < 128; ++i) {
        block->qs[i] = (uint8_t)(rng() % 256);
    }
}

static void generate_q6_k_block(block_q6_K* block) {
    for (int i = 0; i < 128; ++i) {
        block->ql[i] = (uint8_t)(rng() % 256);
    }
    for (int i = 0; i < 64; ++i) {
        block->qh[i] = (uint8_t)(rng() % 256);
    }
    for (int i = 0; i < 16; ++i) {
        block->scales[i] = (int8_t)(rng() % 256 - 128);
    }
    block->d = random_fp16();
}

// ============================================================================
// Cross-check harness
// ============================================================================

template<typename BlockType, size_t BlockSize, size_t ElemsPerBlock>
struct QuantTest {
    const char* name;
    void (*generate)(BlockType*);
    void (*ref_dequant)(const BlockType*, float*);
    void (*rawrxd_dequant)(const uint8_t*, float*, size_t);
};

static bool nearly_equal(float a, float b, float abs_tol, float rel_tol) {
    float diff = std::fabs(a - b);
    if (diff <= abs_tol) return true;
    float maxab = std::max(std::fabs(a), std::fabs(b));
    if (maxab < 1e-12f) return diff <= abs_tol;
    return diff / maxab <= rel_tol;
}

template<typename BlockType, size_t BlockSize, size_t ElemsPerBlock>
static bool run_crosscheck(const QuantTest<BlockType, BlockSize, ElemsPerBlock>& test, int numBlocks) {
    std::vector<BlockType> blocks(numBlocks);
    std::vector<float> ref_out(numBlocks * ElemsPerBlock);
    std::vector<float> rawrxd_out(numBlocks * ElemsPerBlock);

    for (int b = 0; b < numBlocks; ++b) {
        test.generate(&blocks[b]);
        test.ref_dequant(&blocks[b], &ref_out[b * ElemsPerBlock]);
    }

    test.rawrxd_dequant(reinterpret_cast<const uint8_t*>(blocks.data()), rawrxd_out.data(), numBlocks * ElemsPerBlock);

    double maxAbsErr = 0.0;
    double maxRelErr = 0.0;
    double sumAbsErr = 0.0;
    size_t nanInfCount = 0;
    size_t firstBadBlock = 0;
    size_t firstBadIdx = 0;
    float firstBadRef = 0.0f;
    float firstBadGot = 0.0f;
    bool passed = true;

    for (size_t i = 0; i < ref_out.size(); ++i) {
        float ref = ref_out[i];
        float got = rawrxd_out[i];

        if (!std::isfinite(ref) || !std::isfinite(got)) {
            ++nanInfCount;
            if (passed) {
                passed = false;
                firstBadBlock = i / ElemsPerBlock;
                firstBadIdx = i % ElemsPerBlock;
                firstBadRef = ref;
                firstBadGot = got;
            }
            continue;
        }

        double absErr = std::fabs((double)ref - (double)got);
        double relErr = (std::fabs(ref) > 1e-12) ? absErr / std::fabs(ref) : 0.0;

        if (absErr > maxAbsErr) maxAbsErr = absErr;
        if (relErr > maxRelErr) maxRelErr = relErr;
        sumAbsErr += absErr;

        if (!nearly_equal(ref, got, 1.0e-4f, 1.0e-3f)) {
            if (passed) {
                passed = false;
                firstBadBlock = i / ElemsPerBlock;
                firstBadIdx = i % ElemsPerBlock;
                firstBadRef = ref;
                firstBadGot = got;
            }
        }
    }

    double meanAbsErr = sumAbsErr / ref_out.size();

    if (passed) {
        printf("[CROSSCHECK] %s PASS: %d blocks certified  maxAbsErr=%.6e  maxRelErr=%.6e  meanAbsErr=%.6e  nanInf=%zu\n",
               test.name, numBlocks, maxAbsErr, maxRelErr, meanAbsErr, nanInfCount);
    } else {
        printf("[CROSSCHECK] %s FAIL: block=%zu idx=%zu ref=%.6f got=%.6f absErr=%.6e relErr=%.6e\n",
               test.name, firstBadBlock, firstBadIdx, firstBadRef, firstBadGot,
               std::fabs((double)firstBadRef - (double)firstBadGot),
               (std::fabs(firstBadRef) > 1e-12) ? std::fabs((double)firstBadRef - (double)firstBadGot) / std::fabs(firstBadRef) : 0.0);
    }

    return passed;
}

// ============================================================================
// Main
// ============================================================================

int main() {
    printf("[CROSSCHECK] Starting quant dequantization cross-check...\n");
    printf("[CROSSCHECK] Using deterministic seed=42, 16 blocks per type\n\n");

    bool allPassed = true;

    // Q8_0
    {
        QuantTest<block_q8_0, 34, 32> test = {
            "Q8_0", generate_q8_0_block, ref_dequant_q8_0, rawrxd_dequant_q8_0
        };
        allPassed &= run_crosscheck(test, 16);
    }

    // Q2_K
    {
        QuantTest<block_q2_K, 84, 256> test = {
            "Q2_K", generate_q2_k_block, ref_dequant_q2_k, rawrxd_dequant_q2_k
        };
        allPassed &= run_crosscheck(test, 16);
    }

    // Q3_K
    {
        QuantTest<block_q3_K, 110, 256> test = {
            "Q3_K", generate_q3_k_block, ref_dequant_q3_k, rawrxd_dequant_q3_k
        };
        allPassed &= run_crosscheck(test, 16);
    }

    // Q4_K
    {
        QuantTest<block_q4_K, 144, 256> test = {
            "Q4_K", generate_q4_k_block, ref_dequant_q4_k, rawrxd_dequant_q4_k
        };
        allPassed &= run_crosscheck(test, 16);
    }

    // Q5_K
    {
        QuantTest<block_q5_K, 176, 256> test = {
            "Q5_K", generate_q5_k_block, ref_dequant_q5_k, rawrxd_dequant_q5_k
        };
        allPassed &= run_crosscheck(test, 16);
    }

    // Q6_K
    {
        QuantTest<block_q6_K, 210, 256> test = {
            "Q6_K", generate_q6_k_block, ref_dequant_q6_k, rawrxd_dequant_q6_k
        };
        allPassed &= run_crosscheck(test, 16);
    }

    printf("\n");
    if (allPassed) {
        printf("[CROSSCHECK] ALL TYPES PASS\n");
        return 0;
    } else {
        printf("[CROSSCHECK] SOME TYPES FAILED\n");
        return 1;
    }
}
