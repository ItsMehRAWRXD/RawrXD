// ============================================================================
// k2_q6k_masm_streaming_kernel_smoke.cpp
// Additive smoke test that certifies the existing Q6_K MASM GEMV kernel is
// usable from the K2 streaming/residency path. Uses the same deterministic
// synthetic blocks as test_q6k_asm_certification.cpp.
// ============================================================================
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <cstdint>
#include <algorithm>

#pragma pack(push, 1)
struct block_q6_K {
    uint8_t ql[128];
    uint8_t qh[64];
    int8_t  scales[16];
    uint16_t d;
};
#pragma pack(pop)
static_assert(sizeof(block_q6_K) == 210, "block_q6_K must be 210 bytes");

extern "C" void Deep2_Q6_K_GEMV(
    const void* blocks,
    const float* x,
    float* out,
    size_t nBlocks);

static inline float fp16_to_fp32(uint16_t h) {
    const uint32_t sign = (uint32_t)(h & 0x8000u) << 16;
    const uint32_t exp  = (h >> 10) & 0x1fu;
    const uint32_t mant = h & 0x03ffu;
    uint32_t bits;
    if (exp == 0) {
        if (mant == 0) bits = sign;
        else {
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

static float q6k_reference_dot(const block_q6_K* block, const float* x) {
    float d = fp16_to_fp32(block->d);
    float sum = 0.0f;
    for (size_t i = 0; i < 256; ++i) {
        size_t qlIdx = i / 2;
        int qlShift = (i % 2) * 4;
        uint8_t low4 = (block->ql[qlIdx] >> qlShift) & 0x0F;
        size_t qhIdx = i / 4;
        int qhShift = (i % 4) * 2;
        uint8_t high2 = (block->qh[qhIdx] >> qhShift) & 0x03;
        uint32_t q = low4 | (high2 << 4);
        int scaleIdx = (int)(i / 16);
        float scale = static_cast<float>(block->scales[scaleIdx]);
        sum += d * scale * (static_cast<float>(q) - 32.0f) * x[i];
    }
    return sum;
}

static void generate_block(block_q6_K* block, uint32_t seed) {
    auto lcg = [&]() -> uint32_t { seed = seed * 1103515245u + 12345u; return seed; };
    for (int i = 0; i < 128; ++i) block->ql[i] = static_cast<uint8_t>(lcg() & 0xFF);
    for (int i = 0; i < 64; ++i)  block->qh[i] = static_cast<uint8_t>(lcg() & 0xFF);
    for (int i = 0; i < 16; ++i)  block->scales[i] = static_cast<int8_t>((lcg() % 32) - 16);
    block->d = 0x38C0; // ~0.75 in FP16
}

static void generate_input(float* x, uint32_t seed) {
    auto lcg = [&]() -> uint32_t { seed = seed * 1103515245u + 12345u; return seed; };
    for (int i = 0; i < 256; ++i)
        x[i] = ((lcg() % 4001) / 1000.0f) - 2.0f;
}

int main() {
    std::printf("K2_Q6K_MASM_STREAMING_001 smoke\n");

    constexpr int NUM_BLOCKS = 16;
    constexpr float ABS_TOL = 1.0e-3f;

    alignas(64) block_q6_K blocks[NUM_BLOCKS];
    alignas(64) float input[256 * NUM_BLOCKS];
    alignas(64) float refOut[NUM_BLOCKS];
    alignas(64) float asmOut[NUM_BLOCKS];

    for (int b = 0; b < NUM_BLOCKS; ++b) {
        generate_block(&blocks[b], 0x12345678u + b * 0x10000);
        generate_input(&input[b * 256], 0xABCDEF00u + b * 0x10000);
    }

    for (int b = 0; b < NUM_BLOCKS; ++b)
        refOut[b] = q6k_reference_dot(&blocks[b], &input[b * 256]);

    std::memset(asmOut, 0, sizeof(asmOut));
    Deep2_Q6_K_GEMV(blocks, input, asmOut, NUM_BLOCKS);

    float maxAbs = 0.0f;
    for (int b = 0; b < NUM_BLOCKS; ++b) {
        float absErr = std::fabs(refOut[b] - asmOut[b]);
        if (absErr > maxAbs) maxAbs = absErr;
        if (absErr > ABS_TOL) {
            std::printf("  [FAIL] block=%d ref=%.6f asm=%.6f absErr=%.6f\n",
                        b, refOut[b], asmOut[b], absErr);
            return 1;
        }
    }

    std::printf("  [PASS] Q6K_MASM_GEMV streaming certified (%d blocks, maxAbsErr=%.6f)\n",
                NUM_BLOCKS, maxAbs);
    std::printf("K2_Q6K_MASM_STREAMING_001 PASS\n");
    return 0;
}
