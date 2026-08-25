// ============================================================================
// test_q6k_asm_certification.cpp — Q6_K ASM Kernel Synthetic Certification
//
// Purpose: Certify sovereign_q6_k_gemv.asm against the C++ reference
//          implementation using deterministic synthetic Q6_K blocks.
//
// This test must pass BEFORE Q6_K ASM dispatch is trusted in production.
//
// Run with:
//   test_q6k_asm_certification.exe
//
// Expected output on success:
//   [Q6K_CERT] PASS: N blocks certified
//   [Q6K_CERT] maxAbsErr=... maxRelErr=...
//
// Expected output on failure:
//   [Q6K_CERT] FAIL: block=N ref=... asm=... absErr=... relErr=...
//   Exit code: 1
// ============================================================================

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <cstdint>
#include <algorithm>

// ============================================================================
// Q6_K block layout (must match GGUFLoader.hpp and sovereign_q6_k_gemv.asm)
// ============================================================================
#pragma pack(push, 1)
struct block_q6_K {
    uint8_t ql[128];      // low 4 bits
    uint8_t qh[64];       // high 2 bits
    int8_t  scales[16];   // signed scale factors
    uint16_t d;           // FP16 super-scale
};
#pragma pack(pop)

static_assert(sizeof(block_q6_K) == 210, "block_q6_K must be 210 bytes");

// ============================================================================
// FP16 to FP32 conversion (exact, no approximations)
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
            while ((m & 0x0400u) == 0) {
                m <<= 1;
                --e;
            }
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
// C++ reference Q6_K dot product (matches dequantizeQ6KBlock in Deep2Engine.cpp)
// ============================================================================
static float q6k_reference_dot(const block_q6_K* block, const float* x) {
    float d = fp16_to_fp32(block->d);
    float sum = 0.0f;

    for (size_t i = 0; i < 256; ++i) {
        // ql: 2 weights per byte (low/high nibble)
        size_t qlIdx = i / 2;
        int qlShift = (i % 2) * 4;
        uint8_t low4 = (block->ql[qlIdx] >> qlShift) & 0x0F;

        // qh: 4 weights per byte (2-bit groups)
        size_t qhIdx = i / 4;
        int qhShift = (i % 4) * 2;
        uint8_t high2 = (block->qh[qhIdx] >> qhShift) & 0x03;

        uint32_t q = low4 | (high2 << 4);

        // scales: 16 groups of 16 weights each
        int scaleIdx = (int)(i / 16);
        float scale = static_cast<float>(block->scales[scaleIdx]);

        float value = d * scale * (static_cast<float>(q) - 32.0f);
        sum += value * x[i];
    }

    return sum;
}

// ============================================================================
// MASM kernel declaration
// ============================================================================
extern "C" void Deep2_Q6_K_GEMV(
    const void* blocks,
    const float* x,
    float* out,
    size_t nBlocks);

// ============================================================================
// Synthetic Q6_K block generation
// ============================================================================
static void generate_q6k_block(block_q6_K* block, uint32_t seed) {
    // Deterministic pseudo-random
    auto lcg = [&]() -> uint32_t {
        seed = seed * 1103515245u + 12345u;
        return seed;
    };

    // Fill ql with random nibbles
    for (int i = 0; i < 128; ++i) {
        block->ql[i] = static_cast<uint8_t>(lcg() & 0xFF);
    }

    // Fill qh with random 2-bit pairs
    for (int i = 0; i < 64; ++i) {
        block->qh[i] = static_cast<uint8_t>(lcg() & 0xFF);
    }

    // Fill scales with signed values (-8..7 typical, but use wider range)
    for (int i = 0; i < 16; ++i) {
        block->scales[i] = static_cast<int8_t>((lcg() % 32) - 16);
    }

    // d as FP16: use a reasonable scale (0.001 .. 1.0)
    float d_f = 0.001f + (lcg() % 1000) / 1000.0f;
    uint32_t d_bits;
    // Simple FP32->FP16 conversion (round to nearest)
    // For test purposes, just pack a reasonable FP16 value
    // Using a simpler approach: just set a common FP16 pattern
    if (d_f >= 1.0f) {
        d_bits = 0x3C00; // 1.0 in FP16
    } else if (d_f >= 0.5f) {
        d_bits = 0x3800; // 0.5 in FP16
    } else if (d_f >= 0.25f) {
        d_bits = 0x3400; // 0.25 in FP16
    } else {
        d_bits = 0x3000; // 0.125 in FP16
    }
    block->d = static_cast<uint16_t>(d_bits);
}

static void generate_input(float* x, uint32_t seed) {
    auto lcg = [&]() -> uint32_t {
        seed = seed * 1103515245u + 12345u;
        return seed;
    };

    for (int i = 0; i < 256; ++i) {
        // Range: -2.0 .. +2.0
        x[i] = ((lcg() % 4001) / 1000.0f) - 2.0f;
    }
}

// ============================================================================
// Certification harness
// ============================================================================
int main(int argc, char** argv) {
    (void)argc;
    (void)argv;

    constexpr int NUM_BLOCKS = 16;
    constexpr float ABS_TOL = 1.0e-3f;
    constexpr float REL_TOL = 2.0e-3f;

    alignas(64) block_q6_K blocks[NUM_BLOCKS];
    alignas(64) float input[256 * NUM_BLOCKS];
    alignas(64) float refOut[NUM_BLOCKS];
    alignas(64) float asmOut[NUM_BLOCKS];

    // Generate test data
    for (int b = 0; b < NUM_BLOCKS; ++b) {
        generate_q6k_block(&blocks[b], 0x12345678u + b * 0x10000);
        generate_input(&input[b * 256], 0xABCDEF00u + b * 0x10000);
    }

    // Compute reference
    for (int b = 0; b < NUM_BLOCKS; ++b) {
        refOut[b] = q6k_reference_dot(&blocks[b], &input[b * 256]);
    }

    // Call ASM kernel
    std::memset(asmOut, 0, sizeof(asmOut));
    Deep2_Q6_K_GEMV(blocks, input, asmOut, NUM_BLOCKS);

    // Compare
    float maxAbsErr = 0.0f;
    float maxRelErr = 0.0f;
    int failIdx = -1;

    for (int b = 0; b < NUM_BLOCKS; ++b) {
        float ref = refOut[b];
        float asmVal = asmOut[b];
        float diff = std::fabs(ref - asmVal);
        float scale = std::max(1.0f, std::fabs(ref));
        float relErr = diff / scale;

        if (diff > maxAbsErr) maxAbsErr = diff;
        if (relErr > maxRelErr) maxRelErr = relErr;

        if (diff > ABS_TOL && diff > REL_TOL * scale) {
            if (failIdx < 0) failIdx = b;
        }
    }

    if (failIdx >= 0) {
        fprintf(stderr,
            "[Q6K_CERT] FAIL: block=%d ref=%.8g asm=%.8g "
            "absErr=%.6e relErr=%.6e maxAbsErr=%.6e maxRelErr=%.6e\n",
            failIdx, refOut[failIdx], asmOut[failIdx],
            std::fabs(refOut[failIdx] - asmOut[failIdx]),
            std::fabs(refOut[failIdx] - asmOut[failIdx]) / std::max(1.0f, std::fabs(refOut[failIdx])),
            maxAbsErr, maxRelErr);
        return 1;
    }

    fprintf(stderr,
        "[Q6K_CERT] PASS: %d blocks certified\n"
        "[Q6K_CERT] maxAbsErr=%.6e maxRelErr=%.6e\n",
        NUM_BLOCKS, maxAbsErr, maxRelErr);

    return 0;
}
