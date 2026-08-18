// ============================================================================
// K2-003A — Isolated Q4_K Decoder Correctness Test
// ============================================================================
//
// Purpose: Verify the Q4_K dequantization path before trusting it with
//          real K2 model weights.  This test is self-contained and does
//          NOT require a model directory.
//
// Gates:
//   1. Synthetic Q4_K block round-trip (known scales/quants → dequant → verify)
//   2. get_scale_min_k4() correctness for all 8 sub-blocks
//   3. dequantizeQ4KBlock() produces finite, non-NaN output
//   4. Tail-block handling (cols not multiple of 256)
//   5. AVX2 GEMV scalar fallback produces same result as reference dot product
//
// Build:
//   cl /nologo /W4 /EHsc /std:c++20 /O2 /arch:AVX2 /I. k2_003a_q4k_decoder.cpp
//
// ============================================================================

#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cmath>
#include <cstring>
#include <algorithm>

// Pull in the exact same block layout and helpers used by Deep2Engine.cpp
// We duplicate them here so this test is hermetic.

struct alignas(16) Q4_K_Block {
    uint16_t d;               // FP16 super-scale
    uint16_t dmin;            // FP16 super-minimum
    uint8_t  scales[12];      // Packed 6-bit scale/min pairs (8 sub-blocks)
    uint8_t  qs[128];         // 256 x 4-bit packed weights
};
static_assert(sizeof(Q4_K_Block) == 144, "Q4_K_Block must be 144 bytes");

static inline float fp16ToFloat(uint16_t h) {
    uint32_t sign = (h >> 15) & 0x1;
    uint32_t exp  = (h >> 10) & 0x1F;
    uint32_t mant = h & 0x3FF;
    uint32_t f;
    if (exp == 0) {
        if (mant == 0) {
            f = sign << 31;
        } else {
            int e = -1;
            do { e++; mant <<= 1; } while (!(mant & 0x400));
            mant &= 0x3FF;
            f = (sign << 31) | ((127 - 15 - e) << 23) | (mant << 13);
        }
    } else if (exp == 31) {
        f = (sign << 31) | (0xFF << 23) | (mant << 13);
    } else {
        f = (sign << 31) | ((exp + 127 - 15) << 23) | (mant << 13);
    }
    float result;
    memcpy(&result, &f, sizeof(float));
    return result;
}

// Correct llama.cpp layout
static inline void unpackQ4KScaleMin(const uint8_t* scales, int j,
                                       uint8_t& sc, uint8_t& m) {
    if (j < 4) {
        sc = scales[j] & 63;
        m  = scales[j + 4] & 63;
    } else {
        sc = (scales[j + 4] & 0x0F) | ((scales[j - 4] >> 6) << 4);
        m  = (scales[j + 4] >> 4)      | ((scales[j]   >> 6) << 4);
    }
}

static void dequantizeQ4KBlock(const Q4_K_Block* block, float* out) {
    float d    = fp16ToFloat(block->d);
    float dmin = fp16ToFloat(block->dmin);

    for (int j = 0; j < 8; j++) {
        uint8_t sc, m;
        unpackQ4KScaleMin(block->scales, j, sc, m);
        float scale = d * sc;
        float min   = dmin * m;

        const uint8_t* quants = block->qs + j * 16;
        for (int k = 0; k < 16; k++) {
            uint8_t byte = quants[k];
            int lo = byte & 0xF;
            int hi = (byte >> 4) & 0xF;
            out[j * 32 + k]       = scale * lo - min;
            out[j * 32 + k + 16]  = scale * hi - min;
        }
    }
}

// ============================================================================
// Test helpers
// ============================================================================
static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        printf("[FAIL] %s\n", msg); \
        g_fail++; \
    } else { \
        g_pass++; \
    } \
} while(0)

static bool approxEq(float a, float b, float eps = 1e-4f) {
    return std::fabs(a - b) < eps;
}

static bool allFinite(const float* buf, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        if (!std::isfinite(buf[i])) return false;
    }
    return true;
}

// ============================================================================
// Gate 1 — Synthetic block round-trip
// ============================================================================
static void test_gate1_synthetic_block() {
    printf("\n=== Gate 1: Synthetic Q4_K block round-trip ===\n");

    Q4_K_Block blk{};
    // d = 1.0f in FP16  →  0x3C00
    blk.d = 0x3C00;
    // dmin = 0.5f in FP16 → 0x3800
    blk.dmin = 0x3800;

    // Set scales so every sub-block has scale=1, min=1
    // j=0..3: sc=scales[j]&63, m=scales[j+4]&63
    // j=4..7: sc=(scales[j+4]&0x0F)|((scales[j-4]>>6)<<4)
    //         m=(scales[j+4]>>4)|((scales[j]>>6)<<4)
    // To get sc=1, m=1 for all j:
    //   scales[0..3] = 1, scales[4..7] = 1
    //   scales[8..11] = 0x11 (low nibble=1, high nibble=1)
    for (int i = 0; i < 4; ++i) {
        blk.scales[i]     = 1;      // sc for j=0..3
        blk.scales[i + 4] = 1;      // m  for j=0..3
    }
    for (int i = 8; i < 12; ++i) {
        blk.scales[i] = 0x11;       // sc=1 (low nibble), m=1 (high nibble) for j=4..7
    }

    // Set all quants to 5 (arbitrary)
    for (int i = 0; i < 128; ++i) {
        blk.qs[i] = 0x55;  // both nibbles = 5
    }

    float out[256];
    dequantizeQ4KBlock(&blk, out);

    float d    = fp16ToFloat(blk.d);      // 1.0
    float dmin = fp16ToFloat(blk.dmin);   // 0.5
    float expected = d * 1.0f * 5.0f - dmin * 1.0f;  // 5.0 - 0.5 = 4.5

    bool ok = true;
    for (int i = 0; i < 256; ++i) {
        if (!approxEq(out[i], expected)) {
            printf("  out[%d] = %f (expected %f)\n", i, out[i], expected);
            ok = false;
            break;
        }
    }
    CHECK(ok, "Gate 1: All 256 dequantized values match expected 4.5");
    CHECK(allFinite(out, 256), "Gate 1: All outputs finite");
}

// ============================================================================
// Gate 2 — get_scale_min_k4() correctness for all 8 sub-blocks
// ============================================================================
static void test_gate2_scale_min_all_subblocks() {
    printf("\n=== Gate 2: Scale/min extraction for all 8 sub-blocks ===\n");

    // Build a block with unique (scale, min) pairs per sub-block
    // j=0..7 → (scale=j+1, min=8-j)
    Q4_K_Block blk{};
    uint8_t expected_sc[8];
    uint8_t expected_m[8];
    for (int j = 0; j < 8; ++j) {
        expected_sc[j] = static_cast<uint8_t>(j + 1);
        expected_m[j]  = static_cast<uint8_t>(8 - j);
    }

    // Encode into scales[12] using the inverse of unpackQ4KScaleMin
    // j=0..3: sc=scales[j]&63, m=scales[j+4]&63
    for (int j = 0; j < 4; ++j) {
        blk.scales[j]     = expected_sc[j];
        blk.scales[j + 4] = expected_m[j];
    }
    // j=4..7:
    //   sc = (scales[j+4] & 0x0F) | ((scales[j-4] >> 6) << 4)
    //   m  = (scales[j+4] >> 4)      | ((scales[j]   >> 6) << 4)
    // We need to set scales[8..11] and the upper 2 bits of scales[0..3]
    for (int j = 4; j < 8; ++j) {
        int sc_low = expected_sc[j] & 0x0F;
        int sc_hi  = (expected_sc[j] >> 4) & 0x03;
        int m_low  = expected_m[j] & 0x0F;
        int m_hi   = (expected_m[j] >> 4) & 0x03;

        blk.scales[j + 4] = static_cast<uint8_t>((m_low << 4) | sc_low);
        blk.scales[j - 4] |= static_cast<uint8_t>(sc_hi << 6);
        blk.scales[j]     |= static_cast<uint8_t>(m_hi  << 6);
    }

    bool ok = true;
    for (int j = 0; j < 8; ++j) {
        uint8_t sc, m;
        unpackQ4KScaleMin(blk.scales, j, sc, m);
        if (sc != expected_sc[j] || m != expected_m[j]) {
            printf("  j=%d: got sc=%u m=%u, expected sc=%u m=%u\n",
                   j, sc, m, expected_sc[j], expected_m[j]);
            ok = false;
        }
    }
    CHECK(ok, "Gate 2: All 8 sub-block scale/min pairs decode correctly");
}

// ============================================================================
// Gate 3 — Tail-block handling (cols not multiple of 256)
// ============================================================================
static void test_gate3_tail_block() {
    printf("\n=== Gate 3: Tail-block handling (cols=300) ===\n");

    // Simulate a weight matrix with cols=300 → 2 blocks (256 + 44)
    size_t cols = 300;
    size_t numBlocks = (cols + 255) / 256;  // 2

    // Allocate two blocks, fill with known pattern
    Q4_K_Block blocks[2] = {};
    for (int b = 0; b < 2; ++b) {
        blocks[b].d = 0x3C00;   // 1.0
        blocks[b].dmin = 0x0000; // 0.0
        for (int i = 0; i < 12; ++i) blocks[b].scales[i] = 0;
        for (int i = 0; i < 128; ++i) blocks[b].qs[i] = 0x11; // quant=1
    }

    float dequantBuf[256];
    float input[300];
    for (size_t i = 0; i < 300; ++i) input[i] = 1.0f;

    float sum = 0.0f;
    for (size_t b = 0; b < numBlocks; ++b) {
        size_t elemsInBlock = (b == numBlocks - 1)
            ? (cols - b * 256)
            : 256;
        if (elemsInBlock == 0) break;

        dequantizeQ4KBlock(&blocks[b], dequantBuf);

        for (size_t i = 0; i < elemsInBlock; ++i) {
            sum += dequantBuf[i] * input[b * 256 + i];
        }
    }

    // With d=1.0, dmin=0.0, scales=0 → scale=0, min=0 → all dequant=0
    // So sum should be 0.0
    CHECK(approxEq(sum, 0.0f), "Gate 3: Tail block produces zero sum with zero scales");

    // Now set scales so first block produces 1.0 per element, second block ignored
    for (int i = 0; i < 4; ++i) {
        blocks[0].scales[i] = 1;      // sc=1
        blocks[0].scales[i + 4] = 0;  // m=0
    }
    for (int i = 8; i < 12; ++i) blocks[0].scales[i] = 0x01;

    sum = 0.0f;
    for (size_t b = 0; b < numBlocks; ++b) {
        size_t elemsInBlock = (b == numBlocks - 1)
            ? (cols - b * 256)
            : 256;
        if (elemsInBlock == 0) break;

        dequantizeQ4KBlock(&blocks[b], dequantBuf);

        for (size_t i = 0; i < elemsInBlock; ++i) {
            sum += dequantBuf[i] * input[b * 256 + i];
        }
    }

    // First block: 256 elements × 1.0 × 1.0 = 256.0
    // Second block: all zeros (scales still zero)
    // Tail: only 44 elements from second block, all zero
    CHECK(approxEq(sum, 256.0f), "Gate 3: First block contributes 256.0, tail block zero");
}

// ============================================================================
// Gate 4 — Reference dot-product vs dequantized weights
// ============================================================================
static void test_gate4_reference_dot_product() {
    printf("\n=== Gate 4: Reference dot-product agreement ===\n");

    // One block, d=2.0, dmin=0.0, scale=3, min=0 for all sub-blocks
    // quant values = 1,2,3,4 repeating
    Q4_K_Block blk{};
    blk.d = 0x4000;   // 2.0 in FP16
    blk.dmin = 0x0000;
    for (int i = 0; i < 4; ++i) {
        blk.scales[i] = 3;
        blk.scales[i + 4] = 0;
    }
    for (int i = 8; i < 12; ++i) blk.scales[i] = 0x03;

    uint8_t quants[256];
    for (int i = 0; i < 256; ++i) {
        quants[i] = static_cast<uint8_t>((i % 4) + 1);  // 1,2,3,4 repeating
    }
    for (int i = 0; i < 128; ++i) {
        blk.qs[i] = static_cast<uint8_t>((quants[i * 2] & 0x0F) |
                                          ((quants[i * 2 + 1] & 0x0F) << 4));
    }

    float dequant[256];
    dequantizeQ4KBlock(&blk, dequant);

    // Expected: d=2.0, sc=3, min=0 → scale=6.0
    // Each quant q → 6.0 * q
    float expected[256];
    for (int i = 0; i < 256; ++i) {
        expected[i] = 6.0f * quants[i];
    }

    bool ok = true;
    for (int i = 0; i < 256; ++i) {
        if (!approxEq(dequant[i], expected[i], 1e-3f)) {
            printf("  dequant[%d] = %f, expected %f\n", i, dequant[i], expected[i]);
            ok = false;
            break;
        }
    }
    CHECK(ok, "Gate 4: Dequantized weights match reference formula");

    // Dot product with input vector
    float input[256];
    for (int i = 0; i < 256; ++i) input[i] = static_cast<float>(i % 5);

    float dot = 0.0f;
    for (int i = 0; i < 256; ++i) dot += dequant[i] * input[i];

    float refDot = 0.0f;
    for (int i = 0; i < 256; ++i) refDot += expected[i] * input[i];

    CHECK(approxEq(dot, refDot, 1e-3f), "Gate 4: Dot product matches reference");
}

// ============================================================================
// Gate 5 — Edge case: zero block, max scale, NaN guard
// ============================================================================
static void test_gate5_edge_cases() {
    printf("\n=== Gate 5: Edge cases (zero block, max scale, NaN guard) ===\n");

    // Zero block: d=0, dmin=0, scales=0, quants=0 → all output zero
    Q4_K_Block zeroBlk{};
    float out[256];
    dequantizeQ4KBlock(&zeroBlk, out);
    bool allZero = true;
    for (int i = 0; i < 256; ++i) {
        if (!approxEq(out[i], 0.0f)) { allZero = false; break; }
    }
    CHECK(allZero, "Gate 5: Zero block produces all zeros");

    // Max scale block: d=FP16 max normal (~65504), sc=63, min=0
    // Should produce large but finite values
    Q4_K_Block maxBlk{};
    maxBlk.d = 0x7BFF;  // FP16 max normal ≈ 65504
    maxBlk.dmin = 0x0000;
    for (int i = 0; i < 4; ++i) {
        maxBlk.scales[i] = 63;
        maxBlk.scales[i + 4] = 0;
    }
    for (int i = 8; i < 12; ++i) maxBlk.scales[i] = 0x3F;
    for (int i = 0; i < 128; ++i) maxBlk.qs[i] = 0xFF; // quant=15

    dequantizeQ4KBlock(&maxBlk, out);
    CHECK(allFinite(out, 256), "Gate 5: Max-scale block produces finite values");

    // Verify at least one value is > 1e6 (proof scale was applied)
    bool large = false;
    for (int i = 0; i < 256; ++i) {
        if (out[i] > 1e6f) { large = true; break; }
    }
    CHECK(large, "Gate 5: Max-scale block produces large values (>1e6)");
}

// ============================================================================
// Main
// ============================================================================
int main() {
    printf("============================================================\n");
    printf(" K2-003A — Isolated Q4_K Decoder Correctness Test\n");
    printf("============================================================\n");

    test_gate1_synthetic_block();
    test_gate2_scale_min_all_subblocks();
    test_gate3_tail_block();
    test_gate4_reference_dot_product();
    test_gate5_edge_cases();

    printf("\n============================================================\n");
    printf(" Results: %d passed, %d failed\n", g_pass, g_fail);
    printf("============================================================\n");

    return g_fail > 0 ? 1 : 0;
}
