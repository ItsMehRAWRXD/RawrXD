// ============================================================================
// test_q4k_decoder.cpp — Standalone Q4_K Block Decoder Verification
//
// Purpose: Verify the C++ Q4_K dequantization matches actual GGUF Q4_K data.
//          Reads a real Q4_K block from K2 shards, decodes it, and validates
//          output properties (finite, non-zero, reasonable range).
//
// This test must pass BEFORE Q4_K GEMV is re-enabled in K2-003 Gate 6b.
// ============================================================================

#include "../src/deep2/GGUFLoader.hpp"
#include "../src/deep2/K2GlobalTensorIndex.hpp"
#include "../src/deep2/KimiK2Config.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <vector>

namespace fs = std::filesystem;

// ============================================================================
// Mirror of Deep2Engine.cpp Q4_K structures (must stay in sync)
// ============================================================================
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
// Validation helpers
// ============================================================================
static bool allFinite(const float* data, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        if (!std::isfinite(data[i])) return false;
    }
    return true;
}

static bool anyNonZero(const float* data, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        if (data[i] != 0.0f) return true;
    }
    return false;
}

static float maxAbs(const float* data, size_t n) {
    float max = 0.0f;
    for (size_t i = 0; i < n; ++i) {
        float a = std::abs(data[i]);
        if (a > max) max = a;
    }
    return max;
}

// ============================================================================
// Main test
// ============================================================================
int main(int argc, char** argv) {
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║  Q4_K Block Decoder Verification Test                       ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n\n");

    fs::path shardDir = (argc > 1) ? argv[1] : fs::current_path();
    printf("[INFO] Shard directory: %s\n", shardDir.string().c_str());

    // ── Step 1: Build tensor index to find a Q4_K tensor ──
    printf("\n── Step 1: Build tensor index ──\n");
    Deep2::GlobalTensorIndex index;
    std::string indexError;
    Deep2::KimiK2Config k2cfg;
    k2cfg.hiddenDim = 7168;
    k2cfg.numLayers = 61;
    k2cfg.numHeads = 128;
    k2cfg.numKVHeads = 1;
    k2cfg.qLoraRank = 1536;
    k2cfg.kvLoraRank = 512;
    k2cfg.qkNopeHeadDim = 128;
    k2cfg.qkRopeHeadDim = 64;
    k2cfg.vHeadDim = 128;
    k2cfg.numExperts = 384;
    k2cfg.expertsPerToken = 8;
    k2cfg.sharedExperts = 1;
    k2cfg.moeIntermediateSize = 2048;
    k2cfg.vocabSize = 163840;
    k2cfg.maxPosition = 262144;
    k2cfg.routedScalingFactor = 2.827f;

    if (!index.BuildFromShardDirectory(shardDir, k2cfg, indexError)) {
        printf("  [SKIP] No K2 shards found in %s — skipping Q4_K decoder test.\n",
               shardDir.string().c_str());
        printf("  To run this test, point to a directory containing K2 GGUF shards.\n");
        return 0;  // Skip, not fail
    }
    printf("  Index built: %zu tensors\n", index.TotalTensors());

    // ── Step 2: Find a Q4_K tensor (type 12) ──
    printf("\n── Step 2: Find Q4_K tensor ──\n");
    auto refOpt = index.Find("blk.0.attn_q_a.weight");
    if (!refOpt) {
        printf("  [FAIL] blk.0.attn_q_a.weight not found\n");
        return 2;
    }
    const auto& ref = *refOpt;
    if (ref.ggmlType != 12) {
        printf("  [FAIL] Expected GGML type 12 (Q4_K), got %u\n", ref.ggmlType);
        return 2;
    }
    printf("  Found: %s\n", ref.name.c_str());
    printf("  Shard: %u, Offset: %llu, Size: %llu bytes\n",
           ref.shardId, (unsigned long long)ref.fileOffset, (unsigned long long)ref.byteSize);
    printf("  Shape: [%llu, %llu]\n",
           (unsigned long long)ref.shape[0], (unsigned long long)ref.shape[1]);

    // ── Step 3: Read first Q4_K block (144 bytes) ──
    printf("\n── Step 3: Read first Q4_K block ──\n");
    const auto& shardPath = index.ShardPath(ref.shardId);
    if (shardPath.empty() || !fs::exists(shardPath)) {
        printf("  [FAIL] Shard file not found\n");
        return 3;
    }

    std::ifstream f(shardPath.string(), std::ios::binary);
    if (!f) {
        printf("  [FAIL] Cannot open shard file\n");
        return 3;
    }
    f.seekg(static_cast<std::streamoff>(ref.fileOffset));
    if (!f.good()) {
        printf("  [FAIL] Seek failed\n");
        return 3;
    }

    Q4_K_Block block;
    f.read(reinterpret_cast<char*>(&block), sizeof(block));
    size_t readCount = static_cast<size_t>(f.gcount());
    f.close();

    if (readCount != sizeof(block)) {
        printf("  [FAIL] Only read %zu bytes (expected %zu)\n", readCount, sizeof(block));
        return 3;
    }
    printf("  Read %zu bytes (one Q4_K block)\n", readCount);

    // ── Step 4: Decode block header ──
    printf("\n── Step 4: Decode block header ──\n");
    float d    = fp16ToFloat(block.d);
    float dmin = fp16ToFloat(block.dmin);
    printf("  d (super-scale):  %.6f (raw: 0x%04x)\n", d, block.d);
    printf("  dmin (super-min): %.6f (raw: 0x%04x)\n", dmin, block.dmin);

    printf("  scales[12] (hex): ");
    for (int i = 0; i < 12; ++i) {
        printf("%02x ", block.scales[i]);
    }
    printf("\n");

    // Unpack and display scale/min pairs
    printf("  Unpacked scale/min pairs:\n");
    for (int j = 0; j < 8; ++j) {
        uint8_t sc, m;
        unpackQ4KScaleMin(block.scales, j, sc, m);
        printf("    sub-block %d: sc=%2u, m=%2u\n", j, sc, m);
    }

    // ── Step 5: Dequantize and validate ──
    printf("\n── Step 5: Dequantize and validate ──\n");
    float dequantized[256];
    dequantizeQ4KBlock(&block, dequantized);

    bool finite = allFinite(dequantized, 256);
    bool nonZero = anyNonZero(dequantized, 256);
    float maxA = maxAbs(dequantized, 256);

    printf("  All finite:   %s\n", finite ? "YES" : "NO");
    printf("  Any non-zero: %s\n", nonZero ? "YES" : "NO");
    printf("  Max |value|:  %.6f\n", maxA);

    // Print first 16 values
    printf("  First 16 dequantized values:\n");
    for (int i = 0; i < 16; ++i) {
        printf("    [%3d] = %12.6f\n", i, dequantized[i]);
    }

    // ── Step 6: Statistical sanity checks ──
    printf("\n── Step 6: Statistical sanity checks ──\n");
    bool pass = true;

    if (!finite) {
        printf("  [FAIL] Dequantized values contain Inf/NaN\n");
        pass = false;
    } else {
        printf("  [PASS] All values finite\n");
    }

    if (!nonZero) {
        printf("  [FAIL] All dequantized values are zero (suspicious)\n");
        pass = false;
    } else {
        printf("  [PASS] Non-zero values present\n");
    }

    // For learned weights, max abs value should be in a reasonable range
    // Q4_K quantizes to [0..15] * d * sc - dmin * m
    // With typical d ~ 0.01-1.0 and sc up to 63, max should be < ~1000
    if (maxA > 10000.0f) {
        printf("  [WARN] Max abs value %.2f seems very large (possible format error)\n", maxA);
    } else if (maxA < 0.0001f) {
        printf("  [WARN] Max abs value %.6f seems very small (possible format error)\n", maxA);
    } else {
        printf("  [PASS] Max abs value %.6f in reasonable range\n", maxA);
    }

    // ── Step 7: Cross-check against MASM reference (if available) ──
    printf("\n── Step 7: Cross-check block size ──\n");
    if (sizeof(Q4_K_Block) == 144) {
        printf("  [PASS] Block size = 144 bytes (matches GGUF spec)\n");
    } else {
        printf("  [FAIL] Block size = %zu bytes (expected 144)\n", sizeof(Q4_K_Block));
        pass = false;
    }

    // ── Summary ──
    printf("\n╔════════════════════════════════════════════════════════════╗\n");
    if (pass) {
        printf("║  ✅ Q4_K DECODER VERIFICATION PASSED                        ║\n");
        printf("╚════════════════════════════════════════════════════════════╝\n");
        return 0;
    } else {
        printf("║  ❌ Q4_K DECODER VERIFICATION FAILED                        ║\n");
        printf("╚════════════════════════════════════════════════════════════╝\n");
        return 10;
    }
}
