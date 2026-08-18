// ============================================================================
// Deep2Engine_MetadataRegressionTest.cpp
// Metadata-only regression test for DeepSeek2/K2 GGUF parser.
// Loads the real K2 GGUF metadata but does NOT map/materialize model tensors.
// Asserts the exact ground-truth contract before K2-002 bounded execution.
// ============================================================================

#include <cstdio>
#include <cstdlib>
#include <string>
#include "GGUFLoader.hpp"

using namespace Deep2;

static bool g_verbose = true;

#define ASSERT_EQ(field, expected, actual) \
    do { \
        if ((actual) != (expected)) { \
            printf("FAIL: %s expected=%u actual=%u\n", field, \
                   (uint32_t)(expected), (uint32_t)(actual)); \
            return false; \
        } else if (g_verbose) { \
            printf("PASS: %s = %u\n", field, (uint32_t)(actual)); \
        } \
    } while (0)

#define ASSERT_EQ_SIZE(field, expected, actual) \
    do { \
        if ((actual) != (expected)) { \
            printf("FAIL: %s expected=%zu actual=%zu\n", field, \
                   (size_t)(expected), (size_t)(actual)); \
            return false; \
        } else if (g_verbose) { \
            printf("PASS: %s = %zu\n", field, (size_t)(actual)); \
        } \
    } while (0)

#define ASSERT_EQ_FLOAT(field, expected, actual) \
    do { \
        if ((actual) != (expected)) { \
            printf("FAIL: %s expected=%f actual=%f\n", field, \
                   (float)(expected), (float)(actual)); \
            return false; \
        } else if (g_verbose) { \
            printf("PASS: %s = %f\n", field, (float)(actual)); \
        } \
    } while (0)

#define ASSERT_STR_EQ(field, expected, actual) \
    do { \
        if ((actual) != (expected)) { \
            printf("FAIL: %s expected='%s' actual='%s'\n", field, \
                   (expected), (actual).c_str()); \
            return false; \
        } else if (g_verbose) { \
            printf("PASS: %s = '%s'\n", field, (actual).c_str()); \
        } \
    } while (0)

bool RunMetadataRegressionTest(const char* ggufPath) {
    printf("\n========================================\n");
    printf("DeepSeek2 Metadata Regression Test\n");
    printf("========================================\n");
    printf("File: %s\n\n", ggufPath);

    // Load metadata only (no tensor materialization)
    GGUFLoadOptions opts;
    opts.loadTensors = false;
    opts.verbose = false;

    GGUFLoadResult result = GGUFLoader::Load(ggufPath, opts);
    if (!result.success) {
        printf("FAIL: Could not load GGUF metadata: %s\n", result.error);
        return false;
    }

    const ModelMetadata& m = result.metadata;

    // ── Architecture ──
    ASSERT_STR_EQ("architecture", "deepseek2", m.architecture);

    // ── Model dimensions ──
    ASSERT_EQ("block_count", 61, m.numLayers);
    ASSERT_EQ("leading_dense_block_count", 1, m.leadingDenseBlockCount);
    ASSERT_EQ("embedding_length", 7168, m.hiddenSize);
    ASSERT_EQ("vocab_size", 163840, m.vocabSize);
    ASSERT_EQ("context_length", 262144, m.maxPositionEmbeddings);

    // ── Attention / MLA ──
    ASSERT_EQ("attention.head_count", 64, m.numHeads);
    ASSERT_EQ("attention.head_count_kv", 1, m.numKeyValueHeads);
    ASSERT_EQ("attention.q_lora_rank", 1536, m.qLoraRank);
    ASSERT_EQ("attention.kv_lora_rank", 512, m.kvLoraRank);
    ASSERT_EQ("attention.key_length", 576, m.keyLength);
    ASSERT_EQ("attention.value_length", 512, m.valueLength);
    ASSERT_EQ("attention.key_length_mla", 192, m.keyLengthMla);
    ASSERT_EQ("attention.value_length_mla", 128, m.valueLengthMla);
    ASSERT_EQ("rope.dimension_count", 64, m.ropeDimensionCount);

    // ── MoE ──
    ASSERT_EQ("expert_count", 384, m.numExperts);
    ASSERT_EQ("expert_used_count", 8, m.numExpertsPerToken);
    ASSERT_EQ("expert_shared_count", 1, m.numSharedExperts);
    ASSERT_EQ("expert_feed_forward_length", 2048, m.moeIntermediateSize);

    // ── Dense FFN / RoPE ──
    ASSERT_EQ("feed_forward_length", 18432, m.intermediateSize);
    ASSERT_EQ_FLOAT("rope.freq_base", 50000.0f, m.ropeTheta);
    ASSERT_EQ_FLOAT("rope.scaling.factor", 64.0f, m.ropeScaling);

    // ── Derived MLA coherence check ──
    if (m.qLoraRank == 0 || m.kvLoraRank == 0 ||
        m.keyLengthMla == 0 || m.valueLengthMla == 0 ||
        m.ropeDimensionCount == 0) {
        printf("FAIL: MLA metadata is incomplete\n");
        return false;
    }

    uint32_t expectedQkNope = m.keyLengthMla - m.ropeDimensionCount; // 192 - 64 = 128
    if (expectedQkNope != 128) {
        printf("FAIL: Derived qkNopeHeadDim expected=128 actual=%u\n", expectedQkNope);
        return false;
    }
    if (g_verbose) {
        printf("PASS: derived qkNopeHeadDim = %u\n", expectedQkNope);
        printf("PASS: derived qkRopeHeadDim = %u\n", m.ropeDimensionCount);
        printf("PASS: derived vHeadDim      = %u\n", m.valueLengthMla);
    }

    // ── Layer topology sanity ──
    if (m.leadingDenseBlockCount >= m.numLayers) {
        printf("FAIL: leadingDenseBlockCount (%u) >= numLayers (%u)\n",
               m.leadingDenseBlockCount, m.numLayers);
        return false;
    }
    if (g_verbose) {
        printf("PASS: layer topology: 0..%u = dense, %u..%u = MoE\n",
               m.leadingDenseBlockCount - 1,
               m.leadingDenseBlockCount,
               m.numLayers - 1);
    }

    printf("\n========================================\n");
    printf("ALL ASSERTIONS PASSED\n");
    printf("========================================\n\n");
    return true;
}

// ============================================================================
// Main
// ============================================================================
int main(int argc, char* argv[]) {
    const char* ggufPath = nullptr;

    if (argc > 1) {
        ggufPath = argv[1];
    } else {
        // Try common K2 model locations
        const char* candidates[] = {
            "F:\\OllamaModels\\qwen25coder14b-local\\qwen2.5-coder-14b-instruct-q4_k_m.gguf",
            "F:\\OllamaModels\\qwen3.5-q4k-m-local\\qwen3.5-14b-instruct-q4_k_m.gguf",
            nullptr
        };
        for (int i = 0; candidates[i]; ++i) {
            FILE* fp = fopen(candidates[i], "rb");
            if (fp) {
                fclose(fp);
                ggufPath = candidates[i];
                break;
            }
        }
    }

    if (!ggufPath) {
        printf("Usage: %s <path-to-k2.gguf>\n", argv[0]);
        printf("Or place a K2 GGUF at a known location.\n");
        return 1;
    }

    bool ok = RunMetadataRegressionTest(ggufPath);
    return ok ? 0 : 1;
}
