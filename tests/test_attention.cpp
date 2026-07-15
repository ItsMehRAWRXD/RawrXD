#include <gtest/gtest.h>
#include "rawrxd/model/Attention.hpp"
#include "rawrxd/core/Tensor.hpp"
#include <cmath>

using namespace rawrxd::model;
using namespace rawrxd::core;

class AttentionTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Common setup for attention tests
    }
    
    void TearDown() override {
        // Cleanup
    }
};

TEST_F(AttentionTest, MultiHeadAttentionForward) {
    const size_t batchSize = 2;
    const size_t seqLen = 4;
    const size_t embedDim = 64;
    const size_t numHeads = 8;
    const size_t headDim = embedDim / numHeads;
    
    MultiHeadAttentionConfig config;
    config.embedDim = embedDim;
    config.numHeads = numHeads;
    config.headDim = headDim;
    config.dropout = 0.0f; // No dropout for testing
    
    MultiHeadAttention mha(config);
    
    // Initialize with small random weights
    mha.Initialize(/*seed=*/42);
    
    // Create input tensor
    std::vector<size_t> inputShape = {batchSize, seqLen, embedDim};
    Tensor<float> input(inputShape, DataType::FLOAT32);
    
    // Fill with test values
    for (size_t b = 0; b < batchSize; ++b) {
        for (size_t s = 0; s < seqLen; ++s) {
            for (size_t e = 0; e < embedDim; ++e) {
                input.At(b, s, e) = static_cast<float>((b * seqLen + s) * embedDim + e) * 0.01f;
            }
        }
    }
    
    // Forward pass
    Tensor<float> output(inputShape, DataType::FLOAT32);
    KVCache cache(batchSize, numHeads, /*maxSeqLen=*/seqLen, headDim);
    
    bool success = mha.Forward(input, output, /*useCache=*/false, &cache);
    EXPECT_TRUE(success);
    
    // Check output shape
    EXPECT_EQ(output.GetShape()[0], batchSize);
    EXPECT_EQ(output.GetShape()[1], seqLen);
    EXPECT_EQ(output.GetShape()[2], embedDim);
}

TEST_F(AttentionTest, AttentionMasking) {
    const size_t batchSize = 1;
    const size_t seqLen = 4;
    const size_t embedDim = 32;
    const size_t numHeads = 4;
    const size_t headDim = embedDim / numHeads;
    
    MultiHeadAttentionConfig config;
    config.embedDim = embedDim;
    config.numHeads = numHeads;
    config.headDim = headDim;
    config.useBias = false;
    
    MultiHeadAttention mha(config);
    mha.Initialize(/*seed=*/42);
    
    // Create causal mask
    std::vector<size_t> maskShape = {batchSize, numHeads, seqLen, seqLen};
    Tensor<float> causalMask(maskShape, DataType::FLOAT32);
    
    // Fill with causal mask (upper triangle = -inf)
    for (size_t i = 0; i < seqLen; ++i) {
        for (size_t j = 0; j < seqLen; ++j) {
            float value = (j <= i) ? 0.0f : -std::numeric_limits<float>::infinity();
            for (size_t h = 0; h < numHeads; ++h) {
                causalMask.At(0, h, i, j) = value;
            }
        }
    }
    
    // Create input
    std::vector<size_t> inputShape = {batchSize, seqLen, embedDim};
    Tensor<float> input(inputShape, DataType::FLOAT32);
    input.Ones();
    
    // Forward with mask
    Tensor<float> output(inputShape, DataType::FLOAT32);
    KVCache cache(batchSize, numHeads, seqLen, headDim);
    
    bool success = mha.Forward(input, output, /*useCache=*/false, &cache, &causalMask);
    EXPECT_TRUE(success);
    
    // Output should be valid (not NaN or Inf)
    for (size_t i = 0; i < output.GetSize(); ++i) {
        EXPECT_FALSE(std::isnan(output.GetData()[i]));
        EXPECT_FALSE(std::isinf(output.GetData()[i]));
    }
}

TEST_F(AttentionTest, KVCacheOperations) {
    const size_t batchSize = 1;
    const size_t numHeads = 4;
    const size_t maxSeqLen = 8;
    const size_t headDim = 16;
    
    KVCache cache(batchSize, numHeads, maxSeqLen, headDim);
    
    // Initially cache should be empty
    EXPECT_EQ(cache.GetCurrentSeqLen(), 0);
    
    // Update cache with some key-value pairs
    std::vector<size_t> kvShape = {batchSize, numHeads, 2, headDim};
    Tensor<float> keys(kvShape, DataType::FLOAT32);
    Tensor<float> values(kvShape, DataType::FLOAT32);
    keys.Ones();
    values.Ones();
    
    cache.Update(keys, values, /*layerIdx=*/0);
    EXPECT_EQ(cache.GetCurrentSeqLen(), 2);
    
    // Update again
    cache.Update(keys, values, /*layerIdx=*/0);
    EXPECT_EQ(cache.GetCurrentSeqLen(), 4);
    
    // Clear cache
    cache.Clear();
    EXPECT_EQ(cache.GetCurrentSeqLen(), 0);
}

TEST_F(AttentionTest, RotaryEmbeddings) {
    const size_t seqLen = 4;
    const size_t headDim = 32;
    const size_t numHeads = 8;
    
    // Create rotary embedding
    RotaryEmbedding rotary(headDim, /*maxSeqLen=*/seqLen, /*base=*/10000.0f);
    
    // Create test tensor
    std::vector<size_t> shape = {1, numHeads, seqLen, headDim};
    Tensor<float> tensor(shape, DataType::FLOAT32);
    
    // Fill with sequential values
    for (size_t h = 0; h < numHeads; ++h) {
        for (size_t s = 0; s < seqLen; ++s) {
            for (size_t d = 0; d < headDim; ++d) {
                tensor.At(0, h, s, d) = static_cast<float>(s * headDim + d) * 0.01f;
            }
        }
    }
    
    // Apply rotary embeddings
    Tensor<float> output(shape, DataType::FLOAT32);
    bool success = rotary.Apply(tensor, output, /*seqLen=*/seqLen, /*offset=*/0);
    EXPECT_TRUE(success);
    
    // Output should be different from input (rotation applied)
    bool isDifferent = false;
    for (size_t i = 0; i < tensor.GetSize(); ++i) {
        if (std::abs(tensor.GetData()[i] - output.GetData()[i]) > 1e-6f) {
            isDifferent = true;
            break;
        }
    }
    EXPECT_TRUE(isDifferent);
}

TEST_F(AttentionTest, FlashAttentionEquivalence) {
    // Test that Flash Attention produces same results as standard attention
    const size_t batchSize = 1;
    const size_t seqLen = 16;
    const size_t embedDim = 64;
    const size_t numHeads = 8;
    const size_t headDim = embedDim / numHeads;
    
    MultiHeadAttentionConfig config;
    config.embedDim = embedDim;
    config.numHeads = numHeads;
    config.headDim = headDim;
    config.useFlashAttention = false; // Standard attention
    
    MultiHeadAttention mhaStandard(config);
    mhaStandard.Initialize(/*seed=*/42);
    
    config.useFlashAttention = true; // Flash attention
    MultiHeadAttention mhaFlash(config);
    mhaFlash.Initialize(/*seed=*/42);
    
    // Same weights
    mhaFlash.CopyWeightsFrom(mhaStandard);
    
    // Create input
    std::vector<size_t> inputShape = {batchSize, seqLen, embedDim};
    Tensor<float> input(inputShape, DataType::FLOAT32);
    input.RandomNormal(/*mean=*/0.0f, /*std=*/0.02f, /*seed=*/123);
    
    // Forward with standard attention
    Tensor<float> outputStandard(inputShape, DataType::FLOAT32);
    KVCache cacheStandard(batchSize, numHeads, seqLen, headDim);
    mhaStandard.Forward(input, outputStandard, /*useCache=*/false, &cacheStandard);
    
    // Forward with flash attention
    Tensor<float> outputFlash(inputShape, DataType::FLOAT32);
    KVCache cacheFlash(batchSize, numHeads, seqLen, headDim);
    mhaFlash.Forward(input, outputFlash, /*useCache=*/false, &cacheFlash);
    
    // Results should be approximately equal
    float maxDiff = 0.0f;
    for (size_t i = 0; i < outputStandard.GetSize(); ++i) {
        float diff = std::abs(outputStandard.GetData()[i] - outputFlash.GetData()[i]);
        maxDiff = std::max(maxDiff, diff);
    }
    
    // Allow small numerical differences
    EXPECT_LT(maxDiff, 1e-3f);
}

TEST_F(AttentionTest, GroupedQueryAttention) {
    const size_t batchSize = 1;
    const size_t seqLen = 8;
    const size_t embedDim = 64;
    const size_t numHeads = 8;
    const size_t numKVHeads = 2; // Fewer KV heads than query heads
    const size_t headDim = embedDim / numHeads;
    
    MultiHeadAttentionConfig config;
    config.embedDim = embedDim;
    config.numHeads = numHeads;
    config.numKVHeads = numKVHeads;
    config.headDim = headDim;
    config.useGQA = true;
    
    MultiHeadAttention mha(config);
    mha.Initialize(/*seed=*/42);
    
    std::vector<size_t> inputShape = {batchSize, seqLen, embedDim};
    Tensor<float> input(inputShape, DataType::FLOAT32);
    input.Ones();
    
    Tensor<float> output(inputShape, DataType::FLOAT32);
    KVCache cache(batchSize, numKVHeads, seqLen, headDim);
    
    bool success = mha.Forward(input, output, /*useCache=*/false, &cache);
    EXPECT_TRUE(success);
    
    // Output should have correct shape
    EXPECT_EQ(output.GetShape()[2], embedDim);
}

TEST_F(AttentionTest, SlidingWindowAttention) {
    const size_t batchSize = 1;
    const size_t seqLen = 32;
    const size_t embedDim = 64;
    const size_t numHeads = 8;
    const size_t headDim = embedDim / numHeads;
    const size_t windowSize = 8;
    
    MultiHeadAttentionConfig config;
    config.embedDim = embedDim;
    config.numHeads = numHeads;
    config.headDim = headDim;
    config.useSlidingWindow = true;
    config.windowSize = windowSize;
    
    MultiHeadAttention mha(config);
    mha.Initialize(/*seed=*/42);
    
    std::vector<size_t> inputShape = {batchSize, seqLen, embedDim};
    Tensor<float> input(inputShape, DataType::FLOAT32);
    input.Ones();
    
    Tensor<float> output(inputShape, DataType::FLOAT32);
    KVCache cache(batchSize, numHeads, seqLen, headDim);
    
    bool success = mha.Forward(input, output, /*useCache=*/false, &cache);
    EXPECT_TRUE(success);
    
    // Output should be valid
    for (size_t i = 0; i < output.GetSize(); ++i) {
        EXPECT_FALSE(std::isnan(output.GetData()[i]));
        EXPECT_FALSE(std::isinf(output.GetData()[i]));
    }
}
