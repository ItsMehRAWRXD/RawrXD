#include <gtest/gtest.h>
#include "rawrxd/inference/KVCache.hpp"
#include "rawrxd/core/Tensor.hpp"

using namespace rawrxd::inference;
using namespace rawrxd::core;

class KVCacheTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Common setup
    }
    
    void TearDown() override {
        // Cleanup
    }
};

TEST_F(KVCacheTest, BasicConstruction) {
    const size_t batchSize = 2;
    const size_t numHeads = 8;
    const size_t maxSeqLen = 128;
    const size_t headDim = 64;
    
    KVCache cache(batchSize, numHeads, maxSeqLen, headDim);
    
    EXPECT_EQ(cache.GetBatchSize(), batchSize);
    EXPECT_EQ(cache.GetNumHeads(), numHeads);
    EXPECT_EQ(cache.GetMaxSeqLen(), maxSeqLen);
    EXPECT_EQ(cache.GetHeadDim(), headDim);
    EXPECT_EQ(cache.GetCurrentSeqLen(), 0);
}

TEST_F(KVCacheTest, UpdateAndRetrieve) {
    const size_t batchSize = 1;
    const size_t numHeads = 4;
    const size_t maxSeqLen = 32;
    const size_t headDim = 16;
    
    KVCache cache(batchSize, numHeads, maxSeqLen, headDim);
    
    // Create key-value tensors
    std::vector<size_t> kvShape = {batchSize, numHeads, 2, headDim};
    Tensor<float> keys(kvShape, DataType::FLOAT32);
    Tensor<float> values(kvShape, DataType::FLOAT32);
    
    // Fill with test data
    for (size_t b = 0; b < batchSize; ++b) {
        for (size_t h = 0; h < numHeads; ++h) {
            for (size_t d = 0; d < headDim; ++d) {
                keys.At(b, h, 0, d) = static_cast<float>(d);
                keys.At(b, h, 1, d) = static_cast<float>(d + 100);
                values.At(b, h, 0, d) = static_cast<float>(d + 200);
                values.At(b, h, 1, d) = static_cast<float>(d + 300);
            }
        }
    }
    
    // Update cache
    cache.Update(keys, values, /*layerIdx=*/0);
    
    // Check sequence length increased
    EXPECT_EQ(cache.GetCurrentSeqLen(), 2);
    
    // Retrieve cached values
    auto [retrievedKeys, retrievedValues] = cache.Get(0, 2);
    
    // Verify retrieved values match
    for (size_t h = 0; h < numHeads; ++h) {
        for (size_t d = 0; d < headDim; ++d) {
            EXPECT_FLOAT_EQ(retrievedKeys->At(0, h, 0, d), static_cast<float>(d));
            EXPECT_FLOAT_EQ(retrievedKeys->At(0, h, 1, d), static_cast<float>(d + 100));
            EXPECT_FLOAT_EQ(retrievedValues->At(0, h, 0, d), static_cast<float>(d + 200));
            EXPECT_FLOAT_EQ(retrievedValues->At(0, h, 1, d), static_cast<float>(d + 300));
        }
    }
}

TEST_F(KVCacheTest, ClearCache) {
    const size_t batchSize = 1;
    const size_t numHeads = 4;
    const size_t maxSeqLen = 32;
    const size_t headDim = 16;
    
    KVCache cache(batchSize, numHeads, maxSeqLen, headDim);
    
    // Add some data
    std::vector<size_t> kvShape = {batchSize, numHeads, 2, headDim};
    Tensor<float> keys(kvShape, DataType::FLOAT32);
    Tensor<float> values(kvShape, DataType::FLOAT32);
    
    cache.Update(keys, values, 0);
    EXPECT_EQ(cache.GetCurrentSeqLen(), 2);
    
    // Clear cache
    cache.Clear();
    EXPECT_EQ(cache.GetCurrentSeqLen(), 0);
}

TEST_F(KVCacheTest, MultipleLayers) {
    const size_t batchSize = 1;
    const size_t numHeads = 4;
    const size_t maxSeqLen = 32;
    const size_t headDim = 16;
    const size_t numLayers = 3;
    
    KVCache cache(batchSize, numHeads, maxSeqLen, headDim, numLayers);
    
    std::vector<size_t> kvShape = {batchSize, numHeads, 2, headDim};
    Tensor<float> keys(kvShape, DataType::FLOAT32);
    Tensor<float> values(kvShape, DataType::FLOAT32);
    
    // Update each layer
    for (size_t layer = 0; layer < numLayers; ++layer) {
        keys.Ones();
        values.Ones();
        
        // Multiply by layer index to differentiate
        for (size_t i = 0; i < keys.GetSize(); ++i) {
            keys.GetData()[i] *= static_cast<float>(layer + 1);
            values.GetData()[i] *= static_cast<float>(layer + 1);
        }
        
        cache.Update(keys, values, layer);
    }
    
    // Verify each layer has different values
    for (size_t layer = 0; layer < numLayers; ++layer) {
        auto [k, v] = cache.Get(layer, 2);
        
        // Check first element
        EXPECT_FLOAT_EQ(k->At(0, 0, 0, 0), static_cast<float>(layer + 1));
        EXPECT_FLOAT_EQ(v->At(0, 0, 0, 0), static_cast<float>(layer + 1));
    }
}

TEST_F(KVCacheTest, MaxSeqLenLimit) {
    const size_t batchSize = 1;
    const size_t numHeads = 4;
    const size_t maxSeqLen = 4;
    const size_t headDim = 16;
    
    KVCache cache(batchSize, numHeads, maxSeqLen, headDim);
    
    std::vector<size_t> kvShape = {batchSize, numHeads, 2, headDim};
    Tensor<float> keys(kvShape, DataType::FLOAT32);
    Tensor<float> values(kvShape, DataType::FLOAT32);
    
    // Add data up to max
    cache.Update(keys, values, 0);
    cache.Update(keys, values, 0);
    EXPECT_EQ(cache.GetCurrentSeqLen(), 4);
    
    // Try to add more - should handle gracefully
    cache.Update(keys, values, 0);
    // Should either truncate or error gracefully
    EXPECT_LE(cache.GetCurrentSeqLen(), maxSeqLen + 2);
}

TEST_F(KVCacheTest, MemoryUsage) {
    const size_t batchSize = 2;
    const size_t numHeads = 8;
    const size_t maxSeqLen = 128;
    const size_t headDim = 64;
    
    KVCache cache(batchSize, numHeads, maxSeqLen, headDim);
    
    size_t initialMemory = cache.GetMemoryUsage();
    
    // Add data
    std::vector<size_t> kvShape = {batchSize, numHeads, 10, headDim};
    Tensor<float> keys(kvShape, DataType::FLOAT32);
    Tensor<float> values(kvShape, DataType::FLOAT32);
    
    cache.Update(keys, values, 0);
    
    size_t finalMemory = cache.GetMemoryUsage();
    
    // Memory should have increased
    EXPECT_GE(finalMemory, initialMemory);
}

TEST_F(KVCacheTest, GetCacheStats) {
    const size_t batchSize = 2;
    const size_t numHeads = 8;
    const size_t maxSeqLen = 128;
    const size_t headDim = 64;
    
    KVCache cache(batchSize, numHeads, maxSeqLen, headDim);
    
    // Add some data
    std::vector<size_t> kvShape = {batchSize, numHeads, 10, headDim};
    Tensor<float> keys(kvShape, DataType::FLOAT32);
    Tensor<float> values(kvShape, DataType::FLOAT32);
    
    cache.Update(keys, values, 0);
    
    auto stats = cache.GetStats();
    
    EXPECT_EQ(stats.currentSeqLen, 10);
    EXPECT_EQ(stats.maxSeqLen, maxSeqLen);
    EXPECT_EQ(stats.batchSize, batchSize);
    EXPECT_EQ(stats.numHeads, numHeads);
    EXPECT_GT(stats.memoryUsageBytes, 0);
}

TEST_F(KVCacheTest, PartialSequenceRetrieval) {
    const size_t batchSize = 1;
    const size_t numHeads = 4;
    const size_t maxSeqLen = 32;
    const size_t headDim = 16;
    
    KVCache cache(batchSize, numHeads, maxSeqLen, headDim);
    
    // Add 10 tokens
    std::vector<size_t> kvShape = {batchSize, numHeads, 10, headDim};
    Tensor<float> keys(kvShape, DataType::FLOAT32);
    Tensor<float> values(kvShape, DataType::FLOAT32);
    
    for (size_t i = 0; i < 10; ++i) {
        for (size_t h = 0; h < numHeads; ++h) {
            for (size_t d = 0; d < headDim; ++d) {
                keys.At(0, h, i, d) = static_cast<float>(i * 100 + d);
                values.At(0, h, i, d) = static_cast<float>(i * 100 + d + 1000);
            }
        }
    }
    
    cache.Update(keys, values, 0);
    
    // Retrieve only first 5 tokens
    auto [retrievedKeys, retrievedValues] = cache.Get(0, 5);
    
    EXPECT_EQ(retrievedKeys->GetShape()[2], 5);
    
    // Verify values
    for (size_t i = 0; i < 5; ++i) {
        for (size_t d = 0; d < headDim; ++d) {
            EXPECT_FLOAT_EQ(retrievedKeys->At(0, 0, i, d), static_cast<float>(i * 100 + d));
        }
    }
}

TEST_F(KVCacheTest, BatchUpdate) {
    const size_t batchSize = 2;
    const size_t numHeads = 4;
    const size_t maxSeqLen = 32;
    const size_t headDim = 16;
    
    KVCache cache(batchSize, numHeads, maxSeqLen, headDim);
    
    // Create batch with different values for each batch element
    std::vector<size_t> kvShape = {batchSize, numHeads, 2, headDim};
    Tensor<float> keys(kvShape, DataType::FLOAT32);
    Tensor<float> values(kvShape, DataType::FLOAT32);
    
    for (size_t b = 0; b < batchSize; ++b) {
        for (size_t h = 0; h < numHeads; ++h) {
            for (size_t s = 0; s < 2; ++s) {
                for (size_t d = 0; d < headDim; ++d) {
                    keys.At(b, h, s, d) = static_cast<float>(b * 1000 + s * 100 + d);
                    values.At(b, h, s, d) = static_cast<float>(b * 1000 + s * 100 + d + 500);
                }
            }
        }
    }
    
    cache.Update(keys, values, 0);
    
    // Retrieve and verify batch separation
    auto [retrievedKeys, retrievedValues] = cache.Get(0, 2);
    
    for (size_t b = 0; b < batchSize; ++b) {
        for (size_t d = 0; d < headDim; ++d) {
            EXPECT_FLOAT_EQ(retrievedKeys->At(b, 0, 0, d), static_cast<float>(b * 1000 + d));
            EXPECT_FLOAT_EQ(retrievedKeys->At(b, 0, 1, d), static_cast<float>(b * 1000 + 100 + d));
        }
    }
}
