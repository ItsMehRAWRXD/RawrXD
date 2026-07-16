/**
 * @file test_dynamic_batcher.cpp
 * @brief Unit tests for dynamic batching
 */

#include <gtest/gtest.h>
#include "inference/dynamic_batcher.hpp"

using namespace rawrxd::inference;

class DynamicBatcherTest : public ::testing::Test {
protected:
    void SetUp() override {
        config_.max_batch_size = 4;
        config_.max_tokens_per_batch = 512;
        config_.sort_by_length = true;
    }

    DynamicBatchingConfig config_;
};

TEST_F(DynamicBatcherTest, AddRequest) {
    DynamicBatcher batcher(config_);
    
    Request request;
    request.prompt_tokens.resize(10, 1);  // 10 tokens
    
    batcher.addRequest(request);
    
    EXPECT_TRUE(batcher.canAccept());
}

TEST_F(DynamicBatcherTest, GetBatch) {
    DynamicBatcher batcher(config_);
    
    // Add multiple requests
    for (int i = 0; i < 3; ++i) {
        Request request;
        request.prompt_tokens.resize(10 + i * 5, 1);
        batcher.addRequest(request);
    }
    
    auto batch = batcher.getBatch();
    ASSERT_TRUE(batch.has_value());
    EXPECT_EQ(batch->requests.size(), 3);
}

TEST_F(DynamicBatcherTest, SequenceGroup) {
    SequenceGroup group;
    
    Request request;
    request.id = "test";
    std::vector<int> tokens = {1, 2, 3, 4, 5};
    
    group.add(request, tokens);
    
    EXPECT_EQ(group.requests.size(), 1);
    EXPECT_EQ(group.input_ids.size(), 1);
    EXPECT_EQ(group.lengths.size(), 1);
    EXPECT_EQ(group.total_tokens, 5);
    EXPECT_EQ(group.max_length, 5);
    
    group.computePadding();
    
    auto masks = group.getAttentionMasks();
    EXPECT_EQ(masks.size(), 1);
    EXPECT_EQ(masks[0].size(), 5);
}

TEST_F(DynamicBatcherTest, LengthBucketer) {
    std::vector<int> boundaries = {32, 64, 128, 256};
    LengthBucketer bucketer(boundaries);
    
    EXPECT_EQ(bucketer.getBucket(10), 0);   // < 32
    EXPECT_EQ(bucketer.getBucket(32), 0);   // <= 32
    EXPECT_EQ(bucketer.getBucket(50), 1);   // 32 < 50 <= 64
    EXPECT_EQ(bucketer.getBucket(100), 2);  // 64 < 100 <= 128
    EXPECT_EQ(bucketer.getBucket(300), 4);  // > 256
    
    EXPECT_EQ(bucketer.padToBucket(10), 32);
    EXPECT_EQ(bucketer.padToBucket(50), 64);
    EXPECT_EQ(bucketer.padToBucket(300), 300);  // No padding needed
}

TEST_F(DynamicBatcherTest, TokenBudgetBatcher) {
    TokenBudgetBatcher budget_batcher(100);
    
    Request request;
    std::vector<int> tokens(50, 1);
    
    EXPECT_TRUE(budget_batcher.tryAdd(request, tokens));
    EXPECT_EQ(budget_batcher.getRemainingBudget(), 50);
    
    EXPECT_TRUE(budget_batcher.tryAdd(request, tokens));
    EXPECT_EQ(budget_batcher.getRemainingBudget(), 0);
    
    EXPECT_FALSE(budget_batcher.tryAdd(request, tokens));
    
    auto batch = budget_batcher.finalize();
    EXPECT_EQ(batch.requests.size(), 2);
    EXPECT_TRUE(budget_batcher.empty());
}

TEST_F(DynamicBatcherTest, AdaptiveBatchController) {
    AdaptiveBatchController controller(2, 16);
    
    EXPECT_EQ(controller.getOptimalBatchSize(), 2);
    
    // Simulate improving throughput
    controller.recordBatchResult(2, 10.0f);
    controller.recordBatchResult(3, 12.0f);
    controller.recordBatchResult(4, 14.0f);
    
    controller.adjustBatchSize();
    
    // Batch size should have increased
    EXPECT_GE(controller.getOptimalBatchSize(), 2);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
