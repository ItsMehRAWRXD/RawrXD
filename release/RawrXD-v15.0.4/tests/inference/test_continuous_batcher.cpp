/**
 * @file test_continuous_batcher.cpp
 * @brief Unit tests for continuous batching
 */

#include <gtest/gtest.h>
#include "inference/continuous_batcher.hpp"
#include "inference/request_queue.hpp"

using namespace rawrxd::inference;

class ContinuousBatcherTest : public ::testing::Test {
protected:
    void SetUp() override {
        config_.max_batch_size = 4;
        config_.max_tokens_per_batch = 1024;
        config_.batch_timeout_ms = 100.0f;
    }

    ContinuousBatchingConfig config_;
};

TEST_F(ContinuousBatcherTest, Initialization) {
    ContinuousBatcher batcher(config_);
    EXPECT_FALSE(batcher.getStats().total_requests > 0);
}

TEST_F(ContinuousBatcherTest, SubmitRequest) {
    ContinuousBatcher batcher(config_);
    batcher.initialize(nullptr);  // Mock model
    batcher.start();
    
    Request request;
    request.prompt_tokens = {1, 2, 3, 4, 5};
    request.max_new_tokens = 10;
    
    batcher.submitRequest(request);
    
    auto stats = batcher.getStats();
    EXPECT_EQ(stats.total_requests, 1);
    
    batcher.stop();
}

TEST_F(ContinuousBatcherTest, PagedAttentionManager) {
    PagedAttentionManager manager(100);
    
    EXPECT_EQ(manager.getTotalPages(), 100);
    EXPECT_EQ(manager.getFreePages(), 100);
    EXPECT_FLOAT_EQ(manager.getUtilization(), 0.0f);
    
    // Allocate pages
    auto pages = manager.allocatePages(1, 500);  // 500 tokens
    EXPECT_FALSE(pages.empty());
    EXPECT_LT(manager.getFreePages(), 100);
    EXPECT_GT(manager.getUtilization(), 0.0f);
    
    // Get KV cache indices
    auto indices = manager.getKVCacheIndices(1);
    EXPECT_EQ(indices, pages);
    
    // Free pages
    manager.freePages(1);
    EXPECT_EQ(manager.getFreePages(), 100);
    EXPECT_FLOAT_EQ(manager.getUtilization(), 0.0f);
}

TEST_F(ContinuousBatcherTest, PriorityScheduler) {
    PriorityScheduler scheduler;
    
    Request req1;
    req1.id = "low";
    
    Request req2;
    req2.id = "high";
    
    scheduler.enqueue(req1, PriorityScheduler::Priority::LOW);
    scheduler.enqueue(req2, PriorityScheduler::Priority::HIGH);
    
    // Should dequeue high priority first
    auto result = scheduler.dequeue();
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->id, "high");
    
    result = scheduler.dequeue();
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->id, "low");
}

TEST_F(ContinuousBatcherTest, TokenBudgetManager) {
    TokenBudgetManager budget(1000);  // 1000 tokens per minute
    
    EXPECT_TRUE(budget.canProcess(500));
    EXPECT_FALSE(budget.canProcess(1500));
    
    budget.consume(500);
    EXPECT_EQ(budget.getRemainingBudget(), 500);
    
    budget.consume(500);
    EXPECT_EQ(budget.getRemainingBudget(), 0);
    
    EXPECT_FALSE(budget.canProcess(100));
}

TEST_F(ContinuousBatcherTest, DISABLED_FormBatch) {
    // This test requires a full setup with model
    // Skipped in unit tests
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
