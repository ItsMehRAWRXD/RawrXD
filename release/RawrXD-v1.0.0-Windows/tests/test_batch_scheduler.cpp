#include <gtest/gtest.h>
#include "rawrxd/performance/BatchScheduler.hpp"
#include "rawrxd/core/Tensor.hpp"
#include <future>
#include <chrono>

using namespace rawrxd::performance;
using namespace rawrxd::core;

class BatchSchedulerTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Common setup
    }
    
    void TearDown() override {
        // Cleanup
    }
};

TEST_F(BatchSchedulerTest, StaticBatching) {
    StaticBatching batcher(/*batchSize=*/4);
    
    // Create test requests
    std::vector<InferenceRequest> requests;
    for (int i = 0; i < 10; ++i) {
        InferenceRequest req;
        req.requestId = i;
        req.inputIds = {1, 2, 3};
        req.maxTokens = 10;
        requests.push_back(req);
    }
    
    // Create batches
    auto batches = batcher.CreateBatches(requests);
    
    // Should create 3 batches: 4, 4, 2
    EXPECT_EQ(batches.size(), 3);
    EXPECT_EQ(batches[0].size(), 4);
    EXPECT_EQ(batches[1].size(), 4);
    EXPECT_EQ(batches[2].size(), 2);
}

TEST_F(BatchSchedulerTest, StaticBatchingEmpty) {
    StaticBatching batcher(/*batchSize=*/4);
    
    std::vector<InferenceRequest> requests;
    auto batches = batcher.CreateBatches(requests);
    
    EXPECT_TRUE(batches.empty());
}

TEST_F(BatchSchedulerTest, StaticBatchingSingleRequest) {
    StaticBatching batcher(/*batchSize=*/4);
    
    std::vector<InferenceRequest> requests;
    InferenceRequest req;
    req.requestId = 0;
    requests.push_back(req);
    
    auto batches = batcher.CreateBatches(requests);
    
    EXPECT_EQ(batches.size(), 1);
    EXPECT_EQ(batches[0].size(), 1);
}

TEST_F(BatchSchedulerTest, ContinuousBatchingInitialization) {
    ContinuousBatchingScheduler scheduler;
    ContinuousBatchingConfig config;
    config.maxBatchSize = 8;
    config.maxWaitingTokens = 20;
    config.maxWaitingTimeMs = 100;
    
    bool initialized = scheduler.Initialize(config);
    EXPECT_TRUE(initialized);
}

TEST_F(BatchSchedulerTest, ContinuousBatchingAddRequest) {
    ContinuousBatchingScheduler scheduler;
    ContinuousBatchingConfig config;
    config.maxBatchSize = 8;
    scheduler.Initialize(config);
    
    InferenceRequest req;
    req.requestId = 1;
    req.inputIds = {1, 2, 3, 4, 5};
    req.maxTokens = 20;
    
    auto future = scheduler.AddRequest(req);
    
    // Future should be valid
    EXPECT_TRUE(future.valid());
    
    // Should have one pending request
    EXPECT_EQ(scheduler.GetPendingCount(), 1);
}

TEST_F(BatchSchedulerTest, ContinuousBatchingPriority) {
    ContinuousBatchingScheduler scheduler;
    ContinuousBatchingConfig config;
    config.maxBatchSize = 2;
    scheduler.Initialize(config);
    
    // Add low priority request
    InferenceRequest lowReq;
    lowReq.requestId = 1;
    lowReq.priority = RequestPriority::LOW;
    scheduler.AddRequest(lowReq);
    
    // Add high priority request
    InferenceRequest highReq;
    highReq.requestId = 2;
    highReq.priority = RequestPriority::HIGH;
    scheduler.AddRequest(highReq);
    
    // Get next batch - should include high priority first
    auto batch = scheduler.GetNextBatch();
    
    EXPECT_EQ(batch.size(), 2);
    // High priority should be first
    EXPECT_EQ(batch[0].requestId, 2);
}

TEST_F(BatchSchedulerTest, ContinuousBatchingTimeout) {
    ContinuousBatchingScheduler scheduler;
    ContinuousBatchingConfig config;
    config.maxBatchSize = 4;
    config.maxWaitingTimeMs = 50; // Short timeout
    scheduler.Initialize(config);
    
    // Add single request
    InferenceRequest req;
    req.requestId = 1;
    scheduler.AddRequest(req);
    
    // Wait for timeout
    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    
    // Should return batch even with single request due to timeout
    auto batch = scheduler.GetNextBatch();
    EXPECT_EQ(batch.size(), 1);
}

TEST_F(BatchSchedulerTest, ContinuousBatchingCompleteRequest) {
    ContinuousBatchingScheduler scheduler;
    ContinuousBatchingConfig config;
    config.maxBatchSize = 4;
    scheduler.Initialize(config);
    
    InferenceRequest req;
    req.requestId = 1;
    auto future = scheduler.AddRequest(req);
    
    // Complete the request
    InferenceResult result;
    result.requestId = 1;
    result.generatedTokens = {10, 11, 12};
    result.finished = true;
    
    scheduler.CompleteRequest(result);
    
    // Future should be ready
    EXPECT_EQ(future.wait_for(std::chrono::seconds(0)), std::future_status::ready);
    
    auto returnedResult = future.get();
    EXPECT_EQ(returnedResult.requestId, 1);
    EXPECT_EQ(returnedResult.generatedTokens.size(), 3);
}

TEST_F(BatchSchedulerTest, ContinuousBatchingCancelRequest) {
    ContinuousBatchingScheduler scheduler;
    ContinuousBatchingConfig config;
    config.maxBatchSize = 4;
    scheduler.Initialize(config);
    
    InferenceRequest req;
    req.requestId = 1;
    auto future = scheduler.AddRequest(req);
    
    // Cancel the request
    bool cancelled = scheduler.CancelRequest(1);
    EXPECT_TRUE(cancelled);
    
    // Future should be ready with error
    EXPECT_EQ(future.wait_for(std::chrono::seconds(0)), std::future_status::ready);
}

TEST_F(BatchSchedulerTest, ContinuousBatchingBatchFormation) {
    ContinuousBatchingScheduler scheduler;
    ContinuousBatchingConfig config;
    config.maxBatchSize = 4;
    scheduler.Initialize(config);
    
    // Add multiple requests
    for (int i = 0; i < 10; ++i) {
        InferenceRequest req;
        req.requestId = i;
        req.inputIds.resize((i % 3) + 1); // Different lengths
        scheduler.AddRequest(req);
    }
    
    // Get batches until empty
    int totalBatched = 0;
    while (scheduler.GetPendingCount() > 0) {
        auto batch = scheduler.GetNextBatch();
        totalBatched += batch.size();
        
        // Complete all requests in batch
        for (const auto& req : batch) {
            InferenceResult result;
            result.requestId = req.requestId;
            result.finished = true;
            scheduler.CompleteRequest(result);
        }
    }
    
    EXPECT_EQ(totalBatched, 10);
}

TEST_F(BatchSchedulerTest, ContinuousBatchingDynamicBatching) {
    ContinuousBatchingScheduler scheduler;
    ContinuousBatchingConfig config;
    config.maxBatchSize = 8;
    config.maxBatchTotalTokens = 64;
    scheduler.Initialize(config);
    
    // Add requests with varying token counts
    for (int i = 0; i < 5; ++i) {
        InferenceRequest req;
        req.requestId = i;
        req.inputIds.resize(10); // 10 tokens each
        scheduler.AddRequest(req);
    }
    
    // Get batch - should respect maxBatchTotalTokens
    auto batch = scheduler.GetNextBatch();
    
    // Should batch up to token limit
    size_t totalTokens = 0;
    for (const auto& req : batch) {
        totalTokens += req.inputIds.size();
    }
    
    EXPECT_LE(totalTokens, config.maxBatchTotalTokens);
}

TEST_F(BatchSchedulerTest, ContinuousBatchingStats) {
    ContinuousBatchingScheduler scheduler;
    ContinuousBatchingConfig config;
    config.maxBatchSize = 4;
    scheduler.Initialize(config);
    
    // Add and complete some requests
    for (int i = 0; i < 5; ++i) {
        InferenceRequest req;
        req.requestId = i;
        auto future = scheduler.AddRequest(req);
        
        InferenceResult result;
        result.requestId = i;
        result.finished = true;
        scheduler.CompleteRequest(result);
    }
    
    auto stats = scheduler.GetStats();
    
    EXPECT_EQ(stats.totalRequests, 5);
    EXPECT_EQ(stats.completedRequests, 5);
    EXPECT_EQ(stats.pendingRequests, 0);
}

TEST_F(BatchSchedulerTest, BatchPadding) {
    StaticBatching batcher;
    
    // Create requests with different lengths
    std::vector<InferenceRequest> requests;
    for (int i = 0; i < 3; ++i) {
        InferenceRequest req;
        req.requestId = i;
        req.inputIds.resize((i + 1) * 2); // Lengths: 2, 4, 6
        requests.push_back(req);
    }
    
    auto batch = batcher.CreateBatch(requests);
    
    // All should be padded to max length (6)
    for (const auto& req : batch) {
        EXPECT_EQ(req.inputIds.size(), 6);
    }
}

TEST_F(BatchSchedulerTest, BatchAttentionMask) {
    StaticBatching batcher;
    
    std::vector<InferenceRequest> requests;
    InferenceRequest req1;
    req1.requestId = 0;
    req1.inputIds = {1, 2, 3};
    requests.push_back(req1);
    
    InferenceRequest req2;
    req2.requestId = 1;
    req2.inputIds = {4, 5};
    requests.push_back(req2);
    
    auto batch = batcher.CreateBatch(requests);
    auto attentionMask = batcher.CreateAttentionMask(batch);
    
    // Check mask shape
    EXPECT_EQ(attentionMask.GetShape()[0], 2); // Batch size
    EXPECT_EQ(attentionMask.GetShape()[1], 3); // Max length
    
    // First sequence should be all 1s
    EXPECT_EQ(attentionMask.At(0, 0), 1);
    EXPECT_EQ(attentionMask.At(0, 1), 1);
    EXPECT_EQ(attentionMask.At(0, 2), 1);
    
    // Second sequence should have padding
    EXPECT_EQ(attentionMask.At(1, 0), 1);
    EXPECT_EQ(attentionMask.At(1, 1), 1);
    EXPECT_EQ(attentionMask.At(1, 2), 0); // Padding
}
