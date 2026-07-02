// =============================================================================
// batch_splitter_test.cpp
// Test harness for Batch Splitter long-context sequence processing
// =============================================================================

#include <cstdio>
#include <cstdlib>
#include <vector>
#include <random>
#include <chrono>

#include "sovereign_batch_splitter.h"

using namespace Sovereign;

// =============================================================================
// Test Utilities
// =============================================================================

class BatchSplitterTest {
public:
    struct TestResult {
        const char* name;
        bool passed;
        const char* error_msg;
    };
    
    std::vector<TestResult> results;
    
    void RunAllTests() {
        printf("=================================================================\n");
        printf("  Batch Splitter Test Suite\n");
        printf("=================================================================\n\n");
        
        TestFixedWindowStrategy();
        TestDynamicLoadBalancing();
        TestSequenceSplitting();
        TestKVCacheHandover();
        TestPositionOffsetCalculation();
        TestSequenceAggregation();
        TestEdgeCases();
        
        PrintSummary();
    }

private:
    void RecordTest(const char* name, bool passed, const char* error = nullptr) {
        results.push_back({name, passed, error});
        printf("  [%s] %s\n", passed ? "PASS" : "FAIL", name);
        if (!passed && error) {
            printf("       Error: %s\n", error);
        }
    }
    
    void TestFixedWindowStrategy() {
        printf("[TEST] Fixed Window Strategy\n");
        
        FixedWindowStrategy strategy(128);  // 128 token overlap
        
        // Test 1: Sequence fits in one window
        auto chunks1 = strategy.CalculateChunkSizes(1024, 2048, 8);
        RecordTest("Single window (1024 < 2048)", 
                   chunks1.size() == 1 && chunks1[0] == 1024);
        
        // Test 2: Sequence requires splitting
        auto chunks2 = strategy.CalculateChunkSizes(5000, 2048, 8);
        RecordTest("Multi-window split (5000 > 2048)",
                   chunks2.size() > 1);
        
        // Test 3: Verify overlap is accounted for
        uint32_t total = 0;
        for (size_t i = 0; i < chunks2.size(); i++) {
            if (i == 0) {
                total += chunks2[i];
            } else {
                total += chunks2[i] - 128;  // Account for overlap
            }
        }
        RecordTest("Overlap accounting",
                   total >= 5000 && total <= 5000 + 128);
        
        printf("\n");
    }
    
    void TestDynamicLoadBalancing() {
        printf("[TEST] Dynamic Load Balancing\n");
        
        DynamicLoadBalancedStrategy strategy;
        
        // Create mock workers with different loads
        std::vector<LogicalWorker> workers(4);
        workers[0].metrics.tokens_submitted.store(1000);
        workers[1].metrics.tokens_submitted.store(500);   // Least loaded
        workers[2].metrics.tokens_submitted.store(2000);
        workers[3].metrics.tokens_submitted.store(1500);
        
        int selected = strategy.SelectWorkerForChunk(0, 4, workers);
        RecordTest("Select least loaded worker",
                   selected == 1);
        
        printf("\n");
    }
    
    void TestSequenceSplitting() {
        printf("[TEST] Sequence Splitting\n");
        
        BatchSplitter::SplitConfig config;
        config.max_tokens_per_window = 512;
        config.window_overlap = 64;
        config.enable_kv_handover = true;
        
        BatchSplitter splitter(config);
        
        // Create a long sequence
        std::vector<uint32_t> tokens(1500);
        for (size_t i = 0; i < tokens.size(); i++) {
            tokens[i] = (uint32_t)i;
        }
        
        std::vector<LogicalWorker> workers(4);
        auto requests = splitter.SplitSequence(tokens, 1000, 4, workers);
        
        RecordTest("Split creates multiple requests",
                   requests.size() > 1);
        
        if (requests.size() > 1) {
            RecordTest("First segment marked FIRST",
                       requests[0].seq_meta.segment_type == SequenceSegmentType::FIRST);
            
            RecordTest("Last segment marked LAST",
                       requests.back().seq_meta.segment_type == SequenceSegmentType::LAST);
            
            RecordTest("Middle segments marked MIDDLE (if applicable)",
                       requests.size() == 2 || 
                       requests[1].seq_meta.segment_type == SequenceSegmentType::MIDDLE);
            
            RecordTest("Sequence IDs match across segments",
                       requests[0].seq_meta.sequence_id == requests.back().seq_meta.sequence_id);
            
            RecordTest("Segment indices are sequential",
                       requests[0].seq_meta.segment_index == 0 &&
                       requests.back().seq_meta.segment_index == requests.size() - 1);
        }
        
        printf("\n");
    }
    
    void TestKVCacheHandover() {
        printf("[TEST] KV Cache Handover\n");
        
        SplitterCoordinator coordinator;
        
        // Register a KV cache handover
        uint8_t mock_kv_cache[1024];
        coordinator.RegisterKVCacheHandover(1, 100, mock_kv_cache, 1024, 256);
        
        // Consume the handover
        KVCacheHandover* handover = coordinator.ConsumeKVCacheHandover(100);
        
        RecordTest("KV cache handover registered and consumed",
                   handover != nullptr && handover->kv_cache_ptr == mock_kv_cache);
        
        // Try to consume again (should fail)
        KVCacheHandover* handover2 = coordinator.ConsumeKVCacheHandover(100);
        RecordTest("KV cache cannot be consumed twice",
                   handover2 == nullptr);
        
        // Try to consume non-existent
        KVCacheHandover* handover3 = coordinator.ConsumeKVCacheHandover(999);
        RecordTest("Non-existent handover returns null",
                   handover3 == nullptr);
        
        printf("\n");
    }
    
    void TestPositionOffsetCalculation() {
        printf("[TEST] Position Offset Calculation\n");
        
        BatchSplitter::SplitConfig config;
        config.max_tokens_per_window = 256;
        config.window_overlap = 32;
        
        BatchSplitter splitter(config);
        
        std::vector<uint32_t> tokens(600);
        for (size_t i = 0; i < tokens.size(); i++) {
            tokens[i] = (uint32_t)i;
        }
        
        std::vector<LogicalWorker> workers(4);
        auto requests = splitter.SplitSequence(tokens, 2000, 4, workers);
        
        bool offsets_correct = true;
        uint32_t expected_offset = 0;
        for (size_t i = 0; i < requests.size(); i++) {
            if (requests[i].seq_meta.position_offset != expected_offset) {
                offsets_correct = false;
                break;
            }
            // Account for overlap in next offset
            if (i == 0) {
                expected_offset += (uint32_t)requests[i].input_tokens.size();
            } else {
                expected_offset += (uint32_t)requests[i].input_tokens.size() - config.window_overlap;
            }
        }
        
        RecordTest("Position offsets calculated correctly",
                   offsets_correct);
        
        printf("\n");
    }
    
    void TestSequenceAggregation() {
        printf("[TEST] Sequence Aggregation\n");
        
        SplitterCoordinator coordinator;
        
        // Register a 3-segment sequence
        uint64_t seq_id = coordinator.RegisterSequence(3);
        
        // Complete segments out of order
        std::vector<uint32_t> output1 = {1, 2, 3};
        std::vector<uint32_t> output2 = {4, 5, 6};
        std::vector<uint32_t> output3 = {7, 8, 9};
        
        coordinator.CompleteSegment(seq_id, 1, output2);  // Middle first
        RecordTest("Sequence not complete after middle segment",
                   !coordinator.IsSequenceComplete(seq_id));
        
        coordinator.CompleteSegment(seq_id, 0, output1);  // First
        RecordTest("Sequence not complete after first segment",
                   !coordinator.IsSequenceComplete(seq_id));
        
        coordinator.CompleteSegment(seq_id, 2, output3);  // Last
        RecordTest("Sequence complete after all segments",
                   coordinator.IsSequenceComplete(seq_id));
        
        auto final_output = coordinator.GetSequenceOutput(seq_id);
        RecordTest("Aggregated output available",
                   final_output.has_value() && final_output->size() == 9);
        
        if (final_output.has_value() && final_output->size() == 9) {
            bool order_correct = 
                (*final_output)[0] == 1 && (*final_output)[1] == 2 && (*final_output)[2] == 3 &&
                (*final_output)[3] == 4 && (*final_output)[4] == 5 && (*final_output)[5] == 6 &&
                (*final_output)[6] == 7 && (*final_output)[7] == 8 && (*final_output)[8] == 9;
            RecordTest("Output tokens in correct order",
                       order_correct);
        }
        
        printf("\n");
    }
    
    void TestEdgeCases() {
        printf("[TEST] Edge Cases\n");
        
        BatchSplitter::SplitConfig config;
        config.max_tokens_per_window = 512;
        
        BatchSplitter splitter(config);
        std::vector<LogicalWorker> workers(4);
        
        // Test 1: Empty sequence
        std::vector<uint32_t> empty_tokens;
        auto requests1 = splitter.SplitSequence(empty_tokens, 3000, 4, workers);
        RecordTest("Empty sequence handling",
                   requests1.size() == 1 && requests1[0].input_tokens.empty());
        
        // Test 2: Single token
        std::vector<uint32_t> single_token = {42};
        auto requests2 = splitter.SplitSequence(single_token, 3001, 4, workers);
        RecordTest("Single token handling",
                   requests2.size() == 1 && requests2[0].input_tokens.size() == 1);
        
        // Test 3: Exactly at window boundary
        std::vector<uint32_t> exact_window(512);
        auto requests3 = splitter.SplitSequence(exact_window, 3002, 4, workers);
        RecordTest("Exact window boundary (no split needed)",
                   requests3.size() == 1 && requests3[0].seq_meta.segment_type == SequenceSegmentType::COMPLETE);
        
        // Test 4: One token over boundary
        std::vector<uint32_t> over_boundary(513);
        auto requests4 = splitter.SplitSequence(over_boundary, 3003, 4, workers);
        RecordTest("One token over boundary (split needed)",
                   requests4.size() > 1);
        
        printf("\n");
    }
    
    void PrintSummary() {
        int passed = 0;
        int failed = 0;
        
        for (const auto& result : results) {
            if (result.passed) passed++;
            else failed++;
        }
        
        printf("=================================================================\n");
        printf("  TEST SUMMARY\n");
        printf("=================================================================\n");
        printf("Total:  %zu\n", results.size());
        printf("Passed: %d\n", passed);
        printf("Failed: %d\n", failed);
        printf("\n");
        
        if (failed > 0) {
            printf("Failed Tests:\n");
            for (const auto& result : results) {
                if (!result.passed) {
                    printf("  - %s: %s\n", result.name, result.error_msg ? result.error_msg : "Unknown");
                }
            }
        }
        
        printf("\n=================================================================\n");
        printf("  OVERALL: %s\n", failed == 0 ? "PASSED" : "FAILED");
        printf("=================================================================\n");
    }
};

// =============================================================================
// Performance Benchmark
// =============================================================================

void RunPerformanceBenchmark() {
    printf("\n=================================================================\n");
    printf("  Performance Benchmark\n");
    printf("=================================================================\n\n");
    
    BatchSplitter::SplitConfig config;
    config.max_tokens_per_window = 2048;
    config.window_overlap = 128;
    config.enable_load_balancing = true;
    
    BatchSplitter splitter(config);
    std::vector<LogicalWorker> workers(8);
    
    // Benchmark different sequence lengths
    std::vector<uint32_t> lengths = {1024, 4096, 8192, 16384, 32768};
    
    for (uint32_t length : lengths) {
        std::vector<uint32_t> tokens(length);
        for (size_t i = 0; i < tokens.size(); i++) {
            tokens[i] = (uint32_t)i;
        }
        
        auto start = std::chrono::high_resolution_clock::now();
        
        // Run splitting 100 times
        for (int i = 0; i < 100; i++) {
            auto requests = splitter.SplitSequence(tokens, (uint64_t)i * 10000, 8, workers);
            (void)requests;  // Prevent optimization
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        
        double avg_us = duration / 100.0;
        
        printf("Sequence length %5u: %8.2f us per split (%zu chunks)\n",
               length, avg_us, 
               splitter.SplitSequence(tokens, 0, 8, workers).size());
    }
    
    printf("\n");
}

// =============================================================================
// Main Entry Point
// =============================================================================

int main(int argc, char* argv[]) {
    printf("=================================================================\n");
    printf("  Sovereign Batch Splitter Test & Benchmark\n");
    printf("=================================================================\n\n");
    
    // Run functional tests
    BatchSplitterTest test;
    test.RunAllTests();
    
    // Run performance benchmark
    RunPerformanceBenchmark();
    
    // Return success if all tests passed
    bool all_passed = true;
    for (const auto& result : test.results) {
        if (!result.passed) {
            all_passed = false;
            break;
        }
    }
    
    return all_passed ? 0 : 1;
}
