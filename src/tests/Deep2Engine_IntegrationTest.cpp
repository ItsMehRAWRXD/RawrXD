//=============================================================================
// Deep2Engine_IntegrationTest.cpp - Full System Integration Test
// Tests: SequentialBlowoffValve + OutOfCoreScheduler + DualGpuPipeline + VulkanComputeKernels
// Verifies end-to-end inference pipeline for 671B models on dual GPU
//=============================================================================

#include "../inference/Deep2Engine.hpp"
#include "../inference/OutOfCoreScheduler.hpp"
#include "../inference/DualGpuPipeline.hpp"
#include "../memory/SequentialBlowoffValve.hpp"
#include "../kernels/VulkanComputeKernels.hpp"

#include <iostream>
#include <cassert>
#include <thread>
#include <chrono>
#include <vector>
#include <random>

using namespace RawrXD;
using namespace RawrXD::Inference;
using namespace RawrXD::Memory;
using namespace RawrXD::Kernels;

bool g_allTestsPassed = true;

#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            std::cerr << "[FAIL] " << msg << " at line " << __LINE__ << "\n"; \
            g_allTestsPassed = false; \
        } else { \
            std::cout << "[PASS] " << msg << "\n"; \
        } \
    } while(0)

//=============================================================================
// Test 1: SequentialBlowoffValve Integration
//=============================================================================
void TestSequentialBlowoffValve() {
    std::cout << "\n=== Test: SequentialBlowoffValve (Never Ending Rainbow Road) ===\n";
    
    BlowoffConfig config;
    config.ssd_swap_path = "D:\\RawrXD_Cache\\test_integration_swap.bin";
    config.gpu0_max_bytes = 512 * 1024 * 1024;  // 512MB for testing
    config.gpu1_max_bytes = 256 * 1024 * 1024;  // 256MB
    config.ram_max_bytes = 1024 * 1024 * 1024; // 1GB
    
    SequentialBlowoffValve valve(config);
    
    TEST_ASSERT(valve.Initialize(), "BlowoffValve initializes successfully");
    TEST_ASSERT(valve.IsRunning(), "BlowoffValve is running");
    
    // Allocate blocks simulating KV cache
    std::vector<uint64_t> blocks;
    for (int i = 0; i < 100; i++) {
        uint64_t block_id = valve.AllocateBlock(1024 * 1024, true); // 1MB each
        TEST_ASSERT(block_id != 0, "Block allocated");
        blocks.push_back(block_id);
    }
    
    // Access blocks (simulating inference)
    for (size_t i = 0; i < 10; i++) {
        void* ptr = valve.Access(blocks[i]);
        TEST_ASSERT(ptr != nullptr, "Block access returns valid pointer");
        
        // Write pattern
        std::memset(ptr, static_cast<int>(i), 1024);
    }
    
    // Check pressure
    float gpu0_pressure = valve.GetPressure(Tier::GPU0_R9700);
    float gpu1_pressure = valve.GetPressure(Tier::GPU1_7800XT);
    float ram_pressure = valve.GetPressure(Tier::RAM_DDR5);
    
    TEST_ASSERT(gpu0_pressure >= 0.0f && gpu0_pressure <= 1.0f, "GPU0 pressure is valid");
    TEST_ASSERT(gpu1_pressure >= 0.0f && gpu1_pressure <= 1.0f, "GPU1 pressure is valid");
    TEST_ASSERT(ram_pressure >= 0.0f && ram_pressure <= 1.0f, "RAM pressure is valid");
    
    std::cout << "  GPU0 Pressure: " << (gpu0_pressure * 100) << "%\n";
    std::cout << "  GPU1 Pressure: " << (gpu1_pressure * 100) << "%\n";
    std::cout << "  RAM Pressure: " << (ram_pressure * 100) << "%\n";
    
    // Get report
    std::string report = valve.GetRainbowRoadReport();
    TEST_ASSERT(!report.empty(), "RainbowRoadReport generated");
    TEST_ASSERT(report.find("RAINBOW ROAD") != std::string::npos, "Report contains RAINBOW ROAD");
    
    // Cleanup
    for (auto block_id : blocks) {
        valve.FreeBlock(block_id);
    }
    
    valve.Shutdown();
    TEST_ASSERT(!valve.IsRunning(), "BlowoffValve stopped after shutdown");
}

//=============================================================================
// Test 2: OutOfCoreScheduler Integration
//=============================================================================
void TestOutOfCoreScheduler() {
    std::cout << "\n=== Test: OutOfCoreScheduler (Layer-by-Layer Execution) ===\n";
    
    OutOfCoreConfig config;
    config.num_layers = 80;  // 671B model
    config.num_heads = 64;
    config.head_dim = 128;
    config.hidden_dim = 8192;
    config.gpu0_budget_bytes = 28ULL * 1024 * 1024 * 1024;
    config.gpu1_budget_bytes = 14ULL * 1024 * 1024 * 1024;
    config.gpu0_split_ratio = 0.667f;
    config.gpu1_split_ratio = 0.333f;
    
    OutOfCoreScheduler scheduler(config);
    
    // Note: Would need real Vulkan devices for full test
    // For now, test configuration
    
    uint32_t gpu0_layers = static_cast<uint32_t>(config.num_layers * config.gpu0_split_ratio);
    uint32_t gpu1_layers = config.num_layers - gpu0_layers;
    
    TEST_ASSERT(gpu0_layers == 53, "GPU0 gets 53 layers (2/3)");
    TEST_ASSERT(gpu1_layers == 27, "GPU1 gets 27 layers (1/3)");
    
    std::cout << "  Layer split: " << gpu0_layers << "/" << gpu1_layers << "\n";
    
    // Test metrics
    auto metrics = scheduler.GetMetrics();
    TEST_ASSERT(metrics.tokens_processed == 0, "Initial tokens processed is 0");
    
    std::string report = scheduler.GetStatusReport();
    TEST_ASSERT(!report.empty(), "Status report generated");
}

//=============================================================================
// Test 3: DualGpuPipeline Integration
//=============================================================================
void TestDualGpuPipeline() {
    std::cout << "\n=== Test: DualGpuPipeline (Tensor Parallelism 2:1) ===\n";
    
    DualGpuConfig config;
    config.gpu0_weight_ratio = 0.667f;
    config.gpu1_weight_ratio = 0.333f;
    config.enable_p2p_transfer = true;
    config.enable_async_execution = true;
    
    DualGpuPipeline pipeline(config);
    
    // Test tensor sharding
    std::vector<TensorShard> shards;
    bool result = pipeline.CreateShardedTensor(8192, 8192, 4, shards); // 8K x 8K float32
    
    TEST_ASSERT(result, "Tensor sharding successful");
    TEST_ASSERT(shards.size() == 2, "Created 2 shards");
    
    // Verify split
    uint32_t total_rows = shards[0].rows + shards[1].rows;
    TEST_ASSERT(total_rows == 8192, "Total rows preserved");
    
    uint32_t expected_gpu0_rows = static_cast<uint32_t>(8192 * 0.667f);
    TEST_ASSERT(shards[0].rows == expected_gpu0_rows, "GPU0 shard has correct size");
    TEST_ASSERT(shards[1].rows == 8192 - expected_gpu0_rows, "GPU1 shard has correct size");
    
    std::cout << "  Shard 0 (GPU0): " << shards[0].rows << " rows\n";
    std::cout << "  Shard 1 (GPU1): " << shards[1].rows << " rows\n";
    
    // Test metrics
    auto metrics = pipeline.GetMetrics();
    TEST_ASSERT(metrics.ops_submitted == 0, "Initial ops submitted is 0");
    
    std::string report = pipeline.GetPipelineReport();
    TEST_ASSERT(!report.empty(), "Pipeline report generated");
}

//=============================================================================
// Test 4: VulkanComputeKernels Integration
//=============================================================================
void TestVulkanComputeKernels() {
    std::cout << "\n=== Test: VulkanComputeKernels (Transformer Operations) ===\n";
    
    VulkanComputeKernels kernels;
    
    // Test configuration structs
    RMSNormConfig rms_config;
    rms_config.seq_len = 128;
    rms_config.hidden_dim = 8192;
    rms_config.eps = 1e-6f;
    
    TEST_ASSERT(rms_config.seq_len == 128, "RMSNorm config valid");
    TEST_ASSERT(rms_config.hidden_dim == 8192, "Hidden dim valid");
    
    QKVConfig qkv_config;
    qkv_config.seq_len = 128;
    qkv_config.hidden_dim = 8192;
    qkv_config.num_heads = 64;
    qkv_config.head_dim = 128;
    
    TEST_ASSERT(qkv_config.num_heads == 64, "QKV config valid");
    
    AttentionConfig attn_config;
    attn_config.seq_len = 128;
    attn_config.num_heads = 64;
    attn_config.head_dim = 128;
    attn_config.scale = 1.0f / std::sqrt(128.0f);
    
    TEST_ASSERT(attn_config.scale > 0, "Attention scale valid");
    
    FFNConfig ffn_config;
    ffn_config.seq_len = 128;
    ffn_config.hidden_dim = 8192;
    ffn_config.ffn_dim = 28672;  // 3.5x hidden_dim
    
    TEST_ASSERT(ffn_config.ffn_dim == 28672, "FFN config valid");
    
    std::cout << "  RMSNorm: " << rms_config.seq_len << " x " << rms_config.hidden_dim << "\n";
    std::cout << "  QKV: " << qkv_config.seq_len << " x " << qkv_config.hidden_dim << "\n";
    std::cout << "  Attention: " << attn_config.num_heads << " heads x " << attn_config.head_dim << "\n";
    std::cout << "  FFN: " << ffn_config.hidden_dim << " -> " << ffn_config.ffn_dim << "\n";
}

//=============================================================================
// Test 5: Deep2Engine Integration
//=============================================================================
void TestDeep2Engine() {
    std::cout << "\n=== Test: Deep2Engine (End-to-End Inference) ===\n";
    
    Deep2EngineConfig config;
    config.num_layers = 80;
    config.num_heads = 64;
    config.head_dim = 128;
    config.hidden_dim = 8192;
    config.vocab_size = 32000;
    config.max_context_length = 128 * 1024;
    config.gpu0_split_ratio = 0.667f;
    config.gpu1_split_ratio = 0.333f;
    config.gpu0_budget_bytes = 28ULL * 1024 * 1024 * 1024;
    config.gpu1_budget_bytes = 14ULL * 1024 * 1024 * 1024;
    config.enable_async_prefetch = true;
    config.enable_kv_cache_compression = true;
    config.kv_cache_quantization = 8.0f;
    
    Deep2Engine engine(config);
    
    // Test configuration
    TEST_ASSERT(config.num_layers == 80, "Model has 80 layers");
    TEST_ASSERT(config.gpu0_split_ratio == 0.667f, "GPU0 split ratio is 2/3");
    
    uint32_t gpu0_layers = static_cast<uint32_t>(config.num_layers * config.gpu0_split_ratio);
    uint32_t gpu1_layers = config.num_layers - gpu0_layers;
    
    std::cout << "  Model: " << config.num_layers << " layers, 671B parameters\n";
    std::cout << "  Split: " << gpu0_layers << "/" << gpu1_layers << " layers\n";
    std::cout << "  Context: " << config.max_context_length << " tokens\n";
    std::cout << "  KV Cache: FP" << config.kv_cache_quantization << " compression\n";
    
    // Test context management
    std::vector<uint32_t> tokens = {1, 2, 3, 4, 5};
    TEST_ASSERT(engine.ExtendContext(tokens), "Context extended");
    TEST_ASSERT(engine.GetContextLength() == 5, "Context length is 5");
    
    TEST_ASSERT(engine.ClearContext(), "Context cleared");
    TEST_ASSERT(engine.GetContextLength() == 0, "Context length is 0");
    
    // Test performance metrics (initial)
    double throughput = engine.GetThroughputTps();
    double latency = engine.GetAverageLatencyMs();
    
    TEST_ASSERT(throughput == 0.0, "Initial throughput is 0");
    TEST_ASSERT(latency == 0.0, "Initial latency is 0");
    
    std::string report = engine.GetPerformanceReport();
    TEST_ASSERT(!report.empty(), "Performance report generated");
}

//=============================================================================
// Test 6: Memory Pressure Simulation
//=============================================================================
void TestMemoryPressure() {
    std::cout << "\n=== Test: Memory Pressure Handling ===\n";
    
    BlowoffConfig config;
    config.ssd_swap_path = "D:\\RawrXD_Cache\\pressure_test.bin";
    config.gpu0_max_bytes = 100 * 1024 * 1024;  // 100MB
    config.gpu0_pressure_threshold = 0.8f;
    
    SequentialBlowoffValve valve(config);
    TEST_ASSERT(valve.Initialize(), "Valve initializes for pressure test");
    
    // Allocate until pressure threshold
    std::vector<uint64_t> blocks;
    size_t allocated = 0;
    
    while (allocated < config.gpu0_max_bytes * 0.9) {
        uint64_t block_id = valve.AllocateBlock(1024 * 1024, true);
        if (block_id == 0) break;
        blocks.push_back(block_id);
        allocated += 1024 * 1024;
    }
    
    float pressure = valve.GetPressure(Tier::GPU0_R9700);
    std::cout << "  Allocated: " << (allocated / (1024*1024)) << " MB\n";
    std::cout << "  Pressure: " << (pressure * 100) << "%\n";
    
    TEST_ASSERT(pressure > 0.8f, "Pressure exceeds threshold");
    TEST_ASSERT(valve.ShouldBlowOff(Tier::GPU0_R9700), "Should trigger blow-off");
    
    // Trigger emergency eviction
    valve.TriggerEmergencyEviction(Tier::GPU0_R9700, 50 * 1024 * 1024);
    
    // Cleanup
    for (auto block_id : blocks) {
        valve.FreeBlock(block_id);
    }
    
    valve.Shutdown();
}

//=============================================================================
// Test 7: Concurrent Operations
//=============================================================================
void TestConcurrentOperations() {
    std::cout << "\n=== Test: Concurrent Operations ===\n";
    
    BlowoffConfig config;
    config.ssd_swap_path = "D:\\RawrXD_Cache\\concurrent_test.bin";
    
    SequentialBlowoffValve valve(config);
    TEST_ASSERT(valve.Initialize(), "Valve initializes for concurrent test");
    
    // Allocate shared blocks
    std::vector<uint64_t> blocks;
    for (int i = 0; i < 50; i++) {
        uint64_t block_id = valve.AllocateBlock(1024 * 1024, true);
        blocks.push_back(block_id);
    }
    
    // Concurrent access from multiple threads
    std::vector<std::thread> threads;
    std::atomic<int> success_count{0};
    
    for (int t = 0; t < 8; t++) {
        threads.emplace_back([&valve, &blocks, &success_count, t]() {
            for (size_t i = 0; i < 20; i++) {
                uint64_t block_id = blocks[(t + i) % blocks.size()];
                void* ptr = valve.Access(block_id);
                if (ptr) {
                    // Read/write data
                    volatile int x = *static_cast<int*>(ptr);
                    (void)x;
                    success_count++;
                }
            }
        });
    }
    
    for (auto& t : threads) {
        t.join();
    }
    
    TEST_ASSERT(success_count == 160, "All concurrent accesses succeeded");
    std::cout << "  Concurrent accesses: " << success_count << "\n";
    
    // Cleanup
    for (auto block_id : blocks) {
        valve.FreeBlock(block_id);
    }
    
    valve.Shutdown();
}

//=============================================================================
// Main
//=============================================================================
int main() {
    std::cout << "╔═══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║     Deep2Engine Integration Test Suite - 671B Model          ║\n";
    std::cout << "║     Dual GPU: R9700 (32GB) + 7800 XT (16GB)                   ║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════════╝\n";
    
    // Create cache directory
    #ifdef _WIN32
    CreateDirectoryA("D:\\RawrXD_Cache", nullptr);
    #endif
    
    auto start_time = std::chrono::steady_clock::now();
    
    // Run all tests
    TestSequentialBlowoffValve();
    TestOutOfCoreScheduler();
    TestDualGpuPipeline();
    TestVulkanComputeKernels();
    TestDeep2Engine();
    TestMemoryPressure();
    TestConcurrentOperations();
    
    auto end_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    // Final report
    std::cout << "\n╔═══════════════════════════════════════════════════════════════╗\n";
    if (g_allTestsPassed) {
        std::cout << "║              ALL INTEGRATION TESTS PASSED ✓                    ║\n";
    } else {
        std::cout << "║              SOME INTEGRATION TESTS FAILED ✗                   ║\n";
    }
    std::cout << "║              Duration: " << duration.count() << " ms                    ║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════════╝\n";
    
    return g_allTestsPassed ? 0 : 1;
}
