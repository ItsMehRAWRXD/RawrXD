//============================================================================
// nevm_test_harness.cpp
// RawrXD N-EVM v0.2 - Minimal Test Harness
// Validates N-EVM execution path without requiring full model
//============================================================================

#include "nevm_v2.hpp"
#include "nevm_kernels.hpp"
#include "nevm_mmu.hpp"
#include <iostream>
#include <iomanip>
#include <cmath>

using namespace RawrXD::NEVM;

//============================================================================
// Test Results
//============================================================================

struct TestResult {
    const char* name;
    bool passed;
    double duration_ms;
    const char* details;
};

std::vector<TestResult> results;
int tests_passed = 0;
int tests_failed = 0;

//============================================================================
// Test Macros
//============================================================================

#define TEST(name) bool Test_##name()
#define RUN_TEST(name) RunTest(#name, Test_##name)

void RunTest(const char* name, bool (*test_func)()) {
    auto start = std::chrono::high_resolution_clock::now();
    bool passed = test_func();
    auto end = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    double ms = duration.count() / 1000.0;
    
    results.push_back({name, passed, ms, passed ? "OK" : "FAILED"});
    
    if (passed) {
        tests_passed++;
        std::cout << "[PASS] " << std::left << std::setw(40) << name 
                  << " (" << std::fixed << std::setprecision(3) << ms << " ms)\n";
    } else {
        tests_failed++;
        std::cout << "[FAIL] " << name << "\n";
    }
}

#define ASSERT_TRUE(cond) if (!(cond)) { \
    std::cerr << "    Assertion failed: " #cond " at line " << __LINE__ << "\n"; \
    return false; \
}

#define ASSERT_EQ(a, b) if ((a) != (b)) { \
    std::cerr << "    Assertion failed: " #a " == " #b " at line " << __LINE__ << "\n"; \
    std::cerr << "    Expected: " << (b) << ", Got: " << (a) << "\n"; \
    return false; \
}

#define ASSERT_NEAR(a, b, eps) if (std::abs((a) - (b)) > (eps)) { \
    std::cerr << "    Assertion failed: |" #a " - " #b "| < " #eps " at line " << __LINE__ << "\n"; \
    std::cerr << "    Expected: " << (b) << ", Got: " << (a) << ", Diff: " << std::abs((a) - (b)) << "\n"; \
    return false; \
}

//============================================================================
// Test: VTA Address Encoding/Decoding
//============================================================================

TEST(VTA_Encoding) {
    // Test VTA encoding
    uint64_t vta = EncodeVTA(5, 2, 100, 2048);
    
    ASSERT_EQ(ExtractLayer(vta), 5);
    ASSERT_EQ(ExtractTensorType(vta), 2);
    ASSERT_EQ(ExtractBlockIdx(vta), 100);
    ASSERT_EQ(ExtractOffset(vta), 2048);
    
    // Test boundary values
    vta = EncodeVTA(255, 255, 65535, 4294967295ULL);
    ASSERT_EQ(ExtractLayer(vta), 255);
    ASSERT_EQ(ExtractTensorType(vta), 255);
    ASSERT_EQ(ExtractBlockIdx(vta), 65535);
    ASSERT_EQ(ExtractOffset(vta), 4294967295ULL);
    
    return true;
}

//============================================================================
// Test: Neural MMU Basic Operations
//============================================================================

TEST(MMU_Basic) {
    NeuralMMU::Config config;
    config.ram_budget = 1024 * 1024 * 1024;  // 1GB
    config.vram_budget = 256 * 1024 * 1024;  // 256MB
    
    NeuralMMU mmu(config);
    
    // Test translation (should fail - no mapping yet)
    uint64_t test_vta = EncodeVTA(0, 1, 0, 0);
    void* ptr = mmu.Translate(test_vta, 1024, MemoryResidency::RAM);
    ASSERT_TRUE(ptr == nullptr);
    
    // Test stats
    auto stats = mmu.GetStats();
    ASSERT_EQ(stats.ram_allocated, 0);
    ASSERT_EQ(stats.vram_allocated, 0);
    
    return true;
}

//============================================================================
// Test: Precision Controller
//============================================================================

TEST(PrecisionController) {
    PrecisionController::Config config;
    config.default_mode = PrecisionMode::Q4;
    config.enable_adaptive = true;
    
    PrecisionController pc(config);
    
    // Test default precision
    ASSERT_EQ(pc.GetCurrentMode(), PrecisionMode::Q4);
    
    // Test mode switching
    pc.SetMode(PrecisionMode::Q8);
    ASSERT_EQ(pc.GetCurrentMode(), PrecisionMode::Q8);
    
    pc.SetMode(PrecisionMode::FP16);
    ASSERT_EQ(pc.GetCurrentMode(), PrecisionMode::FP16);
    
    return true;
}

//============================================================================
// Test: Residency State Machine
//============================================================================

TEST(ResidencyStateMachine) {
    ResidencyStateMachine rsm;
    
    // Test valid transitions
    ASSERT_TRUE(rsm.CanTransition(ResidencyState::COLD, ResidencyState::MAPPED));
    ASSERT_TRUE(rsm.CanTransition(ResidencyState::MAPPED, ResidencyState::RAM));
    ASSERT_TRUE(rsm.CanTransition(ResidencyState::RAM, ResidencyState::VRAM));
    
    // Test invalid transitions
    ASSERT_FALSE(rsm.CanTransition(ResidencyState::COLD, ResidencyState::VRAM));
    ASSERT_FALSE(rsm.CanTransition(ResidencyState::VRAM, ResidencyState::COLD));
    
    // Test state names
    ASSERT_TRUE(std::string(GetResidencyStateName(ResidencyState::COLD)) == "COLD");
    ASSERT_TRUE(std::string(GetResidencyStateName(ResidencyState::RAM)) == "RAM");
    
    return true;
}

//============================================================================
// Test: NEVM v2 Initialization
//============================================================================

TEST(NEVM_Initialization) {
    NEVM_v2::Config config;
    config.ram_budget = 64ULL * 1024 * 1024 * 1024;
    config.vram_budget = 16ULL * 1024 * 1024 * 1024;
    config.enable_adaptive_precision = true;
    config.enable_prefetch = true;
    config.enable_tracing = false;
    
    NEVM_v2 vm(config);
    
    ASSERT_TRUE(vm.Initialize());
    
    // Verify components created
    ASSERT_TRUE(vm.GetMMU() != nullptr);
    ASSERT_TRUE(vm.GetPrecisionController() != nullptr);
    ASSERT_TRUE(vm.GetPrefetchEngine() != nullptr);
    ASSERT_TRUE(vm.GetResidencyManager() != nullptr);
    ASSERT_TRUE(vm.GetBlockPrecisionController() != nullptr);
    
    // Verify version
    ASSERT_TRUE(std::string(vm.GetVersion()).find("NEVM") != std::string::npos);
    
    return true;
}

//============================================================================
// Test: Kernel Primitives (if available)
//============================================================================

TEST(Kernel_Q4Dequantize) {
    // Test Q4 dequantization
    // Pack 2 4-bit values into 1 byte
    uint8_t packed = 0xAB;  // High nibble = A (10), Low nibble = B (11)
    
    float scale = 0.1f;
    float min_val = -1.0f;
    
    // Dequantize high nibble
    float val_high = DequantizeQ4((packed >> 4) & 0xF, scale, min_val);
    // Dequantize low nibble  
    float val_low = DequantizeQ4(packed & 0xF, scale, min_val);
    
    // Just verify they're in reasonable range
    ASSERT_TRUE(val_high > -2.0f && val_high < 2.0f);
    ASSERT_TRUE(val_low > -2.0f && val_low < 2.0f);
    
    return true;
}

//============================================================================
// Test: Block Granular Precision
//============================================================================

TEST(BlockGranularPrecision) {
    BlockGranularPrecisionController::Config config;
    BlockGranularPrecisionController bgpc(config);
    
    // Create a test block
    uint64_t block_vta = EncodeVTA(0, 1, 0, 0);
    
    // Add states
    bgpc.AddState(block_vta, PrecisionMode::Q4, 0.01f);
    bgpc.AddState(block_vta, PrecisionMode::Q8, 0.005f);
    
    // Select based on tolerance
    auto selected = bgpc.SelectState(block_vta, 0.008f);
    ASSERT_EQ(selected.mode, PrecisionMode::Q8);
    
    selected = bgpc.SelectState(block_vta, 0.02f);
    ASSERT_EQ(selected.mode, PrecisionMode::Q4);
    
    return true;
}

//============================================================================
// Test: Trace System
//============================================================================

TEST(TraceSystem) {
    TraceRecorder::Config config;
    TraceRecorder recorder(config);
    
    // Start recording
    ASSERT_TRUE(recorder.StartRecording(0));
    ASSERT_TRUE(recorder.IsRecording());
    
    // Record some events
    recorder.RecordEvent(TraceEventType::TOKEN_GENERATED, 0, 0.5f);
    recorder.RecordEvent(TraceEventType::LAYER_START, 1, 0.0f);
    recorder.RecordEvent(TraceEventType::LAYER_END, 1, 1.0f);
    
    // Stop recording
    recorder.StopRecording();
    ASSERT_FALSE(recorder.IsRecording());
    
    // Get stats
    auto stats = recorder.GetStats();
    ASSERT_EQ(stats.event_count, 3);
    ASSERT_EQ(stats.token_count, 1);
    
    return true;
}

//============================================================================
// Test: Math Utilities
//============================================================================

TEST(Math_Utilities) {
    // Test RoPE angle calculation
    float angle = CalculateRoPEAngle(0, 0, 64);
    ASSERT_NEAR(angle, 0.0f, 0.0001f);
    
    angle = CalculateRoPEAngle(1, 0, 64);
    ASSERT_TRUE(angle > 0.0f);
    
    // Test SwiGLU
    float swiglu = SwiGLU(1.0f, 0.5f);
    float expected = 1.0f * 0.5f * (1.0f / (1.0f + std::exp(-1.0f)));
    ASSERT_NEAR(swiglu, expected, 0.0001f);
    
    // Test SoftMax
    float input[4] = {1.0f, 2.0f, 3.0f, 4.0f};
    float output[4];
    SoftMax(input, output, 4);
    
    // Verify probabilities sum to 1
    float sum = output[0] + output[1] + output[2] + output[3];
    ASSERT_NEAR(sum, 1.0f, 0.0001f);
    
    // Verify ordering preserved
    ASSERT_TRUE(output[3] > output[2]);
    ASSERT_TRUE(output[2] > output[1]);
    ASSERT_TRUE(output[1] > output[0]);
    
    return true;
}

//============================================================================
// Test: Memory Pool
//============================================================================

TEST(MemoryPool) {
    MemoryPool pool;
    
    // Initialize pool
    ASSERT_TRUE(pool.Initialize(1024 * 1024, MemoryResidency::RAM));
    
    // Allocate blocks
    void* block1 = pool.AllocateBlock(4096);
    ASSERT_TRUE(block1 != nullptr);
    
    void* block2 = pool.AllocateBlock(4096);
    ASSERT_TRUE(block2 != nullptr);
    
    // Free blocks
    pool.FreeBlock(block1);
    pool.FreeBlock(block2);
    
    return true;
}

//============================================================================
// Main
//============================================================================

int main() {
    std::cout << "============================================================================\n";
    std::cout << "RawrXD N-EVM v0.2 Test Harness\n";
    std::cout << "============================================================================\n\n";
    
    auto total_start = std::chrono::high_resolution_clock::now();
    
    // Run all tests
    RUN_TEST(VTA_Encoding);
    RUN_TEST(MMU_Basic);
    RUN_TEST(PrecisionController);
    RUN_TEST(ResidencyStateMachine);
    RUN_TEST(NEVM_Initialization);
    RUN_TEST(Kernel_Q4Dequantize);
    RUN_TEST(BlockGranularPrecision);
    RUN_TEST(TraceSystem);
    RUN_TEST(Math_Utilities);
    RUN_TEST(MemoryPool);
    
    auto total_end = std::chrono::high_resolution_clock::now();
    auto total_duration = std::chrono::duration_cast<std::chrono::milliseconds>(total_end - total_start);
    
    // Summary
    std::cout << "\n============================================================================\n";
    std::cout << "Test Summary\n";
    std::cout << "============================================================================\n";
    std::cout << "Total:  " << (tests_passed + tests_failed) << " tests\n";
    std::cout << "Passed: " << tests_passed << " tests\n";
    std::cout << "Failed: " << tests_failed << " tests\n";
    std::cout << "Time:   " << total_duration.count() << " ms\n";
    std::cout << "============================================================================\n";
    
    if (tests_failed > 0) {
        std::cout << "\nFAILED TESTS:\n";
        for (const auto& r : results) {
            if (!r.passed) {
                std::cout << "  - " << r.name << ": " << r.details << "\n";
            }
        }
        return 1;
    }
    
    std::cout << "\nAll tests passed!\n";
    return 0;
}
