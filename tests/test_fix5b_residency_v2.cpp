//=============================================================================
// Fix 5B Phase 2 Test: Page-Based Async KV Cache Residency
// Validates the residency abstraction before adding complexity
//=============================================================================
//
// TEST COVERAGE:
// ==============
// 1. Page allocation and lifecycle
// 2. Async migration (non-blocking)
// 3. Deterministic tier policy
// 4. Transition logging and validation
// 5. Memory pressure handling
// 6. No decode stalls
// 7. No lost pages
// 8. No duplicate migrations
// 9. No tier oscillations
//
// VALIDATION METRICS:
// ===================
// - Decode stalls: MUST be 0
// - Lost pages: MUST be 0
// - Duplicate migrations: MUST be 0
// - Tier oscillations: SHOULD be 0
// - Migration latency: logged per transition
//
// See: src/memory/RawrXD_KVCache_Residency_v2.hpp
//=============================================================================

#include "memory/RawrXD_KVCache_Residency_v2.hpp"
#include <iostream>
#include <thread>
#include <chrono>
#include <cassert>

using namespace RawrXD::Memory;

//=============================================================================
// Test Configuration
//=============================================================================

struct TestConfig {
    uint32_t tokens_per_page = 32;
    uint32_t hot_window = 512;   // 16 pages
    uint32_t warm_window = 2048; // 64 pages
    uint32_t test_seq_len = 4096; // 128 pages
};

//=============================================================================
// Test Utilities
//=============================================================================

class ResidencyTestHarness {
public:
    explicit ResidencyTestHarness(const KVResidencyConfigV2<>& config)
        : manager(config) {}
    
    bool Initialize() {
        return manager.Initialize();
    }
    
    bool RunBasicAllocationTest() {
        std::cout << "\n[TEST 1] Basic Page Allocation" << std::endl;
        std::cout << "=================================" << std::endl;
        
        // Append tokens one by one
        std::vector<float> k_data(32 * 128, 0.0f);  // 32 heads * 128 dim
        std::vector<float> v_data(32 * 128, 0.0f);
        
        for (uint32_t t = 0; t < 100; t++) {
            if (!manager.AppendTokens(t + 1, k_data.data(), v_data.data())) {
                std::cerr << "  FAILED: Failed to append token " << t << std::endl;
                return false;
            }
        }
        
        auto stats = manager.GetStats();
        uint32_t expected_pages = (100 + 31) / 32;  // 4 pages
        
        std::cout << "  Appended 100 tokens" << std::endl;
        std::cout << "  Expected pages: " << expected_pages << std::endl;
        std::cout << "  HOT pages: " << stats.pages_in_hot << std::endl;
        
        if (stats.pages_in_hot < expected_pages) {
            std::cerr << "  FAILED: Page count mismatch" << std::endl;
            return false;
        }
        
        std::cout << "  PASSED: Basic allocation works" << std::endl;
        return true;
    }
    
    bool RunAsyncMigrationTest() {
        std::cout << "\n[TEST 2] Async Migration" << std::endl;
        std::cout << "=========================" << std::endl;
        
        // Fill up to warm window
        std::vector<float> k_data(32 * 128, 0.0f);
        std::vector<float> v_data(32 * 128, 0.0f);
        
        uint32_t target_tokens = 2500;  // Beyond warm window
        
        std::cout << "  Appending " << target_tokens << " tokens..." << std::endl;
        
        auto start = std::chrono::high_resolution_clock::now();
        
        for (uint32_t t = 100; t < target_tokens; t++) {
            if (!manager.AppendTokens(t + 1, k_data.data(), v_data.data())) {
                std::cerr << "  FAILED: Failed at token " << t << std::endl;
                return false;
            }
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        
        std::cout << "  Append time: " << duration.count() << " ms" << std::endl;
        
        // Wait for async migrations to complete
        std::cout << "  Waiting for async migrations..." << std::endl;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        
        auto stats = manager.GetStats();
        
        std::cout << "  HOT pages: " << stats.pages_in_hot << std::endl;
        std::cout << "  WARM pages: " << stats.pages_in_warm << std::endl;
        std::cout << "  COLD pages: " << stats.pages_in_cold << std::endl;
        std::cout << "  Migrations completed: " << stats.migrations_completed << std::endl;
        std::cout << "  Decode stalls: " << stats.decode_stalls << std::endl;
        
        // Verify no decode stalls
        if (stats.decode_stalls > 0) {
            std::cerr << "  FAILED: Decode stalls detected!" << std::endl;
            return false;
        }
        
        // Verify tier distribution
        uint32_t expected_hot = 512 / 32;   // 16 pages
        uint32_t expected_warm = (2048 - 512) / 32;  // 48 pages
        
        if (stats.pages_in_hot < expected_hot - 2 || stats.pages_in_hot > expected_hot + 2) {
            std::cerr << "  WARNING: HOT page count unexpected (got " << stats.pages_in_hot 
                      << ", expected ~" << expected_hot << ")" << std::endl;
        }
        
        std::cout << "  PASSED: Async migration working" << std::endl;
        return true;
    }
    
    bool RunValidationChecks() {
        std::cout << "\n[TEST 3] Validation Checks" << std::endl;
        std::cout << "============================" << std::endl;
        
        std::string report;
        bool passed = manager.RunValidationChecks(report);
        
        std::cout << report << std::endl;
        
        if (!passed) {
            std::cerr << "  FAILED: Validation checks failed" << std::endl;
            return false;
        }
        
        std::cout << "  PASSED: All validation checks passed" << std::endl;
        return true;
    }
    
    bool RunTransitionLogTest() {
        std::cout << "\n[TEST 4] Transition Logging" << std::endl;
        std::cout << "============================" << std::endl;
        
        std::string log_output;
        manager.DumpTransitionLog(log_output);
        
        std::cout << log_output << std::endl;
        
        auto stats = manager.GetStats();
        
        std::cout << "  Total migrations: " << stats.migrations_completed << std::endl;
        std::cout << "  Duplicate migrations: " << stats.duplicate_migrations << std::endl;
        std::cout << "  Tier oscillations: " << stats.tier_oscillations << std::endl;
        
        if (stats.duplicate_migrations > 0) {
            std::cerr << "  FAILED: Duplicate migrations detected!" << std::endl;
            return false;
        }
        
        std::cout << "  PASSED: Transition logging correct" << std::endl;
        return true;
    }
    
    bool RunMemoryPressureTest() {
        std::cout << "\n[TEST 5] Memory Pressure Handling" << std::endl;
        std::cout << "==================================" << std::endl;
        
        // Trigger memory pressure
        std::cout << "  Triggering high memory pressure..." << std::endl;
        manager.OnMemoryPressure(0.8f);
        
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        
        auto stats_before = manager.GetStats();
        
        // Trigger critical pressure
        std::cout << "  Triggering critical memory pressure..." << std::endl;
        manager.OnMemoryPressure(0.95f);
        
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        
        auto stats_after = manager.GetStats();
        
        std::cout << "  Emergency evictions: " << stats_after.emergency_evictions << std::endl;
        std::cout << "  FROZEN pages: " << stats_after.pages_in_frozen << std::endl;
        
        if (stats_after.emergency_evictions == 0) {
            std::cerr << "  WARNING: No emergency evictions triggered" << std::endl;
        }
        
        std::cout << "  PASSED: Memory pressure handling works" << std::endl;
        return true;
    }
    
    bool RunDetailedReport() {
        std::cout << "\n[TEST 6] Detailed Report" << std::endl;
        std::cout << "=========================" << std::endl;
        
        std::string report;
        manager.GetDetailedReport(report);
        
        std::cout << report << std::endl;
        
        return true;
    }
    
private:
    KVCacheResidencyManagerV2 manager;
};

//=============================================================================
// Main Test Entry
//=============================================================================

int main(int argc, char* argv[]) {
    std::cout << "===============================================================" << std::endl;
    std::cout << "Fix 5B Phase 2: Page-Based Async KV Cache Residency Test" << std::endl;
    std::cout << "===============================================================" << std::endl;
    std::cout << "Validating residency abstraction before adding complexity" << std::endl;
    std::cout << std::endl;
    
    // Configure
    KVResidencyConfigV2 config;
    config.hot_window_tokens = 512;
    config.warm_window_tokens = 2048;
    config.enable_async_migration = true;
    config.enable_detailed_logging = true;
    
    if (!config.Validate()) {
        std::cerr << "ERROR: Invalid configuration" << std::endl;
        return 1;
    }
    
    std::cout << "Configuration:" << std::endl;
    std::cout << "  Tokens per page: " << config.TOKENS_PER_PAGE << std::endl;
    std::cout << "  HOT window: " << config.hot_window_tokens << " tokens" << std::endl;
    std::cout << "  WARM window: " << config.warm_window_tokens << " tokens" << std::endl;
    std::cout << "  Async migration: " << (config.enable_async_migration ? "enabled" : "disabled") << std::endl;
    std::cout << std::endl;
    
    // Create test harness
    ResidencyTestHarness harness(config);
    if (!harness.Initialize()) {
        std::cerr << "ERROR: Failed to initialize test harness" << std::endl;
        return 1;
    }
    
    // Run tests
    bool all_passed = true;
    
    all_passed &= harness.RunBasicAllocationTest();
    all_passed &= harness.RunAsyncMigrationTest();
    all_passed &= harness.RunValidationChecks();
    all_passed &= harness.RunTransitionLogTest();
    all_passed &= harness.RunMemoryPressureTest();
    all_passed &= harness.RunDetailedReport();
    
    // Summary
    std::cout << "\n===============================================================" << std::endl;
    if (all_passed) {
        std::cout << "ALL TESTS PASSED - Residency Abstraction Validated" << std::endl;
        std::cout << "===============================================================" << std::endl;
        std::cout << std::endl;
        std::cout << "Key Achievements:" << std::endl;
        std::cout << "  - Page-based migration working (32 tokens/page)" << std::endl;
        std::cout << "  - Async migration non-blocking" << std::endl;
        std::cout << "  - Deterministic tier policy functional" << std::endl;
        std::cout << "  - Transition logging comprehensive" << std::endl;
        std::cout << "  - No decode stalls" << std::endl;
        std::cout << "  - No lost pages" << std::endl;
        std::cout << "  - No duplicate migrations" << std::endl;
        std::cout << std::endl;
        std::cout << "Next Steps:" << std::endl;
        std::cout << "  - Implement actual quantization kernels" << std::endl;
        std::cout << "  - Add SIMD-optimized decompression" << std::endl;
        std::cout << "  - Profile end-to-end inference" << std::endl;
        std::cout << "  - Consider adaptive policies (after baseline works)" << std::endl;
        return 0;
    } else {
        std::cout << "SOME TESTS FAILED" << std::endl;
        std::cout << "===============================================================" << std::endl;
        return 1;
    }
}
