// =============================================================================
// SovereignTest_NEVMP.cpp - NEVMP Format Integration Tests
// Validates the complete pipeline: Generator -> TensorPatchManager -> Titan
// =============================================================================

#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <random>
#include <chrono>

#include "../src/sovereign/patcher/NEVMP.hpp"
#include "../src/sovereign/patcher/TensorPatchManager.hpp"

using namespace RawrXD::Sovereign;

// =============================================================================
// Test Utilities
// =============================================================================

struct TestResult {
    const char* name;
    bool passed;
    double duration_ms;
    std::string details;
};

std::vector<TestResult> g_results;

#define TEST(name) \
    auto _test_start = std::chrono::high_resolution_clock::now(); \
    bool _test_passed = true; \
    std::string _test_details; \
    try {

#define END_TEST(name) \
    } catch (const std::exception& e) { \
        _test_passed = false; \
        _test_details = e.what(); \
    } \
    auto _test_end = std::chrono::high_resolution_clock::now(); \
    double _test_duration = std::chrono::duration<double, std::milli>(_test_end - _test_start).count(); \
    g_results.push_back({name, _test_passed, _test_duration, _test_details}); \
    std::cout << "[" << (_test_passed ? "PASS" : "FAIL") << "] " << name \
              << " (" << _test_duration << " ms)" << std::endl;

#define ASSERT_TRUE(cond) \
    if (!(cond)) { \
        _test_passed = false; \
        _test_details = "Assertion failed: " #cond; \
        throw std::runtime_error(_test_details); \
    }

#define ASSERT_EQ(a, b) \
    if ((a) != (b)) { \
        _test_passed = false; \
        _test_details = "Expected equality: " #a " == " #b; \
        throw std::runtime_error(_test_details); \
    }

// =============================================================================
// Test 1: Header Validation
// =============================================================================

void Test_HeaderValidation() {
    TEST("Header_Validation")
    
    NEVMP_Header header;
    std::memset(&header, 0, sizeof(header));
    
    // Invalid magic
    header.magic = 0xDEADBEEF;
    header.version = NEVMP_VERSION;
    header.vector_count = 10;
    header.payload_size = 80;  // 10 * sizeof(double)
    ASSERT_TRUE(!header.IsValid());
    
    // Invalid version
    header.magic = NEVMP_MAGIC;
    header.version = 0x99999999;
    ASSERT_TRUE(!header.IsValid());
    
    // Invalid payload size
    header.version = NEVMP_VERSION;
    header.vector_count = 10;
    header.payload_size = 0;
    ASSERT_TRUE(!header.IsValid());
    
    // Valid header
    header.payload_size = 80;
    ASSERT_TRUE(header.IsValid());
    
    END_TEST("Header_Validation")
}

// =============================================================================
// Test 2: Checksum Calculation
// =============================================================================

void Test_ChecksumCalculation() {
    TEST("Checksum_Calculation")
    
    // Test data
    std::vector<uint8_t> data = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    
    uint64_t checksum1 = NEVMP_Header::CalculateChecksum(data.data(), data.size());
    uint64_t checksum2 = NEVMP_Header::CalculateChecksum(data.data(), data.size());
    
    // Checksum should be deterministic
    ASSERT_EQ(checksum1, checksum2);
    
    // Different data should produce different checksum
    data[0] = 0xFF;
    uint64_t checksum3 = NEVMP_Header::CalculateChecksum(data.data(), data.size());
    ASSERT_TRUE(checksum1 != checksum3);
    
    END_TEST("Checksum_Calculation")
}

// =============================================================================
// Test 3: Patch Structure
// =============================================================================

void Test_PatchStructure() {
    TEST("Patch_Structure")
    
    // Verify sizes
    ASSERT_EQ(sizeof(NEVMP_Header), 64);
    ASSERT_EQ(alignof(NEVMP_Header), 64);
    
    // Create a mock patch
    std::vector<uint8_t> buffer(sizeof(NEVMP_Header) + 80);  // Header + 10 doubles
    NEVMP_Patch* patch = reinterpret_cast<NEVMP_Patch*>(buffer.data());
    
    patch->header.magic = NEVMP_MAGIC;
    patch->header.version = NEVMP_VERSION;
    patch->header.vector_count = 10;
    patch->header.payload_size = 80;
    
    // Verify payload access
    double* payload = patch->GetPayload();
    ASSERT_TRUE(payload != nullptr);
    
    // Write to payload
    for (int i = 0; i < 10; ++i) {
        payload[i] = static_cast<double>(i);
    }
    
    // Read back
    for (int i = 0; i < 10; ++i) {
        ASSERT_EQ(payload[i], static_cast<double>(i));
    }
    
    END_TEST("Patch_Structure")
}

// =============================================================================
// Test 4: TensorPatchManager Initialization
// =============================================================================

void Test_TensorPatchManager_Init() {
    TEST("TensorPatchManager_Initialization")
    
    TensorPatchManager manager;
    
    // Initialize without telemetry
    ASSERT_TRUE(manager.Initialize(nullptr));
    ASSERT_TRUE(manager.GetCurrentEpoch() == 0);
    ASSERT_TRUE(manager.GetActivePatchCount() == 0);
    
    manager.Shutdown();
    
    END_TEST("TensorPatchManager_Initialization")
}

// =============================================================================
// Test 5: Patch Registration and Resolution
// =============================================================================

void Test_PatchRegistration() {
    TEST("Patch_Registration_Resolution")
    
    TensorPatchManager manager;
    ASSERT_TRUE(manager.Initialize(nullptr));
    
    // Create a test patch
    std::vector<uint8_t> patch_data(sizeof(NEVMP_Header) + 80);
    NEVMP_Patch* patch = reinterpret_cast<NEVMP_Patch*>(patch_data.data());
    
    patch->header.magic = NEVMP_MAGIC;
    patch->header.version = NEVMP_VERSION;
    patch->header.epoch_id = 1;
    patch->header.vector_count = 10;
    patch->header.payload_size = 80;
    patch->header.target_addr = 0xDEADBEEFCAFE0000;
    
    // Fill payload with test data
    double* payload = patch->GetPayload();
    for (int i = 0; i < 10; ++i) {
        payload[i] = static_cast<double>(i * 3.14159);
    }
    
    // Calculate checksum
    patch->header.checksum = NEVMP_Header::CalculateChecksum(payload, 80);
    
    // Register patch
    NEVMP_Status status = manager.RegisterPatch(patch_data.data(), patch_data.size());
    ASSERT_EQ(status, NEVMP_Status::OK);
    
    // Verify registration
    ASSERT_EQ(manager.GetActivePatchCount(), 1);
    ASSERT_EQ(manager.GetTotalPatchCount(), 1);
    ASSERT_EQ(manager.GetCurrentEpoch(), 1);
    
    // Resolve patch
    ResolvedPatch resolved;
    ASSERT_TRUE(manager.Resolve(0xDEADBEEFCAFE0000, resolved));
    ASSERT_TRUE(resolved.valid);
    ASSERT_EQ(resolved.vector_count, 10);
    ASSERT_EQ(resolved.epoch, 1);
    ASSERT_EQ(resolved.target_addr, 0xDEADBEEFCAFE0000);
    
    // Verify payload data
    for (int i = 0; i < 10; ++i) {
        ASSERT_EQ(resolved.delta_payload[i], static_cast<double>(i * 3.14159));
    }
    
    manager.Shutdown();
    
    END_TEST("Patch_Registration_Resolution")
}

// =============================================================================
// Test 6: Epoch Versioning (Stale Patch Rejection)
// =============================================================================

void Test_EpochVersioning() {
    TEST("Epoch_Versioning")
    
    TensorPatchManager manager;
    ASSERT_TRUE(manager.Initialize(nullptr));
    
    // Create first patch (epoch 1)
    std::vector<uint8_t> patch1_data(sizeof(NEVMP_Header) + 80);
    NEVMP_Patch* patch1 = reinterpret_cast<NEVMP_Patch*>(patch1_data.data());
    patch1->header.magic = NEVMP_MAGIC;
    patch1->header.version = NEVMP_VERSION;
    patch1->header.epoch_id = 1;
    patch1->header.vector_count = 10;
    patch1->header.payload_size = 80;
    patch1->header.target_addr = 0xTARGET0000000001;
    patch1->header.checksum = NEVMP_Header::CalculateChecksum(patch1->GetPayload(), 80);
    
    ASSERT_EQ(manager.RegisterPatch(patch1_data.data(), patch1_data.size()), NEVMP_Status::OK);
    
    // Try to register stale patch (epoch 0)
    std::vector<uint8_t> patch0_data(sizeof(NEVMP_Header) + 80);
    NEVMP_Patch* patch0 = reinterpret_cast<NEVMP_Patch*>(patch0_data.data());
    patch0->header.magic = NEVMP_MAGIC;
    patch0->header.version = NEVMP_VERSION;
    patch0->header.epoch_id = 0;  // Stale!
    patch0->header.vector_count = 10;
    patch0->header.payload_size = 80;
    patch0->header.target_addr = 0xTARGET0000000001;
    patch0->header.checksum = NEVMP_Header::CalculateChecksum(patch0->GetPayload(), 80);
    
    NEVMP_Status status = manager.RegisterPatch(patch0_data.data(), patch0_data.size());
    ASSERT_EQ(status, NEVMP_Status::ERR_INVALID_VERSION);
    
    // Register newer patch (epoch 2)
    std::vector<uint8_t> patch2_data(sizeof(NEVMP_Header) + 80);
    NEVMP_Patch* patch2 = reinterpret_cast<NEVMP_Patch*>(patch2_data.data());
    patch2->header.magic = NEVMP_MAGIC;
    patch2->header.version = NEVMP_VERSION;
    patch2->header.epoch_id = 2;
    patch2->header.vector_count = 10;
    patch2->header.payload_size = 80;
    patch2->header.target_addr = 0xTARGET0000000001;
    patch2->header.checksum = NEVMP_Header::CalculateChecksum(patch2->GetPayload(), 80);
    
    ASSERT_EQ(manager.RegisterPatch(patch2_data.data(), patch2_data.size()), NEVMP_Status::OK);
    
    // Verify epoch updated
    ASSERT_EQ(manager.GetCurrentEpoch(), 2);
    
    manager.Shutdown();
    
    END_TEST("Epoch_Versioning")
}

// =============================================================================
// Test 7: Performance Benchmark (Hot Path)
// =============================================================================

void Test_PerformanceBenchmark() {
    TEST("Performance_Benchmark")
    
    TensorPatchManager manager;
    ASSERT_TRUE(manager.Initialize(nullptr));
    
    // Register multiple patches
    const int NUM_PATCHES = 100;
    std::vector<std::vector<uint8_t>> patch_data(NUM_PATCHES);
    
    for (int i = 0; i < NUM_PATCHES; ++i) {
        patch_data[i].resize(sizeof(NEVMP_Header) + 80);
        NEVMP_Patch* patch = reinterpret_cast<NEVMP_Patch*>(patch_data[i].data());
        
        patch->header.magic = NEVMP_MAGIC;
        patch->header.version = NEVMP_VERSION;
        patch->header.epoch_id = i + 1;
        patch->header.vector_count = 10;
        patch->header.payload_size = 80;
        patch->header.target_addr = 0x1000000000000000ULL + i;
        patch->header.checksum = NEVMP_Header::CalculateChecksum(patch->GetPayload(), 80);
        
        ASSERT_EQ(manager.RegisterPatch(patch_data[i].data(), patch_data[i].size()), 
                 NEVMP_Status::OK);
    }
    
    // Benchmark resolution
    const int ITERATIONS = 100000;
    auto start = std::chrono::high_resolution_clock::now();
    
    ResolvedPatch resolved;
    for (int i = 0; i < ITERATIONS; ++i) {
        uint64_t target = 0x1000000000000000ULL + (i % NUM_PATCHES);
        manager.Resolve(target, resolved);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    double total_ms = std::chrono::duration<double, std::milli>(end - start).count();
    double ns_per_lookup = (total_ms * 1000000.0) / ITERATIONS;
    
    std::cout << "    " << ITERATIONS << " lookups in " << total_ms << " ms" << std::endl;
    std::cout << "    " << ns_per_lookup << " ns per lookup" << std::endl;
    
    // Should be sub-nanosecond on average
    ASSERT_TRUE(ns_per_lookup < 100.0);  // Less than 100ns
    
    manager.Shutdown();
    
    END_TEST("Performance_Benchmark")
}

// =============================================================================
// Main
// =============================================================================

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "NEVMP Format Integration Tests" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    
    // Run all tests
    Test_HeaderValidation();
    Test_ChecksumCalculation();
    Test_PatchStructure();
    Test_TensorPatchManager_Init();
    Test_PatchRegistration();
    Test_EpochVersioning();
    Test_PerformanceBenchmark();
    
    // Summary
    std::cout << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Test Summary" << std::endl;
    std::cout << "========================================" << std::endl;
    
    int passed = 0;
    int failed = 0;
    double total_time = 0.0;
    
    for (const auto& result : g_results) {
        total_time += result.duration_ms;
        if (result.passed) {
            ++passed;
        } else {
            ++failed;
            std::cout << "[FAIL] " << result.name << ": " << result.details << std::endl;
        }
    }
    
    std::cout << "Total: " << g_results.size() << " tests" << std::endl;
    std::cout << "Passed: " << passed << std::endl;
    std::cout << "Failed: " << failed << std::endl;
    std::cout << "Total time: " << total_time << " ms" << std::endl;
    
    return failed == 0 ? 0 : 1;
}
