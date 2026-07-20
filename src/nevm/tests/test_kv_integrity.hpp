//============================================================================
// test_kv_integrity.hpp
// RawrXD N-EVM - KV Integrity Unit Tests
//============================================================================

#pragma once

#include "test_framework.hpp"
#include "../nevm_kv_integrity.hpp"

namespace RawrXD {
namespace NEVM {
namespace Tests {

//============================================================================
// KV Integrity Tests
//============================================================================

TestResult KVIntegrityTests_ChecksumBasic() {
    std::vector<float> data = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f};
    
    uint64_t checksum1 = ChecksumCalculator::CalculateFletcher64(
        reinterpret_cast<const uint8_t*>(data.data()), 
        data.size() * sizeof(float));
    
    uint64_t checksum2 = ChecksumCalculator::CalculateFletcher64(
        reinterpret_cast<const uint8_t*>(data.data()), 
        data.size() * sizeof(float));
    
    // Same data should produce same checksum
    TEST_ASSERT_EQ(checksum1, checksum2);
    TEST_ASSERT_NE(0ULL, checksum1);  // Should not be zero
    
    TEST_SUCCESS();
}

TestResult KVIntegrityTests_ChecksumDifferentData() {
    std::vector<float> data1 = {1.0f, 2.0f, 3.0f};
    std::vector<float> data2 = {1.0f, 2.0f, 3.1f};  // Slightly different
    
    uint64_t checksum1 = ChecksumCalculator::CalculateFletcher64(
        reinterpret_cast<const uint8_t*>(data1.data()), 
        data1.size() * sizeof(float));
    
    uint64_t checksum2 = ChecksumCalculator::CalculateFletcher64(
        reinterpret_cast<const uint8_t*>(data2.data()), 
        data2.size() * sizeof(float));
    
    // Different data should produce different checksums
    TEST_ASSERT_NE(checksum1, checksum2);
    
    TEST_SUCCESS();
}

TestResult KVIntegrityTests_TrackerBasic() {
    KVIntegrityTracker tracker;
    
    // Record a page
    std::vector<float> data = {1.0f, 2.0f, 3.0f, 4.0f};
    uint64_t checksum = ChecksumCalculator::CalculateFletcher64(
        reinterpret_cast<const uint8_t*>(data.data()), 
        data.size() * sizeof(float));
    
    tracker.RecordPageChecksum(0, 0, 0, checksum);
    
    // Verify the page
    bool valid = tracker.VerifyPageChecksum(0, 0, 0, checksum);
    TEST_ASSERT_EQ(true, valid);
    
    // Verify with wrong checksum should fail
    bool invalid = tracker.VerifyPageChecksum(0, 0, 0, checksum + 1);
    TEST_ASSERT_EQ(false, invalid);
    
    TEST_SUCCESS();
}

TestResult KVIntegrityTests_TrackerMultiplePages() {
    KVIntegrityTracker tracker;
    
    // Record multiple pages
    for (uint32_t layer = 0; layer < 3; ++layer) {
        for (uint32_t pos = 0; pos < 10; ++pos) {
            uint64_t checksum = layer * 1000 + pos;  // Fake checksum
            tracker.RecordPageChecksum(layer, pos, 0, checksum);
        }
    }
    
    // Verify all pages
    for (uint32_t layer = 0; layer < 3; ++layer) {
        for (uint32_t pos = 0; pos < 10; ++pos) {
            uint64_t expected = layer * 1000 + pos;
            bool valid = tracker.VerifyPageChecksum(layer, pos, 0, expected);
            TEST_ASSERT_EQ(true, valid);
        }
    }
    
    TEST_SUCCESS();
}

TestResult KVIntegrityTests_MigrationGuard() {
    KVMigrationGuard guard;
    
    // Start migration
    guard.StartMigration(0, 0, 0, 100);
    
    // Should be in progress
    TEST_ASSERT_EQ(true, guard.IsMigrationInProgress());
    
    // Complete migration
    guard.CompleteMigration(true);
    
    // Should not be in progress
    TEST_ASSERT_EQ(false, guard.IsMigrationInProgress());
    
    TEST_SUCCESS();
}

TestResult KVIntegrityTests_MigrationGuardFailure() {
    KVMigrationGuard guard;
    
    // Start migration
    guard.StartMigration(0, 0, 0, 100);
    
    // Fail migration
    guard.CompleteMigration(false);
    
    // Should have error
    TEST_ASSERT_EQ(true, guard.HasError());
    
    auto error = guard.GetLastError();
    TEST_ASSERT_EQ(false, error.success);
    
    TEST_SUCCESS();
}

TestResult KVIntegrityTests_CorruptionDetection() {
    KVIntegrityTracker tracker;
    
    // Record original data
    std::vector<float> original = {1.0f, 2.0f, 3.0f, 4.0f};
    uint64_t checksum = ChecksumCalculator::CalculateFletcher64(
        reinterpret_cast<const uint8_t*>(original.data()), 
        original.size() * sizeof(float));
    
    tracker.RecordPageChecksum(0, 0, 0, checksum);
    
    // Simulate corruption
    std::vector<float> corrupted = {1.0f, 2.0f, 3.0f, 4.1f};  // Changed last value
    uint64_t corrupted_checksum = ChecksumCalculator::CalculateFletcher64(
        reinterpret_cast<const uint8_t*>(corrupted.data()), 
        corrupted.size() * sizeof(float));
    
    // Verify should detect corruption
    bool valid = tracker.VerifyPageChecksum(0, 0, 0, corrupted_checksum);
    TEST_ASSERT_EQ(false, valid);
    
    TEST_SUCCESS();
}

//============================================================================
// Registration
//============================================================================

void RegisterKVIntegrityTests(TestFramework& framework) {
    REGISTER_TEST(framework, KVIntegrityTests, ChecksumBasic);
    REGISTER_TEST(framework, KVIntegrityTests, ChecksumDifferentData);
    REGISTER_TEST(framework, KVIntegrityTests, TrackerBasic);
    REGISTER_TEST(framework, KVIntegrityTests, TrackerMultiplePages);
    REGISTER_TEST(framework, KVIntegrityTests, MigrationGuard);
    REGISTER_TEST(framework, KVIntegrityTests, MigrationGuardFailure);
    REGISTER_TEST(framework, KVIntegrityTests, CorruptionDetection);
}

} // namespace Tests
} // namespace NEVM
} // namespace RawrXD
