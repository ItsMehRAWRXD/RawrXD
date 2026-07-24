//============================================================================
// test_kv_integrity.cpp
// RawrXD N-EVM - Unit Tests for KV Cache Integrity
//============================================================================

#include "../nevm_kv_integrity.hpp"

using namespace RawrXD::NEVM;

TEST(KVIntegrity_ChecksumCalculator) {
    // Test basic checksum calculation
    uint8_t data[] = {0x01, 0x02, 0x03, 0x04, 0x05};
    uint64_t hash1 = ChecksumCalculator::Calculate(data, 5, 0);
    uint64_t hash2 = ChecksumCalculator::Calculate(data, 5, 0);
    
    // Same data should produce same hash
    ASSERT_EQ(hash1, hash2);
    
    // Different data should produce different hash
    uint8_t data2[] = {0x01, 0x02, 0x03, 0x04, 0x06};
    uint64_t hash3 = ChecksumCalculator::Calculate(data2, 5, 0);
    ASSERT_NE(hash1, hash3);
    
    // Different seed should produce different hash
    uint64_t hash4 = ChecksumCalculator::Calculate(data, 5, 12345);
    ASSERT_NE(hash1, hash4);
    
    return true;
}

TEST(KVIntegrity_KVPageIntegrity) {
    KVPageIntegrity integrity;
    integrity.page_id = 42;
    integrity.generation = 1;
    integrity.checksum = 0xDEADBEEF;
    integrity.sequence_length = 128;
    integrity.layer_id = 3;
    integrity.timestamp = 1234567890;
    
    // Valid integrity should pass
    ASSERT_TRUE(integrity.IsValid());
    
    // Invalid page ID should fail
    KVPageIntegrity invalid;
    invalid.page_id = 0xFFFFFFFFFFFFFFFFULL;
    ASSERT_FALSE(invalid.IsValid());
    
    // Zero checksum should fail
    KVPageIntegrity invalid2;
    invalid2.page_id = 1;
    invalid2.checksum = 0;
    ASSERT_FALSE(invalid2.IsValid());
    
    return true;
}

TEST(KVIntegrity_KVIntegrityTracker_Register) {
    KVIntegrityTracker tracker;
    
    uint8_t k_data[] = {0x01, 0x02};
    uint8_t v_data[] = {0x03, 0x04};
    
    tracker.RegisterPage(1, k_data, v_data, 2, 2, 0);
    
    auto integrity = tracker.GetIntegrity(1);
    ASSERT_EQ(1ULL, integrity.page_id);
    ASSERT_EQ(0U, integrity.layer_id);
    ASSERT_TRUE(integrity.IsValid());
    
    return true;
}

TEST(KVIntegrity_KVIntegrityTracker_Verify) {
    KVIntegrityTracker tracker;
    
    uint8_t k_data[] = {0x01, 0x02};
    uint8_t v_data[] = {0x03, 0x04};
    
    tracker.RegisterPage(1, k_data, v_data, 2, 2, 0);
    
    // Verify with same data should pass
    ASSERT_TRUE(tracker.VerifyPage(1, k_data, v_data, 2, 2, "test"));
    
    // Verify with different data should fail
    uint8_t v_data2[] = {0x03, 0x05};
    ASSERT_FALSE(tracker.VerifyPage(1, k_data, v_data2, 2, 2, "test"));
    
    return true;
}

TEST(KVIntegrity_KVIntegrityTracker_Update) {
    KVIntegrityTracker tracker;
    
    uint8_t k_data[] = {0x01, 0x02};
    uint8_t v_data[] = {0x03, 0x04};
    
    tracker.RegisterPage(1, k_data, v_data, 2, 2, 0);
    auto integrity1 = tracker.GetIntegrity(1);
    
    // Update with new data
    uint8_t v_data2[] = {0x05, 0x06};
    tracker.UpdateChecksum(1, k_data, v_data2, 2, 2);
    
    auto integrity2 = tracker.GetIntegrity(1);
    ASSERT_EQ(integrity1.generation + 1, integrity2.generation);
    ASSERT_NE(integrity1.checksum, integrity2.checksum);
    
    return true;
}

TEST(KVIntegrity_KVIntegrityTracker_Violations) {
    KVIntegrityTracker tracker;
    
    uint8_t k_data[] = {0x01, 0x02};
    uint8_t v_data[] = {0x03, 0x04};
    
    // Verify unregistered page should create violation
    ASSERT_FALSE(tracker.VerifyPage(999, k_data, v_data, 2, 2, "test"));
    ASSERT_TRUE(tracker.HasViolations());
    
    auto stats = tracker.GetStats();
    ASSERT_EQ(1ULL, stats.violations_count);
    
    return true;
}

TEST(KVIntegrity_KVIntegrityTracker_Clear) {
    KVIntegrityTracker tracker;
    
    uint8_t k_data[] = {0x01, 0x02};
    uint8_t v_data[] = {0x03, 0x04};
    
    tracker.RegisterPage(1, k_data, v_data, 2, 2, 0);
    tracker.RegisterPage(2, k_data, v_data, 2, 2, 1);
    
    ASSERT_EQ(2ULL, tracker.GetStats().pages_tracked);
    
    tracker.Clear();
    
    ASSERT_EQ(0ULL, tracker.GetStats().pages_tracked);
    ASSERT_FALSE(tracker.HasViolations());
    
    return true;
}

TEST(KVIntegrity_KVMigrationGuard) {
    KVIntegrityTracker tracker;
    
    uint8_t k_data[] = {0x01, 0x02};
    uint8_t v_data[] = {0x03, 0x04};
    
    tracker.RegisterPage(1, k_data, v_data, 2, 2, 0);
    
    // Migration guard should verify on construction
    {
        KVMigrationGuard guard(tracker, 1, k_data, v_data, 2, 2);
        ASSERT_TRUE(guard.IsValid());
    }
    
    return true;
}

TEST(KVIntegrity_KVMigrationGuard_Invalid) {
    KVIntegrityTracker tracker;
    
    uint8_t k_data[] = {0x01, 0x02};
    uint8_t v_data[] = {0x03, 0x04};
    uint8_t v_data2[] = {0x05, 0x06};
    
    tracker.RegisterPage(1, k_data, v_data, 2, 2, 0);
    
    // Migration guard with wrong data should fail
    {
        KVMigrationGuard guard(tracker, 1, k_data, v_data2, 2, 2);
        ASSERT_FALSE(guard.IsValid());
    }
    
    return true;
}
