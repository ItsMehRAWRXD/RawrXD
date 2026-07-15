/**
 * @file test_prefix_cache.cpp
 * @brief Unit tests for prefix caching
 */

#include <gtest/gtest.h>
#include "inference/prefix_cache.hpp"
#include <filesystem>

using namespace rawrxd::inference;

class PrefixCacheTest : public ::testing::Test {
protected:
    void SetUp() override {
        config_.max_entries = 100;
        config_.max_memory_mb = 100;
        config_.min_prefix_length = 5;
        config_.max_prefix_length = 512;
    }

    PrefixCacheConfig config_;
};

TEST_F(PrefixCacheTest, BasicLookup) {
    PrefixCache cache(config_);
    cache.initialize();
    
    std::vector<int> prefix = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    std::vector<uint8_t> kv_data = {0x01, 0x02, 0x03, 0x04};
    
    // Store
    EXPECT_TRUE(cache.store(prefix, kv_data));
    
    // Lookup
    auto result = cache.lookup(prefix);
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(result->kv_cache_data, kv_data);
}

TEST_F(PrefixCacheTest, LookupNonExistent) {
    PrefixCache cache(config_);
    cache.initialize();
    
    std::vector<int> prefix = {1, 2, 3, 4, 5};
    
    auto result = cache.lookup(prefix);
    EXPECT_FALSE(result.has_value());
}

TEST_F(PrefixCacheTest, TooShortPrefix) {
    PrefixCache cache(config_);
    cache.initialize();
    
    std::vector<int> short_prefix = {1, 2, 3};  // Less than min_prefix_length
    std::vector<uint8_t> kv_data = {0x01};
    
    EXPECT_FALSE(cache.store(short_prefix, kv_data));
    
    auto result = cache.lookup(short_prefix);
    EXPECT_FALSE(result.has_value());
}

TEST_F(PrefixCacheTest, Invalidate) {
    PrefixCache cache(config_);
    cache.initialize();
    
    std::vector<int> prefix = {1, 2, 3, 4, 5};
    std::vector<uint8_t> kv_data = {0x01};
    
    cache.store(prefix, kv_data);
    EXPECT_TRUE(cache.lookup(prefix).has_value());
    
    cache.invalidate(prefix);
    EXPECT_FALSE(cache.lookup(prefix).has_value());
}

TEST_F(PrefixCacheTest, Clear) {
    PrefixCache cache(config_);
    cache.initialize();
    
    std::vector<int> prefix1 = {1, 2, 3, 4, 5};
    std::vector<int> prefix2 = {6, 7, 8, 9, 10};
    std::vector<uint8_t> kv_data = {0x01};
    
    cache.store(prefix1, kv_data);
    cache.store(prefix2, kv_data);
    
    cache.clear();
    
    EXPECT_FALSE(cache.lookup(prefix1).has_value());
    EXPECT_FALSE(cache.lookup(prefix2).has_value());
}

TEST_F(PrefixCacheTest, Stats) {
    PrefixCache cache(config_);
    cache.initialize();
    
    std::vector<int> prefix = {1, 2, 3, 4, 5};
    std::vector<uint8_t> kv_data = {0x01};
    
    cache.store(prefix, kv_data);
    
    // Miss
    cache.lookup({10, 11, 12, 13, 14});
    
    // Hit
    cache.lookup(prefix);
    
    auto stats = cache.getStats();
    EXPECT_EQ(stats.num_entries, 1);
    EXPECT_EQ(stats.hits, 1);
    EXPECT_EQ(stats.misses, 1);
    EXPECT_FLOAT_EQ(stats.hit_rate, 0.5f);
}

// Radix tree tests
TEST_F(PrefixCacheTest, RadixTreeInsert) {
    RadixPrefixCache radix_cache(config_);
    
    std::vector<int> prefix = {1, 2, 3, 4, 5};
    std::vector<uint8_t> kv_data = {0x01};
    
    EXPECT_TRUE(radix_cache.insert(prefix, kv_data));
    EXPECT_EQ(radix_cache.getEntryCount(), 1);
}

TEST_F(PrefixCacheTest, RadixTreeLongestPrefixMatch) {
    RadixPrefixCache radix_cache(config_);
    
    std::vector<int> prefix1 = {1, 2, 3};
    std::vector<int> prefix2 = {1, 2, 3, 4, 5};
    std::vector<uint8_t> kv_data = {0x01};
    
    radix_cache.insert(prefix1, kv_data);
    radix_cache.insert(prefix2, kv_data);
    
    std::vector<int> query = {1, 2, 3, 4, 5, 6, 7};
    auto result = radix_cache.longestPrefixMatch(query);
    
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(result->prefix_tokens, prefix2);
}

TEST_F(PrefixCacheTest, RadixTreeAllPrefixMatches) {
    RadixPrefixCache radix_cache(config_);
    
    std::vector<int> prefix1 = {1, 2, 3};
    std::vector<int> prefix2 = {1, 2, 3, 4, 5};
    std::vector<uint8_t> kv_data = {0x01};
    
    radix_cache.insert(prefix1, kv_data);
    radix_cache.insert(prefix2, kv_data);
    
    std::vector<int> query = {1, 2, 3, 4, 5, 6, 7};
    auto results = radix_cache.allPrefixMatches(query);
    
    EXPECT_EQ(results.size(), 2);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
