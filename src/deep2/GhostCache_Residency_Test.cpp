// ============================================================================
// GhostCache_Residency_Test.cpp
// Standalone test for GhostCache (no Deep2Engine dependency)
// Verifies: init, RecordEvict, RecordHit, Decay, SelectVictim, overflow, stats
// ============================================================================

#include "GhostCache.hpp"
#include <cstdio>
#include <cstring>
#include <vector>
#include <string>

using namespace Deep2;

static int g_passed = 0;
static int g_failed = 0;

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        printf("  [FAIL] %s: %s\n", #cond, msg); \
        g_failed++; \
        return false; \
    } \
} while(0)

#define PASS(msg) do { \
    printf("  [PASS] %s\n", msg); \
    g_passed++; \
} while(0)

// ============================================================================
// Test 1: GhostCache basic operations
// ============================================================================
bool Test_GhostCache_Basic() {
    printf("\n[TEST] GhostCache Basic Operations\n");

    GhostCache cache(1024);

    // Record evictions
    cache.RecordEvict("tensor_a", 0);
    cache.RecordEvict("tensor_b", 1);
    cache.RecordEvict("tensor_c", 2);

    // Verify scores
    CHECK(cache.GetReuseScore("tensor_a") == 1, "tensor_a score should be 1 after first eviction");
    CHECK(cache.GetReuseScore("tensor_b") == 1, "tensor_b score should be 1 after first eviction");
    CHECK(cache.GetReuseScore("tensor_c") == 1, "tensor_c score should be 1 after first eviction");
    CHECK(cache.GetReuseScore("tensor_d") == 0, "tensor_d should not exist");

    // Record hits (reloads)
    CHECK(cache.RecordHit("tensor_a", 0) == true, "tensor_a should be a ghost hit");
    CHECK(cache.RecordHit("tensor_a", 0) == true, "tensor_a should be a ghost hit again");
    CHECK(cache.GetReuseScore("tensor_a") == 13, "tensor_a score should be 1 + 6 + 6 = 13");

    // Record another eviction (same tensor)
    cache.RecordEvict("tensor_a", 0);
    CHECK(cache.GetReuseScore("tensor_a") == 14, "tensor_a score should be 13 + 1 = 14 after re-eviction");

    // Select victim: should be tensor_b or tensor_c (lowest score)
    std::string victim = cache.SelectVictim();
    CHECK(victim == "tensor_b" || victim == "tensor_c", "victim should be lowest score");

    // Decay
    cache.Decay();
    CHECK(cache.GetReuseScore("tensor_a") == 13, "tensor_a score should decay from 14 to 13");
    CHECK(cache.GetReuseScore("tensor_b") == 0, "tensor_b score should decay from 1 to 0");

    // Stats
    auto stats = cache.GetStats();
    CHECK(stats.evictionsRecorded == 4, "should have 4 evictions recorded");
    CHECK(stats.hitsRecorded == 2, "should have 2 hits recorded");
    CHECK(stats.decayCycles == 1, "should have 1 decay cycle");
    CHECK(stats.currentSize == 3, "should have 3 entries");

    PASS("GhostCache basic operations");
    return true;
}

// ============================================================================
// Test 2: GhostCache overflow (table full)
// ============================================================================
bool Test_GhostCache_Overflow() {
    printf("\n[TEST] GhostCache Overflow Handling\n");

    GhostCache cache(4); // tiny table

    // Fill table
    cache.RecordEvict("t0", 0);
    cache.RecordEvict("t1", 1);
    cache.RecordEvict("t2", 2);
    cache.RecordEvict("t3", 3);

    // Overflow: should evict oldest
    cache.RecordEvict("t4", 4);

    // t0 should be gone (oldest tick)
    CHECK(cache.GetReuseScore("t0") == 0, "t0 should be evicted from ghost cache");
    CHECK(cache.GetReuseScore("t4") == 1, "t4 should be present");

    PASS("GhostCache overflow handling");
    return true;
}

// ============================================================================
// Test 3: GhostCache score saturation
// ============================================================================
bool Test_GhostCache_Saturation() {
    printf("\n[TEST] GhostCache Score Saturation\n");

    GhostCache cache(64);
    cache.RecordEvict("hot_tensor", 0);

    // Hit 50 times: score should saturate at 255
    for (int i = 0; i < 50; ++i) {
        cache.RecordHit("hot_tensor", 0);
    }

    uint32_t score = cache.GetReuseScore("hot_tensor");
    CHECK(score == 255, "score should saturate at 255");

    PASS("GhostCache score saturation");
    return true;
}

// ============================================================================
// Test 4: GhostCache decay underflow protection
// ============================================================================
bool Test_GhostCache_DecayUnderflow() {
    printf("\n[TEST] GhostCache Decay Underflow Protection\n");

    GhostCache cache(64);
    cache.RecordEvict("cold_tensor", 0);

    // Score is 1. Decay 3 times. Should stop at 0, not underflow.
    cache.Decay();
    cache.Decay();
    cache.Decay();

    CHECK(cache.GetReuseScore("cold_tensor") == 0, "score should not underflow below 0");

    PASS("GhostCache decay underflow protection");
    return true;
}

// ============================================================================
// Test 5: GhostCache entry retrieval
// ============================================================================
bool Test_GhostCache_GetEntry() {
    printf("\n[TEST] GhostCache GetEntry\n");

    GhostCache cache(64);
    cache.RecordEvict("test_tensor", 42);
    cache.RecordHit("test_tensor", 42);

    GhostEntry entry;
    CHECK(cache.GetEntry("test_tensor", entry) == true, "should find existing entry");
    CHECK(entry.layerIndex == 42, "layerIndex should match");
    CHECK(entry.score == 7, "score should be 1 + 6 = 7");
    CHECK(entry.hitCount == 1, "hitCount should be 1");
    CHECK(entry.evictCount == 1, "evictCount should be 1");

    GhostEntry missing;
    CHECK(cache.GetEntry("nonexistent", missing) == false, "should not find missing entry");

    PASS("GhostCache GetEntry");
    return true;
}

// ============================================================================
// Main
// ============================================================================
int main(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("=================================================================\n");
    printf(" GhostCache Standalone Test Suite\n");
    printf("=================================================================\n");

    Test_GhostCache_Basic();
    Test_GhostCache_Overflow();
    Test_GhostCache_Saturation();
    Test_GhostCache_DecayUnderflow();
    Test_GhostCache_GetEntry();

    printf("\n=================================================================\n");
    printf(" Results: %d passed, %d failed\n", g_passed, g_failed);
    printf("=================================================================\n");

    return g_failed > 0 ? 1 : 0;
}
