// ============================================================================
// B015 — WeightResidencyPool Direct Unit Test
// ============================================================================
// Tests the pool in isolation: acquire, commit, release, pin, eviction.
// No transformer or model loader needed.
//
// Usage:
//   b015_pool_direct_test.exe
// ============================================================================

#include "../../src/runtime/memory/WeightResidencyPool.hpp"
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <vector>
#include <chrono>
#include <cmath>

using namespace rawrxd;

// ============================================================================
// Result tracking
// ============================================================================
struct TestResult {
    const char* name;
    bool passed;
    const char* reason;
};

static std::vector<TestResult> g_results;

static void Check(bool condition, const char* name, const char* failReason) {
    g_results.push_back({name, condition, condition ? "" : failReason});
    printf("  %s: %s\n", name, condition ? "PASS" : failReason);
}

// ============================================================================
// Main
// ============================================================================
int main(int argc, char** argv) {
    (void)argc; (void)argv;

    printf("=================================================================\n");
    printf("  B015 — WeightResidencyPool Direct Unit Test\n");
    printf("=================================================================\n\n");

    bool allPassed = true;

    // ========================================================================
    // Test 1: Basic acquire/commit/release
    // ========================================================================
    printf("Test 1: Basic acquire/commit/release\n");
    {
        WeightResidencyPool pool(64 * 1024 * 1024);  // 64 MB

        // Create synthetic weight
        std::vector<float> weight(256 * 128);
        for (size_t i = 0; i < weight.size(); ++i) weight[i] = static_cast<float>(i % 10) * 0.1f;

        // Miss before commit
        ResidentWeight* w = pool.acquire("test.weight");
        Check(w == nullptr, "acquire_miss_before_commit", "Expected nullptr before commit");

        // Commit
        bool committed = pool.commit("test.weight", weight.data(), weight.size() * sizeof(float));
        Check(committed, "commit_success", "commit returned false");
        Check(pool.resident_bytes() == weight.size() * sizeof(float), "resident_bytes_after_commit",
              "resident_bytes mismatch after commit");

        // Hit after commit
        w = pool.acquire("test.weight");
        Check(w != nullptr, "acquire_hit_after_commit", "Expected non-null after commit");
        Check(w->data != nullptr, "data_non_null", "data pointer is null");
        Check(w->bytes == weight.size() * sizeof(float), "bytes_match", "byte size mismatch");

        // Verify data integrity
        bool dataOk = true;
        for (size_t i = 0; i < 10; ++i) {
            if (std::abs(w->data[i] - weight[i]) > 1e-6f) { dataOk = false; break; }
        }
        Check(dataOk, "data_integrity", "data mismatch after commit");

        // Release
        pool.release("test.weight");
        w = pool.acquire("test.weight");
        Check(w != nullptr, "acquire_after_release", "Expected still resident after release");

        // Hits/misses accounting
        Check(pool.hits() > 0, "hits_nonzero", "hits should be > 0");
        Check(pool.misses() > 0, "misses_nonzero", "misses should be > 0");
        Check(pool.hit_rate() > 0.0f, "hit_rate_positive", "hit rate should be > 0");
    }

    // ========================================================================
    // Test 2: LRU eviction at capacity limit
    // ========================================================================
    printf("\nTest 2: LRU eviction at capacity limit\n");
    {
        WeightResidencyPool pool(1024);  // 1 KB — very small to force eviction

        std::vector<float> w1(100);  // 400 bytes
        std::vector<float> w2(100);  // 400 bytes
        std::vector<float> w3(100);  // 400 bytes — should evict w1

        pool.commit("w1", w1.data(), w1.size() * sizeof(float));
        pool.commit("w2", w2.data(), w2.size() * sizeof(float));

        // Touch w1 to make it more recently used
        ResidentWeight* rw = pool.acquire("w1");
        if (rw) pool.release("w1");

        pool.commit("w3", w3.data(), w3.size() * sizeof(float));

        // w2 should be evicted (LRU), w1 should still be resident
        rw = pool.acquire("w1");
        Check(rw != nullptr, "w1_still_resident", "w1 was evicted unexpectedly");
        if (rw) pool.release("w1");

        rw = pool.acquire("w2");
        Check(rw == nullptr, "w2_evicted", "w2 should have been evicted");

        rw = pool.acquire("w3");
        Check(rw != nullptr, "w3_resident", "w3 should be resident");
        if (rw) pool.release("w3");
    }

    // ========================================================================
    // Test 3: Pin prevents eviction
    // ========================================================================
    printf("\nTest 3: Pin prevents eviction\n");
    {
        WeightResidencyPool pool(512);  // 512 bytes

        std::vector<float> w1(50);   // 200 bytes
        std::vector<float> w2(50);   // 200 bytes
        std::vector<float> w3(50);   // 200 bytes

        pool.commit("w1", w1.data(), w1.size() * sizeof(float));
        pool.pin("w1");

        pool.commit("w2", w2.data(), w2.size() * sizeof(float));
        pool.pin("w2");

        // w3 commit should fail — w1 and w2 are pinned, can't evict
        bool committed = pool.commit("w3", w3.data(), w3.size() * sizeof(float));
        Check(!committed, "w3_commit_fails", "w3 should fail to commit when pinned weights fill pool");

        // Unpin w1, then w3 should succeed
        pool.unpin("w1");
        committed = pool.commit("w3", w3.data(), w3.size() * sizeof(float));
        Check(committed, "w3_commit_after_unpin", "w3 should commit after unpinning w1");
    }

    // ========================================================================
    // Test 4: Re-commit updates existing weight
    // ========================================================================
    printf("\nTest 4: Re-commit updates existing weight\n");
    {
        WeightResidencyPool pool(64 * 1024);

        std::vector<float> w1(100, 1.0f);
        std::vector<float> w1_new(100, 2.0f);

        pool.commit("w1", w1.data(), w1.size() * sizeof(float));
        pool.commit("w1", w1_new.data(), w1_new.size() * sizeof(float));

        ResidentWeight* rw = pool.acquire("w1");
        bool updated = false;
        if (rw && rw->data) {
            updated = (rw->data[0] == 2.0f);
        }
        Check(updated, "recommit_updates_data", "re-commit did not update data");
        if (rw) pool.release("w1");
    }

    // ========================================================================
    // Test 5: Performance — repeated acquires are fast
    // ========================================================================
    printf("\nTest 5: Performance — repeated acquires\n");
    {
        WeightResidencyPool pool(64 * 1024 * 1024);

        std::vector<float> weight(256 * 256);
        for (size_t i = 0; i < weight.size(); ++i) weight[i] = static_cast<float>(i % 7) * 0.1f;

        pool.commit("perf.weight", weight.data(), weight.size() * sizeof(float));

        const int iterations = 10000;
        auto t0 = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < iterations; ++i) {
            ResidentWeight* rw = pool.acquire("perf.weight");
            (void)rw;
            pool.release("perf.weight");
        }
        auto t1 = std::chrono::high_resolution_clock::now();
        double totalMs = std::chrono::duration<double, std::milli>(t1 - t0).count();
        double usPerOp = (totalMs * 1000.0) / iterations;

        printf("    %d acquire/release pairs: %.3f ms (%.3f us/op)\n", iterations, totalMs, usPerOp);
        Check(usPerOp < 10.0, "perf_fast", "acquire/release too slow (> 10 us)");
        Check(pool.hits() == static_cast<size_t>(iterations), "perf_all_hits", "not all ops were hits");
    }

    // ========================================================================
    // Test 6: Lifecycle — destructor cleans up
    // ========================================================================
    printf("\nTest 6: Lifecycle — destructor cleans up\n");
    {
        size_t residentBefore = 0;
        {
            WeightResidencyPool pool(64 * 1024 * 1024);
            std::vector<float> weight(1000, 1.0f);
            pool.commit("lifecycle.weight", weight.data(), weight.size() * sizeof(float));
            residentBefore = pool.resident_bytes();
            Check(residentBefore > 0, "resident_before_destroy", "resident bytes should be > 0");
        }
        // Pool destroyed — if we got here without crash, destructor worked
        printf("    Pool destroyed without crash\n");
    }

    // ========================================================================
    // Summary
    // ========================================================================
    printf("\n=================================================================\n");
    printf("  B015 DIRECT TEST SUMMARY\n");
    printf("=================================================================\n\n");

    int passed = 0, failed = 0;
    for (const auto& r : g_results) {
        if (r.passed) {
            ++passed;
        } else {
            ++failed;
            printf("  FAIL: %s — %s\n", r.name, r.reason);
        }
    }

    printf("  Total: %d tests, %d passed, %d failed\n", passed + failed, passed, failed);
    printf("  OVERALL: %s\n", failed == 0 ? "PASS" : "FAIL");
    printf("=================================================================\n");

    return failed == 0 ? 0 : 1;
}
