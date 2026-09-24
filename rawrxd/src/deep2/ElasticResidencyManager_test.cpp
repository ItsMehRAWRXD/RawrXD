// ============================================================================
// ElasticResidencyManager_test.cpp — Runtime certification tests
// ============================================================================
#include "ElasticResidencyManager.hpp"
#include <cassert>
#include <cstdio>
#include <string>
#include <vector>
#include <string>

using namespace Deep2;

static int gFailures = 0;

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        printf("FAIL: %s at line %d\n", msg, __LINE__); \
        ++gFailures; \
    } \
} while(0)

int main() {
    printf("=== ElasticResidencyManager Runtime Certification ===\n\n");

    ElasticResidencyManager mgr;

    // ---- Test 1: Initial miss (tensor never seen) ----
    {
        printf("[TEST 1] Initial miss\n");
        std::vector<std::string> names = {"tensor_a", "tensor_b"};
        mgr.PredictLayerNeeds(0, &names, names.size());
        auto stats = mgr.stats();
        CHECK(stats.predictions == 1, "predictions after first call");
        CHECK(stats.tensorRequests == 2, "tensorRequests after first call");
        CHECK(stats.alreadyResidentHits == 0, "alreadyResidentHits initially 0");
        CHECK(stats.prefetchHits == 0, "prefetchHits initially 0");
        CHECK(stats.misses == 0, "misses initially 0");
        // Both tensors should be in Requested state
        CHECK(mgr.stateOf("tensor_a") == ResidencyState::Requested, "tensor_a requested");
        CHECK(mgr.stateOf("tensor_b") == ResidencyState::Requested, "tensor_b requested");
        printf("  PASS: predictions=%llu requests=%llu\n",
               (unsigned long long)stats.predictions,
               (unsigned long long)stats.tensorRequests);
    }

    // ---- Test 2: Promotion (markResident) ----
    {
        printf("[TEST 2] Promotion\n");
        mgr.markResident("tensor_a", ResidencyTier::VRAM, 1024);
        auto stats = mgr.stats();
        CHECK(stats.promotions == 1, "promotions after markResident");
        CHECK(stats.bytesPromoted == 1024, "bytesPromoted");
        CHECK(stats.vramResidentBytes == 1024, "vramResidentBytes");
        CHECK(mgr.stateOf("tensor_a") == ResidencyState::Resident, "tensor_a resident");
        CHECK(mgr.tierOf("tensor_a") == ResidencyTier::VRAM, "tensor_a VRAM tier");
        printf("  PASS: promotions=%llu vramBytes=%llu\n",
               (unsigned long long)stats.promotions,
               (unsigned long long)stats.vramResidentBytes);
    }

    // ---- Test 3: Resident hit (same layer predicted again) ----
    {
        printf("[TEST 3] Resident hit\n");
        std::vector<std::string> names = {"tensor_a", "tensor_b"};
        mgr.PredictLayerNeeds(0, &names, names.size());
        auto stats = mgr.stats();
        CHECK(stats.predictions == 2, "predictions incremented");
        CHECK(stats.alreadyResidentHits == 1, "alreadyResidentHits for tensor_a");
        // tensor_b still requested, tensor_a stays resident
        CHECK(mgr.stateOf("tensor_a") == ResidencyState::Resident, "tensor_a still resident");
        printf("  PASS: alreadyResidentHits=%llu\n",
               (unsigned long long)stats.alreadyResidentHits);
    }

    // ---- Test 4: Prefetch hit ----
    {
        printf("[TEST 4] Prefetch hit\n");
        mgr.markPrefetched("tensor_b");
        auto stats = mgr.stats();
        CHECK(stats.prefetchHits == 1, "prefetchHits");
        CHECK(mgr.stateOf("tensor_b") == ResidencyState::Prefetching, "tensor_b prefetching");
        printf("  PASS: prefetchHits=%llu\n",
               (unsigned long long)stats.prefetchHits);
    }

    // ---- Test 5: Miss (prefetch failed) ----
    {
        printf("[TEST 5] Miss\n");
        mgr.markMiss("tensor_c", 2048);
        auto stats = mgr.stats();
        CHECK(stats.misses == 1, "misses");
        CHECK(stats.bytesRequested >= 2048, "bytesRequested includes miss");
        CHECK(mgr.stateOf("tensor_c") == ResidencyState::Unknown, "tensor_c unknown after miss");
        printf("  PASS: misses=%llu\n",
               (unsigned long long)stats.misses);
    }

    // ---- Test 6: Budget enforcement / eviction ----
    {
        printf("[TEST 6] Budget enforcement & eviction\n");
        mgr.reset();
        mgr.setBudget(ResidencyTier::VRAM, 500); // 500 byte budget

        mgr.markResident("small_1", ResidencyTier::VRAM, 200);
        mgr.markResident("small_2", ResidencyTier::VRAM, 200);
        mgr.markResident("small_3", ResidencyTier::VRAM, 200); // total 600 > 500

        bool ok = mgr.enforceBudget(ResidencyTier::VRAM);
        CHECK(ok, "enforceBudget returns true");
        auto stats = mgr.stats();
        CHECK(stats.evictions >= 1, "at least one eviction");
        CHECK(stats.bytesEvicted >= 200, "bytes evicted");
        uint64_t vramAfter = stats.vramResidentBytes;
        CHECK(vramAfter <= 500, "VRAM within budget after enforcement");
        printf("  PASS: evictions=%llu vramAfter=%llu\n",
               (unsigned long long)stats.evictions,
               (unsigned long long)vramAfter);
    }

    // ---- Test 7: VRAM / RAM / NVMe tier transitions ----
    {
        printf("[TEST 7] Tier transitions\n");
        mgr.reset();
        mgr.markResident("vram_t", ResidencyTier::VRAM, 100);
        mgr.markResident("ram_t",  ResidencyTier::RAM,  200);
        mgr.markResident("nvme_t", ResidencyTier::NVMe, 300);
        auto stats = mgr.stats();
        CHECK(stats.vramResidentBytes == 100, "VRAM bytes");
        CHECK(stats.ramResidentBytes  == 200, "RAM bytes");
        CHECK(stats.nvmeResidentBytes == 300, "NVMe bytes");
        printf("  PASS: VRAM=%llu RAM=%llu NVMe=%llu\n",
               (unsigned long long)stats.vramResidentBytes,
               (unsigned long long)stats.ramResidentBytes,
               (unsigned long long)stats.nvmeResidentBytes);
    }

    // ---- Test 8: Reset clears state ----
    {
        printf("[TEST 8] Reset clears state\n");
        mgr.reset();
        auto stats = mgr.stats();
        CHECK(stats.predictions == 0, "predictions cleared");
        CHECK(stats.tensorRequests == 0, "tensorRequests cleared");
        CHECK(stats.promotions == 0, "promotions cleared");
        CHECK(stats.evictions == 0, "evictions cleared");
        CHECK(mgr.stateOf("vram_t") == ResidencyState::Unknown, "old tensor unknown");
        printf("  PASS: all counters cleared\n");
    }

    // ---- Test 9: Model switch (same as reset for this provider) ----
    {
        printf("[TEST 9] Model switch\n");
        std::vector<std::string> names = {"model1_w"};
        mgr.PredictLayerNeeds(0, &names, names.size());
        mgr.markResident("model1_w", ResidencyTier::VRAM, 512);
        mgr.reset(); // model switch
        CHECK(mgr.stateOf("model1_w") == ResidencyState::Unknown, "old model tensor cleared");
        auto stats = mgr.stats();
        CHECK(stats.predictions == 0, "predictions cleared on switch");
        printf("  PASS: model switch clears state\n");
    }

    // ---- Test 10: Invalid / zero-byte request ----
    {
        printf("[TEST 10] Invalid / zero-byte request\n");
        mgr.reset();
        std::vector<std::string> empty;
        mgr.PredictLayerNeeds(0, &empty, 0); // empty request
        auto stats = mgr.stats();
        CHECK(stats.predictions == 1, "prediction counted even for empty");
        CHECK(stats.tensorRequests == 0, "no tensorRequests for empty list");

        mgr.PredictLayerNeeds(0, nullptr, 0); // null request
        stats = mgr.stats();
        CHECK(stats.predictions == 2, "prediction counted for null");
        CHECK(stats.tensorRequests == 0, "no tensorRequests for null");
        printf("  PASS: empty/null handled safely\n");
    }

    // ---- Test 11: Hit rate calculation ----
    {
        printf("[TEST 11] Hit rate calculation\n");
        mgr.reset();
        // With no hits or misses, rate should be 0
        CHECK(mgr.PrefetchHitRatePct() == 0.0, "hit rate 0 when empty");

        mgr.markPrefetched("x"); // 1 hit
        mgr.markMiss("y", 100);   // 1 miss
        double rate = mgr.PrefetchHitRatePct();
        CHECK(rate > 49.0 && rate < 51.0, "hit rate ~50%");
        printf("  PASS: hitRate=%.2f%%\n", rate);
    }

    // ---- Test 12: buildPlanForLayer ----
    {
        printf("[TEST 12] buildPlanForLayer\n");
        mgr.reset();
        std::vector<std::string> names = {"plan_a", "plan_b"};
        mgr.PredictLayerNeeds(3, &names, names.size());
        auto plan = mgr.buildPlanForLayer(3);
        CHECK(plan.size() == 2, "plan has 2 requests");
        CHECK(plan[0].tensorName == "plan_a", "first tensor name");
        CHECK(plan[0].desiredTier == ResidencyTier::VRAM, "desired tier VRAM");
        printf("  PASS: plan size=%zu\n", plan.size());
    }

    // ---- Summary ----
    printf("\n=== Results ===\n");
    printf("FAILURES: %d\n", gFailures);
    if (gFailures == 0) {
        printf("VERDICT: PASS\n");
        return 0;
    } else {
        printf("VERDICT: FAIL\n");
        return 1;
    }
}
