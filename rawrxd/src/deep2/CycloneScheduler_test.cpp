// ============================================================================
// CycloneScheduler_test.cpp — Runtime certification tests
// ============================================================================
#include "CycloneScheduler.hpp"
#include <cassert>
#include <cstdio>
#include <chrono>
#include <thread>

using namespace Deep2;

static int gFailures = 0;

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        printf("FAIL: %s at line %d\n", msg, __LINE__); \
        ++gFailures; \
    } \
} while(0)

int main() {
    printf("=== CycloneScheduler Runtime Certification ===\n\n");

    CycloneScheduler cyc;

    // ---- Test 1: reset enables and clears state ----
    {
        printf("[TEST 1] reset\n");
        cyc.reset();
        CHECK(cyc.currentEpoch() == 1, "epoch after reset");
        CHECK(!cyc.hasActiveLayer(), "no active layer after reset");
        CHECK(cyc.activeLayer() == UINT32_MAX, "activeLayer UINT32_MAX");
        auto s = cyc.stats();
        CHECK(s.layerStarts == 0, "starts 0");
        CHECK(s.layerEnds == 0, "ends 0");
        printf("  PASS\n");
    }

    // ---- Test 2: model switch sets layers/epoch ----
    {
        printf("[TEST 2] onModelSwitch\n");
        cyc.onModelSwitch(32, 5);
        CHECK(cyc.currentEpoch() == 5, "epoch set");
        CHECK(cyc.layerState(0) == CycloneLayerState::Idle, "layer idle");
        printf("  PASS\n");
    }

    // ---- Test 3: layer start/end lifecycle ----
    {
        printf("[TEST 3] layer start/end\n");
        cyc.onLayerStart(0, 100);
        CHECK(cyc.hasActiveLayer(), "has active layer");
        CHECK(cyc.activeLayer() == 0, "activeLayer 0");
        CHECK(cyc.layerState(0) == CycloneLayerState::Running, "layer running");

        std::this_thread::sleep_for(std::chrono::microseconds(100));
        cyc.onLayerEnd(0, 100, 0); // auto-duration
        CHECK(!cyc.hasActiveLayer(), "no active layer after end");
        CHECK(cyc.layerState(0) == CycloneLayerState::Complete, "layer complete");
        auto s = cyc.stats();
        CHECK(s.layerStarts == 1, "one start");
        CHECK(s.layerEnds == 1, "one end");
        printf("  PASS\n");
    }

    // ---- Test 4: invalid start while another running ----
    {
        printf("[TEST 4] invalid transition (double start)\n");
        cyc.onModelSwitch(32, 10);
        cyc.onLayerStart(0, 0);
        cyc.onLayerStart(1, 0); // should be rejected
        auto s = cyc.stats();
        CHECK(s.invalidTransitions >= 1, "invalid transition counted");
        CHECK(cyc.activeLayer() == 0, "activeLayer still 0");
        cyc.onLayerEnd(0, 0, 1000); // clean up
        printf("  PASS\n");
    }

    // ---- Test 5: abort ----
    {
        printf("[TEST 5] abort\n");
        cyc.onLayerStart(5, 7);
        cyc.onLayerAbort(5, 7);
        CHECK(!cyc.hasActiveLayer(), "no active after abort");
        auto s = cyc.stats();
        CHECK(s.layerAborts == 1, "one abort");
        CHECK(cyc.layerState(5) == CycloneLayerState::Aborted, "layer aborted");
        printf("  PASS\n");
    }

    // ---- Test 6: timing stats (EMA, min, max) ----
    {
        printf("[TEST 6] timing stats\n");
        cyc.onModelSwitch(4, 20);
        for (uint32_t i = 0; i < 4; ++i) {
            cyc.onLayerStart(i, 0);
            cyc.onLayerEnd(i, 0, 1'000'000ull * (i + 1));
        }
        double ema0 = cyc.layerEmaNs(0);
        double ema3 = cyc.layerEmaNs(3);
        CHECK(ema0 > 0, "ema0 > 0");
        CHECK(ema3 > ema0, "ema3 > ema0");
        CHECK(cyc.layerMinNs(0) == 1'000'000ull, "minNs layer0");
        CHECK(cyc.layerMaxNs(3) == 4'000'000ull, "maxNs layer3");
        printf("  PASS: ema0=%.0f ema3=%.0f\n", ema0, ema3);
    }

    // ---- Test 7: decidePrefetch (no history) ----
    {
        printf("[TEST 7] decidePrefetch no history\n");
        cyc.onModelSwitch(8, 1);
        auto d = cyc.decidePrefetch(3, 0);
        CHECK(d.shouldPrefetch == true, "prefetch true when no history");
        CHECK(d.layer == 3, "decision layer");
        CHECK(d.leadDistance == 1, "lead distance 1");
        printf("  PASS: shouldPrefetch=%d lead=%llu\n", (int)d.shouldPrefetch, (unsigned long long)d.leadDistance);
    }

    // ---- Test 8: decidePrefetch skips last layer ----
    {
        printf("[TEST 8] decidePrefetch last layer\n");
        cyc.onModelSwitch(8, 1);
        auto d = cyc.decidePrefetch(7, 0);
        CHECK(d.shouldPrefetch == false, "no prefetch for last layer");
        printf("  PASS\n");
    }

    // ---- Test 9: decidePrefetch with history (EMA > 1e7 priority 2) ----
    {
        printf("[TEST 9] decidePrefetch with history\n");
        cyc.onModelSwitch(8, 1);
        cyc.onLayerStart(4, 0);
        cyc.onLayerEnd(4, 0, 50'000'000ull); // 50ms EMA
        auto d = cyc.decidePrefetch(3, 0);
        CHECK(d.shouldPrefetch == true, "prefetch true");
        CHECK(d.priority == 2, "priority 2 for large EMA");
        printf("  PASS: priority=%d\n", d.priority);
    }

    // ---- Test 10: stats counters ----
    {
        printf("[TEST 10] stats counters\n");
        cyc.onModelSwitch(8, 1);
        for (uint32_t i = 0; i < 8; ++i) {
            cyc.onLayerStart(i, 0);
            cyc.onLayerEnd(i, 0, 500'000);
        }
        auto d = cyc.decidePrefetch(0, 0);
        (void)d;
        auto s = cyc.stats();
        CHECK(s.layerStarts == 8, "layerStarts");
        CHECK(s.layerEnds == 8, "layerEnds");
        CHECK(s.schedulingDecisions >= 1, "schedulingDecisions");
        printf("  PASS: starts=%llu ends=%llu\n",
               (unsigned long long)s.layerStarts, (unsigned long long)s.layerEnds);
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
