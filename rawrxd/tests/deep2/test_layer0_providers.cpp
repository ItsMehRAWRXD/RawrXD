// ============================================================================
// test_layer0_providers.cpp — Standalone unit test for Layer 0 providers
// Compile: cl /std:c++20 /I. /I.. /I../../include test_layer0_providers.cpp
// ============================================================================
#include "../src/deep2/CycloneScheduler.hpp"
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <cmath>
#include <limits>
#include "../src/deep2/Chamber.hpp"
#include "../src/deep2/PlasmaGovernor.hpp"
#include "../src/deep2/ToroidalKVCache.hpp"

static int g_failures = 0;

#define CHECK(cond) do { \
    if (!(cond)) { \
        std::printf("FAIL: %s at line %d\n", #cond, __LINE__); \
        ++g_failures; \
    } \
} while(0)

#define CHECK_APPROX(a, b) do { \
    if (std::abs((a) - (b)) > 1e-5f) { \
        std::printf("FAIL: %s approx %s at line %d (%g vs %g)\n", #a, #b, __LINE__, static_cast<double>(a), static_cast<double>(b)); \
        ++g_failures; \
    } \
} while(0)

int main() {
    std::printf("=== Layer0 Provider Tests ===\n");

    // Chamber evaluate detects dead neurons and non-finite
    {
        Deep2::Chamber chamber;
        std::vector<float> zeros(128, 0.0f);
        auto r = chamber.evaluate(zeros.data(), zeros.size());
        CHECK(r.status == 1);
        CHECK((r.flags & 0x08) != 0);

        std::vector<float> clean(128);
        for (size_t i = 0; i < clean.size(); ++i) clean[i] = 0.5f + static_cast<float>(i % 7) * 0.1f;
        r = chamber.evaluate(clean.data(), clean.size());
        CHECK(r.status == 0);
        CHECK(r.flags == 0);

        std::vector<float> bad(128, std::numeric_limits<float>::infinity());
        r = chamber.evaluate(bad.data(), bad.size());
        CHECK(r.status == 1);
        CHECK((r.flags & 0x02) != 0);
    }

    // Chamber routePrimitive deterministic routing
    {
        Deep2::Chamber chamber;
        auto r1 = chamber.routePrimitive(0x12345678);
        auto r2 = chamber.routePrimitive(0x12345678);
        CHECK(r1.route == r2.route);
        CHECK(r1.confidence == r2.confidence);
        CHECK(r1.confidence > 0.0f);
    }

    // PlasmaGovernor throttles on thermal violation
    {
        Deep2::PlasmaGovernor gov;
        CHECK_APPROX(gov.currentThrottle(), 1.0f);

        Deep2::ThermalState s;
        s.temp = 95.0f;
        s.hotspot = 110.0f;
        s.powerW = 300.0f;
        gov.update(s);

        float throttle = gov.currentThrottle();
        CHECK(throttle < 1.0f);
        CHECK(throttle >= 0.1f);
        CHECK(gov.violationCount() > 0);
    }

    // PlasmaGovernor clears violation when temps drop
    {
        Deep2::PlasmaGovernor gov;
        Deep2::ThermalState hot{90.0f, 110.0f, 0.0f, 300.0f};
        gov.update(hot);
        float throttleAfterHot = gov.currentThrottle();
        CHECK(throttleAfterHot < 1.0f);

        Deep2::ThermalState cool{70.0f, 80.0f, 0.0f, 100.0f};
        for (int i = 0; i < 10; ++i) gov.update(cool);
        float throttleAfterCool = gov.currentThrottle();
        // EMA decays slowly; throttle should trend upward but not yet fully recover
        CHECK(throttleAfterCool > throttleAfterHot);
        CHECK(throttleAfterCool <= 1.0f);
    }

    // ToroidalKVCache initialize and basic ring ops
    {
        Deep2::ToroidalKVCache kv(4, 8, 64, 128);
        CHECK(kv.initialize());
        CHECK(kv.currentLength() == 0);
        CHECK(kv.capacity() == 128);

        const size_t perToken = kv.numHeads() * kv.headDim(); // 512
        std::vector<float> k(perToken, 1.0f);
        std::vector<float> v(perToken, 2.0f);
        for (size_t l = 0; l < kv.numLayers(); ++l) {
            CHECK(kv.writeLayer(l, k.data(), v.data(), k.size()));
        }
        CHECK(kv.currentLength() == 0); // advance not called yet

        CHECK(kv.advance());
        CHECK(kv.currentLength() == 1);

        std::vector<float> kOut(perToken);
        std::vector<float> vOut(perToken);
        size_t read = kv.readLayer(0, kOut.data(), vOut.data(), kOut.size());
        CHECK(read == 1);
        CHECK_APPROX(kOut[0], 1.0f);
        CHECK_APPROX(vOut[0], 2.0f);
    }

    // ToroidalKVCache wraps around
    {
        Deep2::ToroidalKVCache kv(1, 1, 4, 4);
        CHECK(kv.initialize());
        std::vector<float> data(4, 1.0f);
        for (size_t i = 0; i < 6; ++i) {
            CHECK(kv.writeLayer(0, data.data(), data.data(), data.size()));
            CHECK(kv.advance());
        }
        CHECK(kv.currentLength() == 4);
    }

    // CycloneScheduler lifecycle and timing
    {
        Deep2::CycloneScheduler cyc;
        CHECK(cyc.activeLayer() == UINT32_MAX);
        CHECK(!cyc.hasActiveLayer());
        CHECK(cyc.layerState(0) == Deep2::CycloneLayerState::Idle);
        CHECK(cyc.currentEpoch() == 1);

        cyc.onModelSwitch(4, 1);
        CHECK(cyc.currentEpoch() == 1);

        // onLayerStart sets active layer
        cyc.onLayerStart(0, 1);
        CHECK(cyc.hasActiveLayer());
        CHECK(cyc.activeLayer() == 0);
        CHECK(cyc.layerState(0) == Deep2::CycloneLayerState::Running);

        // onLayerEnd with explicit duration
        cyc.onLayerEnd(0, 1, 1000000);
        CHECK(!cyc.hasActiveLayer());
        CHECK(cyc.layerState(0) == Deep2::CycloneLayerState::Complete);
        CHECK(cyc.layerEmaNs(0) > 0.0);
        CHECK(cyc.layerMinNs(0) == 1000000);
        CHECK(cyc.layerMaxNs(0) == 1000000);
        CHECK(cyc.stats().layerStarts == 1);
        CHECK(cyc.stats().layerEnds == 1);

        // Second pass updates EMA/min/max
        cyc.onLayerStart(0, 2);
        cyc.onLayerEnd(0, 2, 500000);
        CHECK(cyc.layerMinNs(0) == 500000);
        CHECK(cyc.layerMaxNs(0) == 1000000);
        CHECK(cyc.stats().layerEnds == 2);

        // Abort path
        cyc.onLayerStart(1, 3);
        cyc.onLayerAbort(1, 3);
        CHECK(cyc.layerState(1) == Deep2::CycloneLayerState::Aborted);
        CHECK(cyc.stats().layerAborts == 1);

        // Invalid transition guard: double-start
        cyc.onLayerStart(2, 4);
        cyc.onLayerStart(3, 5); // should bump invalidTransitions
        CHECK(cyc.stats().invalidTransitions >= 1);

        // reset clears everything
        cyc.reset();
        CHECK(!cyc.hasActiveLayer());
        CHECK(cyc.layerState(0) == Deep2::CycloneLayerState::Idle);
    }

    // CycloneScheduler decidePrefetch
    {
        Deep2::CycloneScheduler cyc;
        cyc.onModelSwitch(3, 0);
        // No history yet: conservative prefetch for next layer
        auto d0 = cyc.decidePrefetch(0, 0);
        CHECK(d0.shouldPrefetch);
        CHECK(d0.layer == 0);

        // Last layer: should not prefetch
        auto d2 = cyc.decidePrefetch(2, 0);
        CHECK(!d2.shouldPrefetch);
    }

    std::printf("=== %s: %d failure(s) ===\n",
                g_failures == 0 ? "PASS" : "FAIL", g_failures);
    return g_failures == 0 ? 0 : 1;
}
