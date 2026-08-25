// ============================================================================
// KVCacheEquivalenceTest.cpp — Regression suite for Toroidal vs Legacy KV
// Build target: add to CMake when RAWRXD_ENABLE_TOROIDAL_KV is ON or OFF
// ============================================================================

#include "LegacyKVCacheAdapter.hpp"
#include "ToroidalKVCacheAdapter.hpp"
#include "Chamber.hpp"
#include <cstdio>
#include <cmath>
#include <cstring>
#include <vector>
#include <random>
#include <limits>

namespace Deep2 {

static bool g_verbose = false;
static int  g_passed  = 0;
static int  g_failed  = 0;

#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            printf("[FAIL] %s:%d  %s\n", __FILE__, __LINE__, msg); \
            g_failed++; \
            return false; \
        } \
    } while(0)

#define TEST_PASS(name) \
    do { \
        if (g_verbose) printf("[PASS] %s\n", name); \
        g_passed++; \
    } while(0)

// ============================================================================
// Tolerance helpers
// ============================================================================
static bool nearEqual(float a, float b, float tol = 1e-4f) {
    if (!std::isfinite(a) || !std::isfinite(b)) return false;
    float diff = std::fabs(a - b);
    float maxab = std::max(std::fabs(a), std::fabs(b));
    if (maxab < tol) return diff < tol;
    return diff <= tol * maxab;
}

static bool arraysNearEqual(const float* a, const float* b, size_t n, float tol = 1e-4f) {
    for (size_t i = 0; i < n; ++i) {
        if (!nearEqual(a[i], b[i], tol)) {
            if (g_verbose) {
                printf("  mismatch @ %zu: a=%.6e b=%.6e\n", i, (double)a[i], (double)b[i]);
            }
            return false;
        }
    }
    return true;
}

// ============================================================================
// Fill with deterministic pseudo-random values
// ============================================================================
static void fillRandom(float* dst, size_t n, uint32_t seed) {
    uint32_t s = seed ? seed : 0x12345678u;
    for (size_t i = 0; i < n; ++i) {
        s ^= s << 13; s ^= s >> 17; s ^= s << 5;
        dst[i] = static_cast<float>(s % 1000000u) / 1000000.0f - 0.5f;
    }
}

// ============================================================================
// Test 1: Empty cache query returns zero spans
// ============================================================================
static bool testEmptyCache() {
    LegacyKVCacheAdapter legacy;
    ToroidalKVCacheAdapter toroidal;

    legacy.initialize(2, 64, 4, 16);
    toroidal.initialize(2, 64, 4, 16);

    KVSpan s0{}, s1{};
    size_t n = legacy.querySpans(0, 0, 0, 1, s0, s1);
    TEST_ASSERT(n == 0, "legacy empty cache should return 0 spans");

    n = toroidal.querySpans(0, 0, 0, 1, s0, s1);
    TEST_ASSERT(n == 0, "toroidal empty cache should return 0 spans");

    TEST_PASS("testEmptyCache");
    return true;
}

// ============================================================================
// Test 2: Single token write + readback
// ============================================================================
static bool testSingleToken() {
    const size_t L = 2, H = 4, D = 16, MAX = 64;
    LegacyKVCacheAdapter legacy;
    ToroidalKVCacheAdapter toroidal;
    legacy.initialize(L, MAX, H, D);
    toroidal.initialize(L, MAX, H, D);

    std::vector<float> k(H * D), v(H * D);
    fillRandom(k.data(), k.size(), 1);
    fillRandom(v.data(), v.size(), 2);

    for (size_t layer = 0; layer < L; ++layer) {
        for (size_t h = 0; h < H; ++h) {
            legacy.writeKV(layer, h, k.data() + h * D, v.data() + h * D);
            toroidal.writeKV(layer, h, k.data() + h * D, v.data() + h * D);
        }
    }
    legacy.advance();
    toroidal.advance();

    // Read back layer 0, head 0
    KVSpan ls0{}, ls1{}, ts0{}, ts1{};
    size_t ln = legacy.querySpans(0, 0, 0, 1, ls0, ls1);
    size_t tn = toroidal.querySpans(0, 0, 0, 1, ts0, ts1);
    TEST_ASSERT(ln == 1, "legacy single token should return 1 span");
    TEST_ASSERT(tn == 1, "toroidal single token should return 1 span");
    TEST_ASSERT(ls0.count == 1, "legacy span count");
    TEST_ASSERT(ts0.count == 1, "toroidal span count");
    TEST_ASSERT(arraysNearEqual(ls0.keys,   ts0.keys,   D), "keys mismatch");
    TEST_ASSERT(arraysNearEqual(ls0.values, ts0.values, D), "values mismatch");

    TEST_PASS("testSingleToken");
    return true;
}

// ============================================================================
// Test 3: Multi-token prefill (no wrap)
// ============================================================================
static bool testMultiTokenPrefill() {
    const size_t L = 2, H = 4, D = 16, TOKENS = 10, MAX = 64;
    LegacyKVCacheAdapter legacy;
    ToroidalKVCacheAdapter toroidal;
    legacy.initialize(L, MAX, H, D);
    toroidal.initialize(L, MAX, H, D);

    std::vector<float> k(H * D), v(H * D);
    for (size_t t = 0; t < TOKENS; ++t) {
        fillRandom(k.data(), k.size(), 100u + (uint32_t)t);
        fillRandom(v.data(), v.size(), 200u + (uint32_t)t);
        for (size_t layer = 0; layer < L; ++layer) {
            for (size_t h = 0; h < H; ++h) {
                legacy.writeKV(layer, h, k.data() + h * D, v.data() + h * D);
                toroidal.writeKV(layer, h, k.data() + h * D, v.data() + h * D);
            }
        }
        legacy.advance();
        toroidal.advance();
    }

    // Query full range for layer 1, head 2
    KVSpan ls0{}, ls1{}, ts0{}, ts1{};
    size_t ln = legacy.querySpans(1, 2, 0, TOKENS, ls0, ls1);
    size_t tn = toroidal.querySpans(1, 2, 0, TOKENS, ts0, ts1);
    TEST_ASSERT(ln == 1, "legacy prefill should return 1 span");
    TEST_ASSERT(tn == 1, "toroidal prefill (no wrap) should return 1 span");
    TEST_ASSERT(ls0.count == TOKENS, "legacy span count");
    TEST_ASSERT(ts0.count == TOKENS, "toroidal span count");

    for (size_t t = 0; t < TOKENS; ++t) {
        TEST_ASSERT(arraysNearEqual(ls0.keys   + t * ls0.stride, ts0.keys   + t * ts0.stride, D),
                    "prefill keys mismatch");
        TEST_ASSERT(arraysNearEqual(ls0.values + t * ls0.stride, ts0.values + t * ts0.stride, D),
                    "prefill values mismatch");
    }

    TEST_PASS("testMultiTokenPrefill");
    return true;
}

// ============================================================================
// Test 4: Wrap boundary — force toroidal wrap and verify two-span query
// ============================================================================
static bool testWrapBoundary() {
    const size_t L = 1, H = 2, D = 8, MAX = 4;
    ToroidalKVCacheAdapter toroidal;
    toroidal.initialize(L, MAX, H, D);

    std::vector<float> k(H * D), v(H * D);
    for (size_t t = 0; t < 6; ++t) {  // 6 tokens into capacity 4 → wraps
        fillRandom(k.data(), k.size(), 300u + (uint32_t)t);
        fillRandom(v.data(), v.size(), 400u + (uint32_t)t);
        for (size_t h = 0; h < H; ++h) {
            toroidal.writeKV(0, h, k.data() + h * D, v.data() + h * D);
        }
        toroidal.advance();
    }

    // Oldest 2 tokens should be at positions 2,3 (physical 2,3)
    // Newest 2 tokens should be at positions 4,5 (physical 0,1)
    KVSpan s0{}, s1{};
    size_t n = toroidal.querySpans(0, 0, 0, 4, s0, s1);
    TEST_ASSERT(n == 2, "wrap should produce 2 spans");
    TEST_ASSERT(s0.count == 2, "span0 should cover 2 tokens");
    TEST_ASSERT(s1.count == 2, "span1 should cover 2 tokens");

    // Verify the data is actually different (not all zeros)
    float sum = 0.0f;
    for (size_t i = 0; i < s0.count * D; ++i) sum += std::fabs(s0.keys[i]);
    for (size_t i = 0; i < s1.count * D; ++i) sum += std::fabs(s1.keys[i]);
    TEST_ASSERT(sum > 0.0f, "wrapped data should not be all zero");

    TEST_PASS("testWrapBoundary");
    return true;
}

// ============================================================================
// Test 5: Reset + reuse
// ============================================================================
static bool testResetReuse() {
    const size_t L = 1, H = 2, D = 8, MAX = 16;
    LegacyKVCacheAdapter legacy;
    ToroidalKVCacheAdapter toroidal;
    legacy.initialize(L, MAX, H, D);
    toroidal.initialize(L, MAX, H, D);

    std::vector<float> k(H * D), v(H * D);
    fillRandom(k.data(), k.size(), 500);
    fillRandom(v.data(), v.size(), 600);
    for (size_t h = 0; h < H; ++h) {
        legacy.writeKV(0, h, k.data() + h * D, v.data() + h * D);
        toroidal.writeKV(0, h, k.data() + h * D, v.data() + h * D);
    }
    legacy.advance();
    toroidal.advance();

    legacy.reset();
    toroidal.reset();

    TEST_ASSERT(legacy.currentLength() == 0, "legacy reset length");
    TEST_ASSERT(toroidal.currentLength() == 0, "toroidal reset length");

    // Reuse
    fillRandom(k.data(), k.size(), 700);
    fillRandom(v.data(), v.size(), 800);
    for (size_t h = 0; h < H; ++h) {
        legacy.writeKV(0, h, k.data() + h * D, v.data() + h * D);
        toroidal.writeKV(0, h, k.data() + h * D, v.data() + h * D);
    }
    legacy.advance();
    toroidal.advance();

    KVSpan ls0{}, ls1{}, ts0{}, ts1{};
    legacy.querySpans(0, 0, 0, 1, ls0, ls1);
    toroidal.querySpans(0, 0, 0, 1, ts0, ts1);
    TEST_ASSERT(ls0.count == 1 && ts0.count == 1, "reuse query count");
    TEST_ASSERT(arraysNearEqual(ls0.keys, ts0.keys, D), "reuse keys");
    TEST_ASSERT(arraysNearEqual(ls0.values, ts0.values, D), "reuse values");

    TEST_PASS("testResetReuse");
    return true;
}

// ============================================================================
// Test 6: Deterministic repeated execution
// ============================================================================
static bool testDeterministicRepeat() {
    const size_t L = 2, H = 4, D = 16, TOKENS = 5, MAX = 64;

    auto runOnce = [&](std::vector<float>& outKeys, std::vector<float>& outVals) {
        ToroidalKVCacheAdapter toroidal;
        toroidal.initialize(L, MAX, H, D);
        std::vector<float> k(H * D), v(H * D);
        for (size_t t = 0; t < TOKENS; ++t) {
            fillRandom(k.data(), k.size(), 900u + (uint32_t)t);
            fillRandom(v.data(), v.size(), 1000u + (uint32_t)t);
            for (size_t layer = 0; layer < L; ++layer)
                for (size_t h = 0; h < H; ++h)
                    toroidal.writeKV(layer, h, k.data() + h * D, v.data() + h * D);
            toroidal.advance();
        }
        KVSpan s0{}, s1{};
        toroidal.querySpans(0, 0, 0, TOKENS, s0, s1);
        size_t total = s0.count + s1.count;
        outKeys.resize(total * D);
        outVals.resize(total * D);
        if (s0.count > 0) {
            memcpy(outKeys.data(), s0.keys, s0.count * D * sizeof(float));
            memcpy(outVals.data(), s0.values, s0.count * D * sizeof(float));
        }
        if (s1.count > 0) {
            memcpy(outKeys.data() + s0.count * D, s1.keys, s1.count * D * sizeof(float));
            memcpy(outVals.data() + s0.count * D, s1.values, s1.count * D * sizeof(float));
        }
    };

    std::vector<float> keysA, valsA, keysB, valsB;
    runOnce(keysA, valsA);
    runOnce(keysB, valsB);

    TEST_ASSERT(keysA.size() == keysB.size(), "repeat size");
    TEST_ASSERT(arraysNearEqual(keysA.data(), keysB.data(), keysA.size()), "repeat keys");
    TEST_ASSERT(arraysNearEqual(valsA.data(), valsB.data(), valsA.size()), "repeat values");

    TEST_PASS("testDeterministicRepeat");
    return true;
}

// ============================================================================
// Test 7: Legacy vs Toroidal equivalence over long sequence
// ============================================================================
static bool testLongSequenceEquivalence() {
    const size_t L = 2, H = 4, D = 16, TOKENS = 50, MAX = 64;
    LegacyKVCacheAdapter legacy;
    ToroidalKVCacheAdapter toroidal;
    legacy.initialize(L, MAX, H, D);
    toroidal.initialize(L, MAX, H, D);

    std::vector<float> k(H * D), v(H * D);
    for (size_t t = 0; t < TOKENS; ++t) {
        fillRandom(k.data(), k.size(), 1100u + (uint32_t)t);
        fillRandom(v.data(), v.size(), 1200u + (uint32_t)t);
        for (size_t layer = 0; layer < L; ++layer) {
            for (size_t h = 0; h < H; ++h) {
                legacy.writeKV(layer, h, k.data() + h * D, v.data() + h * D);
                toroidal.writeKV(layer, h, k.data() + h * D, v.data() + h * D);
            }
        }
        legacy.advance();
        toroidal.advance();
    }

    // Spot-check multiple layers/heads
    for (size_t layer : {0, 1}) {
        for (size_t head : {0, 2}) {
            KVSpan ls0{}, ls1{}, ts0{}, ts1{};
            size_t ln = legacy.querySpans(layer, head, 0, TOKENS, ls0, ls1);
            size_t tn = toroidal.querySpans(layer, head, 0, TOKENS, ts0, ts1);
            TEST_ASSERT(ln == tn, "span count mismatch");
            size_t legacyTotal = ls0.count + ls1.count;
            size_t toroTotal   = ts0.count + ts1.count;
            TEST_ASSERT(legacyTotal == toroTotal, "total token count mismatch");

            // Compare flattened with correct stride
            std::vector<float> legacyK(legacyTotal * D), legacyV(legacyTotal * D);
            std::vector<float> toroK(toroTotal * D),   toroV(toroTotal * D);
            if (ls0.count > 0) {
                for (size_t i = 0; i < ls0.count; ++i) {
                    memcpy(legacyK.data() + i * D, ls0.keys   + i * ls0.stride, D * sizeof(float));
                    memcpy(legacyV.data() + i * D, ls0.values + i * ls0.stride, D * sizeof(float));
                }
            }
            if (ls1.count > 0) {
                for (size_t i = 0; i < ls1.count; ++i) {
                    memcpy(legacyK.data() + (ls0.count + i) * D, ls1.keys   + i * ls1.stride, D * sizeof(float));
                    memcpy(legacyV.data() + (ls0.count + i) * D, ls1.values + i * ls1.stride, D * sizeof(float));
                }
            }
            if (ts0.count > 0) {
                for (size_t i = 0; i < ts0.count; ++i) {
                    memcpy(toroK.data() + i * D, ts0.keys   + i * ts0.stride, D * sizeof(float));
                    memcpy(toroV.data() + i * D, ts0.values + i * ts0.stride, D * sizeof(float));
                }
            }
            if (ts1.count > 0) {
                for (size_t i = 0; i < ts1.count; ++i) {
                    memcpy(toroK.data() + (ts0.count + i) * D, ts1.keys   + i * ts1.stride, D * sizeof(float));
                    memcpy(toroV.data() + (ts0.count + i) * D, ts1.values + i * ts1.stride, D * sizeof(float));
                }
            }

            char msg[128];
            snprintf(msg, sizeof(msg), "long-seq keys L=%zu H=%zu", layer, head);
            TEST_ASSERT(arraysNearEqual(legacyK.data(), toroK.data(), legacyTotal * D), msg);
            snprintf(msg, sizeof(msg), "long-seq values L=%zu H=%zu", layer, head);
            TEST_ASSERT(arraysNearEqual(legacyV.data(), toroV.data(), legacyTotal * D), msg);
        }
    }

    TEST_PASS("testLongSequenceEquivalence");
    return true;
}

// ============================================================================
// Test 8: Chamber basic lifecycle
// ============================================================================
static bool testChamberLifecycle() {
    rawrxd::Chamber chamber;
    TEST_ASSERT(!chamber.mirrorInitialized(), "chamber uninitialized");

    std::vector<float> mirror(rawrxd::Chamber::MIRROR_DIM);
    fillRandom(mirror.data(), mirror.size(), 1300);
    bool ok = chamber.initMirror(mirror.data(), mirror.size());
    TEST_ASSERT(ok, "chamber initMirror");
    TEST_ASSERT(chamber.mirrorInitialized(), "chamber initialized");

    // Evaluate against identical vector → PASS
    rawrxd::ChamberResult r = chamber.evaluate(mirror.data(), mirror.size());
    TEST_ASSERT(r == rawrxd::ChamberResult::PASS, "identical vector should PASS");

    // Evaluate against orthogonal vector → CLASH
    std::vector<float> ortho(rawrxd::Chamber::MIRROR_DIM);
    for (size_t i = 0; i < ortho.size(); ++i) ortho[i] = (i % 2 == 0) ? 1.0f : -1.0f;
    r = chamber.evaluate(ortho.data(), ortho.size());
    TEST_ASSERT(r == rawrxd::ChamberResult::CLASH, "orthogonal vector should CLASH");

    // Uninitialized chamber → NOT_READY
    rawrxd::Chamber chamber2;
    r = chamber2.evaluate(mirror.data(), mirror.size());
    TEST_ASSERT(r == rawrxd::ChamberResult::NOT_READY, "uninitialized chamber should NOT_READY");

    TEST_PASS("testChamberLifecycle");
    return true;
}

// ============================================================================
// Test 9: Chamber routing table load-factor enforcement
// ============================================================================
static bool testChamberRoutingTable() {
    rawrxd::Chamber chamber;
    std::vector<float> mirror(rawrxd::Chamber::MIRROR_DIM);
    fillRandom(mirror.data(), mirror.size(), 1400);
    chamber.initMirror(mirror.data(), mirror.size());

    // Insert within load factor
    size_t maxRoutes = static_cast<size_t>(
        rawrxd::Chamber::LOAD_FACTOR_MAX * rawrxd::Chamber::ROUTE_TABLE_SIZE);
    std::vector<rawrxd::FormulaRoute> routes;
    for (size_t i = 0; i < maxRoutes; ++i) {
        rawrxd::FormulaRoute r{};
        r.context_hash = 0x12345678ULL + i * 0x100000001b3ULL;
        r.route_id = static_cast<uint32_t>(i);
        r.valid = true;
        routes.push_back(r);
    }
    bool ok = chamber.populateRoutingTable(routes.data(), routes.size());
    TEST_ASSERT(ok, "routing table should accept within load factor");

    // Lookup each inserted route
    for (size_t i = 0; i < routes.size(); ++i) {
        rawrxd::FormulaRoute found = chamber.routePrimitive(routes[i].context_hash);
        TEST_ASSERT(found.valid, "route should be found");
        TEST_ASSERT(found.route_id == routes[i].route_id, "route_id mismatch");
    }

    // Lookup non-existent route → invalid
    rawrxd::FormulaRoute missing = chamber.routePrimitive(0xDEADBEEFCAFEBABEULL);
    TEST_ASSERT(!missing.valid, "missing route should be invalid");

    // Overload should fail
    routes.push_back(routes.back());  // duplicate hash, but we test load factor
    routes.back().context_hash = 0x9999999999999999ULL;
    ok = chamber.populateRoutingTable(routes.data(), routes.size());
    TEST_ASSERT(!ok, "routing table should reject overload");

    TEST_PASS("testChamberRoutingTable");
    return true;
}

// ============================================================================
// Test 10: Prefill → decode transition
// ============================================================================
static bool testPrefillDecodeTransition() {
    const size_t L = 1, H = 2, D = 8, PREFILL = 5, DECODE = 3, MAX = 16;
    LegacyKVCacheAdapter legacy;
    ToroidalKVCacheAdapter toroidal;
    legacy.initialize(L, MAX, H, D);
    toroidal.initialize(L, MAX, H, D);

    std::vector<float> k(H * D), v(H * D);

    // Prefill phase
    for (size_t t = 0; t < PREFILL; ++t) {
        fillRandom(k.data(), k.size(), 1500u + (uint32_t)t);
        fillRandom(v.data(), v.size(), 1600u + (uint32_t)t);
        for (size_t h = 0; h < H; ++h) {
            legacy.writeKV(0, h, k.data() + h * D, v.data() + h * D);
            toroidal.writeKV(0, h, k.data() + h * D, v.data() + h * D);
        }
        legacy.advance();
        toroidal.advance();
    }

    // Decode phase
    for (size_t t = 0; t < DECODE; ++t) {
        fillRandom(k.data(), k.size(), 1700u + (uint32_t)t);
        fillRandom(v.data(), v.size(), 1800u + (uint32_t)t);
        for (size_t h = 0; h < H; ++h) {
            legacy.writeKV(0, h, k.data() + h * D, v.data() + h * D);
            toroidal.writeKV(0, h, k.data() + h * D, v.data() + h * D);
        }
        legacy.advance();
        toroidal.advance();
    }

    // Query full range
    KVSpan ls0{}, ls1{}, ts0{}, ts1{};
    legacy.querySpans(0, 0, 0, PREFILL + DECODE, ls0, ls1);
    toroidal.querySpans(0, 0, 0, PREFILL + DECODE, ts0, ts1);
    size_t legacyTotal = ls0.count + ls1.count;
    size_t toroTotal   = ts0.count + ts1.count;
    TEST_ASSERT(legacyTotal == PREFILL + DECODE, "legacy total tokens");
    TEST_ASSERT(toroTotal == PREFILL + DECODE, "toroidal total tokens");

    TEST_PASS("testPrefillDecodeTransition");
    return true;
}

// ============================================================================
// Main runner
// ============================================================================
bool RunKVCacheEquivalenceTests(bool verbose) {
    g_verbose = verbose;
    g_passed = 0;
    g_failed = 0;

    printf("\n=== KV Cache Equivalence Tests ===\n");

    testEmptyCache();
    testSingleToken();
    testMultiTokenPrefill();
    testWrapBoundary();
    testResetReuse();
    testDeterministicRepeat();
    testLongSequenceEquivalence();
    testChamberLifecycle();
    testChamberRoutingTable();
    testPrefillDecodeTransition();

    printf("\n=== Results: %d passed, %d failed ===\n", g_passed, g_failed);
    return g_failed == 0;
}

} // namespace Deep2

// ============================================================================
// Standalone main for direct execution
// ============================================================================
#ifdef KV_CACHE_EQUIVALENCE_TEST_MAIN
int main(int argc, char** argv) {
    (void)argc; (void)argv;
    bool ok = Deep2::RunKVCacheEquivalenceTests(true);
    return ok ? 0 : 1;
}
#endif
