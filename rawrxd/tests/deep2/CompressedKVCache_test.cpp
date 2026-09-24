// ============================================================================
// CompressedKVCache_test.cpp — Isolated certification tests
// ============================================================================
#include <cstdio>
#include <cmath>
#include <vector>
#include "deep2/CompressedKVCache.h"

using Deep2::CompressedKVCache;
using Deep2::CompressedKVConfig;
using Deep2::KVQuantType;
using Deep2::CompressedKVStats;

static std::vector<float> makeSine(size_t count) {
    std::vector<float> v(count);
    for (size_t i = 0; i < count; ++i)
        v[i] = std::sinf(static_cast<float>(i) * 0.1f);
    return v;
}

// --------------------------------------------------------------------------
// 1) basic_lifecycle
// --------------------------------------------------------------------------
bool test_basic_lifecycle() {
    CompressedKVCache c;
    if (c.isInitialized()) return false;
    if (!c.initialize(2, 4, 64, 128)) return false;
    if (!c.isInitialized()) return false;
    c.shutdown();
    if (c.isInitialized()) return false;
    return true;
}

// --------------------------------------------------------------------------
// 2) encode_decode_q8
// --------------------------------------------------------------------------
bool test_encode_decode_q8() {
    CompressedKVConfig cfg;
    cfg.quantType = KVQuantType::KV_Q8_0;
    cfg.maxEntries = 10;
    CompressedKVCache c(cfg);
    c.initialize(1, 1, 16, 4);
    auto v = makeSine(16);
    if (!c.encode(0, 0, 0, v.data(), v.size())) return false;
    std::vector<float> out(16);
    if (!c.decode(0, 0, 0, out.data(), out.size())) return false;
    c.shutdown();
    return true;
}

// --------------------------------------------------------------------------
// 3) parity_test
// --------------------------------------------------------------------------
bool test_parity_test() {
    CompressedKVConfig cfg;
    cfg.quantType = KVQuantType::KV_Q8_0;
    CompressedKVCache c(cfg);
    c.initialize(1, 1, 32, 4);
    auto v = makeSine(32);
    if (!c.parityTest(v.data(), v.size(), 0.05f)) return false;
    c.shutdown();
    return true;
}

// --------------------------------------------------------------------------
// 4) stats_accounting
// --------------------------------------------------------------------------
bool test_stats_accounting() {
    CompressedKVConfig cfg;
    cfg.quantType = KVQuantType::KV_Q8_0;
    cfg.maxEntries = 10;
    CompressedKVCache c(cfg);
    c.initialize(1, 1, 8, 4);
    c.resetStats();
    auto v = makeSine(8);
    c.encode(0, 0, 0, v.data(), v.size());
    c.decode(0, 0, 0, v.data(), v.size());
    CompressedKVStats st = c.stats();
    if (st.entriesTotal != 1) return false;
    if (st.hits != 1) return false;
    if (st.misses != 0) return false;
    if (st.bytesCompressed == 0) return false;
    if (st.bytesOriginal == 0) return false;
    c.shutdown();
    return true;
}

// --------------------------------------------------------------------------
// 5) eviction
// --------------------------------------------------------------------------
bool test_eviction() {
    CompressedKVConfig cfg;
    cfg.quantType = KVQuantType::KV_Q8_0;
    cfg.maxEntries = 2;
    CompressedKVCache c(cfg);
    c.initialize(1, 1, 8, 4);
    auto v = makeSine(8);
    c.encode(0, 0, 0, v.data(), v.size());
    c.encode(0, 1, 0, v.data(), v.size());
    c.encode(0, 2, 0, v.data(), v.size());
    if (c.currentEntryCount() > 2) return false;
    c.shutdown();
    return true;
}

// --------------------------------------------------------------------------
// 6) touch_and_lru
// --------------------------------------------------------------------------
bool test_touch_and_lru() {
    CompressedKVConfig cfg;
    cfg.quantType = KVQuantType::KV_Q8_0;
    cfg.maxEntries = 2;
    CompressedKVCache c(cfg);
    c.initialize(1, 1, 8, 4);
    auto v = makeSine(8);
    c.encode(0, 0, 0, v.data(), v.size());
    c.encode(0, 1, 0, v.data(), v.size());
    if (!c.touch(0, 0, 0)) return false; // touch oldest to front
    c.encode(0, 2, 0, v.data(), v.size());
    std::vector<float> out(8);
    if (!c.decode(0, 0, 0, out.data(), out.size())) return false; // should survive
    c.shutdown();
    return true;
}

// --------------------------------------------------------------------------
// main
// --------------------------------------------------------------------------
int main(int argc, char** argv) {
    (void)argc; (void)argv;
    struct Case { const char* name; bool (*fn)(); };
    Case cases[] = {
        {"basic_lifecycle",  test_basic_lifecycle},
        {"encode_decode_q8", test_encode_decode_q8},
        {"parity_test",      test_parity_test},
        {"stats_accounting", test_stats_accounting},
        {"eviction",         test_eviction},
        {"touch_and_lru",    test_touch_and_lru},
    };
    int passed = 0, failed = 0;
    for (const auto& c : cases) {
        bool ok = c.fn();
        if (ok) { std::printf("PASS: %s\n", c.name); ++passed; }
        else    { std::printf("FAIL: %s\n", c.name); ++failed; }
    }
    std::printf("=== %d passed, %d failed ===\n", passed, failed);
    return failed ? 1 : 0;
}
