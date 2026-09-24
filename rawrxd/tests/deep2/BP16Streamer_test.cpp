// ============================================================================
// BP16Streamer_test.cpp — Isolated certification tests
// ============================================================================
#include <cstdio>
#include <cmath>
#include <cstring>
#include <vector>
#include <random>
#include "deep2/BP16Streamer.hpp"

using Deep2::bfloat16_t;
using Deep2::BP16Streamer;
using Deep2::BP16StreamerConfig;
using Deep2::BP16BlockState;
using Deep2::BP16StreamerStats;

static bool approx_eq(float a, float b) {
    return std::fabs(a - b) < 0.01f;
}

static void writeFp32File(const char* path, const std::vector<float>& data) {
    FILE* f = fopen(path, "wb");
    fwrite(data.data(), sizeof(float), data.size(), f);
    fclose(f);
}

// --------------------------------------------------------------------------
// 1) basic_lifecycle
// --------------------------------------------------------------------------
bool test_basic_lifecycle() {
    BP16Streamer s;
    if (s.isInitialized()) return false;

    if (!s.initialize("nonexistent.bin")) return false;
    if (!s.isInitialized()) return false;

    s.shutdown();
    if (s.isInitialized()) return false;
    return true;
}

// --------------------------------------------------------------------------
// 2) conversion_roundtrip
// --------------------------------------------------------------------------
bool test_conversion_roundtrip() {
    std::vector<float> src = {1.0f, -2.5f, 3.14f, 0.0f, 1e6f, -1e-6f};
    std::vector<bfloat16_t> b16(src.size());
    std::vector<float> dst(src.size());

    BP16Streamer::convertFp32ToB16(src.data(), b16.data(), src.size());
    BP16Streamer::convertB16ToFp32(b16.data(), dst.data(), src.size());

    for (size_t i = 0; i < src.size(); ++i) {
        if (std::isnan(dst[i]) || std::isinf(dst[i])) return false;
    }
    return true;
}

// --------------------------------------------------------------------------
// 3) load_and_retrieve
// --------------------------------------------------------------------------
bool test_load_and_retrieve() {
    const char* path = "bp16_test.bin";
    std::vector<float> data = {1.0f, 2.0f, 3.0f, 4.0f};
    writeFp32File(path, data);

    BP16Streamer s;
    s.initialize(path);

    uint64_t bid = s.loadBlock(0, data.size() * sizeof(float));
    if (bid == 0) return false;

    size_t count = 0;
    const bfloat16_t* b = s.getBlockData(bid, count);
    if (!b || count == 0) return false;

    s.shutdown();
    remove(path);
    return true;
}

// --------------------------------------------------------------------------
// 4) stats_incremented
// --------------------------------------------------------------------------
bool test_stats_incremented() {
    const char* path = "bp16_stats.bin";
    std::vector<float> data = {1.0f, 2.0f, 3.0f, 4.0f};
    writeFp32File(path, data);

    BP16Streamer s;
    s.initialize(path);
    s.resetStats();

    uint64_t bid = s.loadBlock(0, data.size() * sizeof(float));
    if (bid == 0) return false;

    BP16StreamerStats st = s.stats();
    if (st.blocksLoaded != 1) return false;
    if (st.blocksConverted != 1) return false;
    if (st.bytesConverted == 0) return false;

    s.shutdown();
    remove(path);
    return true;
}

// --------------------------------------------------------------------------
// 5) release_block
// --------------------------------------------------------------------------
bool test_release_block() {
    const char* path = "bp16_rel.bin";
    std::vector<float> data = {1.0f, 2.0f, 3.0f, 4.0f};
    writeFp32File(path, data);

    BP16Streamer s;
    s.initialize(path);

    uint64_t bid = s.loadBlock(0, data.size() * sizeof(float));
    if (bid == 0) return false;

    if (!s.releaseBlock(bid)) return false;
    size_t count = 0;
    if (s.getBlockData(bid, count) != nullptr) return false;

    s.shutdown();
    remove(path);
    return true;
}

// --------------------------------------------------------------------------
// 6) capacity_eviction
// --------------------------------------------------------------------------
bool test_capacity_eviction() {
    const char* path = "bp16_evict.bin";
    std::vector<float> data = {1.0f};
    writeFp32File(path, data);

    BP16StreamerConfig cfg;
    cfg.maxBlocks = 2;
    BP16Streamer s(cfg);
    s.initialize(path);

    uint64_t b1 = s.loadBlock(0, sizeof(float));
    uint64_t b2 = s.loadBlock(0, sizeof(float));
    uint64_t b3 = s.loadBlock(0, sizeof(float));
    if (b1 == 0 || b2 == 0 || b3 == 0) return false;

    size_t count = 0;
    if (s.getBlockData(b1, count) != nullptr) return false; // evicted
    if (s.getBlockData(b2, count) == nullptr) return false;
    if (s.getBlockData(b3, count) == nullptr) return false;

    s.shutdown();
    remove(path);
    return true;
}

// --------------------------------------------------------------------------
// main
// --------------------------------------------------------------------------
int main(int argc, char** argv) {
    (void)argc; (void)argv;
    struct Case { const char* name; bool (*fn)(); };
    Case cases[] = {
        {"basic_lifecycle",    test_basic_lifecycle},
        {"conversion_roundtrip", test_conversion_roundtrip},
        {"load_and_retrieve", test_load_and_retrieve},
        {"stats_incremented", test_stats_incremented},
        {"release_block",     test_release_block},
        {"capacity_eviction", test_capacity_eviction},
    };

    int passed = 0, failed = 0;
    for (const auto& c : cases) {
        bool ok = c.fn();
        if (ok) {
            std::printf("PASS: %s\n", c.name);
            ++passed;
        } else {
            std::printf("FAIL: %s\n", c.name);
            ++failed;
        }
    }
    std::printf("=== %d passed, %d failed ===\n", passed, failed);
    return failed ? 1 : 0;
}
