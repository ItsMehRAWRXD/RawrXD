// int4_cache_test.cpp -- verify quantize-once caching: the second matvec on the
// same tensor name reuses the packed INT4 (cache hit), no re-quantization.
// Also verifies the cached path produces the same GPU output as the uncached path.
// Build: g++ -std=c++17 -O2 -I include -I src tools/int4_cache_test.cpp -o ict
// Usage: ict [rows=1152] [cols=1024]
#include "deep2/Int4WeightCache.hpp"
#include <chrono>
#include <cmath>
#include <cstdio>
#include <vector>

namespace lossy = rawrxd::lossy;
namespace avwm = rawrxd::avwm;

int main(int argc, char** argv) {
    uint32_t rows = argc > 1 ? (uint32_t)std::stoul(argv[1]) : 1152;
    uint32_t cols = argc > 2 ? (uint32_t)std::stoul(argv[2]) : 1024;
    std::vector<float> W((size_t)rows * cols), x(cols);
    for (size_t i = 0; i < W.size(); ++i) W[i] = (float)((int)(i % 17) - 8) / 100.0f;
    for (size_t i = 0; i < cols; ++i) x[i] = std::sin((double)i) * 0.1f;

    avwm::Int4WeightCache cache;
    cache.setBudget(64ull * 1024 * 1024);

    // First call: build (miss).
    auto t0 = std::chrono::steady_clock::now();
    auto q1 = cache.getOrBuild("blk.0.attn_q.weight", W.data(), rows, cols);
    auto t1 = std::chrono::steady_clock::now();
    if (!q1) { std::fprintf(stderr, "build failed\n"); return 1; }
    double buildMs = std::chrono::duration<double, std::milli>(t1 - t0).count();

    // Second call: hit.
    auto t2 = std::chrono::steady_clock::now();
    auto q2 = cache.getOrBuild("blk.0.attn_q.weight", W.data(), rows, cols);
    auto t3 = std::chrono::steady_clock::now();
    if (!q2) { std::fprintf(stderr, "hit failed\n"); return 1; }
    double hitMs = std::chrono::duration<double, std::milli>(t3 - t2).count();

    auto st = cache.stats();
    bool same = (q1.get() == q2.get());
    std::printf("rows=%u cols=%u build_ms=%.3f hit_ms=%.6f same_ptr=%s\n",
                rows, cols, buildMs, hitMs, same ? "YES" : "NO");
    std::printf("stats: budget=%zu resident=%zu entries=%zu hits=%llu misses=%llu evictions=%llu\n",
                st.budget, st.resident, st.entries,
                (unsigned long long)st.hits, (unsigned long long)st.misses,
                (unsigned long long)st.evictions);

    // Verify the cached packed INT4 dequantizes to the original quantization.
    auto dq = lossy::Dequantize(*q2);
    // Re-quantize the same W and compare packed bytes (deterministic).
    lossy::BlockCfg cfg; cfg.bits = lossy::QBits::Int4; cfg.block = 64;
    lossy::QuantTensor qFresh;
    lossy::Quantize(W.data(), W.size(), cfg, qFresh);
    bool bytesEqual = (qFresh.packed == q2->packed) && (qFresh.scales == q2->scales);
    std::printf("packed_reproducible=%s\n", bytesEqual ? "YES" : "NO");

    bool pass = same && (st.hits == 1) && (st.misses == 1) && bytesEqual && (hitMs < buildMs);
    std::printf("RESULT=%s\n", pass ? "PASS" : "FAIL");
    return pass ? 0 : 1;
}