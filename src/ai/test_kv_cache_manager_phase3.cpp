// test_kv_cache_manager_phase3.cpp
// Phase 3 smoke test for hash-based KV cache behavior.

#include "kv_cache_manager.h"

#include <cstdio>
#include <vector>

using namespace RawrXD;

static std::vector<float> MakeKV(size_t n, float seed) {
    std::vector<float> out(n);
    for (size_t i = 0; i < n; ++i) {
        out[i] = seed + static_cast<float>(i % 13) * 0.01f;
    }
    return out;
}

int main() {
    printf("=== KV Cache Manager Phase3 Smoke ===\n");

    // Keep limits tiny so eviction paths are exercised deterministically.
    KVCacheManager mgr(/*max_entries=*/3, /*max_memory_mb=*/1);

    const std::string file = "d:/rawrxd/src/ai/test.cpp";

    const ContextHash h1 = mgr.HashContext(file, "prefix_a", 10, 4);
    const ContextHash h2 = mgr.HashContext(file, "prefix_b", 10, 5);
    const ContextHash h3 = mgr.HashContext(file, "prefix_c", 10, 6);
    const ContextHash h4 = mgr.HashContext(file, "prefix_d", 10, 7);

    mgr.StoreCache(h1, {1, 2, 3}, MakeKV(4096, 1.0f));
    mgr.StoreCache(h2, {1, 2, 4}, MakeKV(4096, 2.0f));
    mgr.StoreCache(h3, {1, 2, 5}, MakeKV(4096, 3.0f));

    if (!mgr.HasCache(h1) || !mgr.HasCache(h2) || !mgr.HasCache(h3)) {
        fprintf(stderr, "FATAL: initial cache inserts missing\n");
        return 1;
    }

    // Exercise hit accounting.
    const KVCacheEntry* e2 = mgr.GetCache(h2);
    if (!e2 || e2->token_ids.size() != 3) {
        fprintf(stderr, "FATAL: expected cache hit for h2\n");
        return 1;
    }

    // Trigger eviction by entry cap.
    mgr.StoreCache(h4, {1, 2, 6}, MakeKV(4096, 4.0f));

    const KVCacheStats stats = mgr.GetStats();
    printf("entries=%d hits=%d misses=%d evictions=%d hit_rate=%.3f mem=%zu bytes\n",
           stats.total_entries,
           stats.cache_hits,
           stats.cache_misses,
           stats.cache_evictions,
           stats.hit_rate,
           stats.total_memory_bytes);

    if (stats.total_entries > 3) {
        fprintf(stderr, "FATAL: entry cap violated\n");
        return 1;
    }

    if (stats.cache_hits < 1) {
        fprintf(stderr, "FATAL: expected at least one cache hit\n");
        return 1;
    }

    if (stats.cache_evictions < 1) {
        fprintf(stderr, "FATAL: expected at least one eviction\n");
        return 1;
    }

    printf("=== KV cache smoke PASSED ===\n");
    return 0;
}
