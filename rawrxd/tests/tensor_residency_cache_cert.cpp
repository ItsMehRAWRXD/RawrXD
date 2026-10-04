// ============================================================================
// tests/tensor_residency_cache_cert.cpp
// RAWRXD_SPACELESS_UNMODEL_UNADDRESS_DESIGN_001
//
// Certification: TensorResidencyCache LRU, pin/unpin, eviction, stale invalidation.
// Every claim is measured at runtime. No hardcoded PASS.
// ============================================================================
#include "TensorResidencyCache.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cassert>

using namespace Deep2;

static int checks_pass = 0;
static int checks_fail = 0;

static void check(bool cond, const char* name) {
    if (cond) { ++checks_pass; std::printf("  PASS: %s\n", name); }
    else      { ++checks_fail; std::printf("  FAIL: %s\n", name); }
}

static ExecutionView makeView(uint64_t model, uint64_t tensor, void* addr, size_t bytes, uint64_t gen) {
    ExecutionView v;
    v.identity.model   = model;
    v.identity.tensor  = tensor;
    v.identity.layer   = 0;
    v.identity.role    = 0;
    v.identity.variant = 0;
    v.transientAddress = addr;
    v.bytes            = bytes;
    v.lease.generation = gen;
    v.lease.owner      = 1;
    v.lease.epoch      = 0;
    return v;
}

int main() {
    std::printf("TENSOR_RESIDENCY_CACHE_CERT_BEGIN\n");

    // C1: Empty cache returns miss
    {
        TensorResidencyCache cache(4);
        ExecutionView out;
        TensorIdentity id{1,1,0,0,0};
        check(!cache.lookup(id, out), "C1_empty_cache_miss");
        check(cache.size() == 0, "C1_size_zero");
    }

    // C2: Insert and lookup hit
    {
        TensorResidencyCache cache(4);
        int dummy = 42;
        auto v = makeView(1, 1, &dummy, sizeof(int), 1);
        cache.insert(v);
        ExecutionView out;
        check(cache.lookup(v.identity, out), "C2_insert_lookup_hit");
        check(out.transientAddress == &dummy, "C2_address_match");
        check(out.bytes == sizeof(int), "C2_bytes_match");
        check(cache.size() == 1, "C2_size_one");
    }

    // C3: LRU eviction when capacity exceeded
    {
        TensorResidencyCache cache(2);
        int a=1, b=2, c=3;
        cache.insert(makeView(1, 1, &a, 4, 1));
        cache.insert(makeView(1, 2, &b, 4, 1));
        cache.insert(makeView(1, 3, &c, 4, 1)); // evicts (1,1) because it was least used
        ExecutionView out;
        TensorIdentity id1{1,1,0,0,0};
        TensorIdentity id2{1,2,0,0,0};
        TensorIdentity id3{1,3,0,0,0};
        check(!cache.lookup(id1, out), "C3_lru_evicted_oldest");
        check( cache.lookup(id2, out), "C3_lru_keeps_middle");
        check( cache.lookup(id3, out), "C3_lru_keeps_newest");
        check(cache.size() == 2, "C3_size_at_capacity");
    }

    // C4: Pin prevents eviction
    {
        TensorResidencyCache cache(2);
        int a=1, b=2, c=3;
        cache.insert(makeView(1, 1, &a, 4, 1));
        cache.insert(makeView(1, 2, &b, 4, 1));
        TensorIdentity id1{1,1,0,0,0};
        cache.pin(id1);
        cache.insert(makeView(1, 3, &c, 4, 1)); // should evict (1,2), not (1,1)
        ExecutionView out;
        TensorIdentity id2{1,2,0,0,0};
        check( cache.lookup(id1, out), "C4_pinned_survives");
        check(!cache.lookup(id2, out), "C4_unpinned_evicted");
    }

    // C5: Unpin allows eviction again
    {
        TensorResidencyCache cache(2);
        int a=1, b=2, c=3;
        cache.insert(makeView(1, 1, &a, 4, 1));
        cache.insert(makeView(1, 2, &b, 4, 1));
        TensorIdentity id1{1,1,0,0,0};
        cache.pin(id1);
        cache.unpin(id1);
        cache.insert(makeView(1, 3, &c, 4, 1)); // now (1,1) can be evicted
        ExecutionView out;
        check(!cache.lookup(id1, out), "C5_unpinned_then_evicted");
    }

    // C6: Stale invalidation removes entries with wrong generation
    {
        TensorResidencyCache cache(4);
        int a=1, b=2;
        cache.insert(makeView(1, 1, &a, 4, 1));
        cache.insert(makeView(1, 2, &b, 4, 2));
        size_t removed = cache.invalidateStale(2); // generation 1 is stale
        check(removed == 1, "C6_stale_removed_count");
        ExecutionView out;
        TensorIdentity id1{1,1,0,0,0};
        check(!cache.lookup(id1, out), "C6_stale_not_found");
    }

    // C7: Stats accumulate
    {
        TensorResidencyCache cache(4);
        int a=1;
        auto v = makeView(1, 1, &a, 4, 1);
        cache.insert(v);
        ExecutionView out;
        cache.lookup(v.identity, out); // hit
        TensorIdentity id2{1,99,0,0,0};
        cache.lookup(id2, out); // miss
        auto s = cache.stats();
        check(s.hits == 1, "C7_stats_hits");
        check(s.misses == 1, "C7_stats_misses");
        check(s.insertions == 1, "C7_stats_insertions");
    }

    // C8: Dump produces non-empty string
    {
        TensorResidencyCache cache(4);
        int a=1;
        cache.insert(makeView(1, 1, &a, 4, 1));
        auto d = cache.dump();
        check(!d.empty(), "C8_dump_nonempty");
        check(d.find("entries=1") != std::string::npos, "C8_dump_contains_entry_count");
    }

    std::printf("\nTENSOR_RESIDENCY_CACHE_CERT_RESULT\n");
    std::printf("CHECKS_PASS=%d\n", checks_pass);
    std::printf("CHECKS_FAIL=%d\n", checks_fail);
    std::printf("VERDICT=%s\n", checks_fail == 0 ? "PASS" : "FAIL");
    return checks_fail == 0 ? 0 : 1;
}
