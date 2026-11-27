// idcache_test.cpp — CPU test: identity-keyed cache (no cross-id reuse, LRU eviction).
#include "reap/ReapIdentityCache.hpp"
#include "reap/ReapSelectionIdentity.hpp"
#include <cstdio>
using namespace RawrXD::Reap;
static int fails = 0;
static void ck(bool ok, const char* n) { std::printf("%s %s\n", ok ? "OK" : "FAIL", n); if (!ok) ++fails; }
int main() {
    uint64_t w = 100;
    uint64_t idA = CacheIdentity(w, SelectionFingerprint({{0,{1,3}}}, 1, 4096, 1), true);
    uint64_t idB = CacheIdentity(w, SelectionFingerprint({{0,{2,5}}}, 1, 4096, 1), true);
    IdentityCache c(2);
    c.Insert(idA);
    ck(c.Lookup(idA), "hit_A");
    ck(!c.Lookup(idB), "miss_B");   // different selection => no cross reuse
    c.Insert(idB); c.Insert(idA);   // refresh A, then insert B (size 2)
    c.Insert(idA + 1);              // third distinct -> evict LRU (B)
    ck(!c.Lookup(idB), "B_evicted");
    ck(c.Lookup(idA), "A_retained");
    ck(c.Size() == 2, "bounded_size");
    std::printf("FAILS=%d\nIDCACHE=%s\n", fails, fails ? "FAIL" : "PASS");
    return fails ? 1 : 0;
}