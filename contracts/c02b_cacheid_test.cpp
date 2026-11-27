// c02b_cacheid_test.cpp — CPU test: cache identity prevents cross-selection reuse.
#include "reap/ReapSelectionIdentity.hpp"
#include <cstdio>
using namespace RawrXD::Reap;
static int fails = 0;
static void ck(bool ok, const char* n) { std::printf("%s %s\n", ok ? "OK" : "FAIL", n); if (!ok) ++fails; }
int main() {
    uint64_t wkey = 12345;
    uint64_t fpA = SelectionFingerprint({{0,{1,3}}}, 1, 4096, 1);
    uint64_t fpB = SelectionFingerprint({{0,{2,5}}}, 1, 4096, 1);
    uint64_t idA = CacheIdentity(wkey, fpA, true);
    uint64_t idA2 = CacheIdentity(wkey, fpA, true);
    uint64_t idB = CacheIdentity(wkey, fpB, true);
    ck(idA == idA2, "deterministic");
    ck(idA != idB, "cross_selection_differs");
    ck(CacheIdentity(wkey, 0, true) != CacheIdentity(wkey, 0, false), "valid_vs_invalid_domain");
    ck(CacheIdentity(wkey, 0, false) != wkey, "invalid_not_bare_key");   // zero fp invalid != bare key
    std::printf("FAILS=%d\nCACHEID=%s\n", fails, fails ? "FAIL" : "PASS");
    return fails ? 1 : 0;
}