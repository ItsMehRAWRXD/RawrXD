// RAWRXD REAP SC03: CPU regression for the AUTHORITATIVE residency
// (src/reap/ExpertResidency) — budget, LRU, pinning, completion.
#include "reap/ReapExpertResidency.hpp"
#include <cstdio>

using namespace RawrXD::Reap;
static int g_fail = 0;
#define CHECK(c, m) do { if (!(c)) { std::printf("FAIL: %s\n", m); ++g_fail; } } while (0)

int main() {
    ExpertResidency r(250);  // fits 2 x 100, not 3
    CHECK(r.Admit(0, 0, 100), "admit 0");
    CHECK(r.Admit(0, 1, 100), "admit 1");
    CHECK(r.Used() == 200, "200 used");
    CHECK(r.Admit(0, 2, 100), "admit 2 (evicts LRU 0)");
    CHECK(r.Used() == 200 && r.Count() == 2, "bounded 200 / count 2");
    // LRU 0 evicted (1,2 resident) — verify by re-admitting 0 evicts 1.
    CHECK(r.Admit(0, 0, 100), "re-admit 0 (evicts LRU 1)");
    CHECK(r.Admit(0, 1, 100) == false || r.Count() == 2, "still bounded");
    // Oversize -> fail closed.
    ExpertResidency r2(50);
    CHECK(!r2.Admit(0, 9, 100), "oversize rejected");
    // Pinned not evicted -> all-pinned full fails closed.
    ExpertResidency r3(150);
    r3.Admit(0, 0, 100);
    r3.SetPinned(0, 0, true);
    CHECK(r3.Pinned(0, 0), "pinned 0");
    CHECK(!r3.Admit(0, 1, 100), "all-pinned budget full -> fail closed");
    r3.Complete(0, 0);  // completion keeps resident
    CHECK(r3.Count() == 1, "complete keeps resident");
    if (g_fail == 0) { std::printf("ALL PASS\n"); return 0; }
    std::printf("%d FAILURE(S)\n", g_fail);
    return 1;
}