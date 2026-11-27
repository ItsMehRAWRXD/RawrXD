// RAWRXD REAP (Streaming): CPU regression for bounded expert residency.
#include "deep2/ReapStreamResidency.hpp"
#include <cstdio>
#include <string>

using namespace RawrXD::Reap;
static int g_fail = 0;
#define CHECK(c, m) do { if (!(c)) { std::printf("FAIL: %s\n", m); ++g_fail; } } while (0)

int main() {
    std::string e;
    StreamResidency r(250);  // budget fits 2 x 100, not 3
    CHECK(r.Admit(0, 100, e), "admit 0");
    CHECK(r.Admit(1, 100, e), "admit 1");
    CHECK(r.ResidentBytes() == 200, "200 resident");
    CHECK(r.Admit(2, 100, e), "admit 2 (evicts LRU 0)");
    CHECK(r.ResidentBytes() == 200, "still 200 (bounded)");
    CHECK(!r.Resident(0) && r.Resident(1) && r.Resident(2), "LRU 0 evicted; 1,2 resident");
    CHECK(r.Count() == 2, "count 2 (never full bank)");
    // Single expert exceeds budget -> fail closed.
    StreamResidency r2(50);
    CHECK(!r2.Admit(9, 100, e), "expert exceeds budget rejected");
    // Pinned expert not evicted -> budget full fails closed.
    StreamResidency r3(150);
    r3.Admit(0, 100, e); r3.SetPinned(0, true);
    CHECK(!r3.Admit(1, 100, e), "all-pinned budget full -> fail closed");
    if (g_fail == 0) { std::printf("ALL PASS\n"); return 0; }
    std::printf("%d FAILURE(S)\n", g_fail);
    return 1;
}