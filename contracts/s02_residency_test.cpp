// s02_residency_test.cpp — CPU test for bounded expert residency (LRU + budget).
#include "reap/ReapExpertResidency.hpp"
#include <cstdio>
using namespace RawrXD::Reap;
static int fails = 0;
static void ck(bool ok, const char* n) { std::printf("%s %s\n", ok ? "OK" : "FAIL", n); if (!ok) ++fails; }
int main() {
    ExpertResidency r(100);            // 100-byte budget
    ck(r.Admit(0, 0, 40), "admit0");
    ck(r.Admit(0, 1, 40), "admit1");
    ck(r.Used() == 80 && r.Count() == 2, "used80");
    ck(r.Admit(0, 2, 40), "admit2_evicts_lru");   // evicts expert0 (LRU)
    ck(r.Used() == 80 && r.Count() == 2, "still80");
    ck(!r.Admit(0, 3, 200), "reject_oversize");   // single expert > budget
    ck(r.Used() == 80, "unchanged_after_reject");
    std::printf("FAILS=%d\nS02_RESIDENCY=%s\n", fails, fails ? "FAIL" : "PASS");
    return fails ? 1 : 0;
}