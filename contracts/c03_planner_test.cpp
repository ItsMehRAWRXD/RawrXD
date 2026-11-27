// c03_planner_test.cpp — CPU test for hardware-aware planner.
#include "reap/ReapPlanner.hpp"
#include <cstdio>
using namespace RawrXD::Reap;
static int fails = 0;
static void ck(bool ok, const char* n) { std::printf("%s %s\n", ok ? "OK" : "FAIL", n); if (!ok) ++fails; }
int main() {
    Capacity cap; cap.hostRamBytes = 64ULL<<30; cap.dedicatedVramBytes = 32ULL<<30; cap.sharedVramBytes = 16ULL<<30; cap.devices=1;
    ModelGeom g; g.nonexpertBytes = 2ULL<<30; g.expertBytesTotal = 16ULL<<30; g.kvBytes = 4ULL<<30; g.scratchBytes = 1ULL<<30; g.expertCount = 128;
    auto p = PlanReap(cap, g, 16ULL<<30, 2);   // Streaming, 16GB target
    ck(p.feasible, "stream_feasible");
    ck(p.retainedExperts > 0 && p.retainedExperts <= 128, "retain_range");
    ck(p.peakBytes <= p.availableBytes, "peak_within_capacity");
    // Insufficient memory -> infeasible (base > capacity).
    Capacity tiny; tiny.hostRamBytes = 1ULL<<30; tiny.dedicatedVramBytes=0; tiny.sharedVramBytes=0;
    auto p2 = PlanReap(tiny, g, 0, 1);
    ck(!p2.feasible, "reject_insufficient");
    // Overflow-safe: huge sizes -> infeasible, not wrap.
    ModelGeom big = g; big.nonexpertBytes = ~0ULL; big.kvBytes = ~0ULL;
    auto p3 = PlanReap(cap, big, 0, 1);
    ck(!p3.feasible, "overflow_rejected");
    std::printf("FAILS=%d\nC03_PLANNER=%s\n", fails, fails ? "FAIL" : "PASS");
    return fails ? 1 : 0;
}