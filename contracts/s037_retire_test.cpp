// s037_retire_test.cpp — CPU test: retirement ledger + cancellation.
#include "reap/ReapRetirement.hpp"
#include <cstdio>
using namespace RawrXD::Reap;
static int fails = 0;
static void ck(bool ok, const char* n) { std::printf("%s %s\n", ok ? "OK" : "FAIL", n); if (!ok) ++fails; }
int main() {
    RetirementLedger l;
    l.Retire(100); l.Retire(50);
    ck(l.Pending() == 150, "pending150");
    l.Complete(100);
    ck(l.Pending() == 50, "pending50_after_complete");
    l.Complete(999);   // over-complete clamps to 0
    ck(l.Pending() == 0, "clamp_zero");
    ck(!l.Cancelled(), "not_cancelled");
    l.Cancel();
    ck(l.Cancelled(), "cancelled");
    std::printf("FAILS=%d\nS037_RETIRE=%s\n", fails, fails ? "FAIL" : "PASS");
    return fails ? 1 : 0;
}