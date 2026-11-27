// s036g_resv_test.cpp — CPU test: reserve-before-allocate + rollback.
#include "reap/ReapDeviceReservation.hpp"
#include <cstdio>
using namespace RawrXD::Reap;
static int fails = 0;
static void ck(bool ok, const char* n) { std::printf("%s %s\n", ok ? "OK" : "FAIL", n); if (!ok) ++fails; }
int main() {
    DeviceReservation r(100);
    ck(r.Reserve(40), "reserve40");
    ck(r.Reserved()==40, "reserved40");
    ck(r.Reserve(40), "reserve40b");
    ck(!r.Reserve(40), "reject_over_budget");   // 80+40 > 100
    r.Rollback(40);                              // not allocated
    ck(r.Reserved()==40, "after_rollback40");
    r.Commit(40);                                // allocated
    ck(r.Reserved()==0, "after_commit0");
    std::printf("FAILS=%d\nS036G_RESV=%s\n", fails, fails?"FAIL":"PASS");
    return fails?1:0;
}