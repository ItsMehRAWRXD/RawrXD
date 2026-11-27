// s038_admission_test.cpp — CPU test: hardware-aware admission + retirement.
#include "reap/ReapAdmission.hpp"
#include <cstdio>
using namespace RawrXD::Reap;
static int fails = 0;
static void ck(bool ok, const char* n) { std::printf("%s %s\n", ok ? "OK" : "FAIL", n); if (!ok) ++fails; }
int main() {
    Capacity cap; cap.hostRamBytes=64ULL<<30; cap.dedicatedVramBytes=32ULL<<30; cap.sharedVramBytes=16ULL<<30; cap.devices=1;
    ModelGeom g; g.nonexpertBytes=2ULL<<30; g.expertBytesTotal=16ULL<<30; g.kvBytes=4ULL<<30; g.scratchBytes=1ULL<<30; g.expertCount=128;
    auto a = Admit(cap, g, 16ULL<<30, 2, 0);            // Streaming, no retirement
    ck(a.admit, "admit_stream");
    // Pending retirement pushes over capacity -> reject (no silent fallback).
    auto b = Admit(cap, g, 16ULL<<30, 2, 50ULL<<30);
    ck(!b.admit, "reject_retirement_pressure");
    // Tiny capacity -> infeasible.
    Capacity tiny; tiny.hostRamBytes=1ULL<<30; tiny.dedicatedVramBytes=0; tiny.sharedVramBytes=0;
    auto c = Admit(tiny, g, 0, 1, 0);
    ck(!c.admit, "reject_infeasible");
    std::printf("FAILS=%d\nS038_ADMISSION=%s\n", fails, fails ? "FAIL" : "PASS");
    return fails ? 1 : 0;
}