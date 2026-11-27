// a04_gate_test.cpp — negative acceptance tests (objective-derived gate).
#include "reap/AcceptanceGate.hpp"
#include <cstdio>
using namespace RawrXD::Reap;
static int fails = 0;
static void ck(bool ok, const char* n) { std::printf("%s %s\n", ok ? "OK" : "FAIL", n); if (!ok) ++fails; }
int main() {
    auto calc = DeriveExpected("Build calc.cpp using Win32; produce calc.exe");
    ck(calc.src=="calc.cpp" && calc.exe=="calc.exe", "derive_calc");
    // Correct calc: src+exe created, real API, compiled -> PASS.
    ck(VerifyAcceptance(calc, true, true, true, true, true, true), "calc_pass");
    // Stale exe (pre-existing, not created) -> FAIL.
    ck(!VerifyAcceptance(calc, true, true, true, false, true, true), "stale_exe_fail");
    // Failed compilation -> FAIL.
    ck(!VerifyAcceptance(calc, true, false, true, false, true, false), "compile_fail");
    // Missing source -> FAIL.
    ck(!VerifyAcceptance(calc, false, false, false, false, false, false), "missing_fail");
    std::printf("FAILS=%d\nA04_GATE=%s\n", fails, fails?"FAIL":"PASS");
    return fails?1:0;
}