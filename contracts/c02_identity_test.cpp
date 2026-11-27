// c02_identity_test.cpp — CPU test for deterministic transformation identity.
#include "reap/ReapSelectionIdentity.hpp"
#include <cstdio>
using namespace RawrXD::Reap;
static int fails = 0;
static void ck(bool ok, const char* n) { std::printf("%s %s\n", ok ? "OK" : "FAIL", n); if (!ok) ++fails; }
int main() {
    ExpertSelection a{{0,{1,3,5}}};
    ExpertSelection b{{0,{1,3,5}}};
    ExpertSelection c{{0,{1,3,7}}};   // different selection
    uint64_t fa = SelectionFingerprint(a, 42, 4096, 1);
    uint64_t fb = SelectionFingerprint(b, 42, 4096, 1);
    uint64_t fc = SelectionFingerprint(c, 42, 4096, 1);
    ck(fa == fb, "deterministic_same");
    ck(fa != fc, "different_selection_differs");
    ck(SelectionFingerprint(a, 43, 4096, 1) != fa, "checkpoint_identity");
    ck(SelectionFingerprint(a, 42, 8192, 1) != fa, "geometry_identity");
    ck(SelectionFingerprint(a, 42, 4096, 2) != fa, "mode_identity");
    std::printf("FAILS=%d\nC02_IDENTITY=%s\n", fails, fails ? "FAIL" : "PASS");
    return fails ? 1 : 0;
}