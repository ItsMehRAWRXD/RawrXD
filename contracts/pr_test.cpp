// pr_test.cpp — CPU test: immutable placement identity propagation.
#include "reap/ReapPlacementRequest.hpp"
#include <cstdio>
using namespace RawrXD::Reap;
static int fails = 0;
static void ck(bool ok, const char* n) { std::printf("%s %s\n", ok ? "OK" : "FAIL", n); if (!ok) ++fails; }
int main() {
    uint64_t fpA = SelectionFingerprint({{0,{1,3}}}, 1, 4096, 1);
    uint64_t fpB = SelectionFingerprint({{0,{2,5}}}, 1, 4096, 1);
    PlacementRequest a; a.checkpointId=1; a.selectionFingerprint=fpA; a.mode=1; a.selectionValid=true;
    PlacementRequest b = a;   // identical request
    PlacementRequest c = a; c.selectionFingerprint = fpB;   // different selection
    ck(a.Identity() == b.Identity(), "identical_same");
    ck(a.Identity() != c.Identity(), "cross_selection_differs");
    PlacementRequest d = a; d.selectionValid = false;       // invalid selection
    ck(d.Identity() != a.Identity(), "invalid_distinct");
    ck(a.Identity() == a.Identity(), "immutable_repeat");
    std::printf("FAILS=%d\nPLACEMENT_ID=%s\n", fails, fails ? "FAIL" : "PASS");
    return fails ? 1 : 0;
}