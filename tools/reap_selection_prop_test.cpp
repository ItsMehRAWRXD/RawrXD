// RAWRXD REAP V06.1: CPU regression for selection propagation + count derivation.
#include "reap/ReapRuntimePlan.hpp"
#include <cstdio>
#include <string>

using namespace RawrXD::Reap;
static int g_fail = 0;
#define CHECK(c, m) do { if (!(c)) { std::printf("FAIL: %s\n", m); ++g_fail; } } while (0)

int main() {
    std::string e;
    Selection s{{0, {0, 1, 2}}, {1, {1, 2, 3}}};
    bool uniform = false;
    CHECK(SelectionExpertCount(s, uniform) == 3 && uniform, "count 3 uniform");
    CHECK(ValidateRuntimeSelection(s, 3, e), "valid selection matches activeExperts=3");
    CHECK(!ValidateRuntimeSelection(s, 2, e), "count mismatch rejected");
    Selection dup{{0, {0, 0, 1}}, {1, {1, 2, 3}}};
    CHECK(!ValidateRuntimeSelection(dup, 3, e), "duplicate expert rejected");
    Selection inconsistent{{0, {0, 1, 2}}, {1, {1, 2}}};
    CHECK(!ValidateRuntimeSelection(inconsistent, 0, e), "inconsistent per-layer count rejected");
    // Empty selection: count 0, not uniform; validation fails closed.
    Selection empty;
    CHECK(SelectionExpertCount(empty, uniform) == 0 && !uniform, "empty -> 0 not uniform");
    CHECK(!ValidateRuntimeSelection(empty, 0, e), "empty selection rejected");
    // RuntimeInjection carries the selection (compile-time propagation check).
    RuntimeInjection inj;
    inj.hasSelection = true;
    inj.selection = s;
    inj.expertCount = SelectionExpertCount(s, uniform);
    CHECK(inj.hasSelection && inj.selection.size() == 2 && inj.expertCount == 3,
          "RuntimeInjection carries selection + derived count");
    if (g_fail == 0) { std::printf("ALL PASS\n"); return 0; }
    std::printf("%d FAILURE(S)\n", g_fail);
    return 1;
}