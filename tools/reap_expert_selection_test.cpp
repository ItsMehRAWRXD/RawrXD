// RAWRXD REAP V01: CPU regression for the storage-independent selection validator.
#include "deep2/ReapExpertSelection.hpp"
#include <cstdio>
#include <string>

using namespace RawrXD::Reap;

static int g_fail = 0;
#define CHECK(c, m) do { if (!(c)) { std::printf("FAIL: %s\n", m); ++g_fail; } } while (0)

int main() {
    std::string e;
    Selection s{{0, {0, 1, 2}}, {1, {1, 2, 3}}};
    CHECK(ValidateSelection(s, 3, e), "valid selection (3 per layer)");
    Selection dup{{0, {0, 0, 1}}};
    CHECK(!ValidateSelection(dup, 3, e), "duplicate expert rejected");
    Selection wrongCount{{0, {0, 1}}};
    CHECK(!ValidateSelection(wrongCount, 3, e), "wrong activeExperts count rejected");
    Selection empty;
    CHECK(!ValidateSelection(empty, 3, e), "empty selection rejected");
    Selection zeroActive{{0, {0, 1, 2}}};
    CHECK(ValidateSelection(zeroActive, 0, e), "activeExperts=0 allows any non-empty count");
    if (g_fail == 0) { std::printf("ALL PASS\n"); return 0; }
    std::printf("%d FAILURE(S)\n", g_fail);
    return 1;
}