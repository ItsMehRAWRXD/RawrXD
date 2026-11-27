// RAWRXD A01: CPU regression for the REAP transformation-mode selector.
// Exercises the SAME ParseRuntimeMode production uses. No Vulkan, no GGUF.
#include "reap/ReapRuntimePlan.hpp"
#include <cstdio>
#include <string>

using namespace RawrXD::Reap;

static int g_fail = 0;
#define CHECK(cond, msg) do { if (!(cond)) { std::printf("FAIL: %s\n", msg); ++g_fail; } } while (0)

int main() {
    std::string m, e;
    CHECK(ParseRuntimeMode("physical", m, e) && m == "PHYSICAL", "physical");
    CHECK(ParseRuntimeMode("VIRTUAL", m, e) && m == "VIRTUAL", "virtual upper");
    CHECK(ParseRuntimeMode("Streaming", m, e) && m == "STREAMING", "streaming mixed");
    CHECK(ParseRuntimeMode("", m, e) && m == "PHYSICAL", "empty defaults physical");
    CHECK(ParseRuntimeMode("  virtual  ", m, e) && m == "VIRTUAL", "trim+lower");
    CHECK(!ParseRuntimeMode("bogus", m, e), "invalid rejected (no silent fallback)");
    if (g_fail == 0) { std::printf("ALL PASS\n"); return 0; }
    std::printf("%d FAILURE(S)\n", g_fail);
    return 1;
}