// RAWRXD A07/A08: CPU regression for the SINGLE authoritative REAP mode contract.
// Exercises ParseTransformMode/TransformModeName (RP01). No Vulkan, no GGUF.
#include "reap/ReapRuntimePlan.hpp"
#include <cstdio>
#include <string>

using namespace RawrXD::Reap;

static int g_fail = 0;
#define CHECK(cond, msg) do { if (!(cond)) { std::printf("FAIL: %s\n", msg); ++g_fail; } } while (0)

int main() {
    TransformMode m;
    CHECK(ParseTransformMode("PHYSICAL", m) && m == TransformMode::Physical, "physical");
    CHECK(ParseTransformMode("VIRTUAL", m) && m == TransformMode::Virtual, "virtual");
    CHECK(ParseTransformMode("STREAMING", m) && m == TransformMode::Streaming, "streaming");
    CHECK(!ParseTransformMode("bogus", m), "invalid rejected (no silent fallback)");
    CHECK(!ParseTransformMode("", m), "empty rejected by strict parser (caller defaults)");
    CHECK(std::string(TransformModeName(TransformMode::Virtual)) == "VIRTUAL", "name virtual");
    CHECK(std::string(TransformModeName(TransformMode::Streaming)) == "STREAMING", "name streaming");
    if (g_fail == 0) { std::printf("ALL PASS\n"); return 0; }
    std::printf("%d FAILURE(S)\n", g_fail);
    return 1;
}