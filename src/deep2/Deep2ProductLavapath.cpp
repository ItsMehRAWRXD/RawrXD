// Deep2ProductLavapath.cpp — product E2E via choreograph-out + LavaPath.
#include "ProductStreamer.hpp"
#include <cstdio>

namespace {

rawr::product::Runtime g_runtime{};

bool RealGenerateStream() {
    // Wire Deep2Engine::generateStream; only token callback may set
    // g_runtime.outputCommitted. Returning false = not yet wired → UNAVAILABLE.
    return false;
}

bool RealProductEffect() { return false; }
bool RealPersist() { return false; }

bool RealTeardown() {
    if (!g_runtime.streamFinished && g_runtime.materialized.modelEver)
        return false;

    if (g_runtime.materialized.kvEver) {
        std::puts("TD=03 KV_RELEASE_BEGIN");
        g_runtime.kvReleased = true;
        std::puts("TD=04 KV_RELEASE_END");
    }
    if (g_runtime.materialized.windowEver) {
        std::puts("TD=05 WINDOW_RELEASE_BEGIN");
        g_runtime.windowReleased = true;
        std::puts("TD=06 WINDOW_RELEASE_END");
    }
    if (g_runtime.materialized.gpuEver) {
        std::puts("TD=07 GPU_DESTROY_BEGIN");
        g_runtime.gpuReleased = true;
        std::puts("TD=08 GPU_DESTROY_END");
    }
    if (g_runtime.materialized.modelEver) {
        std::puts("TD=09 MODEL_DESTROY_BEGIN");
        g_runtime.modelReleased = true;
        std::puts("TD=10 MODEL_DESTROY_END");
    }
    if (g_runtime.materialized.kvEver || g_runtime.materialized.windowEver ||
        g_runtime.materialized.gpuEver || g_runtime.materialized.modelEver) {
        g_runtime.cleanExit = true;
        std::puts("TD=11 CLEAN_EXIT");
    }
    return true;
}

} // namespace

int main() {
    using namespace rawr::product;
    using rawr::lavapath::Result;

    // Observe — do not seed. Unwired sample → prerequisites unknown/false.
    g_runtime.frontDoor = false;
    g_runtime.modelAddressable = false;
    g_runtime.executionAvailable = false;

    Goal goal{};
    goal.generate = true; // this run only needs generate path
    // tool/workspace/persist default false → choreographed out

    ProductStreamer product(
        g_runtime, goal,
        RealGenerateStream, RealProductEffect, RealPersist, RealTeardown);

    std::puts("HIDDEN_BLOCKER=0");
    std::puts("REQUIRE_ALL_FEATURES=0");
    std::puts("REQUIRE_ONLY_GOAL_PATH=1");

    const Result result = product.run();

    switch (result) {
    case Result::Complete:
        std::puts("RAWRXD_PRODUCT_E2E_001=PASS");
        return 0;
    case Result::Unavailable:
        std::puts("RAWRXD_PRODUCT_E2E_001=OPEN");
        std::puts("RESULT=UNAVAILABLE");
        return 2;
    case Result::Unknown:
        std::puts("RAWRXD_PRODUCT_E2E_001=OPEN");
        std::puts("RESULT=UNKNOWN");
        return 3;
    case Result::Incomplete:
        std::puts("RAWRXD_PRODUCT_E2E_001=OPEN");
        std::puts("RESULT=INCOMPLETE");
        return 4;
    case Result::Failed:
    default:
        std::puts("RAWRXD_PRODUCT_E2E_001=FAIL");
        return 1;
    }
}
