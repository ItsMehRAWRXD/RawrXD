// runtime_generator_budget_smoke.cpp — RuntimeGenerator budget-aware layer split
#include "regenerative/RuntimeGenerator.hpp"
#include <cstdio>
#include <cstdlib>

using namespace Deep2::Regenerative;

static int fail(const char* m) {
    std::printf("  [FAIL] %s\n", m);
    return 1;
}
static void pass(const char* m) { std::printf("  [PASS] %s\n", m); }

int main() {
    std::printf("RUNTIME_GENERATOR_BUDGET_001 smoke\n");

    // Default dual-GPU split when GPU1 is much less busy and has VRAM.
    {
        GeneratorInputs in;
        in.hardware = {97.0, 32.0, 0.8, 9.0, 2};
        in.workload = {28, 384, 1, true, 0};
        in.budgets = {20.0, 50.0, false, 0};
        const RuntimeImage img = GenerateRuntime(in);
        if (img.gpu0LayerEnd != 14 || img.gpu1LayerBegin != 14 || img.gpu1LayerEnd != 28)
            return fail("DEFAULT_DUAL_GPU_SPLIT");
        if (img.prefetchHorizon != 2)
            return fail("DEFAULT_PREFETCH_HORIZON");
        pass("DEFAULT_DUAL_GPU_SPLIT");
        pass("DEFAULT_PREFETCH_HORIZON");
    }

    // Budget clamp: 10 layers max on a 10GB/layer budget with 100GB cap.
    {
        GeneratorInputs in;
        in.hardware = {97.0, 32.0, 0.8, 9.0, 2};
        in.workload = {28, 384, 1, true, 1024ULL * 1024 * 1024}; // 1 GiB/layer
        in.budgets = {20.0, 50.0, false, 10ULL * 1024 * 1024 * 1024}; // 10 GiB
        const RuntimeImage img = GenerateRuntime(in);
        const uint32_t active = img.gpu0LayerEnd - img.gpu0LayerBegin +
                                img.gpu1LayerEnd - img.gpu1LayerBegin;
        if (active > 10)
            return fail("BUDGET_CLAMPED_LAYER_COUNT");
        if (img.prefetchHorizon != 1)
            return fail("BUDGET_TIGHT_PREFETCH_HORIZON");
        pass("BUDGET_CLAMPED_LAYER_COUNT");
        pass("BUDGET_TIGHT_PREFETCH_HORIZON");
    }

    // Very tight budget: single GPU, one layer.
    {
        GeneratorInputs in;
        in.hardware = {97.0, 32.0, 0.8, 9.0, 2};
        in.workload = {28, 384, 1, true, 2ULL * 1024 * 1024 * 1024}; // 2 GiB/layer
        in.budgets = {20.0, 50.0, false, 2ULL * 1024 * 1024 * 1024}; // 2 GiB
        const RuntimeImage img = GenerateRuntime(in);
        if (img.gpu0LayerEnd != 1 || img.gpu1LayerEnd != 0)
            return fail("TIGHT_BUDGET_SINGLE_LAYER");
        pass("TIGHT_BUDGET_SINGLE_LAYER");
    }

    std::printf("RUNTIME_GENERATOR_BUDGET_001 PASS\n");
    return 0;
}
