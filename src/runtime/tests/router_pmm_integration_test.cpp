// =============================================================================
// router_pmm_integration_test.cpp
// B003 boundary gate:
//   - Execution loop calls predict()/prefetch().
//   - Router performs ensureResident() + dispatch + recordCompletion().
// =============================================================================

#include "TensorExecutionRouter.hpp"
#include "memory/PredictiveMemoryManager.hpp"

#include <cmath>
#include <cstdint>
#include <cstdio>

using namespace RawrXD;
using namespace RawrXD::Memory;

static PredictiveMemoryConfig makeConfig() {
    PredictiveMemoryConfig cfg;
    DeviceMemoryPool vram;
    vram.device = 0;
    vram.capacity = 256 * 1024 * 1024;
    cfg.vramPools.push_back(vram);
    cfg.systemRAMBytes = 512 * 1024 * 1024;
    cfg.lookaheadDepth = 3;
    cfg.maxConcurrentTransfers = 1;
    return cfg;
}

static bool nearlyEqual(float a, float b, float eps = 1e-5f) {
    return std::fabs(a - b) <= eps;
}

int main() {
    PredictiveMemoryManager mgr(makeConfig());
    TensorExecutionRouter router;

    router.setMemoryManager(&mgr);
    router.advanceLayer(1);

    float weights[6] = {
        1.0f, 2.0f, 3.0f,
        4.0f, 5.0f, 6.0f
    };
    float inputVec[3] = { 1.0f, 2.0f, 3.0f };
    float outputVec[2] = { 0.0f, 0.0f };

    TensorHandle weight;
    weight.name = "w";
    weight.host_ptr = weights;
    weight.device_ptr = nullptr;
    weight.bytes = sizeof(weights);
    weight.is_hot = false;
    weight.is_quantized = false;
    weight.quant_kind = 0;

    TensorView input;
    input.data = inputVec;
    input.size = 3;
    input.gpu_buffer = nullptr;

    TensorView output;
    output.data = outputVec;
    output.size = 2;
    output.gpu_buffer = nullptr;

    // B003 contract: predict/prefetch are execution-loop responsibilities.
    const TensorId tid = static_cast<TensorId>(
        reinterpret_cast<uintptr_t>(weight.host_ptr));
    mgr.registerTensor(tid, weight.bytes);
    mgr.predict(1);
    mgr.prefetch(1);

    router.matmul(input, weight, output, /*M=*/2, /*K=*/3);

    // CPU reference:
    // row0 = 1*1 + 2*2 + 3*3 = 14
    // row1 = 4*1 + 5*2 + 6*3 = 32
    const bool mathOk = nearlyEqual(outputVec[0], 14.0f) &&
                        nearlyEqual(outputVec[1], 32.0f);
    if (!mathOk) {
        std::printf("FAIL: matmul output mismatch: [%f, %f]\n",
                    outputVec[0], outputVec[1]);
        return 1;
    }

    const bool resident = mgr.residencyTracker().isResident(tid);
    if (!resident) {
        std::printf("FAIL: tensor not resident after router dispatch\n");
        return 1;
    }

    std::printf("PASS: B003 router/PMM boundary integration\n");
    return 0;
}
