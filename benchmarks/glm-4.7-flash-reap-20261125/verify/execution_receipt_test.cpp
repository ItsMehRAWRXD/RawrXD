// Logic test for Deep2MultiGpu_EmitExecutionReceipt: verifies the separate
// per-LUID counters are emitted verbatim (plumbing only; values are synthetic
// test inputs, NOT measured hardware results).
#include "Deep2MultiGpuLayerPlan.hpp"
#include <cstdio>
#include <cstring>

static int fails = 0;
static void expect(const char* label, bool ok) {
    if (!ok) { std::printf("FAIL: %s\n", label); ++fails; }
}

int main() {
    Deep2::MultiGpuLayerPlan p;
    p.gpuSlotCount = 2;
    p.slotLayersCompleted[0] = 29;  p.slotLayersCompleted[1] = 18;
    p.slotDispatchesSubmitted[0] = 100; p.slotDispatchesSubmitted[1] = 60;
    p.slotDispatchesCompleted[0] = 100; p.slotDispatchesCompleted[1] = 60;
    p.slotWeightBytesActual[0] = 738553344ull; p.slotWeightBytesActual[1] = 154804224ull;
    p.slotExecutionNs[0] = 1000000ull; p.slotExecutionNs[1] = 500000ull;
    p.gpuOverlapNs = 250000ull;
    p.crossDeviceTransferBytes = 1024ull;
    p.crossDeviceTransferNs = 2000ull;

    // Capture to a buffer via a temp file.
    FILE* f = std::tmpfile();
    Deep2::Deep2MultiGpu_EmitExecutionReceipt(f, p);
    std::rewind(f);
    char buf[4096]; size_t n = std::fread(buf, 1, sizeof(buf) - 1, f); buf[n] = 0;
    std::fclose(f);

    // Separate counters must appear independently (layers != dispatches).
    expect("GPU0_LAYERS_COMPLETED", std::strstr(buf, "GPU0_LAYERS_COMPLETED=29"));
    expect("GPU1_LAYERS_COMPLETED", std::strstr(buf, "GPU1_LAYERS_COMPLETED=18"));
    expect("GPU0_DISPATCHES_SUBMITTED", std::strstr(buf, "GPU0_DISPATCHES_SUBMITTED=100"));
    expect("GPU0_DISPATCHES_COMPLETED", std::strstr(buf, "GPU0_DISPATCHES_COMPLETED=100"));
    expect("GPU1_WEIGHT_BYTES_ACTUAL", std::strstr(buf, "GPU1_WEIGHT_BYTES_ACTUAL=154804224"));
    expect("GPU0_EXECUTION_NS", std::strstr(buf, "GPU0_EXECUTION_NS=1000000"));
    expect("GPU_OVERLAP_NS", std::strstr(buf, "GPU_OVERLAP_NS=250000"));
    expect("CROSS_DEVICE_TRANSFER_BYTES", std::strstr(buf, "CROSS_DEVICE_TRANSFER_BYTES=1024"));
    expect("NUMERICAL_PARITY_NOT_RUN", std::strstr(buf, "NUMERICAL_PARITY=NOT_RUN"));
    expect("DECODE_TPS_NOT_RUN", std::strstr(buf, "DECODE_TPS=NOT_RUN"));

    if (fails == 0) std::printf("EXECUTION_RECEIPT_ACCEPTANCE PASS\n");
    return fails ? 1 : 0;
}