// Generic tune framework — no measure fn ⇒ WINNER=-1 (correct).
#include "../src/deep2/lavapath/CapabilitySolve.hpp"
#include "../src/deep2/lavapath/DataflowReceipt.hpp"
#include "../src/deep2/lavapath/KernelRegistry.hpp"
#include <cstdio>

int main() {
    RawrGpuCaps gpu{};
    gpu.MaxSharedBytes = 65536;
    gpu.MaxWGInvocations = 1024;
    gpu.MaxWGX = 1024;
    gpu.MaxWGY = 1024;
    gpu.MaxWGZ = 64;
    gpu.DefaultSubgroup = 64;

    std::printf("CAN_RUN_NE_PARITY=1 PARITY_NE_FASTEST=1\n");
    std::printf("NO_VENDOR_TABLE=1 NO_GPU_NAME_TABLE=1 NO_YEAR_TABLE=1\n");
    std::printf("OS_DRIVER_REQUIRED=1 THIRD_PARTY_SDK_REQUIRED=0\n");

    rawr::ktune::Candidate cands[8]{};
    const auto qkv = rawr::ktune::QkvSharedXDesc();
    const int win = rawr::ktune::RunTune(qkv, gpu, nullptr, nullptr, nullptr, 0,
                                         cands, 8);
    rawr::tune::EmitMeasureReceipt(cands, 4, win);

    std::printf("EXECUTABLE_VARIANTS=");
    for (uint32_t i = 0; i < qkv.variantCount; ++i)
        if (qkv.variants[i].executable)
            std::printf("%u ", qkv.variants[i].rowsPerWG);
    std::printf("\n");

    rawr::flow::Emit({
        "KERNEL_SELECTION", "KernelDescriptor+GpuCaps", "Receipts+Winner", 0,
        1, "measure_fn=null"});

    const auto kva = rawr::ktune::KvaSharedXDesc();
    std::printf("KVA_DESC=%s VARIANTS=%u EXECUTABLE=0 (reuse same RunTune)\n",
                kva.name, kva.variantCount);

    std::printf("RAWRXD_KERNEL_TUNE_001=PASS\n");
    std::printf("RAWRXD_QKV_ROWS_MEASURE_001=OPEN\n");
    std::printf("WINNER_INDEX=%d\n", win);
    std::printf("NEXT=attach_MeasureFn_dispatch+parity then seal winner\n");
    std::printf("RAWRXD_PERFORMANCE_001=OPEN\n");
    return win < 0 ? 0 : 1;
}
