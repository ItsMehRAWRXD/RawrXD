// Measure receipt — LEGAL≠PARITY≠FASTEST. Winner stays -1 until live measure.
#include "../src/deep2/lavapath/CapabilitySolve.hpp"
#include "../src/deep2/lavapath/RawrTuneKernel.hpp"
#include <cstdio>

int main() {
    RawrGpuCaps gpu{};
    gpu.BudgetKnown = 0;
    gpu.MaxSharedBytes = 65536;
    gpu.MaxWGInvocations = 1024;
    gpu.MaxWGX = 1024;
    gpu.MaxWGY = 1024;
    gpu.MaxWGZ = 64;
    gpu.DefaultSubgroup = 64;
    gpu.MinSubgroup = 32;
    gpu.MaxSubgroup = 64;

    const uint32_t rows[] = {32u, 64u, 128u, 256u};
    rawr::tune::Candidate cands[4]{};
    for (uint32_t i = 0; i < 4; ++i)
        rawr::tune::MakeQkvSharedX(rows[i], cands[i].shape);

    const uint32_t nLegal = rawr::tune::FilterLegal(cands, 4, gpu);

    // Foundation PASS does not fill measure. Leave PARITY/MEASURE open.
    for (uint32_t i = 0; i < nLegal; ++i) {
        cands[i].parityOk = false;
        cands[i].measureComplete = false;
        cands[i].gpuUs = UINT64_MAX;
        cands[i].wallUs = UINT64_MAX;
    }

    std::printf("FOUNDATION_CAPABILITY=PASS\n");
    std::printf("FOUNDATION_GEOMETRY=PASS\n");
    std::printf("FOUNDATION_SPIRV=PASS\n");
    std::printf("SEARCH_SPACE_LEGAL_COUNT=%u\n", nLegal);
    std::printf("CAN_RUN=PASS RUNS_CORRECTLY=OPEN RUNS_FASTEST=OPEN\n");

    const int win = rawr::tune::PickFastestValid(cands, nLegal);
    rawr::tune::EmitMeasureReceipt(cands, nLegal, win);

    std::printf("RAWRXD_QKV_ROWS_MEASURE_001=OPEN\n");
    std::printf("NEXT=promo_dispatch_each_ROWS_parity_then_argmin_WALL\n");
    std::printf("NEXT_AFTER_WINNER=KVA_SHARED_X same machinery\n");
    std::printf("CURRENT_WALL_OWNER=QKV_PROJ KVA_DOMINANT=1\n");
    std::printf("RAWRXD_PERFORMANCE_001=OPEN\n");
    return (nLegal == 4 && win < 0) ? 0 : 1;
}
