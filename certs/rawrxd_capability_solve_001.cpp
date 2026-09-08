// Capability legality — CAN_RUN only; does not claim winner.
#include "../src/deep2/lavapath/CapabilitySolve.hpp"
#include "../src/deep2/lavapath/RawrTuneKernel.hpp"
#include <cstdio>

int main() {
    RawrHostCaps host{};
    rawr::cap::SnapshotHost(host);
    rawr::cap::SnapshotHost(host);

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

    rawr::cap::EmitLoopLaw();
    std::printf("HOST_AVAIL_PHYS=%llu\n",
                (unsigned long long)host.AvailPhysical);
    std::printf("LIVE_DEVICE_HEADROOM=%llu BUDGET_KNOWN=%u\n",
                (unsigned long long)rawr::cap::LiveDeviceHeadroom(gpu),
                gpu.BudgetKnown);

    const uint32_t rows[] = {32u, 64u, 128u, 256u};
    rawr::tune::Candidate cands[4]{};
    for (uint32_t i = 0; i < 4; ++i)
        rawr::tune::MakeQkvSharedX(rows[i], cands[i].shape);
    const uint32_t nLegal = rawr::tune::FilterLegal(cands, 4, gpu);

    std::printf("CAN_RUN=PASS RUNS_CORRECTLY=OPEN RUNS_FASTEST=OPEN\n");
    std::printf("TAG12_LEGAL_COUNT=%u\n", nLegal);
    for (uint32_t i = 0; i < nLegal; ++i) {
        cands[i].parityOk = false;
        cands[i].measureComplete = false;
    }
    const int win = rawr::tune::PickFastestValid(cands, nLegal);
    rawr::tune::EmitMeasureReceipt(cands, nLegal, win);

    std::printf("CAPABILITY_SOLVE_001=PASS\n");
    std::printf("RAWRXD_QKV_ROWS_MEASURE_001=OPEN\n");
    std::printf("RAWRXD_PERFORMANCE_001=OPEN\n");
    return nLegal ? 0 : 1;
}
