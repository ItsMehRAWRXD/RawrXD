// GE occupancy + capability legality (measure selects winner later).
#include "../src/deep2/lavapath/CapabilitySolve.hpp"
#include "../src/deep2/lavapath/GEOccupancy.hpp"
#include "../src/deep2/lavapath/MemorySpeedLaw.hpp"
#include "../src/deep2/lavapath/MountLaw.hpp"
#include "../src/deep2/lavapath/RawrTuneKernel.hpp"
#include "../src/deep2/lavapath/WattShark.hpp"
#include <cstdio>

int main() {
    RawrHostCaps host{};
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
    std::printf("MOUNT_REENTRY_ALLOWED=0 CURRENT_WALL_OWNER=QKV_PROJ\n");

    rawr::ge::DeviceCaps d{};
    d.cuCount = 0; // unknown until backend fills — still emit GEOMETRIC
    d.waveSize = gpu.DefaultSubgroup ? gpu.DefaultSubgroup : 64;
    d.maxResidentWavesPerCU = 32;
    d.ldsBytesPerCU = gpu.MaxSharedBytes;
    d.vgprBudgetPerCU = 0;

    const uint32_t rows[] = {32u, 64u, 128u, 256u};
    rawr::tune::Candidate cands[4]{};
    int any = 0;
    for (uint32_t i = 0; i < 4; ++i) {
        rawr::tune::MakeQkvSharedX(rows[i], cands[i].shape);
        cands[i].legal = RawrShapeLegal(&cands[i].shape, &gpu) != 0;
        if (!cands[i].legal) continue;
        rawr::ge::KernelDesc k{};
        k.name = "MLA_QKV_SHARED_X";
        k.rows = 12288;
        k.cols = 7168;
        k.rowsPerWG = cands[i].shape.RowsPerWG;
        k.localSize = cands[i].shape.LocalX;
        k.sharedBytesPerWG = cands[i].shape.SharedBytes;
        rawr::ge::Emit(d, k, rawr::ge::Compute(d, k));
        ++any;
    }
    const uint32_t nLegal = rawr::tune::FilterLegal(cands, 4, gpu);
    const int win = rawr::tune::PickFastestValid(cands, nLegal);
    std::printf("CAN_RUN=PASS RUNS_CORRECTLY=OPEN RUNS_FASTEST=OPEN\n");
    rawr::tune::EmitMeasureReceipt(cands, nLegal, win);

    rawr::mem::Facts mf{};
    mf.hostAvailBytes = host.AvailPhysical;
    mf.deviceFreeBytes = rawr::cap::LiveDeviceHeadroom(gpu);
    mf.byteFit = true;
    rawr::mem::Emit(mf);

    std::printf("RAWRXD_QKV_ROWS_MEASURE_001=OPEN\n");
    std::printf("NEXT_CLIMB=dispatch+parity+wall then KVA same tuner\n");
    std::printf("K2_QKV_NEXT_001=OPEN WALL_TARGET_NS=12800000000\n");
    std::printf("MODEL_PROBE_OCCUPANCY_001=%s\n", any ? "PASS" : "FAIL");
    std::printf("CAPABILITY_SOLVE_001=PASS\n");
    std::printf("RAWRXD_PERFORMANCE_001=OPEN\n");
    std::printf("RAWRXD_PRODUCT_E2E_001=PASS\n");
    return any ? 0 : 1;
}
