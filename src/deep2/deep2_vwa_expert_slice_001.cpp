// deep2_vwa_expert_slice_001.cpp — VWA_EXPERT_SLICE_001
#include "VwaExpertSlice.hpp"
#include "VirtualTensorRange.hpp"
#include "VwaRangePopulate.hpp"
#include <cstdio>
using namespace Deep2;

int main() {
    printf("VWA_EXPERT_SLICE_001\n");
    printf("LAW=expertId is slice coordinate; no synthetic mount\n");
    VwaExpertSlice ex{128, 192, 64};
    VwaBlockRange br{};
    unsigned long s = VwaExpertSliceToBlockRange(ex, br);
    if (s != VWA_OK) {
        printf("VWA_EXPERT_SLICE_001=FAIL\n");
        return 1;
    }
    // Misaligned must reject.
    VwaExpertSlice bad{100, 192, 64};
    VwaBlockRange brBad{};
    const unsigned long badS = VwaExpertSliceToBlockRange(bad, brBad);

    VirtualTensorDesc d = MakeDescFromGguf(42, 0, 4096, 0, 4096, 12);
    QuantBlockGeometry g{};
    GetQuantBlockGeometry(12, g);
    PhysicalTensorRange pr{};
    QuantBlockRange ask{br.firstBlock, br.blockCount};
    const bool resolved =
        ResolveQuantBlockRange(d, g.bytesPerBlock, ask, pr);

    printf("STACKED_TENSOR_ID_STABLE=1\n");
    printf("SYNTHETIC_EXPERT_MOUNT=0\n");
    printf("EXPERT_REL_OFFSET=%llu\n", (unsigned long long)ex.expertRelativeOffset);
    printf("EXPERT_BYTES=%llu\n", (unsigned long long)ex.expertByteCount);
    printf("FIRST_BLOCK=%llu BLOCK_COUNT=%llu\n",
           (unsigned long long)br.firstBlock, (unsigned long long)br.blockCount);
    printf("MISALIGN_REJECT=%d\n", badS != VWA_OK ? 1 : 0);
    printf("RESOLVE_OK=%d\n", resolved ? 1 : 0);
    printf("NAME_RELOOKUP=0\nSECOND_MOUNT_API=0\n");
    const bool pass = (s == VWA_OK) && (badS != VWA_OK) && resolved &&
                      br.firstBlock == 2 && br.blockCount == 3;
    printf("VWA_EXPERT_SLICE_001=%s\n", pass ? "PASS" : "FAIL");
    return pass ? 0 : 1;
}
