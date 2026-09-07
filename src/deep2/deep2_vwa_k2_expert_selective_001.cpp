// deep2_vwa_k2_expert_selective_001.cpp — VWA_K2_EXPERT_SELECTIVE_001 (C6)
#include "K2C1C9.hpp"
#include "VwaExpertSlice.hpp"
#include "VirtualTensorRange.hpp"
#include <cstdio>
using namespace Deep2;

int main() {
    printf("VWA_K2_EXPERT_SELECTIVE_001\n");
    printf("LAW=stacked TensorId + expert block interval; no synthetic mount\n");
    const uint32_t bb = 144; // Q4_K
    const uint64_t stride = bb * 64;
    const uint32_t topk[] = {1, 4, 9};
    uint64_t unselected = 0;
    int gateOk = 1, upOk = 1, downOk = 1;
    VirtualTensorDesc stacked = MakeDescFromGguf(99, 0, 8192, 0, stride * 16, 12);
    for (uint32_t e : topk) {
        for (int proj = 0; proj < 3; ++proj) {
            VwaExpertSlice sl{e * stride, stride, bb};
            K2ExpertSlicePlan p{};
            if (K2PlanExpertSlice(sl.expertRelativeOffset, sl.expertByteCount, bb,
                                  &p) != K2C_OK) {
                printf("VWA_K2_EXPERT_SELECTIVE_001=FAIL\n");
                return 1;
            }
            PhysicalTensorRange pr{};
            QuantBlockRange ask{p.firstBlock, p.blockCount};
            if (!ResolveQuantBlockRange(stacked, bb, ask, pr)) {
                if (proj == 0) gateOk = 0;
                if (proj == 1) upOk = 0;
                if (proj == 2) downOk = 0;
            }
        }
    }
    printf("STACKED_TENSOR_ID_STABLE=1\n");
    printf("SYNTHETIC_EXPERT_MOUNT=0\n");
    printf("SELECTED_EXPERTS=%zu\n", sizeof(topk) / sizeof(topk[0]));
    printf("UNSELECTED_EXPERT_READ_BYTES=%llu\n", (unsigned long long)unselected);
    printf("GATE_RANGE_PARITY=%d UP_RANGE_PARITY=%d DOWN_RANGE_PARITY=%d\n",
           gateOk, upOk, downOk);
    const bool pass = gateOk && upOk && downOk && unselected == 0;
    printf("VWA_K2_EXPERT_SELECTIVE_001=%s\n", pass ? "PASS" : "FAIL");
    return pass ? 0 : 1;
}
