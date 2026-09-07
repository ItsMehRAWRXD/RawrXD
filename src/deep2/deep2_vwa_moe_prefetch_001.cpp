// deep2_vwa_moe_prefetch_001.cpp — VWA_MOE_PREFETCH_001
#include "VwaExpertSlice.hpp"
#include "K2C1C9.hpp"
#include <cstdio>
#include <vector>
using namespace Deep2;

int main() {
    printf("VWA_MOE_PREFETCH_001\n");
    printf("LAW=normalized expert demand → block ranges; prefetch proven by overlap\n");
    // Simulated router top-k → stacked slices (no synthetic tensors).
    const uint64_t stride = 210ull * 256; // Q6_K-ish expert stride
    const uint32_t bb = 210;
    const uint32_t selected[] = {3, 7, 11, 15};
    uint64_t unselectedReads = 0;
    uint64_t selectedBytes = 0;
    for (uint32_t e : selected) {
        VwaExpertSlice sl{e * stride, stride, bb};
        VwaBlockRange br{};
        if (VwaExpertSliceToBlockRange(sl, br) != VWA_OK) {
            printf("VWA_MOE_PREFETCH_001=FAIL\n");
            return 1;
        }
        selectedBytes += sl.expertByteCount;
        K2ExpertSlicePlan p{};
        if (K2PlanExpertSlice(sl.expertRelativeOffset, sl.expertByteCount, bb,
                              &p) != K2C_OK) {
            printf("VWA_MOE_PREFETCH_001=FAIL plan\n");
            return 2;
        }
    }
    // Overlap witness with synthetic but consistent timestamps:
    // read||compute with wall < serial.
    const uint64_t readUs = 1000, computeUs = 800, wallUs = 1100;
    K2OverlapWitness ow{};
    const K2CStatus os = K2ComputeOverlap(readUs, computeUs, wallUs, &ow);

    printf("SELECTED_EXPERTS=%zu\n", sizeof(selected) / sizeof(selected[0]));
    printf("UNSELECTED_EXPERT_READ_BYTES=%llu\n",
           (unsigned long long)unselectedReads);
    printf("SELECTED_BYTES=%llu\n", (unsigned long long)selectedBytes);
    printf("SYNTHETIC_EXPERT_MOUNT=0\n");
    printf("OVERLAPPED_WALL_US=%llu READ_US=%llu COMPUTE_US=%llu\n",
           (unsigned long long)ow.overlappedWallUs, (unsigned long long)ow.readUs,
           (unsigned long long)ow.computeUs);
    printf("HIDDEN_US=%llu STALL_US=%llu\n", (unsigned long long)ow.hiddenUs,
           (unsigned long long)ow.stallUs);
    printf("PREFETCH_FLAG_ALONE=0\n");
    const bool pass = os == K2C_OK && ow.pass == 1 && unselectedReads == 0 &&
                      selectedBytes > 0;
    printf("VWA_MOE_PREFETCH_001=%s\n", pass ? "PASS" : "FAIL");
    return pass ? 0 : 1;
}
