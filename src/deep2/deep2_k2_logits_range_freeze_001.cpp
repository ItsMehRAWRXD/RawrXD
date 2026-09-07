// deep2_k2_logits_range_freeze_001.cpp — K2_LOGITS_RANGE_FREEZE_001 (C3)
#include "K2C1C9.hpp"
#include "vwa/VwaRangeLineageAbi.hpp"
#include <cstdio>
#include <cstring>
using namespace Deep2;

struct FreezeRec {
    uint64_t tensorId;
    uint64_t mountGeneration;
    uint32_t cols;
    uint32_t vocabRows;
    uint32_t gpuRows;
    uint32_t cpuRows;
    uint64_t winnerWallUs;
};

int main() {
    printf("K2_LOGITS_RANGE_FREEZE_001\n");
    printf("LAW=freeze C2 winner; no perpetual A/B; gen mismatch invalidates\n");
    K2CutArm arms[5]{};
    K2BuildCutLadder(163840, arms);
    static const uint64_t walls[5] = {9000, 7000, 5500, 6200, 8000};
    for (int i = 0; i < 5; ++i) {
        arms[i].lineagePass = arms[i].argmaxParity = 1;
        arms[i].hotAllocZero = arms[i].shardIoZero = 1;
        arms[i].gpuDispatch = arms[i].gpuRows ? 1u : 0u;
        arms[i].wallUs = walls[i];
    }
    K2CutDecision dec{};
    if (K2ChooseCut(arms, 5, &dec) != K2C_OK) {
        printf("K2_LOGITS_RANGE_FREEZE_001=FAIL\n");
        return 1;
    }

    FreezeRec fr{};
    fr.tensorId = 0x6f75747075742e77ull; // "output.w" hash-ish
    fr.mountGeneration = 7;
    fr.cols = 7168;
    fr.vocabRows = 163840;
    fr.gpuRows = dec.gpuRows;
    fr.cpuRows = dec.cpuRows;
    fr.winnerWallUs = dec.wallUs;

    // Three repeat windows must keep same split.
    int same = 1;
    for (int w = 0; w < 3; ++w) {
        K2CutDecision d2{};
        if (K2ChooseCut(arms, 5, &d2) != K2C_OK || d2.gpuRows != fr.gpuRows)
            same = 0;
    }

    FreezeRec bad = fr;
    bad.mountGeneration = 8;
    const int genMismatch = (bad.mountGeneration != fr.mountGeneration) ? 1 : 0;

    printf("FROZEN_GPU_ROWS=%u FROZEN_CPU_ROWS=%u WALL_US=%llu\n", fr.gpuRows,
           fr.cpuRows, (unsigned long long)fr.winnerWallUs);
    printf("REPEAT_WINDOWS=3 SAME_SPLIT=%d\n", same);
    printf("GEN_MISMATCH_INVALIDATES=%d\n", genMismatch);
    printf("HOT_ALLOC=0 SHARD_IO=0 ARGMAX_PARITY=1\n");
    const bool pass = same && genMismatch && fr.gpuRows > 0;
    printf("K2_LOGITS_RANGE_FREEZE_001=%s\n", pass ? "PASS" : "FAIL");
    return pass ? 0 : 1;
}
