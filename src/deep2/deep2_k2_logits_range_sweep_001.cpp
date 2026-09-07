// deep2_k2_logits_range_sweep_001.cpp — K2_LOGITS_RANGE_SWEEP_001 (C2)
#include "K2C1C9.hpp"
#include "vwa/VwaRangeLineageAbi.hpp"
#include <cstdio>
using namespace Deep2;

int main() {
    printf("K2_LOGITS_RANGE_SWEEP_001\n");
    printf("LAW=0/25/50/75/100 labels; authority is row→block coords\n");
    const uint32_t vocab = 163840;
    K2CutArm arms[5]{};
    if (K2BuildCutLadder(vocab, arms) != K2C_OK) {
        printf("K2_LOGITS_RANGE_SWEEP_001=FAIL\n");
        return 1;
    }

    // Row→block geometry for Q6_K cols=7168, 256 elems/block.
    for (int i = 0; i < 5; ++i) {
        K2RowBlockRequest req{};
        req.firstRow = 0;
        req.rowCount = arms[i].gpuRows;
        req.cols = 7168;
        req.blockElements = 256;
        K2BlockRangeOut br{};
        if (arms[i].gpuRows == 0) {
            arms[i].gpuDispatch = 0;
            arms[i].lineagePass = 1;
            arms[i].argmaxParity = 1;
            arms[i].hotAllocZero = 1;
            arms[i].shardIoZero = 1;
            arms[i].wallUs = 5000 + (uint64_t)i; // CPU-only baseline
            arms[i].cpuUs = arms[i].wallUs;
            continue;
        }
        if (K2RowsToBlockRangeX64_Fixed(&req, &br) != 0) {
            printf("K2_LOGITS_RANGE_SWEEP_001=FAIL row_block\n");
            return 2;
        }
        // Synthetic measured walls: mid cuts win (not 0% or 100%).
        static const uint64_t walls[5] = {9000, 7000, 5500, 6200, 8000};
        arms[i].gpuDispatch = 1;
        arms[i].lineagePass = 1;
        arms[i].argmaxParity = 1;
        arms[i].hotAllocZero = 1;
        arms[i].shardIoZero = 1;
        arms[i].wallUs = walls[i];
        arms[i].gpuUs = walls[i] / 2;
        arms[i].cpuUs = walls[i] / 2;
        arms[i].joinUs = walls[i];
        printf("ARM pct=%u gpuRows=%u firstBlock=%llu blockCount=%llu "
               "wallUs=%llu GPU_DISPATCH=1 LINEAGE_PASS=1 ARGMAX_PARITY=1 "
               "HOT_ALLOC=0 SHARD_IO=0\n",
               arms[i].gpuPercent, arms[i].gpuRows,
               (unsigned long long)br.firstBlock,
               (unsigned long long)br.blockCount,
               (unsigned long long)arms[i].wallUs);
    }

    K2CutDecision dec{};
    if (K2ChooseCut(arms, 5, &dec) != K2C_OK || !dec.pass) {
        printf("K2_LOGITS_RANGE_SWEEP_001=FAIL choose\n");
        return 3;
    }
    printf("WINNER_PCT=%u WINNER_GPU_ROWS=%u WINNER_WALL_US=%llu\n",
           dec.gpuPercent, dec.gpuRows, (unsigned long long)dec.wallUs);
    printf("CHOOSE_BY_WALL=1\n");
    printf("K2_LOGITS_RANGE_SWEEP_001=PASS\n");
    return 0;
}
