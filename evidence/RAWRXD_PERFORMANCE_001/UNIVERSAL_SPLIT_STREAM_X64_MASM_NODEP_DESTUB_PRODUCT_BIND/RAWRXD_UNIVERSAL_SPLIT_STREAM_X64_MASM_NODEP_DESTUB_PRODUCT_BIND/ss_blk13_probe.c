/* ss_blk13_probe.c — inventory check for fail block */
#include "ss_model_plan.h"
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv)
{
    SsModelPlan p; uint32_t i; const SsBlockPlan *b;
    const char *m = argc > 1 ? argv[1]
        : "F:\\OllamaModels\\DeepSeek-R1-Q4_K_M-COMPLETE\\DeepSeek-R1-Q4_K_M-00001-of-00011.gguf";
    memset(&p, 0, sizeof p);
    if (ss_model_plan_build_split(m, &p)) { printf("plan_fail\n"); return 1; }
    for (i = 12; i <= 14; ++i) {
        b = &p.blocks[i];
        printf("blk%u idx=%u roles=%u moe=%u attn=%d ffn=%d router=%d eG=%d eU=%d eD=%d sh=%d dens=%d\n",
               i, b->blockIndex, b->rolesBound, b->isMoe, b->attnNorm.present, b->ffnNorm.present,
               b->router.present, b->expertGate.present, b->expertUp.present, b->expertDown.present,
               b->sharedGate.present, b->denseGate.present);
        printf("  eG bytes=%llu dims=%u,%llu,%llu,%llu shard=%u\n",
               (unsigned long long)b->expertGate.bytes, b->expertGate.nDims,
               (unsigned long long)b->expertGate.dims[0], (unsigned long long)b->expertGate.dims[1],
               (unsigned long long)b->expertGate.dims[2], b->expertGate.shardIndex);
    }
    return 0;
}
