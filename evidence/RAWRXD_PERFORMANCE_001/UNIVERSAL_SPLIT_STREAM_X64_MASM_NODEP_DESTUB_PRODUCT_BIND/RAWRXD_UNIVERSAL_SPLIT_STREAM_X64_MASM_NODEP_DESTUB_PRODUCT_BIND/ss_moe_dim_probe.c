/* ss_moe_dim_probe.c — print dense/MoE tensor dims then exit */
#include "ss_model_plan.h"
#include <stdio.h>
int main(int argc, char **argv)
{
    SsModelPlan p; const SsBlockPlan *b0, *b3;
    if (argc < 2) return 2;
    memset(&p, 0, sizeof p);
    if (ss_model_plan_build_split(argv[1], &p)) return 1;
    b0 = &p.blocks[0]; b3 = &p.blocks[3];
    printf("embd=%u experts=%u topk=%u shared=%u\n",
           p.embeddingLength, p.expertCount, p.expertTopK, p.expertSharedCount);
    printf("b0 denseGate nd=%u d0=%llu d1=%llu d2=%llu bytes=%llu codec=%u\n",
           b0->denseGate.nDims, (unsigned long long)b0->denseGate.dims[0],
           (unsigned long long)b0->denseGate.dims[1], (unsigned long long)b0->denseGate.dims[2],
           (unsigned long long)b0->denseGate.bytes, b0->denseGate.codec);
    printf("b0 denseUp nd=%u d0=%llu d1=%llu bytes=%llu\n",
           b0->denseUp.nDims, (unsigned long long)b0->denseUp.dims[0],
           (unsigned long long)b0->denseUp.dims[1], (unsigned long long)b0->denseUp.bytes);
    printf("b0 denseDown nd=%u d0=%llu d1=%llu bytes=%llu\n",
           b0->denseDown.nDims, (unsigned long long)b0->denseDown.dims[0],
           (unsigned long long)b0->denseDown.dims[1], (unsigned long long)b0->denseDown.bytes);
    printf("b3 moe=%u router nd=%u d0=%llu d1=%llu bytes=%llu codec=%u\n",
           b3->isMoe, b3->router.nDims, (unsigned long long)b3->router.dims[0],
           (unsigned long long)b3->router.dims[1], (unsigned long long)b3->router.bytes,
           b3->router.codec);
    printf("b3 expGate nd=%u d0=%llu d1=%llu d2=%llu bytes=%llu codec=%u\n",
           b3->expertGate.nDims, (unsigned long long)b3->expertGate.dims[0],
           (unsigned long long)b3->expertGate.dims[1], (unsigned long long)b3->expertGate.dims[2],
           (unsigned long long)b3->expertGate.bytes, b3->expertGate.codec);
    printf("b3 sharedGate nd=%u d0=%llu d1=%llu present=%d\n",
           b3->sharedGate.nDims, (unsigned long long)b3->sharedGate.dims[0],
           (unsigned long long)b3->sharedGate.dims[1], b3->sharedGate.present);
    return 0;
}
