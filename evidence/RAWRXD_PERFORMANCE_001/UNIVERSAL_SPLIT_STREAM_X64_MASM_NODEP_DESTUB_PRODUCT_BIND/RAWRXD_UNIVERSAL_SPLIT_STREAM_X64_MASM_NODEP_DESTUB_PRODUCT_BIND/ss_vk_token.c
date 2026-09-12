/* ss_vk_token.c — host argmax over logits → abbreviated token commit */
#include "ss_vk_api.h"
#include <stdio.h>
int ss_vk_token_commit(SsVk *v)
{
    void *map = 0; float *f; uint32_t i, best = 0; float bv;
    if (!v || !v->logits_op || !v->logitsb || !v->logitsmem || !v->vocab_n) return 100;
    if (v->a.map(v->dev, v->logitsmem, 0, (VkDeviceSize)v->vocab_n * 4ull, 0, &map) != VK_SUCCESS)
        return 100;
    f = (float *)map; bv = f[0];
    for (i = 1; i < v->vocab_n; ++i) if (f[i] > bv) { bv = f[i]; best = i; }
    v->a.unmap(v->dev, v->logitsmem);
    v->next_token = best;
    v->token_op = 1;
    printf("TOKEN_SELECTED=1 TOKEN_ID=%u TOKEN_COMMIT=1 ARGMAX=1\n", best);
    printf("DECODE_KIND=ABBREVIATED_SPLIT_STREAM FULL_MODEL_FORWARD=0 PROMOTE=0\n");
    return 0;
}
