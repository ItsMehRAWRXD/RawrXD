/* ss_vk_block_util.c — shared upload/observe helpers for plan-bound blocks */
#include "ss_vk_api.h"
#include "ss_model_plan.h"
#include <string.h>
uint32_t ss_vk_codec_ty(uint32_t c)
{
    if (c == SS_CODEC_F32) return 0;
    if (c == SS_CODEC_Q4_K) return 12;
    if (c == SS_CODEC_Q6_K) return 14;
    return 12;
}
int ss_vk_upload(SsVk *v, const void *host, uint64_t n, VkBuffer *b, VkDeviceMemory *m)
{
    void *map = 0;
    if (ss_vk_mkbuf(v, (VkDeviceSize)n, b, m, &map)) return 100;
    memcpy(map, host, (size_t)n); v->a.unmap(v->dev, *m);
    return 0;
}
int ss_vk_fin_obs(SsVk *v, VkDeviceMemory mem, uint32_t n, int *ok)
{
    void *map = 0; float *f; uint32_t i; int fin = 1, saw = 0, nonc = 0; float first = 0.f;
    if (v->a.map(v->dev, mem, 0, (VkDeviceSize)n * 4ull, 0, &map) != VK_SUCCESS) return 100;
    f = (float *)map;
    for (i = 0; i < n; ++i) {
        if (!(f[i] == f[i]) || f[i] > 1e30f || f[i] < -1e30f) { fin = 0; break; }
        if (!saw) { first = f[i]; saw = 1; } else if (f[i] != first) nonc = 1;
    }
    v->a.unmap(v->dev, mem);
    *ok = fin && (n <= 1u || nonc);
    return 0;
}
void ss_vk_dropb(SsVk *v, VkBuffer *b, VkDeviceMemory *m)
{
    if (*b) { v->a.destroy_buf(v->dev, *b, 0); *b = 0; }
    if (*m) { v->a.free_mem(v->dev, *m, 0); *m = 0; }
}
