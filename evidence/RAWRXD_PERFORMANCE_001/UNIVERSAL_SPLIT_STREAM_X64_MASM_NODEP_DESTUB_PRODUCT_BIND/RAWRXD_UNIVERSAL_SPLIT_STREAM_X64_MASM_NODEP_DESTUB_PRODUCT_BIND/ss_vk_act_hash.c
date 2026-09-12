/* ss_vk_act_hash.c — FNV-1a over activation floats for continuity */
#include "ss_vk_api.h"
uint64_t ss_vk_act_hash(SsVk *v, VkDeviceMemory mem, uint32_t n)
{
    void *map = 0; float *f; uint32_t i; uint64_t h = 14695981039346656037ull;
    if (!v || !mem || !n) return 0;
    if (v->a.map(v->dev, mem, 0, (VkDeviceSize)n * 4ull, 0, &map) != VK_SUCCESS)
        return 0;
    f = (float *)map;
    for (i = 0; i < n; ++i) {
        uint32_t u;
        u = *(const uint32_t *)&f[i];
        h ^= (uint64_t)u;
        h *= 1099511628211ull;
    }
    v->a.unmap(v->dev, mem);
    return h ? h : 1ull;
}
