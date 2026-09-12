/* ss_vk_mem.c — host-visible buffer helpers for block-op intermediates */
#include "ss_vk_api.h"
uint32_t ss_vk_host_type(SsVk *v, uint32_t bits)
{
    VkPhysicalDeviceMemoryProperties mp; uint32_t i;
    v->a.memprops(v->phys, &mp);
    for (i = 0; i < mp.memoryTypeCount; ++i)
        if ((bits & (1u << i)) &&
            (mp.memoryTypes[i].propertyFlags & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT) &&
            (mp.memoryTypes[i].propertyFlags & VK_MEMORY_PROPERTY_HOST_COHERENT_BIT))
            return i;
    for (i = 0; i < mp.memoryTypeCount; ++i)
        if (bits & (1u << i)) return i;
    return 0xFFFFFFFFu;
}
int ss_vk_mkbuf(SsVk *v, VkDeviceSize sz, VkBuffer *b, VkDeviceMemory *m, void **map)
{
    VkBufferCreateInfo bi = { VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO };
    VkMemoryRequirements req; VkMemoryAllocateInfo ai = { VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO };
    uint32_t ty;
    bi.size = sz; bi.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT;
    if (v->a.create_buf(v->dev, &bi, 0, b) != VK_SUCCESS) return 100;
    v->a.buf_req(v->dev, *b, &req);
    ty = ss_vk_host_type(v, req.memoryTypeBits);
    if (ty == 0xFFFFFFFFu) return 100;
    ai.allocationSize = req.size; ai.memoryTypeIndex = ty;
    if (v->a.alloc_mem(v->dev, &ai, 0, m) != VK_SUCCESS) return 100;
    if (v->a.bind_mem(v->dev, *b, *m, 0) != VK_SUCCESS) return 100;
    if (map) {
        if (v->a.map(v->dev, *m, 0, sz, 0, map) != VK_SUCCESS || !*map) return 100;
    }
    return 0;
}
