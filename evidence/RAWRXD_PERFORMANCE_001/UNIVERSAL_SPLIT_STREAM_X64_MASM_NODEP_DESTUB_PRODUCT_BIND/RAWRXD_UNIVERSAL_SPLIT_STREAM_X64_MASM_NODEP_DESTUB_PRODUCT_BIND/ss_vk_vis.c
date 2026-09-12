/* ss_vk_vis.c — bounded read of exact imported range; not a weight reupload */
#include "ss_vk_api.h"
int ss_vk_vis(SsVk *v)
{
    VkBufferCreateInfo bi = { VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO };
    VkMemoryRequirements req; VkPhysicalDeviceMemoryProperties mp;
    VkMemoryAllocateInfo ai = { VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO };
    VkCommandPoolCreateInfo pci = { VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO };
    VkCommandBufferAllocateInfo cai = { VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO };
    VkCommandBufferBeginInfo bgi = { VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO };
    VkCommandBuffer cb; VkBufferCopy c0 = { 0 }, c1 = { 0 }; VkSubmitInfo sub = { VK_STRUCTURE_TYPE_SUBMIT_INFO };
    VkMemoryBarrier mb = { VK_STRUCTURE_TYPE_MEMORY_BARRIER };
    uint32_t i, ty = 0xFFFFFFFFu; void *map = 0; uint64_t n;
    if (!v || !v->bound || !v->sync_ok || !v->bytes) return 100;
    n = v->bytes < 512ull ? v->bytes : 512ull;
    v->vis_n = n;
    v->a.create_pool = (PFN_vkCreateCommandPool)v->a.gdpa(v->dev, "vkCreateCommandPool");
    v->a.alloc_cb = (PFN_vkAllocateCommandBuffers)v->a.gdpa(v->dev, "vkAllocateCommandBuffers");
    v->a.begin_cb = (PFN_vkBeginCommandBuffer)v->a.gdpa(v->dev, "vkBeginCommandBuffer");
    v->a.end_cb = (PFN_vkEndCommandBuffer)v->a.gdpa(v->dev, "vkEndCommandBuffer");
    v->a.cmd_copy = (PFN_vkCmdCopyBuffer)v->a.gdpa(v->dev, "vkCmdCopyBuffer");
    v->a.cmd_bar = (PFN_vkCmdPipelineBarrier)v->a.gdpa(v->dev, "vkCmdPipelineBarrier");
    v->a.map = (PFN_vkMapMemory)v->a.gdpa(v->dev, "vkMapMemory");
    v->a.unmap = (PFN_vkUnmapMemory)v->a.gdpa(v->dev, "vkUnmapMemory");
    bi.size = n; bi.usage = VK_BUFFER_USAGE_TRANSFER_DST_BIT;
    if (v->a.create_buf(v->dev, &bi, 0, &v->vis) != VK_SUCCESS) return 100;
    v->a.buf_req(v->dev, v->vis, &req);
    v->a.memprops(v->phys, &mp);
    for (i = 0; i < mp.memoryTypeCount; ++i)
        if ((req.memoryTypeBits & (1u << i)) &&
            (mp.memoryTypes[i].propertyFlags & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT) &&
            (mp.memoryTypes[i].propertyFlags & VK_MEMORY_PROPERTY_HOST_COHERENT_BIT)) {
            ty = i; break;
        }
    if (ty == 0xFFFFFFFFu)
        for (i = 0; i < mp.memoryTypeCount; ++i)
            if ((req.memoryTypeBits & (1u << i)) &&
                (mp.memoryTypes[i].propertyFlags & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT)) {
                ty = i; break;
            }
    if (ty == 0xFFFFFFFFu) return 100;
    ai.allocationSize = req.size; ai.memoryTypeIndex = ty;
    if (v->a.alloc_mem(v->dev, &ai, 0, &v->vismem) != VK_SUCCESS) return 100;
    if (v->a.bind_mem(v->dev, v->vis, v->vismem, 0) != VK_SUCCESS) return 100;
    pci.queueFamilyIndex = v->qfam;
    if (v->a.create_pool(v->dev, &pci, 0, &v->pool) != VK_SUCCESS) return 100;
    cai.commandPool = v->pool; cai.commandBufferCount = 1;
    if (v->a.alloc_cb(v->dev, &cai, &cb) != VK_SUCCESS) return 100;
    if (v->a.begin_cb(cb, &bgi) != VK_SUCCESS) return 100;
    mb.srcAccessMask = VK_ACCESS_MEMORY_WRITE_BIT;
    mb.dstAccessMask = VK_ACCESS_TRANSFER_READ_BIT;
    v->a.cmd_bar(cb, VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT, VK_PIPELINE_STAGE_TRANSFER_BIT, 0, 1, &mb, 0, 0, 0, 0);
    if (v->bytes <= 512ull) {
        c0.size = v->bytes;
        v->a.cmd_copy(cb, v->wbuf, v->vis, 1, &c0);
    } else {
        c0.size = 256; c1.srcOffset = v->bytes - 256; c1.dstOffset = 256; c1.size = 256;
        v->a.cmd_copy(cb, v->wbuf, v->vis, 1, &c0);
        v->a.cmd_copy(cb, v->wbuf, v->vis, 1, &c1);
    }
    if (v->a.end_cb(cb) != VK_SUCCESS) return 100;
    sub.commandBufferCount = 1; sub.pCommandBuffers = &cb;
    if (v->a.qsubmit(v->q, 1, &sub, 0) != VK_SUCCESS) return 100;
    if (v->a.qidle(v->q) != VK_SUCCESS) return 100;
    if (v->a.map(v->dev, v->vismem, 0, n, 0, &map) != VK_SUCCESS || !map) return 100;
    v->a.unmap(v->dev, v->vismem);
    v->vis_ok = 1;
    return 0;
}
