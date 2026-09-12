/* ss_vk_prim.c — dispatch on imported wbuf only; no reupload/reimport */
#include "ss_vk_api.h"
int ss_vk_pipe(SsVk *v);
static uint32_t host_type(SsVk *v, uint32_t bits)
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
int ss_vk_prim(SsVk *v)
{
    VkBufferCreateInfo bi = { VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO };
    VkMemoryRequirements req; VkMemoryAllocateInfo ai = { VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO };
    VkDescriptorBufferInfo wi = { 0 }, oi = { 0 };
    VkWriteDescriptorSet w[2] = {
        { VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET },
        { VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET }
    };
    VkCommandBufferAllocateInfo cai = { VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO };
    VkCommandBufferBeginInfo bgi = { VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO };
    VkSubmitInfo sub = { VK_STRUCTURE_TYPE_SUBMIT_INFO };
    VkCommandBuffer cb; uint32_t nw, ty, pc[3], out[6]; void *map = 0;
    if (!v || !v->bound || !v->sync_ok || !v->vis_ok || !v->wbuf || v->bytes < 4) return 100;
    if (ss_vk_pipe(v)) return 100;
    v->a.cmd_bp = (PFN_vkCmdBindPipeline)v->a.gdpa(v->dev, "vkCmdBindPipeline");
    v->a.cmd_bds = (PFN_vkCmdBindDescriptorSets)v->a.gdpa(v->dev, "vkCmdBindDescriptorSets");
    v->a.cmd_pc = (PFN_vkCmdPushConstants)v->a.gdpa(v->dev, "vkCmdPushConstants");
    v->a.cmd_disp = (PFN_vkCmdDispatch)v->a.gdpa(v->dev, "vkCmdDispatch");
    if (!v->a.cmd_disp || !v->pool) return 100;
    bi.size = 24; bi.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT;
    if (v->a.create_buf(v->dev, &bi, 0, &v->outb) != VK_SUCCESS) return 100;
    v->a.buf_req(v->dev, v->outb, &req);
    ty = host_type(v, req.memoryTypeBits);
    if (ty == 0xFFFFFFFFu) return 100;
    ai.allocationSize = req.size; ai.memoryTypeIndex = ty;
    if (v->a.alloc_mem(v->dev, &ai, 0, &v->outmem) != VK_SUCCESS) return 100;
    if (v->a.bind_mem(v->dev, v->outb, v->outmem, 0) != VK_SUCCESS) return 100;
    nw = (uint32_t)(v->bytes / 4ull); if (nw > 16u) nw = 16u; if (!nw) nw = 1u;
    wi.buffer = v->wbuf; wi.range = (VkDeviceSize)nw * 4ull;
    oi.buffer = v->outb; oi.range = 24;
    w[0].dstSet = v->dset; w[0].dstBinding = 0;
    w[0].descriptorCount = 1; w[0].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    w[0].pBufferInfo = &wi;
    w[1] = w[0]; w[1].dstBinding = 1; w[1].pBufferInfo = &oi;
    v->a.upd_ds(v->dev, 2, w, 0, 0);
    v->same_mem = 1;
    cai.commandPool = v->pool; cai.commandBufferCount = 1;
    if (v->a.alloc_cb(v->dev, &cai, &cb) != VK_SUCCESS) return 100;
    if (v->a.begin_cb(cb, &bgi) != VK_SUCCESS) return 100;
    v->a.cmd_bp(cb, VK_PIPELINE_BIND_POINT_COMPUTE, v->pipe);
    v->a.cmd_bds(cb, VK_PIPELINE_BIND_POINT_COMPUTE, v->pl, 0, 1, &v->dset, 0, 0);
    pc[0] = nw; pc[1] = (uint32_t)v->bytes; pc[2] = (uint32_t)(v->bytes >> 32);
    v->a.cmd_pc(cb, v->pl, VK_SHADER_STAGE_COMPUTE_BIT, 0, 12, pc);
    v->a.cmd_disp(cb, 1, 1, 1);
    v->prim_disp = 1;
    if (v->a.end_cb(cb) != VK_SUCCESS) return 100;
    sub.commandBufferCount = 1; sub.pCommandBuffers = &cb;
    if (v->a.qsubmit(v->q, 1, &sub, 0) != VK_SUCCESS) return 100;
    if (v->a.qidle(v->q) != VK_SUCCESS) return 100;
    v->prim_done = 1;
    if (v->a.map(v->dev, v->outmem, 0, 24, 0, &map) != VK_SUCCESS || !map) return 100;
    for (ty = 0; ty < 6; ++ty) out[ty] = ((uint32_t *)map)[ty];
    v->a.unmap(v->dev, v->outmem);
    if (out[1] != nw || out[2] != pc[1] || out[3] != pc[2]) return 100;
    v->out_acc = out[0];
    v->out_ok = 1;
    return 0;
}
