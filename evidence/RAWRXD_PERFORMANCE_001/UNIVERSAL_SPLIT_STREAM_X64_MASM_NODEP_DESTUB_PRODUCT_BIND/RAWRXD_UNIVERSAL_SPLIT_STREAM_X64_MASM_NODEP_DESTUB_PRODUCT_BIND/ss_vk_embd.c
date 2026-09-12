/* ss_vk_embd.c — Q4_K/F32 embedding lookup on imported HOT; host maps output only */
#include "ss_vk_api.h"
#include "ss_vk_block_util.h"
#include <stdio.h>
static int finf(float x) { return x == x && x <= 1e30f && x >= -1e30f; }
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
static int geo(SsVk *v)
{
    uint64_t cols, rows, need;
    if (v->tensor_type == 12) {
        cols = v->dim0 ? v->dim0 : 0;
        rows = v->dim1 ? v->dim1 : 0;
        if (!cols || !rows || (cols % 256ull) || cols * rows != v->element_count)
            return 100;
        need = rows * (cols / 256ull) * 144ull;
        if (need != v->bytes) return 100;
        v->embd_dim = (uint32_t)cols;
        v->geo_ok = 1;
        return 0;
    }
    if (v->tensor_type == 0) {
        cols = v->dim0 ? v->dim0 : (v->bytes / 4ull);
        rows = v->dim1 ? v->dim1 : 1ull;
        if (!cols || rows * cols * 4ull != v->bytes) return 100;
        v->embd_dim = (uint32_t)cols;
        v->geo_ok = 1;
        return 0;
    }
    return 100;
}
int ss_vk_embd(SsVk *v)
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
    VkCommandBuffer cb = 0; uint32_t ty, pc[4], i, groups; void *map = 0; float *f; int fin = 1;
    float first = 0.f; int saw = 0, nonc = 0;
    if (!v || !v->bound || !v->sync_ok || !v->vis_ok || !v->wbuf) {
        printf("EMBD_FAIL stage=precond\n"); fflush(stdout); return 100;
    }
    if (geo(v)) {
        printf("EMBD_FAIL stage=geo ty=%u d0=%llu d1=%llu bytes=%llu\n",
               v->tensor_type, (unsigned long long)v->dim0,
               (unsigned long long)v->dim1, (unsigned long long)v->bytes);
        fflush(stdout); return 100;
    }
    if (v->token_id >= (v->dim1 ? v->dim1 : 1ull)) {
        printf("EMBD_FAIL stage=token_id id=%u rows=%llu\n", v->token_id,
               (unsigned long long)(v->dim1 ? v->dim1 : 1ull));
        fflush(stdout); return 100;
    }
    ss_vk_cmd_reclaim(v);
    if (!v->pool && ss_vk_pool_recreate(v)) {
        printf("EMBD_FAIL stage=pool_recreate\n"); fflush(stdout); return 100;
    }
    ss_vk_dropb(v, &v->outb, &v->outmem);
    if (ss_vk_pipe(v)) { printf("EMBD_FAIL stage=pipe\n"); fflush(stdout); return 100; }
    v->a.cmd_bp = (PFN_vkCmdBindPipeline)v->a.gdpa(v->dev, "vkCmdBindPipeline");
    v->a.cmd_bds = (PFN_vkCmdBindDescriptorSets)v->a.gdpa(v->dev, "vkCmdBindDescriptorSets");
    v->a.cmd_pc = (PFN_vkCmdPushConstants)v->a.gdpa(v->dev, "vkCmdPushConstants");
    v->a.cmd_disp = (PFN_vkCmdDispatch)v->a.gdpa(v->dev, "vkCmdDispatch");
    if (!v->a.cmd_disp || !v->pool) {
        printf("EMBD_FAIL stage=cmd_fn\n"); fflush(stdout); return 100;
    }
    bi.size = (VkDeviceSize)v->embd_dim * 4ull;
    bi.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT;
    if (v->a.create_buf(v->dev, &bi, 0, &v->outb) != VK_SUCCESS) {
        printf("EMBD_FAIL stage=create_buf\n"); fflush(stdout); return 100;
    }
    v->a.buf_req(v->dev, v->outb, &req);
    ty = host_type(v, req.memoryTypeBits);
    if (ty == 0xFFFFFFFFu) {
        printf("EMBD_FAIL stage=host_type\n"); fflush(stdout); return 100;
    }
    ai.allocationSize = req.size; ai.memoryTypeIndex = ty;
    if (v->a.alloc_mem(v->dev, &ai, 0, &v->outmem) != VK_SUCCESS) {
        printf("EMBD_FAIL stage=alloc_mem need=%llu\n",
               (unsigned long long)req.size); fflush(stdout); return 100;
    }
    if (v->a.bind_mem(v->dev, v->outb, v->outmem, 0) != VK_SUCCESS) {
        printf("EMBD_FAIL stage=bind_mem\n"); fflush(stdout); return 100;
    }
    wi.buffer = v->wbuf; wi.range = v->bytes;
    oi.buffer = v->outb; oi.range = bi.size;
    w[0].dstSet = v->dset; w[0].dstBinding = 0;
    w[0].descriptorCount = 1; w[0].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    w[0].pBufferInfo = &wi;
    w[1] = w[0]; w[1].dstBinding = 1; w[1].pBufferInfo = &oi;
    v->a.upd_ds(v->dev, 2, w, 0, 0);
    v->same_mem = 1;
    cai.commandPool = v->pool; cai.commandBufferCount = 1;
    if (v->a.alloc_cb(v->dev, &cai, &cb) != VK_SUCCESS) {
        printf("EMBD_FAIL stage=alloc_cb\n"); fflush(stdout); return 100;
    }
    if (v->a.begin_cb(cb, &bgi) != VK_SUCCESS) {
        printf("EMBD_FAIL stage=begin_cb\n"); fflush(stdout); return 100;
    }
    v->a.cmd_bp(cb, VK_PIPELINE_BIND_POINT_COMPUTE, v->pipe);
    v->a.cmd_bds(cb, VK_PIPELINE_BIND_POINT_COMPUTE, v->pl, 0, 1, &v->dset, 0, 0);
    pc[0] = v->token_id; pc[1] = v->embd_dim;
    pc[2] = (uint32_t)(v->dim1 ? v->dim1 : 1ull); pc[3] = v->tensor_type;
    v->a.cmd_pc(cb, v->pl, VK_SHADER_STAGE_COMPUTE_BIT, 0, 16, pc);
    groups = (v->embd_dim + 63u) / 64u;
    v->a.cmd_disp(cb, groups, 1, 1);
    v->prim_disp = 1;
    if (v->a.end_cb(cb) != VK_SUCCESS) {
        printf("EMBD_FAIL stage=end_cb\n"); fflush(stdout); return 100;
    }
    sub.commandBufferCount = 1; sub.pCommandBuffers = &cb;
    {
        VkResult qr = v->a.qsubmit(v->q, 1, &sub, 0);
        if (qr != VK_SUCCESS) {
            printf("EMBD_FAIL stage=qsubmit vr=%d — recreating pool\n", (int)qr);
            fflush(stdout);
            if (v->a.free_cb) v->a.free_cb(v->dev, v->pool, 1, &cb);
            cb = 0;
            if (ss_vk_pool_recreate(v)) return 100;
            cai.commandPool = v->pool;
            if (v->a.alloc_cb(v->dev, &cai, &cb) != VK_SUCCESS) return 100;
            if (v->a.begin_cb(cb, &bgi) != VK_SUCCESS) return 100;
            v->a.cmd_bp(cb, VK_PIPELINE_BIND_POINT_COMPUTE, v->pipe);
            v->a.cmd_bds(cb, VK_PIPELINE_BIND_POINT_COMPUTE, v->pl, 0, 1, &v->dset, 0, 0);
            v->a.cmd_pc(cb, v->pl, VK_SHADER_STAGE_COMPUTE_BIT, 0, 16, pc);
            v->a.cmd_disp(cb, groups, 1, 1);
            if (v->a.end_cb(cb) != VK_SUCCESS) return 100;
            sub.pCommandBuffers = &cb;
            qr = v->a.qsubmit(v->q, 1, &sub, 0);
            if (qr != VK_SUCCESS) {
                printf("EMBD_FAIL stage=qsubmit_retry vr=%d\n", (int)qr);
                fflush(stdout); return 100;
            }
        }
    }
    if (v->a.qidle(v->q) != VK_SUCCESS) {
        printf("EMBD_FAIL stage=qidle\n"); fflush(stdout); return 100;
    }
    if (v->a.free_cb) v->a.free_cb(v->dev, v->pool, 1, &cb);
    v->prim_done = 1;
    if (v->a.map(v->dev, v->outmem, 0, bi.size, 0, &map) != VK_SUCCESS || !map) {
        printf("EMBD_FAIL stage=map\n"); fflush(stdout); return 100;
    }
    f = (float *)map;
    for (i = 0; i < v->embd_dim; ++i) {
        if (!finf(f[i])) { fin = 0; break; }
        if (!saw) { first = f[i]; saw = 1; }
        else if (f[i] != first) nonc = 1;
    }
    v->a.unmap(v->dev, v->outmem);
    v->embd_n = v->embd_dim;
    v->out_finite = fin;
    v->out_ok = fin && (v->embd_dim <= 1u || nonc);
    v->out_acc = (uint64_t)v->embd_n;
    v->model_op = v->out_ok ? 1 : 0;
    if (!v->model_op) {
        printf("EMBD_FAIL stage=observe fin=%d nonc=%d first=%g dim=%u ty=%u\n",
               fin, nonc, (double)first, v->embd_dim, v->tensor_type);
        fflush(stdout);
    }
    return v->model_op ? 0 : 100;
}
