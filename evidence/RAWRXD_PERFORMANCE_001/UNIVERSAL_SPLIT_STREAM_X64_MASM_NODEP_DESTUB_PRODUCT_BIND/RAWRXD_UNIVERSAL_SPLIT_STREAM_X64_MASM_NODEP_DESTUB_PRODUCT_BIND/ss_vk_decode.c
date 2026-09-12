/* ss_vk_decode.c — N-step abbreviated embd→attn_norm→onorm→lmhead TPS */
#include "ss_vk_api.h"
#include "ss_vk_rmsnorm_spv.h"
#include "ss_vk_gemv_spv.h"
#include <stdio.h>
#include <string.h>
#include <windows.h>
static void bind_cmd(SsVk *v)
{
    v->a.cmd_bp = (PFN_vkCmdBindPipeline)v->a.gdpa(v->dev, "vkCmdBindPipeline");
    v->a.cmd_bds = (PFN_vkCmdBindDescriptorSets)v->a.gdpa(v->dev, "vkCmdBindDescriptorSets");
    v->a.cmd_pc = (PFN_vkCmdPushConstants)v->a.gdpa(v->dev, "vkCmdPushConstants");
    v->a.cmd_disp = (PFN_vkCmdDispatch)v->a.gdpa(v->dev, "vkCmdDispatch");
    v->a.cmd_bar = (PFN_vkCmdPipelineBarrier)v->a.gdpa(v->dev, "vkCmdPipelineBarrier");
}
static int embd_tok(SsVk *v, uint32_t tid)
{
    VkDescriptorBufferInfo wi = { 0 }, oi = { 0 };
    VkWriteDescriptorSet w[2] = {
        { VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET },
        { VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET }
    };
    VkCommandBufferAllocateInfo cai = { VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO };
    VkCommandBufferBeginInfo bgi = { VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO };
    VkSubmitInfo sub = { VK_STRUCTURE_TYPE_SUBMIT_INFO };
    VkCommandBuffer cb; uint32_t pc[4], groups;
    if (!v->pipe || !v->outb || tid >= (uint32_t)(v->dim1 ? v->dim1 : 1ull)) return 100;
    v->token_id = tid;
    wi.buffer = v->wbuf; wi.range = v->bytes;
    oi.buffer = v->outb; oi.range = (VkDeviceSize)v->embd_dim * 4ull;
    w[0].dstSet = v->dset; w[0].dstBinding = 0; w[0].descriptorCount = 1;
    w[0].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER; w[0].pBufferInfo = &wi;
    w[1] = w[0]; w[1].dstBinding = 1; w[1].pBufferInfo = &oi;
    v->a.upd_ds(v->dev, 2, w, 0, 0);
    cai.commandPool = v->pool; cai.commandBufferCount = 1;
    if (v->a.alloc_cb(v->dev, &cai, &cb) != VK_SUCCESS) return 100;
    if (v->a.begin_cb(cb, &bgi) != VK_SUCCESS) return 100;
    v->a.cmd_bp(cb, VK_PIPELINE_BIND_POINT_COMPUTE, v->pipe);
    v->a.cmd_bds(cb, VK_PIPELINE_BIND_POINT_COMPUTE, v->pl, 0, 1, &v->dset, 0, 0);
    pc[0] = tid; pc[1] = v->embd_dim;
    pc[2] = (uint32_t)(v->dim1 ? v->dim1 : 1ull); pc[3] = v->tensor_type;
    v->a.cmd_pc(cb, v->pl, VK_SHADER_STAGE_COMPUTE_BIT, 0, 16, pc);
    groups = (v->embd_dim + 63u) / 64u;
    v->a.cmd_disp(cb, groups, 1, 1);
    if (v->a.end_cb(cb) != VK_SUCCESS) return 100;
    sub.commandBufferCount = 1; sub.pCommandBuffers = &cb;
    if (v->a.qsubmit(v->q, 1, &sub, 0) != VK_SUCCESS) return 100;
    return v->a.qidle(v->q) == VK_SUCCESS ? 0 : 100;
}
static int rms_run(SsVk *v, VkBuffer inb, VkBuffer wb, uint64_t wbytes, VkBuffer outb)
{
    VkShaderModule sm = 0; VkDescriptorSetLayout dsl = 0;
    VkPipelineLayout pl = 0; VkPipeline pipe = 0;
    VkDescriptorPool dp = 0; VkDescriptorSet ds = 0;
    VkCommandBufferAllocateInfo cai = { VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO };
    VkCommandBufferBeginInfo bgi = { VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO };
    VkSubmitInfo sub = { VK_STRUCTURE_TYPE_SUBMIT_INFO };
    VkWriteDescriptorSet w[3]; VkDescriptorBufferInfo bi[3];
    VkCommandBuffer cb; uint32_t pc[2], i; float eps = 1e-6f; int rc = 100;
    if (ss_vk_pipe3(v, ss_vk_rmsnorm_spv, ss_vk_rmsnorm_spv_words, 8,
                    &sm, &dsl, &pl, &pipe, &dp, &ds)) return 100;
    bi[0].buffer = inb; bi[0].offset = 0; bi[0].range = (VkDeviceSize)v->embd_dim * 4ull;
    bi[1].buffer = wb; bi[1].offset = 0; bi[1].range = wbytes;
    bi[2].buffer = outb; bi[2].offset = 0; bi[2].range = (VkDeviceSize)v->embd_dim * 4ull;
    for (i = 0; i < 3; ++i) {
        memset(&w[i], 0, sizeof w[i]);
        w[i].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET; w[i].dstSet = ds;
        w[i].dstBinding = i; w[i].descriptorCount = 1;
        w[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER; w[i].pBufferInfo = &bi[i];
    }
    v->a.upd_ds(v->dev, 3, w, 0, 0);
    cai.commandPool = v->pool; cai.commandBufferCount = 1;
    if (v->a.alloc_cb(v->dev, &cai, &cb) != VK_SUCCESS) goto done;
    if (v->a.begin_cb(cb, &bgi) != VK_SUCCESS) goto done;
    v->a.cmd_bp(cb, VK_PIPELINE_BIND_POINT_COMPUTE, pipe);
    v->a.cmd_bds(cb, VK_PIPELINE_BIND_POINT_COMPUTE, pl, 0, 1, &ds, 0, 0);
    pc[0] = v->embd_dim; memcpy(&pc[1], &eps, 4);
    v->a.cmd_pc(cb, pl, VK_SHADER_STAGE_COMPUTE_BIT, 0, 8, pc);
    v->a.cmd_disp(cb, 1, 1, 1);
    if (v->a.end_cb(cb) != VK_SUCCESS) goto done;
    sub.commandBufferCount = 1; sub.pCommandBuffers = &cb;
    if (v->a.qsubmit(v->q, 1, &sub, 0) != VK_SUCCESS) goto done;
    if (v->a.qidle(v->q) != VK_SUCCESS) goto done;
    rc = 0;
done:
    if (pipe) v->a.destroy_pipe(v->dev, pipe, 0);
    if (pl) v->a.destroy_pl(v->dev, pl, 0);
    if (dsl) v->a.destroy_dsl(v->dev, dsl, 0);
    if (dp) v->a.destroy_dp(v->dev, dp, 0);
    if (sm) v->a.destroy_sm(v->dev, sm, 0);
    return rc;
}
static int gemv_lm(SsVk *v)
{
    VkShaderModule sm = 0; VkDescriptorSetLayout dsl = 0;
    VkPipelineLayout pl = 0; VkPipeline pipe = 0;
    VkDescriptorPool dp = 0; VkDescriptorSet ds = 0;
    VkCommandBufferAllocateInfo cai = { VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO };
    VkCommandBufferBeginInfo bgi = { VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO };
    VkSubmitInfo sub = { VK_STRUCTURE_TYPE_SUBMIT_INFO };
    VkWriteDescriptorSet w[3]; VkDescriptorBufferInfo bi[3];
    VkCommandBuffer cb; uint32_t pc[3], i; int rc = 100;
    if (ss_vk_pipe3(v, ss_vk_gemv_spv, ss_vk_gemv_spv_words, 12,
                    &sm, &dsl, &pl, &pipe, &dp, &ds)) return 100;
    bi[0].buffer = v->lbuf; bi[0].offset = 0; bi[0].range = v->lbytes;
    bi[1].buffer = v->actb; bi[1].offset = 0; bi[1].range = (VkDeviceSize)v->embd_dim * 4ull;
    bi[2].buffer = v->logitsb; bi[2].offset = 0; bi[2].range = (VkDeviceSize)v->vocab_n * 4ull;
    for (i = 0; i < 3; ++i) {
        memset(&w[i], 0, sizeof w[i]);
        w[i].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET; w[i].dstSet = ds;
        w[i].dstBinding = i; w[i].descriptorCount = 1;
        w[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER; w[i].pBufferInfo = &bi[i];
    }
    v->a.upd_ds(v->dev, 3, w, 0, 0);
    cai.commandPool = v->pool; cai.commandBufferCount = 1;
    if (v->a.alloc_cb(v->dev, &cai, &cb) != VK_SUCCESS) goto done;
    if (v->a.begin_cb(cb, &bgi) != VK_SUCCESS) goto done;
    v->a.cmd_bp(cb, VK_PIPELINE_BIND_POINT_COMPUTE, pipe);
    v->a.cmd_bds(cb, VK_PIPELINE_BIND_POINT_COMPUTE, pl, 0, 1, &ds, 0, 0);
    pc[0] = v->vocab_n; pc[1] = v->embd_dim; pc[2] = 14;
    v->a.cmd_pc(cb, pl, VK_SHADER_STAGE_COMPUTE_BIT, 0, 12, pc);
    v->a.cmd_disp(cb, (v->vocab_n + 63u) / 64u, 1, 1);
    if (v->a.end_cb(cb) != VK_SUCCESS) goto done;
    sub.commandBufferCount = 1; sub.pCommandBuffers = &cb;
    if (v->a.qsubmit(v->q, 1, &sub, 0) != VK_SUCCESS) goto done;
    if (v->a.qidle(v->q) != VK_SUCCESS) goto done;
    rc = 0;
done:
    if (pipe) v->a.destroy_pipe(v->dev, pipe, 0);
    if (pl) v->a.destroy_pl(v->dev, pl, 0);
    if (dsl) v->a.destroy_dsl(v->dev, dsl, 0);
    if (dp) v->a.destroy_dp(v->dev, dp, 0);
    if (sm) v->a.destroy_sm(v->dev, sm, 0);
    return rc;
}
static int argmax(SsVk *v)
{
    void *map = 0; float *f; uint32_t i, best = 0; float bv;
    if (v->a.map(v->dev, v->logitsmem, 0, (VkDeviceSize)v->vocab_n * 4ull, 0, &map) != VK_SUCCESS)
        return 100;
    f = (float *)map; bv = f[0];
    for (i = 1; i < v->vocab_n; ++i) if (f[i] > bv) { bv = f[i]; best = i; }
    v->a.unmap(v->dev, v->logitsmem);
    v->next_token = best;
    return 0;
}
int ss_vk_abbrev_decode(SsVk *v, const char *shard, uint32_t steps)
{
    VkBuffer tmp = 0; VkDeviceMemory tmpm = 0;
    LARGE_INTEGER f0, t0, t1; uint32_t s, tid; double sec;
    (void)shard;
    if (!v || !v->token_op || !steps || !v->anorm_wb || !v->onorm_wb || !v->lbuf || !v->logitsb)
        return 100;
    if (ss_vk_mkbuf(v, (VkDeviceSize)v->embd_dim * 4ull, &tmp, &tmpm, 0)) return 100;
    bind_cmd(v);
    tid = v->next_token;
    QueryPerformanceFrequency(&f0);
    QueryPerformanceCounter(&t0);
    for (s = 0; s < steps; ++s) {
        if (embd_tok(v, tid)) goto fail;
        if (rms_run(v, v->outb, v->anorm_wb, (uint64_t)v->embd_dim * 4ull, tmp)) goto fail;
        if (rms_run(v, tmp, v->onorm_wb, (uint64_t)v->embd_dim * 4ull, v->actb)) goto fail;
        if (gemv_lm(v)) goto fail;
        if (argmax(v)) goto fail;
        tid = v->next_token;
    }
    QueryPerformanceCounter(&t1);
    sec = (double)(t1.QuadPart - t0.QuadPart) / (double)f0.QuadPart;
    if (sec <= 0.0) sec = 1e-9;
    v->decode_steps = steps;
    v->abbrev_tps = (double)steps / sec;
    v->decode_loop = 1;
    printf("ABBREVIATED_DECODE_STEPS=%u ABBREVIATED_TPS=%.6f\n", steps, v->abbrev_tps);
    printf("DECODE_KIND=ABBREVIATED_SPLIT_STREAM FULL_MODEL_FORWARD=0\n");
    printf("TPS_SCOPE=PRODUCT_CHAIN_ONLY DECODE_LOOP_RAN=1 PROMOTE=0\n");
    if (tmp) v->a.destroy_buf(v->dev, tmp, 0);
    if (tmpm) v->a.free_mem(v->dev, tmpm, 0);
    return 0;
fail:
    if (tmp) v->a.destroy_buf(v->dev, tmp, 0);
    if (tmpm) v->a.free_mem(v->dev, tmpm, 0);
    return 100;
}
