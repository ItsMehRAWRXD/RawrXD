/* ss_vk_block_exec.c — RMSNorm+GEMV dispatch after tensors imported */
#include "ss_vk_api.h"
#include "ss_vk_rmsnorm_spv.h"
#include "ss_vk_gemv_spv.h"
#include <string.h>
static int finf(float x) { return x == x && x <= 1e30f && x >= -1e30f; }
static void bind_cmd(SsVk *v)
{
    v->a.cmd_bp = (PFN_vkCmdBindPipeline)v->a.gdpa(v->dev, "vkCmdBindPipeline");
    v->a.cmd_bds = (PFN_vkCmdBindDescriptorSets)v->a.gdpa(v->dev, "vkCmdBindDescriptorSets");
    v->a.cmd_pc = (PFN_vkCmdPushConstants)v->a.gdpa(v->dev, "vkCmdPushConstants");
    v->a.cmd_disp = (PFN_vkCmdDispatch)v->a.gdpa(v->dev, "vkCmdDispatch");
    v->a.cmd_bar = (PFN_vkCmdPipelineBarrier)v->a.gdpa(v->dev, "vkCmdPipelineBarrier");
}
int ss_vk_block_exec(SsVk *v, VkBuffer nwb, uint64_t nbytes, VkBuffer nob, VkBuffer qob,
                     VkDeviceMemory qom, uint32_t rows, uint32_t cols)
{
    VkShaderModule sm_n = 0, sm_g = 0; VkDescriptorSetLayout dsl_n = 0, dsl_g = 0;
    VkPipelineLayout pl_n = 0, pl_g = 0; VkPipeline pipe_n = 0, pipe_g = 0;
    VkDescriptorPool dp_n = 0, dp_g = 0; VkDescriptorSet ds_n = 0, ds_g = 0;
    VkCommandBufferAllocateInfo cai = { VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO };
    VkCommandBufferBeginInfo bgi = { VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO };
    VkSubmitInfo sub = { VK_STRUCTURE_TYPE_SUBMIT_INFO };
    VkMemoryBarrier mb = { VK_STRUCTURE_TYPE_MEMORY_BARRIER };
    VkWriteDescriptorSet w[3]; VkDescriptorBufferInfo bi[3];
    VkCommandBuffer cb; uint32_t pc_n[2], pc_g[3], i; float eps = 1e-6f, *f, first = 0.f;
    int fin = 1, saw = 0, nonc = 0; void *map = 0;
    if (ss_vk_pipe3(v, ss_vk_rmsnorm_spv, ss_vk_rmsnorm_spv_words, 8,
                    &sm_n, &dsl_n, &pl_n, &pipe_n, &dp_n, &ds_n)) return 100;
    if (ss_vk_pipe3(v, ss_vk_gemv_spv, ss_vk_gemv_spv_words, 12,
                    &sm_g, &dsl_g, &pl_g, &pipe_g, &dp_g, &ds_g)) return 100;
    bind_cmd(v);
    bi[0].buffer = v->outb; bi[0].offset = 0; bi[0].range = (VkDeviceSize)v->embd_dim * 4ull;
    bi[1].buffer = nwb; bi[1].offset = 0; bi[1].range = nbytes;
    bi[2].buffer = nob; bi[2].offset = 0; bi[2].range = (VkDeviceSize)v->embd_dim * 4ull;
    for (i = 0; i < 3; ++i) {
        memset(&w[i], 0, sizeof w[i]);
        w[i].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET; w[i].dstSet = ds_n;
        w[i].dstBinding = i; w[i].descriptorCount = 1;
        w[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER; w[i].pBufferInfo = &bi[i];
    }
    v->a.upd_ds(v->dev, 3, w, 0, 0);
    bi[0].buffer = v->pbuf; bi[0].range = v->pbytes;
    bi[1].buffer = nob; bi[1].range = (VkDeviceSize)v->embd_dim * 4ull;
    bi[2].buffer = qob; bi[2].range = (VkDeviceSize)rows * 4ull;
    for (i = 0; i < 3; ++i) { w[i].dstSet = ds_g; w[i].dstBinding = i; w[i].pBufferInfo = &bi[i]; }
    v->a.upd_ds(v->dev, 3, w, 0, 0);
    cai.commandPool = v->pool; cai.commandBufferCount = 1;
    if (v->a.alloc_cb(v->dev, &cai, &cb) != VK_SUCCESS) return 100;
    if (v->a.begin_cb(cb, &bgi) != VK_SUCCESS) return 100;
    v->a.cmd_bp(cb, VK_PIPELINE_BIND_POINT_COMPUTE, pipe_n);
    v->a.cmd_bds(cb, VK_PIPELINE_BIND_POINT_COMPUTE, pl_n, 0, 1, &ds_n, 0, 0);
    pc_n[0] = v->embd_dim; memcpy(&pc_n[1], &eps, 4);
    v->a.cmd_pc(cb, pl_n, VK_SHADER_STAGE_COMPUTE_BIT, 0, 8, pc_n);
    v->a.cmd_disp(cb, 1, 1, 1); v->rms_disp = 1;
    mb.srcAccessMask = VK_ACCESS_SHADER_WRITE_BIT; mb.dstAccessMask = VK_ACCESS_SHADER_READ_BIT;
    v->a.cmd_bar(cb, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
                 0, 1, &mb, 0, 0, 0, 0);
    v->a.cmd_bp(cb, VK_PIPELINE_BIND_POINT_COMPUTE, pipe_g);
    v->a.cmd_bds(cb, VK_PIPELINE_BIND_POINT_COMPUTE, pl_g, 0, 1, &ds_g, 0, 0);
    pc_g[0] = rows; pc_g[1] = cols; pc_g[2] = 12;
    v->a.cmd_pc(cb, pl_g, VK_SHADER_STAGE_COMPUTE_BIT, 0, 12, pc_g);
    v->a.cmd_disp(cb, (rows + 63u) / 64u, 1, 1); v->proj_disp = 1;
    if (v->a.end_cb(cb) != VK_SUCCESS) return 100;
    sub.commandBufferCount = 1; sub.pCommandBuffers = &cb;
    if (v->a.qsubmit(v->q, 1, &sub, 0) != VK_SUCCESS) return 100;
    if (v->a.qidle(v->q) != VK_SUCCESS) return 100;
    v->rms_done = v->proj_done = 1;
    if (v->a.map(v->dev, qom, 0, (VkDeviceSize)rows * 4ull, 0, &map) != VK_SUCCESS) return 100;
    f = (float *)map;
    for (i = 0; i < rows; ++i) {
        if (!finf(f[i])) { fin = 0; break; }
        if (!saw) { first = f[i]; saw = 1; } else if (f[i] != first) nonc = 1;
    }
    v->a.unmap(v->dev, qom);
    v->block_n = rows; v->block_finite = fin; v->block_ok = fin && (rows <= 1u || nonc);
    v->chain_gpu = 1; v->block_op = v->block_ok ? 1 : 0;
    if (pipe_n) v->a.destroy_pipe(v->dev, pipe_n, 0);
    if (pipe_g) v->a.destroy_pipe(v->dev, pipe_g, 0);
    if (pl_n) v->a.destroy_pl(v->dev, pl_n, 0); if (pl_g) v->a.destroy_pl(v->dev, pl_g, 0);
    if (dsl_n) v->a.destroy_dsl(v->dev, dsl_n, 0); if (dsl_g) v->a.destroy_dsl(v->dev, dsl_g, 0);
    if (dp_n) v->a.destroy_dp(v->dev, dp_n, 0); if (dp_g) v->a.destroy_dp(v->dev, dp_g, 0);
    if (sm_n) v->a.destroy_sm(v->dev, sm_n, 0); if (sm_g) v->a.destroy_sm(v->dev, sm_g, 0);
    return v->block_op ? 0 : 100;
}
