/* ss_vk_op_gemv_tile.c — GEMV tile with weight/logits byte offsets */
#include "ss_vk_ops.h"
#include "ss_vk_gemv_spv.h"
#include <stdio.h>
#include <string.h>
static void bind_cmd(SsVk *v)
{
    v->a.cmd_bp = (PFN_vkCmdBindPipeline)v->a.gdpa(v->dev, "vkCmdBindPipeline");
    v->a.cmd_bds = (PFN_vkCmdBindDescriptorSets)v->a.gdpa(v->dev, "vkCmdBindDescriptorSets");
    v->a.cmd_pc = (PFN_vkCmdPushConstants)v->a.gdpa(v->dev, "vkCmdPushConstants");
    v->a.cmd_disp = (PFN_vkCmdDispatch)v->a.gdpa(v->dev, "vkCmdDispatch");
}
int ss_vk_op_gemv_tile(SsVk *v, VkBuffer wb, uint64_t w_off, uint64_t w_bytes,
                       VkBuffer xb, VkBuffer yb, uint64_t y_off,
                       uint32_t nrows, uint32_t cols, uint32_t codec)
{
    VkShaderModule sm = 0; VkDescriptorSetLayout dsl = 0; VkPipelineLayout pl = 0;
    VkPipeline pipe = 0; VkDescriptorPool dp = 0; VkDescriptorSet ds = 0;
    VkCommandBufferAllocateInfo cai = { VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO };
    VkCommandBufferBeginInfo bgi = { VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO };
    VkSubmitInfo sub = { VK_STRUCTURE_TYPE_SUBMIT_INFO };
    VkWriteDescriptorSet w[3]; VkDescriptorBufferInfo bi[3];
    VkCommandBuffer cb = 0; uint32_t pc[3], i; int rc = 100; VkResult vr;
    if (!v || !wb || !xb || !yb || !nrows || !cols || !w_bytes) return 100;
    if (ss_vk_pipe3(v, ss_vk_gemv_spv, ss_vk_gemv_spv_words, 12,
                    &sm, &dsl, &pl, &pipe, &dp, &ds)) return 100;
    bind_cmd(v);
    memset(bi, 0, sizeof bi);
    bi[0].buffer = wb; bi[0].offset = (VkDeviceSize)w_off; bi[0].range = (VkDeviceSize)w_bytes;
    bi[1].buffer = xb; bi[1].offset = 0; bi[1].range = (VkDeviceSize)cols * 4ull;
    bi[2].buffer = yb; bi[2].offset = (VkDeviceSize)y_off; bi[2].range = (VkDeviceSize)nrows * 4ull;
    for (i = 0; i < 3; ++i) {
        memset(&w[i], 0, sizeof w[i]);
        w[i].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET; w[i].dstSet = ds;
        w[i].dstBinding = i; w[i].descriptorCount = 1;
        w[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER; w[i].pBufferInfo = &bi[i];
    }
    v->a.upd_ds(v->dev, 3, w, 0, 0);
    cai.commandPool = v->pool; cai.commandBufferCount = 1;
    if (v->a.alloc_cb(v->dev, &cai, &cb) || v->a.begin_cb(cb, &bgi)) goto done;
    v->a.cmd_bp(cb, VK_PIPELINE_BIND_POINT_COMPUTE, pipe);
    v->a.cmd_bds(cb, VK_PIPELINE_BIND_POINT_COMPUTE, pl, 0, 1, &ds, 0, 0);
    pc[0] = nrows; pc[1] = cols; pc[2] = codec;
    v->a.cmd_pc(cb, pl, VK_SHADER_STAGE_COMPUTE_BIT, 0, 12, pc);
    v->a.cmd_disp(cb, (nrows + 63u) / 64u, 1, 1);
    if (v->a.end_cb(cb)) goto done;
    sub.commandBufferCount = 1; sub.pCommandBuffers = &cb;
    vr = v->a.qsubmit(v->q, 1, &sub, 0);
    if (vr != VK_SUCCESS) { rc = (int)vr; goto done; }
    vr = v->a.qidle(v->q);
    if (vr != VK_SUCCESS) { rc = (int)vr; goto done; }
    rc = 0;
done:
    if (cb && v->a.free_cb) v->a.free_cb(v->dev, v->pool, 1, &cb);
    if (pipe) v->a.destroy_pipe(v->dev, pipe, 0);
    if (pl) v->a.destroy_pl(v->dev, pl, 0);
    if (dsl) v->a.destroy_dsl(v->dev, dsl, 0);
    if (dp) v->a.destroy_dp(v->dev, dp, 0);
    if (sm) v->a.destroy_sm(v->dev, sm, 0);
    return rc;
}
