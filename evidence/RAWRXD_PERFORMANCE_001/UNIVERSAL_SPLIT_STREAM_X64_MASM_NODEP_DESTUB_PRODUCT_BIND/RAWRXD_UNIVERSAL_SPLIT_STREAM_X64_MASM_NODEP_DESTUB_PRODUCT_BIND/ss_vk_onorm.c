/* ss_vk_onorm.c — DEEP2_OUTPUT_NORM on retained blk.0 act[7168] */
#include "ss_vk_api.h"
#include "ss_gguf_find.h"
#include "ss_vk_rmsnorm_spv.h"
#include "ss_evidence.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int finf(float x) { return x == x && x <= 1e30f && x >= -1e30f; }
static int read_abs(const char *path, uint64_t abs, uint64_t n, void *dst)
{
    FILE *f = fopen(path, "rb"); size_t got;
    if (!f) return 1;
    if (_fseeki64(f, (__int64)abs, SEEK_SET)) { fclose(f); return 1; }
    got = fread(dst, 1, (size_t)n, f); fclose(f);
    return got == n ? 0 : 1;
}
static void bind_cmd(SsVk *v)
{
    v->a.cmd_bp = (PFN_vkCmdBindPipeline)v->a.gdpa(v->dev, "vkCmdBindPipeline");
    v->a.cmd_bds = (PFN_vkCmdBindDescriptorSets)v->a.gdpa(v->dev, "vkCmdBindDescriptorSets");
    v->a.cmd_pc = (PFN_vkCmdPushConstants)v->a.gdpa(v->dev, "vkCmdPushConstants");
    v->a.cmd_disp = (PFN_vkCmdDispatch)v->a.gdpa(v->dev, "vkCmdDispatch");
}
int ss_vk_onorm(SsVk *v, const char *shard)
{
    SsGgufTensor t; void *hw = 0, *map = 0; SsTensorId id;
    VkBuffer nob = 0; VkDeviceMemory nom = 0;
    VkShaderModule sm = 0; VkDescriptorSetLayout dsl = 0;
    VkPipelineLayout pl = 0; VkPipeline pipe = 0;
    VkDescriptorPool dp = 0; VkDescriptorSet ds = 0;
    VkCommandBufferAllocateInfo cai = { VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO };
    VkCommandBufferBeginInfo bgi = { VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO };
    VkSubmitInfo sub = { VK_STRUCTURE_TYPE_SUBMIT_INFO };
    VkWriteDescriptorSet w[3]; VkDescriptorBufferInfo bi[3];
    VkCommandBuffer cb; uint32_t pc[2], i; float eps = 1e-6f, *f, first = 0.f;
    int fin = 1, saw = 0, nonc = 0;
    if (!v || !v->block_op || !v->actb || !shard) return 100;
    if (ss_gguf_find(shard, "output_norm.weight", &t) || !t.found) return 100;
    if (t.type != 0 || t.dim0 != (uint64_t)v->embd_dim) return 100;
    id.name = "output_norm.weight"; id.abs_off = t.abs_off; id.bytes = t.bytes;
    id.codec = t.type; id.dim0 = t.dim0; id.dim1 = 1; id.hash = ss_tensor_id_hash(&id);
    ss_tensor_id_print(&id, "bind");
    hw = malloc((size_t)t.bytes);
    if (!hw || read_abs(shard, t.abs_off, t.bytes, hw)) { free(hw); return 100; }
    ss_copy_add_host(t.bytes);
    if (ss_vk_mkbuf(v, (VkDeviceSize)t.bytes, &v->onorm_wb, &v->onorm_wm, &map)) {
        free(hw); return 100;
    }
    memcpy(map, hw, (size_t)t.bytes); v->a.unmap(v->dev, v->onorm_wm); map = 0; free(hw);
    if (ss_vk_mkbuf(v, (VkDeviceSize)v->embd_dim * 4ull, &nob, &nom, 0)) return 100;
    if (ss_vk_pipe3(v, ss_vk_rmsnorm_spv, ss_vk_rmsnorm_spv_words, 8,
                    &sm, &dsl, &pl, &pipe, &dp, &ds)) goto fail;
    bind_cmd(v);
    bi[0].buffer = v->actb; bi[0].offset = 0; bi[0].range = (VkDeviceSize)v->embd_dim * 4ull;
    bi[1].buffer = v->onorm_wb; bi[1].offset = 0; bi[1].range = t.bytes;
    bi[2].buffer = nob; bi[2].offset = 0; bi[2].range = (VkDeviceSize)v->embd_dim * 4ull;
    for (i = 0; i < 3; ++i) {
        memset(&w[i], 0, sizeof w[i]);
        w[i].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET; w[i].dstSet = ds;
        w[i].dstBinding = i; w[i].descriptorCount = 1;
        w[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER; w[i].pBufferInfo = &bi[i];
    }
    v->a.upd_ds(v->dev, 3, w, 0, 0);
    ss_barrier_note("blk0_attn_norm", "output_norm");
    cai.commandPool = v->pool; cai.commandBufferCount = 1;
    if (v->a.alloc_cb(v->dev, &cai, &cb) != VK_SUCCESS) goto fail;
    if (v->a.begin_cb(cb, &bgi) != VK_SUCCESS) goto fail;
    v->a.cmd_bp(cb, VK_PIPELINE_BIND_POINT_COMPUTE, pipe);
    v->a.cmd_bds(cb, VK_PIPELINE_BIND_POINT_COMPUTE, pl, 0, 1, &ds, 0, 0);
    pc[0] = v->embd_dim; memcpy(&pc[1], &eps, 4);
    v->a.cmd_pc(cb, pl, VK_SHADER_STAGE_COMPUTE_BIT, 0, 8, pc);
    v->a.cmd_disp(cb, 1, 1, 1);
    if (v->a.end_cb(cb) != VK_SUCCESS) goto fail;
    sub.commandBufferCount = 1; sub.pCommandBuffers = &cb;
    if (v->a.qsubmit(v->q, 1, &sub, 0) != VK_SUCCESS) goto fail;
    if (v->a.qidle(v->q) != VK_SUCCESS) goto fail;
    if (v->a.map(v->dev, nom, 0, (VkDeviceSize)v->embd_dim * 4ull, 0, &map) != VK_SUCCESS)
        goto fail;
    f = (float *)map;
    for (i = 0; i < v->embd_dim; ++i) {
        if (!finf(f[i])) { fin = 0; break; }
        if (!saw) { first = f[i]; saw = 1; } else if (f[i] != first) nonc = 1;
    }
    v->a.unmap(v->dev, nom);
    /* Swap live activation to onorm output. */
    if (v->actb) v->a.destroy_buf(v->dev, v->actb, 0);
    if (v->actmem) v->a.free_mem(v->dev, v->actmem, 0);
    v->actb = nob; v->actmem = nom; nob = 0; nom = 0;
    v->onorm_op = fin && (v->embd_dim <= 1u || nonc) ? 1 : 0;
    printf("INPUT_FROM_BLOCK_OP=1 OUTPUT_NORM_TENSOR_REAL=1 OUTPUT_NORM_WEIGHT=output_norm.weight\n");
    printf("OUTPUT_NORM_DISPATCHED=1 OUTPUT_NORM_COMPLETED=1 HOST_ACTIVATION_ROUNDTRIP=0\n");
    printf("OUTPUT_NORM_FINITE=%d OUTPUT_NORM_NONCONSTANT=%d DEEP2_OUTPUT_NORM=%s\n",
           fin, nonc, v->onorm_op ? "PASS" : "FAIL");
    if (pipe) v->a.destroy_pipe(v->dev, pipe, 0);
    if (pl) v->a.destroy_pl(v->dev, pl, 0);
    if (dsl) v->a.destroy_dsl(v->dev, dsl, 0);
    if (dp) v->a.destroy_dp(v->dev, dp, 0);
    if (sm) v->a.destroy_sm(v->dev, sm, 0);
    return v->onorm_op ? 0 : 100;
fail:
    if (nob) v->a.destroy_buf(v->dev, nob, 0);
    if (nom) v->a.free_mem(v->dev, nom, 0);
    if (pipe) v->a.destroy_pipe(v->dev, pipe, 0);
    if (pl) v->a.destroy_pl(v->dev, pl, 0);
    if (dsl) v->a.destroy_dsl(v->dev, dsl, 0);
    if (dp) v->a.destroy_dp(v->dev, dp, 0);
    if (sm) v->a.destroy_sm(v->dev, sm, 0);
    return 100;
}
