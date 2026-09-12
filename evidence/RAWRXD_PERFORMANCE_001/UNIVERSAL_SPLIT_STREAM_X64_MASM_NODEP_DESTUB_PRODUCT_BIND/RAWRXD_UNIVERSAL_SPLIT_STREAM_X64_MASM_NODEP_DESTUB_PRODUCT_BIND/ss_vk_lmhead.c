/* ss_vk_lmhead.c — Q6_K lm-head GEMV → logits[vocab] on imported HOT */
#include "ss_vk_api.h"
#include "ss_gguf_find.h"
#include "ss_vk_gemv_spv.h"
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
static void capture_act(SsVk *v)
{
    FILE *f; void *map = 0; size_t n;
    if (!v->actb || !v->actmem) return;
    n = (size_t)v->embd_dim * 4ull;
    if (v->a.map(v->dev, v->actmem, 0, n, 0, &map) != VK_SUCCESS || !map) return;
    f = fopen("act_7168.f32", "wb");
    if (f) { fwrite(map, 1, n, f); fclose(f); printf("ACT_CAPTURE=act_7168.f32 BYTES=%zu\n", n); }
    v->a.unmap(v->dev, v->actmem);
}
int ss_vk_lmhead(SsVk *v, const char *shard, SsVkPromote2 promote2)
{
    SsGgufTensor t; void *hw = 0, *pnt = 0, *fnt = 0, *map = 0;
    SsTensorId id; uint64_t fval = 0; uint32_t rows, cols, i;
    VkShaderModule sm = 0; VkDescriptorSetLayout dsl = 0;
    VkPipelineLayout pl = 0; VkPipeline pipe = 0;
    VkDescriptorPool dp = 0; VkDescriptorSet ds = 0;
    VkCommandBufferAllocateInfo cai = { VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO };
    VkCommandBufferBeginInfo bgi = { VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO };
    VkSubmitInfo sub = { VK_STRUCTURE_TYPE_SUBMIT_INFO };
    VkWriteDescriptorSet w[3]; VkDescriptorBufferInfo bi[3];
    VkCommandBuffer cb; uint32_t pc[3]; float *f, first = 0.f;
    int fin = 1, saw = 0, nonc = 0;
    if (!v || !v->onorm_op || !v->actb || !shard || !promote2) return 100;
    if (ss_gguf_find(shard, "output.weight", &t) || !t.found) return 100;
    if (t.type != 14 || t.dim0 != (uint64_t)v->embd_dim) return 100;
    rows = (uint32_t)t.dim1; cols = (uint32_t)t.dim0;
    id.name = "output.weight"; id.abs_off = t.abs_off; id.bytes = t.bytes;
    id.codec = t.type; id.dim0 = t.dim0; id.dim1 = t.dim1; id.hash = ss_tensor_id_hash(&id);
    ss_tensor_id_print(&id, "bind");
    printf("LMHEAD_GEO rows=%u cols=%u q6k_nblk=%u wg=%u LEN=%llu\n",
           rows, cols, (cols + 255u) / 256u, (rows + 63u) / 64u,
           (unsigned long long)t.bytes);
    hw = malloc((size_t)t.bytes);
    if (!hw) return 100;
    if (read_abs(shard, t.abs_off, t.bytes, hw)) { free(hw); return 100; }
    ss_copy_add_host(t.bytes);
    if (promote2(hw, t.bytes, &pnt, &fnt, &fval) || !pnt) { free(hw); return 100; }
    ss_copy_add_d3d_upload(t.bytes);
    free(hw); hw = 0;
    if (ss_vk_import_lm(v, pnt, t.bytes)) return 100;
    if (v->a.qidle && v->a.qidle(v->q) != VK_SUCCESS) return 100;
    (void)fnt; (void)fval;
    if (ss_tensor_id_check(&id, id.hash)) return 100;
    if (!v->logitsb) {
        if (ss_vk_mkbuf(v, (VkDeviceSize)rows * 4ull, &v->logitsb, &v->logitsmem, 0))
            return 100;
    }
    if (ss_vk_pipe3(v, ss_vk_gemv_spv, ss_vk_gemv_spv_words, 12,
                    &sm, &dsl, &pl, &pipe, &dp, &ds)) return 100;
    bind_cmd(v);
    bi[0].buffer = v->lbuf; bi[0].offset = 0; bi[0].range = v->lbytes;
    bi[1].buffer = v->actb; bi[1].offset = 0; bi[1].range = (VkDeviceSize)v->embd_dim * 4ull;
    bi[2].buffer = v->logitsb; bi[2].offset = 0; bi[2].range = (VkDeviceSize)rows * 4ull;
    for (i = 0; i < 3; ++i) {
        memset(&w[i], 0, sizeof w[i]);
        w[i].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET; w[i].dstSet = ds;
        w[i].dstBinding = i; w[i].descriptorCount = 1;
        w[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER; w[i].pBufferInfo = &bi[i];
    }
    v->a.upd_ds(v->dev, 3, w, 0, 0);
    ss_barrier_note("output_norm", "lmhead_q6k");
    cai.commandPool = v->pool; cai.commandBufferCount = 1;
    if (v->a.alloc_cb(v->dev, &cai, &cb) != VK_SUCCESS) goto fail;
    if (v->a.begin_cb(cb, &bgi) != VK_SUCCESS) goto fail;
    v->a.cmd_bp(cb, VK_PIPELINE_BIND_POINT_COMPUTE, pipe);
    v->a.cmd_bds(cb, VK_PIPELINE_BIND_POINT_COMPUTE, pl, 0, 1, &ds, 0, 0);
    pc[0] = rows; pc[1] = cols; pc[2] = 14;
    v->a.cmd_pc(cb, pl, VK_SHADER_STAGE_COMPUTE_BIT, 0, 12, pc);
    v->a.cmd_disp(cb, (rows + 63u) / 64u, 1, 1);
    if (v->a.end_cb(cb) != VK_SUCCESS) goto fail;
    sub.commandBufferCount = 1; sub.pCommandBuffers = &cb;
    if (v->a.qsubmit(v->q, 1, &sub, 0) != VK_SUCCESS) goto fail;
    if (v->a.qidle(v->q) != VK_SUCCESS) goto fail;
    if (v->a.map(v->dev, v->logitsmem, 0, (VkDeviceSize)rows * 4ull, 0, &map) != VK_SUCCESS)
        goto fail;
    f = (float *)map;
    for (i = 0; i < rows; ++i) {
        if (!finf(f[i])) { fin = 0; break; }
        if (!saw) { first = f[i]; saw = 1; } else if (f[i] != first) nonc = 1;
    }
    v->a.unmap(v->dev, v->logitsmem);
    v->vocab_n = rows;
    v->logits_op = fin && nonc && rows == 129280u ? 1 : 0;
    capture_act(v);
    printf("LMHEAD_WEIGHT=output.weight LMHEAD_QUANT=Q6_K LMHEAD_IMPORTED_HOT=1\n");
    printf("LOGITS_COUNT=%u LOGITS_FINITE=%d LOGITS_NONCONSTANT=%d DEEP2_LOGITS=%s\n",
           rows, fin, nonc, v->logits_op ? "PASS" : "FAIL");
    printf("FULL_MODEL_FORWARD=0 HOST_ACTIVATION_ROUNDTRIP=0\n");
    if (pipe) v->a.destroy_pipe(v->dev, pipe, 0);
    if (pl) v->a.destroy_pl(v->dev, pl, 0);
    if (dsl) v->a.destroy_dsl(v->dev, dsl, 0);
    if (dp) v->a.destroy_dp(v->dev, dp, 0);
    if (sm) v->a.destroy_sm(v->dev, sm, 0);
    return v->logits_op ? 0 : 100;
fail:
    if (pipe) v->a.destroy_pipe(v->dev, pipe, 0);
    if (pl) v->a.destroy_pl(v->dev, pl, 0);
    if (dsl) v->a.destroy_dsl(v->dev, dsl, 0);
    if (dp) v->a.destroy_dp(v->dev, dp, 0);
    if (sm) v->a.destroy_sm(v->dev, sm, 0);
    return 100;
}
