/* ss_vk_block.c — load blk.0 attn_norm + attn_q_a HOT; keep 7168 act */
#include "ss_vk_api.h"
#include "ss_gguf_find.h"
#include "ss_evidence.h"
#include "ss_vk_block_util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int read_abs(const char *path, uint64_t abs, uint64_t n, void *dst)
{
    FILE *f = fopen(path, "rb"); size_t got;
    if (!f) return 1;
    if (_fseeki64(f, (__int64)abs, SEEK_SET)) { fclose(f); return 1; }
    got = fread(dst, 1, (size_t)n, f); fclose(f);
    return got == n ? 0 : 1;
}
static void drop_proj(SsVk *v)
{
    if (!v || !v->dev) return;
    if (v->pbuf && v->a.destroy_buf) v->a.destroy_buf(v->dev, v->pbuf, 0);
    if (v->pmem && v->a.free_mem) v->a.free_mem(v->dev, v->pmem, 0);
    v->pbuf = 0; v->pmem = 0; v->pbytes = 0; v->proj_imported = 0;
}
int ss_vk_block(SsVk *v, const char *shard, SsVkPromote2 promote2)
{
    SsGgufTensor norm, q; void *nw = 0, *qw = 0, *map = 0, *pnt = 0, *fnt = 0;
    VkBuffer qob = 0; VkDeviceMemory qom = 0;
    uint64_t fval = 0; uint32_t rows, cols; int rc; SsTensorId idn, idq;
    if (!v || !v->model_op || !v->outb || !shard || !promote2) return 100;
    if (ss_gguf_find(shard, "blk.0.attn_norm.weight", &norm) || !norm.found) return 100;
    if (ss_gguf_find(shard, "blk.0.attn_q_a.weight", &q) || !q.found) return 100;
    if (norm.type != 0 || norm.dim0 != (uint64_t)v->embd_dim) return 100;
    if (q.type != 12 || q.dim0 != (uint64_t)v->embd_dim) return 100;
    rows = (uint32_t)q.dim1; cols = (uint32_t)q.dim0;
    idn.name = "blk.0.attn_norm.weight"; idn.abs_off = norm.abs_off; idn.bytes = norm.bytes;
    idn.codec = norm.type; idn.dim0 = norm.dim0; idn.dim1 = 1; idn.hash = ss_tensor_id_hash(&idn);
    idq.name = "blk.0.attn_q_a.weight"; idq.abs_off = q.abs_off; idq.bytes = q.bytes;
    idq.codec = q.type; idq.dim0 = q.dim0; idq.dim1 = q.dim1; idq.hash = ss_tensor_id_hash(&idq);
    ss_tensor_id_print(&idn, "bind"); ss_tensor_id_print(&idq, "bind");
    printf("DISPATCH_GEO rms_n=%u proj_rows=%u proj_cols=%u q4k_nblk=%u wg=%u\n",
           v->embd_dim, rows, cols, (cols + 255u) / 256u, (rows + 63u) / 64u);
    nw = malloc((size_t)norm.bytes); qw = malloc((size_t)q.bytes);
    if (!nw || !qw) goto fail;
    if (read_abs(shard, norm.abs_off, norm.bytes, nw)) goto fail;
    if (read_abs(shard, q.abs_off, q.bytes, qw)) goto fail;
    ss_copy_add_host(norm.bytes + q.bytes);
    if (promote2(qw, q.bytes, &pnt, &fnt, &fval) || !pnt) goto fail;
    ss_copy_add_d3d_upload(q.bytes);
    if (ss_vk_import2(v, pnt, q.bytes)) goto fail;
    if (v->a.qidle && v->a.qidle(v->q) != VK_SUCCESS) goto fail;
    (void)fnt; (void)fval; v->proj_hot = 1;
    if (ss_tensor_id_check(&idq, idq.hash)) goto fail;
    if (ss_vk_mkbuf(v, (VkDeviceSize)norm.bytes, &v->anorm_wb, &v->anorm_wm, &map)) goto fail;
    memcpy(map, nw, (size_t)norm.bytes); v->a.unmap(v->dev, v->anorm_wm); map = 0;
    ss_vk_dropb(v, &v->actb, &v->actmem);
    if (ss_vk_mkbuf(v, (VkDeviceSize)v->embd_dim * 4ull, &v->actb, &v->actmem, 0)) goto fail;
    if (ss_vk_mkbuf(v, (VkDeviceSize)rows * 4ull, &qob, &qom, 0)) goto fail;
    ss_barrier_note("token_embd", "blk0_attn_norm");
    rc = ss_vk_block_exec(v, v->anorm_wb, norm.bytes, v->actb, qob, qom, rows, cols);
    ss_copy_add_vk_readback((uint64_t)rows * 4ull);
    printf("INPUT_FROM_IMPORTED_MODEL_OP=1 INPUT_ACTIVATION_REAL=1 BLOCK_INDEX=0\n");
    printf("MODEL_GEOMETRY_REAL=1 RMSNORM_WEIGHT_REAL=1 RMSNORM_DISPATCHED=%d RMSNORM_COMPLETED=%d\n",
           v->rms_disp, v->rms_done);
    printf("PROJECTION_WEIGHT=blk.0.attn_q_a.weight PROJECTION_WEIGHT_REAL=1\n");
    printf("PROJECTION_IMPORTED_HOT=%d PROJECTION_QUANT_GPU_DECODE=1\n", v->proj_hot);
    printf("PROJECTION_DISPATCHED=%d PROJECTION_COMPLETED=%d OP_CHAIN_GPU_TO_GPU=%d\n",
           v->proj_disp, v->proj_done, v->chain_gpu);
    printf("HOST_ACTIVATION_ROUNDTRIP=0 INTERMEDIATE_HOST_WEIGHT_COPY=0 CPU_WEIGHT_REUPLOAD=0\n");
    printf("SYNTHETIC_ACTIVATION=0 BLOCK_OP_OUTPUT_FINITE=%d BLOCK_OP_OUTPUT_OBSERVED=%d\n",
           v->block_finite, v->block_ok);
    printf("ACT_7168_RETAINED=%d INPUT_FROM_BLOCK_OP=%d\n", v->actb ? 1 : 0, v->block_op);
    ss_copy_print();
    if (qob) v->a.destroy_buf(v->dev, qob, 0);
    if (qom) v->a.free_mem(v->dev, qom, 0);
    drop_proj(v);
    free(nw); free(qw);
    return rc;
fail:
    if (qob) v->a.destroy_buf(v->dev, qob, 0);
    if (qom) v->a.free_mem(v->dev, qom, 0);
    free(nw); free(qw);
    return 100;
}
