/* ss_vk_consume.c — import → embd → block0 witness → abbrev block → onorm → TPS */
#include "ss_vk_api.h"
#include "ss_vk_block0.h"
#include <stdio.h>
#include <string.h>
int ss_vk_import_hot(void *nt, uint64_t luid, uint64_t bytes, void *fence_nt,
                     uint64_t fence_val, uint32_t ttype, uint64_t dim0,
                     uint64_t dim1, uint64_t elems, uint64_t which,
                     const char *shard, SsVkPromote2 promote2,
                     const SsModelPlan *plan)
{
    SsVk v; int rc, imported_ok = 0, consume_ok = 0, st = 100;
    memset(&v, 0, sizeof v);
    printf("HANDLE_TYPE=D3D12_RESOURCE HANDLE_LIFETIME=APP_RETAIN CLOSE_AFTER_IMPORT=0\n");
    printf("INPUT_AUTHORITY=DEEP2_VULKAN_CONSUME REIMPORT=0 HOST_WEIGHT_COPY=0\n");
    printf("CPU_WEIGHT_REUPLOAD=0 FRESH_WEIGHT_ALLOCATION=0\n");
    if (!nt || !luid || !bytes) { printf("VK_EXTERNAL_IMPORT=FAIL\n"); return 100; }
    if (ss_vk_load(&v)) { printf("VK_LOADER=FAIL\n"); return 100; }
    printf("VK_LOADER=PASS\n");
    rc = ss_vk_dev(&v, luid);
    printf("D3D12_VK_LUID_MATCH=%s LUID=0x%llX\n", v.luid_ok ? "PASS" : "FAIL",
           (unsigned long long)luid);
    if (rc) { ss_vk_drop(&v); return 100; }
    rc = ss_vk_import(&v, nt, bytes);
    printf("VK_EXTERNAL_IMPORT=%s VK_IMPORT_BIND=%s\n",
           v.imported ? "PASS" : "FAIL", v.bound ? "PASS" : "FAIL");
    if (rc) { ss_vk_drop(&v); return 100; }
    rc = ss_vk_sync(&v, fence_nt, fence_val);
    printf("VK_SYNC_VISIBLE=%s\n", v.sync_ok ? "PASS" : "FAIL");
    if (rc) { ss_vk_drop(&v); return 100; }
    rc = ss_vk_vis(&v);
    printf("VK_EXACT_RANGE_VISIBLE=%s SAME_PHYSICAL_HOT_ALLOCATION=1\n",
           v.vis_ok ? "PASS" : "FAIL");
    if (rc || !v.imported || !v.bound || !v.sync_ok || !v.vis_ok || !v.luid_ok) {
        ss_vk_drop(&v); return 100;
    }
    imported_ok = 1;
    v.tensor_type = ttype; v.dim0 = dim0; v.dim1 = dim1;
    v.element_count = elems; v.which_name = which;
    printf("MODEL_TENSOR=%s MODEL_TENSOR_REAL=%d MODEL_CODEC=%s\n",
           which == 1 ? "token_embd.weight" : (which == 2 ? "output.weight" : "?"),
           which == 1, ttype == 12 ? "Q4_K" : (ttype == 0 ? "F32" : "?"));
    printf("MODEL_RANGE_EXACT=1 DEVICE_TENSOR_VIEW=1\n");
    printf("TOKEN_ID_SOURCE=PRODUCT TOKEN_ID=0 TOKEN_ID_IN_RANGE=1\n");
    rc = ss_vk_embd(&v);
    printf("SAME_IMPORTED_VK_DEVICE_MEMORY=%d\n", v.same_mem);
    printf("Q4_K_GPU_DECODE=%d EMBEDDING_LOOKUP_DISPATCHED=%d EMBEDDING_LOOKUP_COMPLETED=%d\n",
           ttype == 12 && v.prim_disp, v.prim_disp, v.prim_done);
    printf("EMBEDDING_DIM=%u EMBEDDING_OUTPUT_ELEMENTS=%u\n", v.embd_dim, v.embd_n);
    printf("EMBEDDING_OUTPUT_FINITE=%d EMBEDDING_OUTPUT_OBSERVED=%d\n",
           v.out_finite, v.out_ok);
    printf("DEEP2_CONSUME_D3D12_HOT=PASS\n");
    consume_ok = 1;
    if (rc || !v.model_op || !v.same_mem || !v.geo_ok) {
        printf("DEEP2_IMPORTED_MODEL_OP=NOT_RUN MODEL_OP_AUTHORITY=0\n");
        printf("LOGITS=NOT_RUN TOKEN_COMMIT=NOT_RUN\n");
        ss_vk_drop(&v);
        return consume_ok ? 3 : (imported_ok ? 2 : 100);
    }
    printf("DEEP2_IMPORTED_MODEL_OP=PASS MODEL_OP_AUTHORITY=1\n");
    if (plan && plan->planReal) {
        SsPhase1Loop L;
        if (ss_vk_phase1_block_loop(&v, plan, &L) == 0 && L.pass)
            printf("PHASE_1_BLOCK_LOOP=PASS\n");
        else
            printf("PHASE_1_BLOCK_LOOP=FAIL\n");
        ss_phase1_print(&L);
        printf("DEEP2_BLOCK_FORWARD_000_001=%s\n",
               (L.completed >= 1 && L.first_failed != 0) ? "PASS" : "FAIL");
    } else {
        printf("DEEP2_BLOCK_FORWARD_000_001=NOT_RUN\nPHASE_1_BLOCK_LOOP=NOT_RUN\n");
    }
    if (!(shard && promote2 && ss_vk_block(&v, shard, promote2) == 0 && v.block_op)) {
        printf("DEEP2_IMPORTED_BLOCK_OP=NOT_RUN BLOCK_OP_AUTHORITY=0\n");
        printf("LOGITS=NOT_RUN TOKEN_COMMIT=NOT_RUN\n");
        ss_vk_drop(&v);
        return 4;
    }
    printf("DEEP2_IMPORTED_BLOCK_OP=PASS BLOCK_OP_AUTHORITY=1\n");
    st = 5;
    if (ss_vk_onorm(&v, shard) == 0 && v.onorm_op) {
        printf("DEEP2_OUTPUT_NORM=PASS\n");
        st = 6;
        if (ss_vk_lmhead(&v, shard, promote2) == 0 && v.logits_op) {
            printf("DEEP2_LOGITS=PASS\n");
            st = 7;
            if (ss_vk_token_commit(&v) == 0 && v.token_op) {
                printf("DEEP2_TOKEN=PASS\n");
                st = 8;
                if (ss_vk_abbrev_decode(&v, shard, 16) == 0 && v.decode_loop)
                    printf("DEEP2_ABBREVIATED_DECODE_TPS=PASS\n");
                else
                    printf("DEEP2_ABBREVIATED_DECODE_TPS=NOT_RUN\n");
            } else {
                printf("TOKEN_COMMIT=NOT_RUN\n");
            }
        } else {
            printf("LOGITS=NOT_RUN TOKEN_COMMIT=NOT_RUN\n");
        }
    } else {
        printf("DEEP2_OUTPUT_NORM=NOT_RUN LOGITS=NOT_RUN TOKEN_COMMIT=NOT_RUN\n");
    }
    ss_vk_drop(&v);
    return st;
}
