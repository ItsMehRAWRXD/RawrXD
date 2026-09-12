/* ss_vk_full_block_loop.c — 0..N-1 continuity: output[n] → input[n+1] */
#include "ss_full_block_loop.h"
#include "ss_vk_api.h"
#include "ss_model_plan.h"
#include "ss_vk_block_util.h"
#include <stdio.h>
#include <string.h>
uint64_t ss_vk_act_hash(SsVk *v, VkDeviceMemory mem, uint32_t n);
int ss_vk_run_resolved_block(SsVk *v, const SsModelPlan *plan, uint32_t i,
                             int *was_moe, int *attn_ok, int *ffn_ok, int *bind_ok);
int ss_vk_full_block_loop(SsVk *v, const SsModelPlan *plan, SsFullBlockLoop *L)
{
    uint32_t i, emb; uint64_t prev = 0, cur_h; int moe, attn, ffn, bind, ok = 0;
    VkBuffer xin; VkDeviceMemory xinm;
    if (!v || !plan || !L || !plan->planReal || !plan->blockCount) return 100;
    memset(L, 0, sizeof *L);
    emb = plan->embeddingLength;
    L->declared = plan->blockCount; L->plan_count = plan->blockCount;
    L->first_block = 0; L->last_block = plan->blockCount - 1;
    L->ffn_from_tensors = 1; L->block_order_valid = 1;
    L->continuity_need = plan->blockCount > 0 ? plan->blockCount - 1 : 0;
    /* Structural: drop prior witness act; input[0] = embedding. */
    ss_vk_dropb(v, &v->actb, &v->actmem);
    L->synthetic_reset = 0; L->embd_reload = 0; L->repeated_blk0 = 0;
    for (i = 0; i < plan->blockCount; ++i) {
        L->entered++;
        xin = v->actb ? v->actb : v->outb;
        xinm = v->actb ? v->actmem : v->outmem;
        if (!xin || !xinm) { L->first_fail_block = i; L->block_order_valid = 0; break; }
        if (i > 0 && xin == v->outb) L->embd_reload++;
        if (i == 0 && xin != v->outb) { L->first_fail_block = i; break; }
        cur_h = ss_vk_act_hash(v, xinm, emb);
        if (i > 0) {
            if (cur_h && prev && cur_h == prev) L->continuity_match++;
            else { L->first_fail_block = i; break; }
        }
        {
            int rc = ss_vk_run_resolved_block(v, plan, i, &moe, &attn, &ffn, &bind);
            if (rc) {
                L->first_fail_block = i;
                if (plan->blocks[i].blockIndex != i) L->block_order_valid = 0;
                printf("FULL_BLOCK_FAIL i=%u rc=%d bind=%d attn=%d ffn=%d\n",
                       i, rc, bind, attn, ffn);
                fflush(stdout);
                break;
            }
        }
        printf("FULL_BLOCK_OK i=%u moe=%d\n", i, moe);
        fflush(stdout);
        if (bind) L->bind_ok++;
        if (attn) L->attn_ok++;
        if (ffn) L->ffn_ok++;
        if (moe) L->moe_exec++; else L->dense_exec++;
        if (!v->actb || !v->actmem) { L->first_fail_block = i; break; }
        if (ss_vk_fin_obs(v, v->actmem, emb, &ok) || !ok) {
            L->first_fail_block = i; break;
        }
        L->residual_ok++;
        prev = ss_vk_act_hash(v, v->actmem, emb);
        L->completed++;
    }
    L->chain_continuity_valid =
        (L->continuity_match == L->continuity_need) && !L->embd_reload
        && !L->repeated_blk0 && !L->synthetic_reset;
    L->final_out_real = (L->completed == plan->blockCount) && L->residual_ok == plan->blockCount;
    L->all_blocks_completed = L->final_out_real && L->chain_continuity_valid
        && L->bind_ok == plan->blockCount && L->attn_ok == plan->blockCount
        && L->ffn_ok == plan->blockCount && L->block_order_valid;
    L->full_model_forward = L->all_blocks_completed;
    L->pass = L->all_blocks_completed;
    return L->pass ? 0 : 100;
}
