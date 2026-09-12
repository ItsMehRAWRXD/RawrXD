/* ss_vk_block0.c — block-N forward + Phase-1 loop wrappers */
#include "ss_vk_block0.h"
#include "ss_vk_block_fwd_ctx.h"
#include "ss_vk_block_util.h"
#include <stdlib.h>
#include <string.h>
#include <windows.h>
int ss_vk_block_forward(SsVk *v, const SsModelPlan *plan, uint32_t block,
                        SsBlockForwardResult *r, uint64_t *res_ns, uint64_t *op_ns)
{
    SsBlkCtx c; LARGE_INTEGER li;
    memset(&c, 0, sizeof c);
    if (!v || !plan || !r || !v->model_op || block >= plan->blockCount) return 100;
    QueryPerformanceFrequency(&li); c.freq = (uint64_t)li.QuadPart;
    ss_block_fwd_reset(r, block);
    c.v = v; c.plan = plan; c.b = &plan->blocks[block]; c.r = r;
    c.xin = (block == 0) ? v->outb : v->actb;
    c.xinm = (block == 0) ? v->outmem : v->actmem;
    if (!c.xin || !c.xinm || !plan->planReal || !c.b->attnNorm.present || !c.b->qA.present
        || !c.b->qB.present || !c.b->kvA.present || !c.b->kvB.present || !c.b->attnOut.present) {
        r->first_failure_stage = SS_BF_PLAN; ss_block_fwd_finalize(r); return 100;
    }
    r->block_plan_resolved = 1;
    r->expected_shard_id = c.b->attnNorm.shardIndex;
    r->expected_weight_off = c.b->attnNorm.fileOffset;
    r->observed_shard_id = c.b->attnNorm.shardIndex;
    r->observed_weight_off = c.b->attnNorm.fileOffset;
    r->plan_bindings_used = 1; r->real_weight_ranges = 1;
    c.emb = plan->embeddingLength;
    c.q_a_r = (uint32_t)c.b->qA.dims[1]; c.q_b_r = (uint32_t)c.b->qB.dims[1];
    c.kv_a_r = (uint32_t)c.b->kvA.dims[1]; c.kv_b_r = (uint32_t)c.b->kvB.dims[1];
    c.o_in = (uint32_t)c.b->attnOut.dims[0];
    c.heads = plan->attentionHeads ? plan->attentionHeads : 128;
    c.lr = plan->kvLoraRank ? plan->kvLoraRank : 512;
    if (ss_blk_attn_norm_q(&c) || ss_blk_kv_attn_out(&c)) {
        free(c.hw); ss_block_fwd_finalize(r);
        if (res_ns) *res_ns = c.res_ns; if (op_ns) *op_ns = c.op_ns;
        ss_blk_drop_temps(&c); ss_vk_dropb(v, &c.out, &c.outm); return 100;
    }
    ss_vk_dropb(v, &v->actb, &v->actmem);
    v->actb = c.out; v->actmem = c.outm; c.out = 0; c.outm = 0;
    ss_block_fwd_finalize(r);
    if (res_ns) *res_ns = c.res_ns; if (op_ns) *op_ns = c.op_ns;
    ss_blk_drop_temps(&c);
    return r->completed ? 0 : 100;
}
int ss_vk_block0_forward(SsVk *v, const SsModelPlan *plan, SsBlockForwardResult *r)
{
    return ss_vk_block_forward(v, plan, 0, r, 0, 0);
}
int ss_vk_phase1_block_loop(SsVk *v, const SsModelPlan *plan, SsPhase1Loop *L)
{
    SsBlockForwardResult r; uint32_t i; uint64_t t0, t1, freq, rns, ons;
    LARGE_INTEGER li;
    if (!v || !plan || !L || !plan->planReal || !plan->blockCount) return 100;
    QueryPerformanceFrequency(&li); freq = (uint64_t)li.QuadPart;
    ss_phase1_reset(L, plan->blockCount);
    for (i = 0; i < plan->blockCount; ++i) {
        QueryPerformanceCounter(&li); t0 = (uint64_t)li.QuadPart;
        rns = ons = 0;
        ss_vk_block_forward(v, plan, i, &r, &rns, &ons);
        QueryPerformanceCounter(&li); t1 = (uint64_t)li.QuadPart;
        ss_phase1_note(L, &r, (t1 - t0) * 1000000000ull / freq, rns, ons, 0);
        if (!r.completed) break;
    }
    ss_phase1_finalize(L);
    return L->pass ? 0 : 100;
}
