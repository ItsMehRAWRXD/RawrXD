/* ss_vk_block_fwd_q.c — attn_norm + MLA Q */
#include "ss_vk_block_fwd_ctx.h"
#include "ss_vk_ops.h"
#include "ss_vk_block_util.h"
#include "ss_plan_load.h"
#include <stdlib.h>
#include <windows.h>
static void add_ns(SsBlkCtx *c, uint64_t t0, uint64_t t1, int res)
{
    uint64_t d = (t1 - t0) * 1000000000ull / c->freq;
    if (res) c->res_ns += d; else c->op_ns += d;
}
int ss_blk_attn_norm_q(SsBlkCtx *c)
{
    LARGE_INTEGER li; uint64_t t0, t1;
    QueryPerformanceCounter(&li); t0 = (uint64_t)li.QuadPart;
    c->r->attn_norm_bound = 1;
    if (ss_plan_load_ref(c->plan, &c->b->attnNorm, &c->hw, &c->hn)
        || ss_vk_upload(c->v, c->hw, c->hn, &c->wn, &c->wnm)) return 100;
    free(c->hw); c->hw = 0;
    QueryPerformanceCounter(&li); t1 = (uint64_t)li.QuadPart; add_ns(c, t0, t1, 1);
    if (ss_vk_mkbuf(c->v, (VkDeviceSize)c->emb * 4ull, &c->xn, &c->xnm, 0)) return 100;
    QueryPerformanceCounter(&li); t0 = (uint64_t)li.QuadPart;
    c->r->attn_norm_disp = 1;
    if (ss_vk_op_rms(c->v, c->xin, c->wn, c->hn, c->xn, c->emb)) return 100;
    c->r->attn_norm_done = 1;
    QueryPerformanceCounter(&li); t1 = (uint64_t)li.QuadPart; add_ns(c, t0, t1, 0);
    c->r->mla_q_bound = c->b->qA.present && c->b->qANorm.present && c->b->qB.present;
    if (!c->r->mla_q_bound) return 100;
    QueryPerformanceCounter(&li); t0 = (uint64_t)li.QuadPart;
    if (ss_plan_load_ref(c->plan, &c->b->qA, &c->hw, &c->hn)
        || ss_vk_upload(c->v, c->hw, c->hn, &c->wqa, &c->wqam)) return 100;
    free(c->hw); c->hw = 0;
    QueryPerformanceCounter(&li); t1 = (uint64_t)li.QuadPart; add_ns(c, t0, t1, 1);
    if (ss_vk_mkbuf(c->v, (VkDeviceSize)c->q_a_r * 4ull, &c->qa, &c->qam, 0)) return 100;
    QueryPerformanceCounter(&li); t0 = (uint64_t)li.QuadPart;
    c->r->mla_q_disp = 1;
    if (ss_vk_op_gemv(c->v, c->wqa, c->b->qA.bytes, c->xn, c->qa, c->q_a_r, c->emb,
                      ss_vk_codec_ty(c->b->qA.codec))) return 100;
    QueryPerformanceCounter(&li); t1 = (uint64_t)li.QuadPart; add_ns(c, t0, t1, 0);
    QueryPerformanceCounter(&li); t0 = (uint64_t)li.QuadPart;
    if (ss_plan_load_ref(c->plan, &c->b->qANorm, &c->hw, &c->hn)
        || ss_vk_upload(c->v, c->hw, c->hn, &c->wqan, &c->wqanm)) return 100;
    free(c->hw); c->hw = 0;
    QueryPerformanceCounter(&li); t1 = (uint64_t)li.QuadPart; add_ns(c, t0, t1, 1);
    if (ss_vk_mkbuf(c->v, (VkDeviceSize)c->q_a_r * 4ull, &c->qan, &c->qanm, 0)) return 100;
    QueryPerformanceCounter(&li); t0 = (uint64_t)li.QuadPart;
    if (ss_vk_op_rms(c->v, c->qa, c->wqan, c->hn, c->qan, c->q_a_r)) return 100;
    QueryPerformanceCounter(&li); t1 = (uint64_t)li.QuadPart; add_ns(c, t0, t1, 0);
    QueryPerformanceCounter(&li); t0 = (uint64_t)li.QuadPart;
    if (ss_plan_load_ref(c->plan, &c->b->qB, &c->hw, &c->hn)
        || ss_vk_upload(c->v, c->hw, c->hn, &c->wqb, &c->wqbm)) return 100;
    free(c->hw); c->hw = 0;
    QueryPerformanceCounter(&li); t1 = (uint64_t)li.QuadPart; add_ns(c, t0, t1, 1);
    if (ss_vk_mkbuf(c->v, (VkDeviceSize)c->q_b_r * 4ull, &c->q, &c->qm, 0)) return 100;
    QueryPerformanceCounter(&li); t0 = (uint64_t)li.QuadPart;
    if (ss_vk_op_gemv(c->v, c->wqb, c->b->qB.bytes, c->qan, c->q, c->q_b_r, c->q_a_r,
                      ss_vk_codec_ty(c->b->qB.codec))) return 100;
    c->r->mla_q_done = 1;
    QueryPerformanceCounter(&li); t1 = (uint64_t)li.QuadPart; add_ns(c, t0, t1, 0);
    return 0;
}
