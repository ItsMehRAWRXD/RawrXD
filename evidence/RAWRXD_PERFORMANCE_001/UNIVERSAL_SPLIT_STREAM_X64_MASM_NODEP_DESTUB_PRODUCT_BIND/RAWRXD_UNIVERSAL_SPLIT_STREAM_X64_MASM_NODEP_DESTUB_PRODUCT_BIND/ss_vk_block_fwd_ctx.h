/* ss_vk_block_fwd_ctx.h — scratch for one plan-bound block */
#ifndef SS_VK_BLOCK_FWD_CTX_H
#define SS_VK_BLOCK_FWD_CTX_H
#include "ss_vk_api.h"
#include "ss_model_plan.h"
#include "ss_block_forward.h"
typedef struct SsBlkCtx {
    SsVk *v; const SsModelPlan *plan; const SsBlockPlan *b;
    SsBlockForwardResult *r;
    VkBuffer xin, wn, xn, wqa, qa, wqan, qan, wqb, q;
    VkBuffer wkva, kva, wkvan, kvan, wkvb, kv, wo, ao, out;
    VkDeviceMemory xinm, wnm, xnm, wqam, qam, wqanm, qanm, wqbm, qm;
    VkDeviceMemory wkvam, kvam, wkvanm, kvanm, wkvbm, kvm, wom, aom, outm;
    uint32_t emb, q_a_r, q_b_r, kv_a_r, kv_b_r, o_in, heads, lr;
    uint64_t res_ns, op_ns, freq;
    void *hw; uint64_t hn;
} SsBlkCtx;
int ss_blk_attn_norm_q(SsBlkCtx *c);
int ss_blk_kv_attn_out(SsBlkCtx *c);
void ss_blk_drop_temps(SsBlkCtx *c);
#endif
