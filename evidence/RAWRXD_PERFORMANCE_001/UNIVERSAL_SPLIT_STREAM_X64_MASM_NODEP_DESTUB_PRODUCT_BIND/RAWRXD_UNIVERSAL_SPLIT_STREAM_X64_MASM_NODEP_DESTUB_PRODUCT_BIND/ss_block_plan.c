/* ss_block_plan.c — operator → exact tensor refs (no full-block load) */
#include "ss_block_plan.h"
#include <string.h>
static void add(SsOpResidency *o, const SsTensorRef *r)
{
    if (!r || !r->present || o->count >= 16) return;
    o->refs[o->count++] = r;
}
int ss_block_op_residency(const SsBlockPlan *b, SsBlockOp op, SsOpResidency *out)
{
    if (!b || !out) return 1;
    memset(out, 0, sizeof *out); out->op = op;
    switch (op) {
    case SS_OP_ATTN_NORM: add(out, &b->attnNorm); break;
    case SS_OP_ATTN_PROJ:
        add(out, &b->qA); add(out, &b->qB); add(out, &b->kvA); add(out, &b->kvB);
        add(out, &b->attnOut); add(out, &b->qANorm); add(out, &b->kvANorm);
        break;
    case SS_OP_FFN_NORM: add(out, &b->ffnNorm); break;
    case SS_OP_MOE_ROUTER: add(out, &b->router); add(out, &b->expProbsB); break;
    case SS_OP_MOE_EXPERTS:
        add(out, &b->expertGate); add(out, &b->expertUp); add(out, &b->expertDown);
        add(out, &b->sharedGate); add(out, &b->sharedUp); add(out, &b->sharedDown);
        break;
    case SS_OP_DENSE_FFN:
        add(out, &b->denseGate); add(out, &b->denseUp); add(out, &b->denseDown);
        break;
    default: return 1;
    }
    return out->count ? 0 : 1;
}
