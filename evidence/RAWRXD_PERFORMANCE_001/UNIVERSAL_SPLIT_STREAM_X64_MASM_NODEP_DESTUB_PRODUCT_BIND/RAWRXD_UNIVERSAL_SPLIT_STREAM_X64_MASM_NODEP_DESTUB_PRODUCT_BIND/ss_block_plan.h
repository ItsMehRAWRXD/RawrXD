/* ss_block_plan.h — per-operator residency ranges from SsBlockPlan */
#ifndef SS_BLOCK_PLAN_H
#define SS_BLOCK_PLAN_H
#include "ss_model_plan.h"
typedef enum SsBlockOp {
    SS_OP_ATTN_NORM = 1,
    SS_OP_ATTN_PROJ,
    SS_OP_ATTN_SCORE,
    SS_OP_FFN_NORM,
    SS_OP_MOE_ROUTER,
    SS_OP_MOE_EXPERTS,
    SS_OP_DENSE_FFN
} SsBlockOp;
typedef struct SsOpResidency {
    const SsTensorRef *refs[16];
    uint32_t count;
    SsBlockOp op;
} SsOpResidency;
int ss_block_op_residency(const SsBlockPlan *b, SsBlockOp op, SsOpResidency *out);
#endif
