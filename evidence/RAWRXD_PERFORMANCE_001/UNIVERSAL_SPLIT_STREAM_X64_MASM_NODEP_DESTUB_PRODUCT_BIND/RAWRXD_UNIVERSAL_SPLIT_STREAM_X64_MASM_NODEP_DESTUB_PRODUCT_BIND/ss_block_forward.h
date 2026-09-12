/* ss_block_forward.h — full transformer block; NOT_RUN until kernels exist */
#ifndef SS_BLOCK_FORWARD_H
#define SS_BLOCK_FORWARD_H
#include "ss_model_plan.h"
#include "ss_kv_cache.h"
#include <stdint.h>
typedef struct SsActView {
    void *buffer; void *memory;
    uint64_t bytes; uint32_t elements;
    uint32_t producerBlock; uint32_t producerOp;
} SsActView;
int ss_forward_block(const SsModelPlan *model, uint32_t block, uint32_t position,
                     SsKvCache *kv, const SsActView *in, SsActView *out);
#endif
