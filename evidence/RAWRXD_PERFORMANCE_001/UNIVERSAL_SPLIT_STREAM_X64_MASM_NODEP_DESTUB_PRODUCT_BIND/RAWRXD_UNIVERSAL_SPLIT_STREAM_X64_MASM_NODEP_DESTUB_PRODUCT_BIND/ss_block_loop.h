/* ss_block_loop.h — Phase-1 61-block aggregate; FULL_MODEL_FORWARD stays 0 */
#ifndef SS_BLOCK_LOOP_H
#define SS_BLOCK_LOOP_H
#include "ss_model_plan.h"
#include "ss_block_forward.h"
#include <stdint.h>
typedef struct SsPhase1Loop {
    uint32_t expected, issued, completed;
    uint32_t id_match, weight_match, plan_bind, real_weight;
    uint32_t skipped, dup;
    int32_t first_failed;
    uint64_t block_ns[SS_MAX_BLOCKS];
    uint64_t residency_ns[SS_MAX_BLOCKS];
    uint64_t op_ns[SS_MAX_BLOCKS];
    uint64_t barrier_ns[SS_MAX_BLOCKS];
    uint64_t total_ns;
    int pass;
} SsPhase1Loop;
void ss_phase1_reset(SsPhase1Loop *L, uint32_t expected);
void ss_phase1_note(SsPhase1Loop *L, const SsBlockForwardResult *r,
                    uint64_t block_ns, uint64_t res_ns, uint64_t op_ns, uint64_t bar_ns);
void ss_phase1_finalize(SsPhase1Loop *L);
void ss_phase1_print(const SsPhase1Loop *L);
#endif
