/* ss_block_loop.c — Phase-1 aggregate finalize/print */
#include "ss_block_loop.h"
#include <stdio.h>
#include <string.h>
void ss_phase1_reset(SsPhase1Loop *L, uint32_t expected)
{
    if (!L) return;
    memset(L, 0, sizeof *L);
    L->expected = expected;
    L->first_failed = -1;
}
void ss_phase1_note(SsPhase1Loop *L, const SsBlockForwardResult *r,
                    uint64_t block_ns, uint64_t res_ns, uint64_t op_ns, uint64_t bar_ns)
{
    uint32_t i;
    if (!L || !r) return;
    i = r->block_index;
    if (i >= SS_MAX_BLOCKS) return;
    L->issued++;
    L->block_ns[i] = block_ns;
    L->residency_ns[i] = res_ns;
    L->op_ns[i] = op_ns;
    L->barrier_ns[i] = bar_ns;
    L->total_ns += block_ns;
    if (r->block_plan_resolved) L->plan_bind++;
    if (r->real_weight_ranges) L->real_weight++;
    if (r->expected_shard_id == r->observed_shard_id
        && r->block_index == i) L->id_match++;
    if (r->expected_weight_off == r->observed_weight_off
        && r->expected_weight_off != 0) L->weight_match++;
    if (r->completed) L->completed++;
    else if (L->first_failed < 0) L->first_failed = (int32_t)i;
}
void ss_phase1_finalize(SsPhase1Loop *L)
{
    if (!L) return;
    L->pass = L->expected > 0 && L->issued == L->expected
        && L->completed == L->expected && L->skipped == 0 && L->dup == 0
        && L->id_match == L->expected && L->weight_match == L->expected
        && L->plan_bind == L->expected && L->real_weight == L->expected
        && L->first_failed < 0;
}
void ss_phase1_print(const SsPhase1Loop *L)
{
    uint32_t i;
    if (!L) return;
    printf("PHASE_1_BLOCK_LOOP=%s\n", L->pass ? "PASS" : "FAIL");
    printf("BLOCK_LOOP_EXPECTED=%u BLOCK_LOOP_ISSUED=%u BLOCK_LOOP_COMPLETED=%u\n",
           L->expected, L->issued, L->completed);
    printf("BLOCK_ID_MATCH_COUNT=%u WEIGHT_RANGE_MATCH_COUNT=%u\n",
           L->id_match, L->weight_match);
    printf("PLAN_BINDING_COUNT=%u REAL_WEIGHT_BLOCK_COUNT=%u\n",
           L->plan_bind, L->real_weight);
    printf("SKIPPED_BLOCKS=%u DUPLICATE_BLOCKS=%u FIRST_FAILED_BLOCK=%s\n",
           L->skipped, L->dup,
           L->first_failed < 0 ? "NONE" : "SET");
    if (L->first_failed >= 0)
        printf("FIRST_FAILED_BLOCK_INDEX=%d\n", L->first_failed);
    printf("BLOCKS_COMPLETED=%u/%u TOTAL_BLOCK_NS=%llu\n",
           L->completed, L->expected, (unsigned long long)L->total_ns);
    for (i = 0; i < L->expected && i < SS_MAX_BLOCKS; ++i) {
        if ((i % 8u) == 0u || i + 1u == L->expected || (uint32_t)L->first_failed == i)
            printf("BLOCK_NS[%u]=%llu RESIDENCY_NS=%llu OP_NS=%llu BARRIER_NS=%llu\n",
                   i, (unsigned long long)L->block_ns[i],
                   (unsigned long long)L->residency_ns[i],
                   (unsigned long long)L->op_ns[i],
                   (unsigned long long)L->barrier_ns[i]);
    }
    printf("FULL_MODEL_FORWARD=0 ALL_BLOCKS_COMPLETED=0 PROMOTE=0\n");
    printf("ATTENTION_REAL=0 KV_CACHE_REAL=0 MOE_ROUTER_REAL=0\n");
    printf("NEXT_GATE=%s\n", L->pass ? "DEEP2_MOE_OR_FULL_BLOCK_FFN"
                                     : "PHASE_1_BLOCK_LOOP");
}
