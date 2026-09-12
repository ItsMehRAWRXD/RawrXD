/* ss_gate_check.c — cross-gate receipt consistency; no authority mint */
#include "ss_evidence.h"
#include <stdio.h>
int ss_gate_reconcile(uint64_t deep2_status, uint64_t phase_rc,
                      int model_op, int block_op, int math_obs)
{
    int fail = 0;
    printf("GATE_CHECK deep2_status=%llu phase_rc=%llu model_op=%d block_op=%d math_obs=%d\n",
           (unsigned long long)deep2_status, (unsigned long long)phase_rc,
           model_op, block_op, math_obs);
    if (model_op && !math_obs) {
        printf("GATE_CONTRADICTION MODEL_OP=PASS but REAL_TENSOR_MATH_OBSERVED=0\n");
        fail = 1;
    }
    if (block_op && deep2_status < 5) {
        printf("GATE_CONTRADICTION BLOCK_OP=PASS but deep2_status<%llu\n",
               (unsigned long long)deep2_status);
        fail = 1;
    }
    if (block_op && ss_barrier_seq() < 1) {
        printf("GATE_CONTRADICTION BLOCK_OP=PASS but BARRIER_SEQ=0\n");
        fail = 1;
    }
    if (phase_rc == 105 && deep2_status == 5)
        printf("GATE_NEXT_OK CURRENT_STOP=OUTPUT_NORM_NOT_RUN NEXT_GATE=DEEP2_OUTPUT_NORM\n");
    if (phase_rc == 106 && deep2_status == 6)
        printf("GATE_NEXT_OK CURRENT_STOP=LM_HEAD_HOLD NEXT_GATE=DEEP2_LOGITS\n");
    if (phase_rc == 107 && deep2_status == 7)
        printf("GATE_NEXT_OK CURRENT_STOP=TOKEN_HOLD NEXT_GATE=DEEP2_TOKEN\n");
    if (phase_rc == 108 && deep2_status == 8)
        printf("GATE_NEXT_OK CURRENT_STOP=DECODE_HOLD DECODE_KIND=ABBREVIATED_SPLIT_STREAM\n");
    if (phase_rc != 0 && phase_rc < 100)
        printf("GATE_NOTE phase_rc=%llu is product-hold not success\n",
               (unsigned long long)phase_rc);
    printf("GATE_CHECK_AUTHORITY_MINT=0 FULL_MODEL_FORWARD=0 PROMOTE=0\n");
    printf("GATE_CHECK=%s\n", fail ? "FAIL" : "PASS");
    return fail;
}
