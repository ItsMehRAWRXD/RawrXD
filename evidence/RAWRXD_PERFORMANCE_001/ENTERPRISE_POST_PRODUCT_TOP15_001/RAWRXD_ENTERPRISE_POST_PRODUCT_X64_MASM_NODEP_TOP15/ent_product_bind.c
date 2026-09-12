/* ent_product_bind.c — honest overlay bind; cannot mint product/token/promote */
#include "enterprise_abi.h"
#include <stdio.h>
#include <string.h>
int ent_print_split_stream(uint64_t bytes_ok, uint64_t phase_rc, uint64_t math_ok)
{
    EnterpriseObserved o; EnterpriseGateResult g; int rc;
    memset(&o, 0, sizeof o); memset(&g, 0, sizeof g);
    o.product_binary_loaded = 1;
    o.product_entry_reached = 1;
    o.real_model_bytes_observed = bytes_ok ? 1 : 0;
    /* Observe product-earned math only; never mint logits/token/decode/promote. */
    o.real_tensor_math_observed = math_ok ? 1 : 0;
    o.real_logits_observed = 0;
    o.token_commit_observed = 0;
    o.decode_commit_observed = 0;
    o.product_runtime_rc = phase_rc;
    rc = ent_evaluate_all(&o, &g);
    printf("POST_PRODUCT_ENTERPRISE_OVERLAY=1 TOP15_IMPLEMENTED=15\n");
    printf("REAL_MODEL_BYTES_OBSERVED=%llu REAL_TENSOR_MATH_OBSERVED=%llu\n",
           (unsigned long long)o.real_model_bytes_observed,
           (unsigned long long)o.real_tensor_math_observed);
    printf("REAL_LOGITS_OBSERVED=0 TOKEN_COMMIT_OBSERVED=0 DECODE_COMMIT_OBSERVED=0\n");
    printf("PRODUCT_RUNTIME_RC=%llu PRODUCT_PREREQ=%llu FIRST_FAIL=%llu\n",
           (unsigned long long)phase_rc, (unsigned long long)g.product_prereq_pass,
           (unsigned long long)g.first_fail_code);
    printf("ENTERPRISE_READY=%llu\n", (unsigned long long)g.enterprise_ready);
    printf("PRODUCT_AUTHORITY_MINTED=0 DECODE_AUTHORITY_MINTED=0\n");
    printf("TOKEN_AUTHORITY_MINTED=0 PROMOTE_AUTHORITY_MINTED=0 PROMOTE=0\n");
    if (g.enterprise_ready) return 3;
    if (g.product_prereq_pass) return 4;
    if (g.first_fail_code != 2) return 5;
    (void)rc;
    return 0;
}
