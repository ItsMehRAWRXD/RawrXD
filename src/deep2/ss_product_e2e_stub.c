/* ss_product_e2e_stub.c — satisfy deep2_benchmark --phase split-stream link.
 * Full MASM destub product lives under evidence/; normal stream phase unused. */
#include <stdio.h>

int ss_product_e2e(const char* model_path, const char* prompt) {
    (void)prompt;
    fprintf(stderr,
            "ss_product_e2e: stub only (model=%s); use phase=stream for K2\n",
            model_path ? model_path : "(null)");
    return 2;
}
