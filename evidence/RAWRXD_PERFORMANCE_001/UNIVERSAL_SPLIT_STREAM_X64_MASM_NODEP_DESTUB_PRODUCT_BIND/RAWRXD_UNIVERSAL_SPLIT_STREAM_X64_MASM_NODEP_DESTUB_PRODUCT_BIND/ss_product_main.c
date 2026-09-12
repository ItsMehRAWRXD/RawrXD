/* ss_product_main.c — split-stream product entry (no full-model harness) */
#include "ss_phase_abi.h"
#include <stdio.h>
#include <string.h>
int ss_product_e2e(const char *model_path, const char *prompt);
int main(int argc, char **argv)
{
    const char *model = 0; const char *phase = 0; int i;
    for (i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--model") && i + 1 < argc) model = argv[++i];
        else if (!strcmp(argv[i], "--phase") && i + 1 < argc) phase = argv[++i];
    }
    if (!model) { printf("USAGE=deep2_benchmark.exe --model <gguf> --phase split-stream\nPROMOTE=0\n"); return 1; }
    if (phase && strcmp(phase, "split-stream")) {
        printf("PHASE=%s FULL_HARNESS=deep2_benchmark_full.exe TOKEN_COMMIT=NOT_RUN PROMOTE=0\n", phase);
        return 20;
    }
    return ss_product_e2e(model, "");
}
