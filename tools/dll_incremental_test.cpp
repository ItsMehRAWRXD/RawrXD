// dll_incremental_test.cpp
// Incremental (O(n)) teacher-forced decode through RawrXDCore.dll
// Feeds one token at a time and saves logits after each position.

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#include <string>
#include <direct.h>
#include "ModelGenieRuntime.h"

const int VOCAB_SIZE = 102400;
const int NUM_POSITIONS = 65;

const int teacher_forced_tokens[NUM_POSITIONS] = {
    1, 185, 16, 15, 15, 15, 15, 15, 15, 15, 12, 384, 2, 16, 24, 207, 71955, 1392, 13, 1002,
    6, 95, 3882, 124, 2, 16, 146, 24, 151, 384, 37, 1827, 253, 16, 24, 92, 1024, 1827, 253,
    16, 24, 92, 12, 22, 738, 30840, 4399, 4633, 15, 23, 0, 626, 726, 1628, 2285, 966, 6, 4, 0,
    82, 10, 113, 4647, 1075, 2
};

int main(int argc, char* argv[]) {
    int start_pos = 0;
    int end_pos = NUM_POSITIONS;
    if (argc > 2) {
        start_pos = atoi(argv[1]);
        end_pos = atoi(argv[2]);
        if (start_pos < 0) start_pos = 0;
        if (end_pos > NUM_POSITIONS) end_pos = NUM_POSITIONS;
    }

    printf("=== DLL Incremental Teacher-Forced Decode (pos %d..%d) ===\n", start_pos, end_pos);
    fflush(stdout);

    HMODULE coreDll = LoadLibraryA("F:\\rawrxd\\build_cert\\bin\\Release\\RawrXDCore.dll");
    if (!coreDll) {
        printf("Failed to load DLL: %lu\n", GetLastError());
        return 1;
    }

    mg_error_t (*mg_model_load)(const char*, const mg_model_config_t*, mg_model_t**) =
        (mg_error_t (*)(const char*, const mg_model_config_t*, mg_model_t**))GetProcAddress(coreDll, "mg_model_load");
    void (*mg_model_free)(mg_model_t*) = (void (*)(mg_model_t*))GetProcAddress(coreDll, "mg_model_free");
    mg_error_t (*mg_context_create)(mg_model_t*, mg_context_t**) =
        (mg_error_t (*)(mg_model_t*, mg_context_t**))GetProcAddress(coreDll, "mg_context_create");
    void (*mg_context_free)(mg_context_t*) = (void (*)(mg_context_t*))GetProcAddress(coreDll, "mg_context_free");
    mg_error_t (*mg_context_eval_buffer)(mg_context_t*, const uint32_t*, size_t, float*, size_t*) =
        (mg_error_t (*)(mg_context_t*, const uint32_t*, size_t, float*, size_t*))GetProcAddress(coreDll, "mg_context_eval_buffer");
    mg_error_t (*mg_context_reset)(mg_context_t*) =
        (mg_error_t (*)(mg_context_t*))GetProcAddress(coreDll, "mg_context_reset");

    if (!mg_model_load || !mg_context_create || !mg_context_eval_buffer || !mg_context_reset) {
        printf("Missing required exports\n");
        return 1;
    }

    mg_model_config_t mgConfig{};
    mgConfig.max_seq_len = 1024;
    mgConfig.use_kv_cache = true;
    mgConfig.num_threads = 4;

    mg_model_t* mgModel = NULL;
    mg_error_t rc = mg_model_load("F:\\rawrxd\\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf", &mgConfig, &mgModel);
    if (rc != MG_SUCCESS || !mgModel) {
        printf("mg_model_load failed: %d\n", rc);
        return 1;
    }

    mg_context_t* mgContext = NULL;
    rc = mg_context_create(mgModel, &mgContext);
    if (rc != MG_SUCCESS || !mgContext) {
        printf("mg_context_create failed: %d\n", rc);
        return 1;
    }

    _mkdir("F:\\rawrxd\\evidence\\RAWRXD_DEEP2_DLL_EQUIVALENCE_001");

    /*
     * Incremental strategy: to reach position P we must replay tokens 0..P-1
     * (positions before start_pos) then capture logits at each of 0..end_pos-1
     * while continuing to feed the forced tokens.
     *
     * mg_context_eval_buffer re-processes the whole buffer, so instead we do
     * a single pass of 65 incremental evals and capture logits at every
     * position.  When start_pos > 0 we must still replay the prefix.
     */

    // Build the full token list to feed.  We feed tokens one at a time is not
    // exposed via eval_buffer, so we call eval_buffer once per step with the
    // growing prefix, but WITHOUT resetting the context (incremental KV).
    float* logits = new float[VOCAB_SIZE];

    // If start_pos > 0, replay the prefix without capturing.
    for (int p = 0; p < start_pos; ++p) {
        uint32_t tok = (uint32_t)teacher_forced_tokens[p];
        size_t lc = VOCAB_SIZE;
        rc = mg_context_eval_buffer(mgContext, &tok, 1, logits, &lc);
        if (rc != MG_SUCCESS) {
            printf("Prefix replay failed at %d: %d\n", p, rc);
            delete[] logits;
            mg_context_free(mgContext);
            mg_model_free(mgModel);
            FreeLibrary(coreDll);
            return 1;
        }
    }
    printf("Prefix replay done (0..%d)\n", start_pos - 1);
    fflush(stdout);

    int completed = 0;
    for (int pos = start_pos; pos < end_pos; ++pos) {
        printf("Processing position %d...\n", pos);
        fflush(stdout);

        uint32_t tok = (uint32_t)teacher_forced_tokens[pos];
        size_t logits_count = VOCAB_SIZE;
        rc = mg_context_eval_buffer(mgContext, &tok, 1, logits, &logits_count);

        if (rc != MG_SUCCESS) {
            printf("mg_context_eval_buffer failed at pos %d: %d\n", pos, rc);
            continue;
        }

        char path[512];
        sprintf(path, "F:\\rawrxd\\evidence\\RAWRXD_DEEP2_DLL_EQUIVALENCE_001\\dll_logits_pos%d.bin", pos);
        FILE* f = fopen(path, "wb");
        if (f) {
            fwrite(logits, sizeof(float), VOCAB_SIZE, f);
            fclose(f);
            int am = 0;
            for (int i = 1; i < VOCAB_SIZE; ++i) if (logits[i] > logits[am]) am = i;
            printf("  Saved dll_logits_pos%d.bin (argmax=%d)\n", pos, am);
        } else {
            printf("  FAILED to save dll_logits_pos%d.bin\n", pos);
        }
        fflush(stdout);
        completed++;
    }

    printf("\nCompleted %d positions (%d..%d)\n", completed, start_pos, end_pos - 1);

    delete[] logits;
    mg_context_free(mgContext);
    mg_model_free(mgModel);
    FreeLibrary(coreDll);
    return 0;
}
