// dll_full_65_test.cpp
// Simple test to run 65 positions through DLL and save logits

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

int main() {
    printf("=== DLL 65-Position Logit Capture ===\n");
    fflush(stdout);
    
    // Load Core DLL
    HMODULE coreDll = LoadLibraryA("F:\\rawrxd\\build_cert\\bin\\Release\\RawrXDCore.dll");
    if (!coreDll) {
        printf("Failed to load DLL: %lu\n", GetLastError());
        return 1;
    }
    
    // Get ModelGenieRuntime functions
    mg_error_t (*mg_model_load)(const char*, const mg_model_config_t*, mg_model_t**) = 
        (mg_error_t (*)(const char*, const mg_model_config_t*, mg_model_t**))GetProcAddress(coreDll, "mg_model_load");
    void (*mg_model_free)(mg_model_t*) = 
        (void (*)(mg_model_t*))GetProcAddress(coreDll, "mg_model_free");
    mg_error_t (*mg_context_create)(mg_model_t*, mg_context_t**) = 
        (mg_error_t (*)(mg_model_t*, mg_context_t**))GetProcAddress(coreDll, "mg_context_create");
    void (*mg_context_free)(mg_context_t*) = 
        (void (*)(mg_context_t*))GetProcAddress(coreDll, "mg_context_free");
    mg_error_t (*mg_context_eval_buffer)(mg_context_t*, const uint32_t*, size_t, float*, size_t*) = 
        (mg_error_t (*)(mg_context_t*, const uint32_t*, size_t, float*, size_t*))GetProcAddress(coreDll, "mg_context_eval_buffer");
    mg_error_t (*mg_context_reset)(mg_context_t*) = 
        (mg_error_t (*)(mg_context_t*))GetProcAddress(coreDll, "mg_context_reset");
    
    if (!mg_model_load || !mg_context_create || !mg_context_eval_buffer || !mg_context_reset) {
        printf("Missing required functions\n");
        return 1;
    }
    
    printf("Functions loaded\n");
    fflush(stdout);
    
    // Load model
    mg_model_config_t mgConfig{};
    mgConfig.max_seq_len = 1024;
    mgConfig.use_kv_cache = true;
    mgConfig.num_threads = 4;
    
    mg_model_t* mgModel = NULL;
    mg_error_t rc = mg_model_load("F:\\rawrxd\\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf", &mgConfig, &mgModel);
    if (rc != MG_SUCCESS || !mgModel) {
        printf("Failed to load model: %d\n", rc);
        return 1;
    }
    
    mg_context_t* mgContext = NULL;
    rc = mg_context_create(mgModel, &mgContext);
    if (rc != MG_SUCCESS || !mgContext) {
        printf("Failed to create context: %d\n", rc);
        return 1;
    }
    
    printf("Model loaded, vocab size: %zu\n", 102400);
    fflush(stdout);
    
    // Create output directory
    _mkdir("F:\\rawrxd\\evidence\\RAWRXD_DEEP2_DLL_EQUIVALENCE_001");
    
    // Run all 65 positions
    float* logits = new float[102400];
    int completed = 0;
    
    for (int pos = 0; pos < NUM_POSITIONS; pos++) {
        printf("Processing position %d...\n", pos);
        fflush(stdout);
        
        mg_context_reset(mgContext);
        
        std::vector<uint32_t> prompt_tokens;
        for (int i = 0; i <= pos; i++) {
            prompt_tokens.push_back(teacher_forced_tokens[i]);
        }
        
        size_t logits_count = VOCAB_SIZE;
        rc = mg_context_eval_buffer(mgContext, prompt_tokens.data(), prompt_tokens.size(), logits, &logits_count);
        
        if (rc != MG_SUCCESS) {
            printf("mg_context_eval_buffer failed at pos %d: %d\n", pos, rc);
            continue;
        }
        
        // Save logits
        char path[512];
        sprintf(path, "F:\\rawrxd\\evidence\\RAWRXD_DEEP2_DLL_EQUIVALENCE_001\\dll_logits_pos%d.bin", pos);
        FILE* f = fopen(path, "wb");
        if (f) {
            fwrite(logits, sizeof(float), VOCAB_SIZE, f);
            fclose(f);
            printf("  Saved dll_logits_pos%d.bin (argmax=%d)\n", pos, 
                   (int)std::distance(logits, std::max_element(logits, logits + VOCAB_SIZE)));
        } else {
            printf("  Failed to save dll_logits_pos%d.bin\n", pos);
        }
        
        completed++;
    }
    
    printf("\nCompleted %d/%d positions\n", completed, NUM_POSITIONS);
    
    delete[] logits;
    mg_context_free(mgContext);
    mg_model_free(mgModel);
    FreeLibrary(coreDll);
    
    return 0;
}