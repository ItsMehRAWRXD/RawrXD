//===============================================================================
// AI Model Caller - Pure MASM Implementation Header
// Replaces simulated inference with real forward pass using pure assembly
//===============================================================================

#ifndef AI_MODEL_CALLER_MASM_H
#define AI_MODEL_CALLER_MASM_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

//===============================================================================
// Initialization
//===============================================================================

bool AIModelCaller_MASM_Init(void);
void AIModelCaller_MASM_Deinit(void);

//===============================================================================
// Model Management
//===============================================================================

bool AIModelCaller_MASM_LoadModel(const char* model_path);
void AIModelCaller_MASM_UnloadModel(void);
bool AIModelCaller_MASM_IsModelLoaded(void);

//===============================================================================
// Token Generation
//===============================================================================

int AIModelCaller_MASM_GenerateToken(const int* input_tokens, int n_tokens, int pos);
int AIModelCaller_MASM_Generate(const int* input_tokens, int n_input,
                                 int* output_tokens, int max_output,
                                 float temperature);

//===============================================================================
// KV Cache Management
//===============================================================================

bool AIModelCaller_MASM_InitKVCache(int n_ctx, int n_embd, int n_head);
void AIModelCaller_MASM_ClearKVCache(void);

//===============================================================================
// Perplexity Calculation
//===============================================================================

float AIModelCaller_MASM_CalculatePerplexity(const int* tokens, int n_tokens);

//===============================================================================
// Model Configuration
//===============================================================================

void AIModelCaller_MASM_GetConfig(int* n_layers, int* n_embd, int* n_head, int* n_vocab, int* n_ctx);
void AIModelCaller_MASM_SetConfig(int n_layers, int n_embd, int n_head, int n_vocab, int n_ctx);

//===============================================================================
// C Interface
//===============================================================================

// Initialization
bool ai_model_caller_masm_init(void);
void ai_model_caller_masm_deinit(void);

// Model management
bool ai_model_caller_masm_load_model(const char* model_path);
void ai_model_caller_masm_unload_model(void);
bool ai_model_caller_masm_is_model_loaded(void);

// Generation
int ai_model_caller_masm_generate_token(const int* input_tokens, int n_tokens, int pos);
int ai_model_caller_masm_generate(const int* input_tokens, int n_input,
                                   int* output_tokens, int max_output,
                                   float temperature);

// KV cache
bool ai_model_caller_masm_init_kv_cache(int n_ctx, int n_embd, int n_head);
void ai_model_caller_masm_clear_kv_cache(void);

// Perplexity
float ai_model_caller_masm_perplexity(const int* tokens, int n_tokens);

// Config
void ai_model_caller_masm_get_config(int* n_layers, int* n_embd, int* n_head, int* n_vocab, int* n_ctx);
void ai_model_caller_masm_set_config(int n_layers, int n_embd, int n_head, int n_vocab, int n_ctx);

#ifdef __cplusplus
}
#endif

#endif // AI_MODEL_CALLER_MASM_H
