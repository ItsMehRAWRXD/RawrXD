//===============================================================================
// Inference Engine - Pure MASM Implementation Header
// Replaces GGML dependency with pure x64 assembly operations
//===============================================================================

#ifndef INFERENCE_ENGINE_MASM_H
#define INFERENCE_ENGINE_MASM_H

#include "../ggml_masm/ggml_masm_pure.h"
#include <vector>
#include <string>

//===============================================================================
// Model Configuration
//===============================================================================

struct ModelConfig {
    int n_vocab;    // Vocabulary size
    int n_ctx;      // Context length
    int n_embd;     // Embedding dimension
    int n_head;     // Number of attention heads
    int n_layer;    // Number of transformer layers
    int n_ff;       // Feed-forward dimension
};

//===============================================================================
// CPU Inference Engine
//===============================================================================

class CPUInferenceEngine {
public:
    CPUInferenceEngine();
    ~CPUInferenceEngine();
    
    // Initialization
    bool Initialize(int threads = 4);
    void Shutdown();
    
    // Model management
    bool LoadModel(const char* model_path);
    void UnloadModel();
    bool IsModelLoaded() const;
    
    // Generation
    int GenerateToken(const std::vector<int>& input_tokens, int pos);
    std::vector<int> Generate(const std::vector<int>& input_tokens, 
                               int max_tokens = 256,
                               float temperature = 0.8f);
    
    // Evaluation
    float CalculatePerplexity(const std::vector<int>& tokens);
    
    // Configuration
    const ModelConfig& GetConfig() const { return model_config; }
    void SetThreads(int threads) { n_threads = threads; }
    
private:
    // Internal methods
    bool InitKVCache();
    ggml_masm_tensor* GetTokenEmbedding(int token_id);
    ggml_masm_tensor* ForwardPass(ggml_masm_tensor* input, int pos, int layer_idx);
    int SampleToken(float* logits, int n_vocab);
    
    // State
    ggml_masm_context* ctx;
    std::vector<ggml_masm_kv_cache> kv_cache;
    ModelConfig model_config;
    bool model_loaded;
    int n_threads;
};

//===============================================================================
// C Interface for FFI
//===============================================================================

#ifdef __cplusplus
extern "C" {
#endif

// Engine lifecycle
void* cpu_inference_engine_create(void);
void cpu_inference_engine_destroy(void* engine);
bool cpu_inference_engine_initialize(void* engine, int threads);
void cpu_inference_engine_shutdown(void* engine);

// Model management
bool cpu_inference_engine_load_model(void* engine, const char* model_path);
void cpu_inference_engine_unload_model(void* engine);
bool cpu_inference_engine_is_loaded(void* engine);

// Generation
int cpu_inference_engine_generate_token(void* engine, const int* tokens, int n_tokens, int pos);
int cpu_inference_engine_generate(void* engine, const int* input_tokens, int n_input,
                                   int* output_tokens, int max_output, float temperature);

// Evaluation
float cpu_inference_engine_perplexity(void* engine, const int* tokens, int n_tokens);

#ifdef __cplusplus
}
#endif

#endif // INFERENCE_ENGINE_MASM_H
