#pragma once
// ============================================================================
// inference_engine_real.h - Real Inference Engine Header
// Provides C and C++ interfaces for real transformer inference
// ============================================================================

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <string>

// ============================================================================
// C INTERFACE
// ============================================================================

#ifdef __cplusplus
extern "C" {
#endif

// Create/Destroy
__declspec(dllexport) void* RawrInferenceEngine_Create();
__declspec(dllexport) void RawrInferenceEngine_Destroy(void* engine);

// Initialization
__declspec(dllexport) int RawrInferenceEngine_Initialize(
    void* engine,
    int n_vocab,
    int n_embd,
    int n_head,
    int n_layer);

// Model loading
__declspec(dllexport) int RawrInferenceEngine_LoadModel(void* engine, const char* model_path);

// Generation
__declspec(dllexport) int RawrInferenceEngine_Generate(
    void* engine,
    const char* prompt,
    int max_tokens,
    char* output_buffer,
    int output_buffer_size);

__declspec(dllexport) int RawrInferenceEngine_GenerateTokens(
    void* engine,
    const int* input_tokens,
    int n_input_tokens,
    int max_new_tokens,
    int* output_tokens,
    int max_output_tokens);

// Cleanup
__declspec(dllexport) void RawrInferenceEngine_Cleanup(void* engine);

// Status
__declspec(dllexport) int RawrInferenceEngine_IsInitialized(void* engine);
__declspec(dllexport) int RawrInferenceEngine_IsModelLoaded(void* engine);

// Legacy compatibility
__declspec(dllexport) void* InferenceEngine_Create(void* config);
__declspec(dllexport) int InferenceEngine_Initialize(void* engine, const char* model_path);
__declspec(dllexport) int InferenceEngine_GetVocabSize(void* engine);
__declspec(dllexport) int InferenceEngine_GetEmbeddingDim(void* engine);
__declspec(dllexport) void InferenceEngine_UnloadModel(void* engine);
__declspec(dllexport) int InferenceEngine_Generate(
    void* engine,
    const char* prompt,
    int max_tokens,
    char* output_buffer,
    int output_buffer_size);
__declspec(dllexport) void InferenceEngine_Destroy(void* engine);

#ifdef __cplusplus
}
#endif

// ============================================================================
// C++ INTERFACE
// ============================================================================

#ifdef __cplusplus

namespace RawrXD {
namespace Inference {

// Model configuration
struct ModelConfig {
    int n_vocab = 32000;
    int n_embd = 4096;
    int n_head = 32;
    int n_layer = 32;
    int n_ctx = 4096;
    float temperature = 0.8f;
    int top_k = 40;
    float top_p = 0.9f;
};

// Inference result
struct InferenceResult {
    std::vector<int> tokens;
    std::vector<float> logits;
    float confidence = 0.0f;
    float perplexity = 0.0f;
    float generation_time_ms = 0.0f;
    int tokens_generated = 0;
    bool success = false;
    std::string error_message;
};

// Real inference engine class
class RealInferenceEngine {
public:
    RealInferenceEngine();
    ~RealInferenceEngine();
    
    // Disable copy
    RealInferenceEngine(const RealInferenceEngine&) = delete;
    RealInferenceEngine& operator=(const RealInferenceEngine&) = delete;
    
    // Enable move
    RealInferenceEngine(RealInferenceEngine&&) noexcept;
    RealInferenceEngine& operator=(RealInferenceEngine&&) noexcept;
    
    // Initialize with configuration
    bool Initialize(const ModelConfig& config);
    
    // Load model from file
    bool LoadModel(const std::string& model_path);
    
    // Generate text from prompt
    std::string Generate(const std::string& prompt, int max_tokens);
    
    // Generate with detailed result
    InferenceResult GenerateDetailed(const std::vector<int>& input_tokens, int max_new_tokens);
    
    // Generate tokens
    std::vector<int> GenerateTokens(const std::vector<int>& input_tokens, int max_new_tokens);
    
    // Get logits for input
    std::vector<float> GetLogits(const std::vector<int>& tokens);
    
    // Calculate perplexity
    float CalculatePerplexity(const std::string& text);
    
    // Cleanup
    void Cleanup();
    
    // Status
    bool IsInitialized() const;
    bool IsModelLoaded() const;
    const std::string& GetModelPath() const;
    const ModelConfig& GetConfig() const;
    
private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// Convenience function to create engine
std::unique_ptr<RealInferenceEngine> CreateInferenceEngine(const ModelConfig& config = ModelConfig());

} // namespace Inference
} // namespace RawrXD

#endif // __cplusplus
