#pragma once

#include "rawrxd/compatibility/ArchitectureDetector.hpp"
#include <memory>
#include <functional>

namespace rawrxd {
namespace compatibility {

// Forward declarations
class TensorView;
class KernelContext;

// Model-specific adaptation layer
class ModelAdapter {
public:
    ModelAdapter(ModelArchitecture arch);
    ~ModelAdapter() = default;

    // Initialize adapter for specific architecture
    void Initialize(const ModelConfig& config);
    
    // Tensor format conversion
    void ConvertInputFormat(TensorView* input);
    void ConvertOutputFormat(TensorView* output);
    
    // Attention adaptation
    void AdaptAttentionMask(TensorView* mask, int seq_len);
    void AdaptPositionIds(TensorView* position_ids, int start_pos);
    
    // RoPE adaptation
    void ComputeRoPE(TensorView* q, TensorView* k, int start_pos, float theta);
    void AdaptRoPEScaling(float* scale, int seq_len);
    
    // Normalization adaptation
    void AdaptRMSNorm(TensorView* x, float eps);
    void AdaptLayerNorm(TensorView* x, float eps);
    
    // Activation adaptation
    void ApplyActivation(TensorView* x);
    
    // KV cache adaptation
    void AdaptKVCache(TensorView* k_cache, TensorView* v_cache, int layer_idx);
    
    // Special token handling
    int GetBOSToken();
    int GetEOSToken();
    int GetPadToken();
    std::vector<int> GetStopTokens();
    
    // Architecture-specific features
    bool UseSlidingWindow();
    int GetSlidingWindowSize();
    bool UseGQA();
    int GetNumKVHeads();
    
    // Mixture of Experts (for Mixtral)
    void RouteExperts(TensorView* hidden_states, int* expert_indices, float* expert_weights);
    
    // Get architecture info
    ModelArchitecture GetArchitecture() const { return arch_; }
    const ModelConfig& GetConfig() const { return config_; }

private:
    ModelArchitecture arch_;
    ModelConfig config_;
    
    // Architecture-specific handlers
    void InitializeLlama3();
    void InitializeMistral();
    void InitializeMixtral();
    void InitializePhi3();
    void InitializeQwen2();
    void InitializeDeepSeek();
    void InitializeCodestral();
    void InitializeGemma2();
    
    // RoPE cache
    std::vector<float> rope_cos_cache_;
    std::vector<float> rope_sin_cache_;
    int rope_cache_len_ = 0;
    
    // ALiBi slopes (for DeepSeek)
    std::vector<float> alibi_slopes_;
};

// Factory for creating adapters
class ModelAdapterFactory {
public:
    static std::unique_ptr<ModelAdapter> Create(ModelArchitecture arch);
    static std::unique_ptr<ModelAdapter> Create(const std::string& model_name);
    static std::unique_ptr<ModelAdapter> CreateFromGGUF(const std::string& gguf_path);
};

// Compatibility layer for tokenizer differences
class TokenizerAdapter {
public:
    TokenizerAdapter(ModelArchitecture arch);
    
    // Special token mapping
    int MapToken(int original_token);
    int UnmapToken(int mapped_token);
    
    // Chat template handling
    std::string ApplyChatTemplate(const std::vector<std::pair<std::string, std::string>>& messages);
    
    // Token preprocessing
    std::string PreprocessInput(const std::string& input);
    std::string PostprocessOutput(const std::string& output);
    
    // Check if tokenizer requires special handling
    bool RequiresSpecialPreprocessing();
    bool UsesByteFallback();
    bool UsesSentencePiece();
    bool UsesTiktoken();

private:
    ModelArchitecture arch_;
    std::unordered_map<int, int> token_map_;
    std::unordered_map<int, int> reverse_map_;
};

} // namespace compatibility
} // namespace rawrxd
