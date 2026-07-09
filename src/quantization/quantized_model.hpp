// ============================================================================
// Quantized Model - Production Integration
// ============================================================================
// High-level interface for quantized inference in RawrXD
// Provides runtime switching between F32/Q8_0/Q4_0
// ============================================================================

#pragma once

#include "quantized_inference.hpp"
#include "quantized_transformer_layer.hpp"
#include <string>
#include <memory>
#include <vector>
#include <unordered_map>
namespace rawrxd {
namespace quantization {

// ============================================================================
// Quantization Mode
// ============================================================================

enum class QuantizationMode {
    AUTO,       // Automatically select based on available memory
    F32,        // Full precision (reference)
    Q8_0,       // 8-bit quantization (4x compression)
    Q4_0        // 4-bit quantization (8x compression, default)
};

// ============================================================================
// Quantized Model Configuration
// ============================================================================

struct QuantizedModelConfig {
    // Model architecture
    size_t vocab_size = 128256;
    size_t hidden_size = 3072;
    size_t num_layers = 28;
    size_t num_heads = 24;
    size_t num_kv_heads = 8;
    size_t intermediate_size = 8192;
    size_t max_seq_length = 4096;
    
    // Quantization settings
    QuantizationMode mode = QuantizationMode::Q4_0;
    bool use_gqa = true;           // Grouped Query Attention
    bool use_flash_attn = false;   // Flash attention (future)
    
    // Performance settings
    size_t batch_size = 1;
    bool use_avx512 = true;
    
    // Get effective quant type
    QuantType GetQuantType() const {
        switch (mode) {
            case QuantizationMode::F32: return QuantType::F32;
            case QuantizationMode::Q8_0: return QuantType::Q8_0;
            case QuantizationMode::Q4_0:
            case QuantizationMode::AUTO:
            default: return QuantType::Q4_0;
        }
    }
    
    // Calculate memory requirements
    size_t GetMemoryRequirementBytes() const;
    size_t GetMemoryRequirementGB() const {
        return GetMemoryRequirementBytes() / (1024 * 1024 * 1024);
    }
};

// ============================================================================
// Quantized Model
// ============================================================================
// Main interface for quantized inference

class QuantizedModel {
public:
    QuantizedModel();
    ~QuantizedModel();
    
    // Disable copy (unique_ptr members)
    QuantizedModel(const QuantizedModel&) = delete;
    QuantizedModel& operator=(const QuantizedModel&) = delete;
    
    // Enable move
    QuantizedModel(QuantizedModel&&) = default;
    QuantizedModel& operator=(QuantizedModel&&) = default;
    
    // Initialize with configuration
    bool Initialize(const QuantizedModelConfig& config);
    
    // Load from GGUF file
    bool LoadFromGGUF(const std::string& path);
    
    // Set quantization mode at runtime
    bool SetQuantizationMode(QuantizationMode mode);
    QuantizationMode GetQuantizationMode() const;
    
    // Inference
    // input_tokens: token IDs [batch_size, seq_len]
    // output_logits: logits [batch_size, seq_len, vocab_size]
    bool Forward(const std::vector<int32_t>& input_tokens,
                 std::vector<float>& output_logits,
                 size_t batch_size = 1,
                 size_t seq_len = 1);
    
    // Generate next token
    // Returns token ID
    int32_t GenerateNextToken(const std::vector<int32_t>& context_tokens,
                             float temperature = 1.0f,
                             int32_t top_k = 40);
    
    // KV cache management
    void ClearKVCache();
    size_t GetKVCacheSize() const;
    
    // Memory and performance
    size_t GetMemoryUsage() const;
    size_t GetMemorySavings() const;  // vs F32
    double GetLastInferenceTimeMs() const;
    double GetThroughputTokensPerSec() const;
    
    // Status
    bool IsInitialized() const { return initialized_; }
    bool IsLoaded() const { return model_loaded_; }
    std::string GetModelInfo() const;
    
    // Static factory methods
    static std::unique_ptr<QuantizedModel> CreateLlama3_2_3B(QuantizationMode mode = QuantizationMode::Q4_0);
    static std::unique_ptr<QuantizedModel> CreateGemma3_1B(QuantizationMode mode = QuantizationMode::Q4_0);
    static std::unique_ptr<QuantizedModel> CreatePhi3Mini(QuantizationMode mode = QuantizationMode::Q4_0);
    
private:
    QuantizedModelConfig config_;
    bool initialized_ = false;
    bool model_loaded_ = false;
    
    // Model weights
    QuantizedTensor token_embeddings_;
    std::vector<float> output_norm_;
    QuantizedTensor lm_head_;
    std::vector<std::unique_ptr<QuantizedTransformerLayerExtended>> layers_;
    
    // KV cache
    std::vector<float> kv_cache_k_;
    std::vector<float> kv_cache_v_;
    size_t current_seq_length_ = 0;
    
    // Performance tracking
    double last_inference_time_ms_ = 0.0;
    size_t total_tokens_generated_ = 0;
    
    // Helper methods
    bool InitializeLayers();
    bool LoadWeightsFromGGUF(const std::string& path);
    bool InitializeKVCache();
};

// ============================================================================
// Quantized Model Manager
// ============================================================================
// Singleton for managing model instances

class QuantizedModelManager {
public:
    static QuantizedModelManager& GetInstance();
    
    // Create or get model
    QuantizedModel* GetOrCreateModel(const std::string& model_name);
    
    // Set default quantization mode
    void SetDefaultMode(QuantizationMode mode) { default_mode_ = mode; }
    QuantizationMode GetDefaultMode() const { return default_mode_; }
    
    // Memory management
    size_t GetTotalMemoryUsage() const;
    void ReleaseUnusedModels();
    
    // List available models
    std::vector<std::string> ListAvailableModels() const;
    
private:
    QuantizedModelManager() = default;
    ~QuantizedModelManager() = default;
    
    QuantizedModelManager(const QuantizedModelManager&) = delete;
    QuantizedModelManager& operator=(const QuantizedModelManager&) = delete;
    
    std::unordered_map<std::string, std::unique_ptr<QuantizedModel>> models_;
    QuantizationMode default_mode_ = QuantizationMode::Q4_0;
};

// ============================================================================
// Convenience Functions
// ============================================================================

// Quick inference with default settings
bool RunQuantizedInference(const std::string& model_path,
                            const std::vector<int32_t>& input_tokens,
                            std::vector<float>& output_logits,
                            QuantizationMode mode = QuantizationMode::Q4_0);

// Get memory savings for a model
std::pair<size_t, size_t> CalculateMemorySavings(const std::string& model_path);

// Check if model can run with current memory
bool CanRunModel(const std::string& model_path, QuantizationMode mode = QuantizationMode::Q4_0);

} // namespace quantization
} // namespace rawrxd
