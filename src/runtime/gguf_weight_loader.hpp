/**
 * @file gguf_weight_loader.hpp
 * @brief RawrXD GGUF Weight Loader
 *
 * Loads transformer weights from GGUF files with support for:
 * - F32, F16, Q4_0, Q8_0, Q4_K, Q6_K quantization formats
 * - Memory-mapped file access for efficient loading
 * - Transformer block weights (attention, FFN, norms)
 * - Embedding and output weights
 *
 * @copyright RawrXD 2026
 */

#pragma once

#include "../model/model_context.h"

#include <cstdint>
#include <vector>
#include <string>
#include <memory>
#include <unordered_map>
#include <functional>

namespace rawrxd {
namespace runtime {

// ============================================================================
// Quantization Types
// ============================================================================

enum class QuantizationType {
    F32,
    F16,
    Q4_0,   // 4-bit, block size 32
    Q4_1,   // 4-bit, block size 32 with bias
    Q5_0,   // 5-bit, block size 32
    Q5_1,   // 5-bit, block size 32 with bias
    Q8_0,   // 8-bit, block size 32
    Q8_1,   // 8-bit, block size 32 with bias
    Q2_K,   // 2-bit K-quant
    Q3_K,   // 3-bit K-quant
    Q4_K,   // 4-bit K-quant
    Q5_K,   // 5-bit K-quant
    Q6_K,   // 6-bit K-quant
    Q8_K,   // 8-bit K-quant
    Unknown
};

// ============================================================================
// Tensor Data
// ============================================================================

struct TensorData {
    std::string name;
    std::vector<uint64_t> shape;
    QuantizationType quant_type;
    
    // Raw data pointer (memory-mapped or allocated)
    const void* data = nullptr;
    size_t size = 0;
    
    // Dequantized F32 data (if applicable)
    std::vector<float> f32_data;
    
    // Whether this tensor owns its data
    bool owns_data = false;
    
    // Get element count
    uint64_t GetElementCount() const;
    
    // Get size in bytes
    size_t GetSizeBytes() const;
    
    // Dequantize to F32 (if needed)
    const float* GetF32Data();
    
    // Access element at index (returns dequantized F32)
    float GetElement(size_t index);
};

// ============================================================================
// Weight Loading Progress
// ============================================================================

struct LoadingProgress {
    uint32_t total_tensors = 0;
    uint32_t loaded_tensors = 0;
    uint64_t total_bytes = 0;
    uint64_t loaded_bytes = 0;
    std::string current_tensor;
    
    float GetPercentComplete() const {
        if (total_bytes == 0) return 0.0f;
        return static_cast<float>(loaded_bytes) / static_cast<float>(total_bytes) * 100.0f;
    }
};

using ProgressCallback = std::function<void(const LoadingProgress&)>;

// ============================================================================
// Transformer Weights
// ============================================================================

struct TransformerWeights {
    // Token embeddings
    TensorData token_embeddings;
    
    // Output weights (language model head)
    TensorData output_weights;
    
    // Per-layer weights
    struct LayerWeights {
        // Attention
        TensorData attn_q;
        TensorData attn_k;
        TensorData attn_v;
        TensorData attn_o;
        
        // Attention norms
        TensorData attn_norm;
        TensorData attn_norm_bias;  // Optional
        
        // FFN (SwiGLU)
        TensorData ffn_gate;  // Gating weights
        TensorData ffn_up;    // Up projection
        TensorData ffn_down;  // Down projection
        
        // FFN norms
        TensorData ffn_norm;
        TensorData ffn_norm_bias;  // Optional
    };
    
    std::vector<LayerWeights> layers;
    
    // Final norm
    TensorData final_norm;
    TensorData final_norm_bias;  // Optional
    
    // Get total size in bytes
    size_t GetTotalSizeBytes() const;
    
    // Get number of layers
    size_t GetLayerCount() const { return layers.size(); }
};

// ============================================================================
// GGUF Weight Loader
// ============================================================================

class GGUFWeightLoader {
public:
    GGUFWeightLoader();
    ~GGUFWeightLoader();
    
    // Disable copy, enable move
    GGUFWeightLoader(const GGUFWeightLoader&) = delete;
    GGUFWeightLoader& operator=(const GGUFWeightLoader&) = delete;
    GGUFWeightLoader(GGUFWeightLoader&&) noexcept;
    GGUFWeightLoader& operator=(GGUFWeightLoader&&) noexcept;
    
    /**
     * Load weights from GGUF file.
     */
    bool LoadFromFile(const std::string& path, const ProgressCallback& callback = nullptr);
    
    /**
     * Load weights from ModelContext (already parsed GGUF).
     */
    bool LoadFromContext(const model::ModelContext& context, const ProgressCallback& callback = nullptr);
    
    /**
     * Check if loaded.
     */
    bool IsLoaded() const { return loaded_; }
    
    /**
     * Get loaded weights.
     */
    const TransformerWeights& GetWeights() const { return weights_; }
    TransformerWeights& GetWeights() { return weights_; }
    
    /**
     * Get specific tensor by name.
     */
    const TensorData* GetTensor(const std::string& name) const;
    
    /**
     * Get last error.
     */
    const std::string& GetLastError() const { return last_error_; }
    
    /**
     * Get loading progress.
     */
    const LoadingProgress& GetProgress() const { return progress_; }
    
    /**
     * Unload all weights.
     */
    void Unload();
    
    /**
     * Get memory-mapped file handle (for debugging).
     */
    void* GetFileHandle() const { return file_handle_; }
    
    /**
     * Get memory-mapped base address.
     */
    const uint8_t* GetMappedBase() const { return mapped_base_; }
    
private:
    bool loaded_ = false;
    std::string last_error_;
    LoadingProgress progress_;
    
    // Memory-mapped file
    void* file_handle_ = nullptr;
    void* mapping_handle_ = nullptr;
    const uint8_t* mapped_base_ = nullptr;
    size_t mapped_size_ = 0;
    
    // Loaded weights
    TransformerWeights weights_;
    std::unordered_map<std::string, TensorData*> tensor_map_;
    
    // Internal methods
    bool MapFile(const std::string& path);
    void UnmapFile();
    bool ParseTensors(const model::ModelContext& context);
    bool LoadTensor(const model::TensorInfo& info, TensorData& out_data);
    
    // Quantization helpers
    QuantizationType ConvertGGMLType(uint32_t ggml_type);
    bool DequantizeTensor(TensorData& data);
    
    // Dequantization implementations
    bool DequantizeQ4_0(const void* src, float* dst, size_t num_elements);
    bool DequantizeQ4_1(const void* src, float* dst, size_t num_elements);
    bool DequantizeQ8_0(const void* src, float* dst, size_t num_elements);
    bool DequantizeF16(const void* src, float* dst, size_t num_elements);
    bool DequantizeQ4_K(const void* src, float* dst, size_t num_elements);
    bool DequantizeQ6_K(const void* src, float* dst, size_t num_elements);
    
    // Weight name mapping
    std::string MapWeightName(const std::string& gguf_name);
    bool IsAttentionWeight(const std::string& name);
    bool IsFFNWeight(const std::string& name);
    bool IsNormWeight(const std::string& name);
};

// ============================================================================
// Convenience Functions
// ============================================================================

// Quick load without class instantiation
std::unique_ptr<TransformerWeights> LoadTransformerWeights(
    const std::string& gguf_path,
    std::string* error = nullptr,
    const ProgressCallback& callback = nullptr
);

// Get quantization type name
const char* GetQuantizationName(QuantizationType type);

// Calculate dequantized size
size_t CalculateDequantizedSize(QuantizationType type, size_t num_elements);

} // namespace runtime
} // namespace rawrxd
