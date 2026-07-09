/**
 * @file attention_contracts.h
 * @brief RawrXD L4.3 Attention Contracts and State Management
 *
 * Defines tensor layouts, attention configuration, and KV cache ABI.
 * Establishes contracts before attention kernel implementation.
 *
 * @copyright RawrXD 2026
 */

#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>

namespace rawrxd {
namespace attention {

// ============================================================================
// Tensor Layout Contract
// ============================================================================

/**
 * @brief Strict tensor layout descriptor
 *
 * Kernels must not guess layout. All dimensions and strides explicit.
 */
struct TensorView {
    float* data;                    // Base pointer
    
    // Dimensions
    uint32_t rows;                  // Outer dimension
    uint32_t cols;                  // Inner dimension
    uint32_t depth;                 // For 3D tensors (heads, seq, dim)
    
    // Strides (in elements, not bytes)
    uint32_t row_stride;            // Distance between rows
    uint32_t col_stride;            // Distance between cols (usually 1)
    uint32_t depth_stride;          // Distance between depth slices
    
    // Metadata
    uint32_t total_elements;
    bool is_contiguous;
    
    TensorView()
        : data(nullptr)
        , rows(0)
        , cols(0)
        , depth(1)
        , row_stride(0)
        , col_stride(1)
        , depth_stride(0)
        , total_elements(0)
        , is_contiguous(false)
    {}
    
    // Access element at (row, col)
    float& at(uint32_t row, uint32_t col) {
        return data[row * row_stride + col * col_stride];
    }
    
    const float& at(uint32_t row, uint32_t col) const {
        return data[row * row_stride + col * col_stride];
    }
    
    // Access 3D element at (depth, row, col)
    float& at3(uint32_t d, uint32_t row, uint32_t col) {
        return data[d * depth_stride + row * row_stride + col * col_stride];
    }
    
    // Validate layout is sane
    bool IsValid() const {
        if (!data) return false;
        if (rows == 0 || cols == 0) return false;
        if (col_stride == 0) return false;
        return true;
    }
    
    // Check if layout matches expected shape
    bool MatchesShape(uint32_t expected_rows, uint32_t expected_cols) const {
        return rows == expected_rows && cols == expected_cols;
    }
    
    // Create contiguous view from raw data
    static TensorView CreateContiguous(float* data, uint32_t rows, uint32_t cols) {
        TensorView view;
        view.data = data;
        view.rows = rows;
        view.cols = cols;
        view.depth = 1;
        view.row_stride = cols;
        view.col_stride = 1;
        view.depth_stride = rows * cols;
        view.total_elements = rows * cols;
        view.is_contiguous = true;
        return view;
    }
    
    // Create 3D contiguous view
    static TensorView CreateContiguous3D(float* data, uint32_t depth, uint32_t rows, uint32_t cols) {
        TensorView view;
        view.data = data;
        view.depth = depth;
        view.rows = rows;
        view.cols = cols;
        view.row_stride = cols;
        view.col_stride = 1;
        view.depth_stride = rows * cols;
        view.total_elements = depth * rows * cols;
        view.is_contiguous = true;
        return view;
    }
};

// ============================================================================
// Attention Configuration
// ============================================================================

/**
 * @brief Complete attention operation configuration
 *
 * Passed to every attention kernel. No global state.
 */
struct AttentionConfig {
    // Architecture
    uint32_t num_heads;             // Number of query heads
    uint32_t num_kv_heads;          // Number of key/value heads (GQA)
    uint32_t head_dim;              // Dimension per head
    uint32_t context_length;        // Maximum sequence length
    
    // Behavior
    bool causal;                    // Apply causal mask
    bool use_alibi;                 // ALiBi position bias
    bool use_rope;                  // RoPE position encoding
    float rope_theta;               // RoPE base frequency
    float scale;                    // Attention scale (typically 1/sqrt(head_dim))
    
    // Numerics
    float softmax_cap;              // Clip softmax logits (0 = no cap)
    float attention_dropout;        // Dropout rate (0 = no dropout)
    
    // Validation
    bool validate_inputs;           // Check all inputs before execution
    bool compute_checksums;         // Debug: compute tensor checksums
    
    AttentionConfig()
        : num_heads(0)
        , num_kv_heads(0)
        , head_dim(0)
        , context_length(0)
        , causal(true)
        , use_alibi(false)
        , use_rope(true)
        , rope_theta(10000.0f)
        , scale(0.0f)
        , softmax_cap(0.0f)
        , attention_dropout(0.0f)
        , validate_inputs(true)
        , compute_checksums(false)
    {}
    
    // Compute scale if not set
    void ComputeScale() {
        if (scale == 0.0f && head_dim > 0) {
            scale = 1.0f / std::sqrt(static_cast<float>(head_dim));
        }
    }
    
    // Validate configuration
    bool IsValid() const {
        if (num_heads == 0) return false;
        if (num_kv_heads == 0) return false;
        if (head_dim == 0) return false;
        if (context_length == 0) return false;
        if (num_heads % num_kv_heads != 0) return false;  // GQA constraint
        return true;
    }
    
    // Get number of query heads per KV head (for GQA)
    uint32_t GetQueryHeadsPerKV() const {
        return num_heads / num_kv_heads;
    }
    
    // Total hidden dimension
    uint32_t GetHiddenDim() const {
        return num_heads * head_dim;
    }
};

// ============================================================================
// KV Cache ABI
// ============================================================================

/**
 * @brief KV Cache state management
 *
 * Attention kernels consume the cache, do not own it.
 * Cache is pre-allocated to max_context_length.
 */
struct KVCache {
    // Cache buffers (pre-allocated)
    float* key_cache;               // [max_position, num_kv_heads, head_dim]
    float* value_cache;             // [max_position, num_kv_heads, head_dim]
    
    // Cache layout
    uint32_t max_position;            // Maximum sequence position
    uint32_t current_position;        // Next position to write
    
    // Strides for indexing
    uint32_t pos_stride;            // stride between positions
    uint32_t head_stride;             // stride between heads
    uint32_t dim_stride;              // stride within head (usually 1)
    
    // State
    bool is_initialized;
    uint32_t batch_idx;               // For batched inference
    
    KVCache()
        : key_cache(nullptr)
        , value_cache(nullptr)
        , max_position(0)
        , current_position(0)
        , pos_stride(0)
        , head_stride(0)
        , dim_stride(1)
        , is_initialized(false)
        , batch_idx(0)
    {}
    
    // Initialize cache with pre-allocated buffers
    bool Initialize(float* k_buffer, float* v_buffer, 
                    uint32_t max_pos, uint32_t num_kv_heads, uint32_t head_dim) {
        if (!k_buffer || !v_buffer) return false;
        if (max_pos == 0 || num_kv_heads == 0 || head_dim == 0) return false;
        
        key_cache = k_buffer;
        value_cache = v_buffer;
        max_position = max_pos;
        current_position = 0;
        
        // Layout: [position, head, dim]
        pos_stride = num_kv_heads * head_dim;
        head_stride = head_dim;
        dim_stride = 1;
        
        is_initialized = true;
        return true;
    }
    
    // Get pointer to key at (position, head)
    float* GetKey(uint32_t pos, uint32_t head) {
        if (!key_cache || pos >= max_position) return nullptr;
        return key_cache + pos * pos_stride + head * head_stride;
    }
    
    // Get pointer to value at (position, head)
    float* GetValue(uint32_t pos, uint32_t head) {
        if (!value_cache || pos >= max_position) return nullptr;
        return value_cache + pos * pos_stride + head * head_stride;
    }
    
    // Append new K,V at current_position
    bool Append(const float* new_key, const float* new_value, 
                uint32_t num_kv_heads, uint32_t head_dim) {
        if (current_position >= max_position) return false;
        
        for (uint32_t h = 0; h < num_kv_heads; ++h) {
            float* k_dest = GetKey(current_position, h);
            float* v_dest = GetValue(current_position, h);
            
            if (!k_dest || !v_dest) return false;
            
            std::memcpy(k_dest, new_key + h * head_dim, head_dim * sizeof(float));
            std::memcpy(v_dest, new_value + h * head_dim, head_dim * sizeof(float));
        }
        
        current_position++;
        return true;
    }
    
    // Reset cache (keep allocation, clear position)
    void Reset() {
        current_position = 0;
    }
    
    // Check if cache can accept more tokens
    bool HasCapacity() const {
        return current_position < max_position;
    }
    
    // Get current sequence length
    uint32_t GetSequenceLength() const {
        return current_position;
    }
    
    // Validate cache state
    bool IsValid() const {
        return is_initialized && 
               key_cache != nullptr && 
               value_cache != nullptr &&
               current_position <= max_position;
    }
};

// ============================================================================
// Attention Inputs/Outputs
// ============================================================================

/**
 * @brief Attention operation inputs
 */
struct AttentionInputs {
    // Query, Key, Value projections (from transformer primitive pipeline)
    TensorView query;               // [num_heads, head_dim]
    TensorView key;                 // [num_kv_heads, head_dim]  (or use cache)
    TensorView value;               // [num_kv_heads, head_dim]  (or use cache)
    
    // Optional: use KV cache instead of separate K,V
    KVCache* kv_cache;              // nullptr = use provided K,V
    
    // Position information
    uint32_t seq_position;          // Current sequence position
    uint32_t seq_length;          // Total sequence length (for non-causal)
    
    // Attention mask (optional)
    const float* attention_mask;    // [seq_length] or nullptr
    
    AttentionInputs()
        : kv_cache(nullptr)
        , seq_position(0)
        , seq_length(1)
        , attention_mask(nullptr)
    {}
    
    // Validate inputs
    bool IsValid(const AttentionConfig& config) const {
        if (!query.IsValid()) return false;
        if (!query.MatchesShape(config.num_heads, config.head_dim)) return false;
        
        if (kv_cache) {
            if (!kv_cache->IsValid()) return false;
        } else {
            if (!key.IsValid() || !value.IsValid()) return false;
            if (!key.MatchesShape(config.num_kv_heads, config.head_dim)) return false;
            if (!value.MatchesShape(config.num_kv_heads, config.head_dim)) return false;
        }
        
        return true;
    }
};

/**
 * @brief Attention operation outputs
 */
struct AttentionOutputs {
    TensorView output;              // [num_heads, head_dim] - attention result
    
    // Optional: attention weights for analysis
    float* attention_weights;       // [num_heads, seq_length] or nullptr
    
    // KV cache update (if cache provided)
    bool kv_cache_updated;
    
    AttentionOutputs()
        : attention_weights(nullptr)
        , kv_cache_updated(false)
    {}
};

// ============================================================================
// Validation Contracts
// ============================================================================

/**
 * @brief Validation result for attention operations
 */
struct ValidationResult {
    bool passed;
    float cosine_similarity;
    float max_absolute_error;
    float rmse;
    std::vector<std::string> errors;
    
    ValidationResult()
        : passed(false)
        , cosine_similarity(0.0f)
        , max_absolute_error(0.0f)
        , rmse(0.0f)
    {}
    
    void AddError(const std::string& error) {
        errors.push_back(error);
        passed = false;
    }
    
    bool IsPassing(float cosine_threshold = 0.999f, 
                    float max_error_threshold = 0.01f) const {
        return cosine_similarity >= cosine_threshold &&
               max_absolute_error <= max_error_threshold;
    }
};

/**
 * @brief Attention validator interface
 */
class AttentionValidator {
public:
    // Validate attention output against reference
    static ValidationResult Validate(
        const AttentionConfig& config,
        const AttentionInputs& inputs,
        const AttentionOutputs& outputs,
        const AttentionOutputs& reference_outputs
    );
    
    // Compute cosine similarity between two attention outputs
    static float ComputeCosineSimilarity(
        const TensorView& a, 
        const TensorView& b
    );
    
    // Compute max absolute error
    static float ComputeMaxError(
        const TensorView& a,
        const TensorView& b
    );
    
    // Compute RMSE
    static float ComputeRMSE(
        const TensorView& a,
        const TensorView& b
    );
};

// ============================================================================
// Attention State (for multi-layer models)
// ============================================================================

/**
 * @brief Complete attention state for a transformer layer
 */
struct LayerAttentionState {
    uint32_t layer_idx;
    KVCache kv_cache;
    
    // Statistics (for debugging/analysis)
    uint32_t tokens_processed;
    float avg_attention_entropy;
    
    LayerAttentionState() : layer_idx(0), tokens_processed(0), avg_attention_entropy(0.0f) {}
};

/**
 * @brief Model-wide attention state
 */
struct ModelAttentionState {
    uint32_t num_layers;
    std::vector<LayerAttentionState> layer_states;
    
    bool Initialize(uint32_t layers, uint32_t max_context, 
                    uint32_t num_kv_heads, uint32_t head_dim) {
        num_layers = layers;
        layer_states.resize(layers);
        
        for (uint32_t i = 0; i < layers; ++i) {
            layer_states[i].layer_idx = i;
            // Note: actual buffer allocation happens outside
        }
        
        return true;
    }
    
    KVCache* GetLayerCache(uint32_t layer_idx) {
        if (layer_idx >= num_layers) return nullptr;
        return &layer_states[layer_idx].kv_cache;
    }
    
    void ResetAllCaches() {
        for (auto& state : layer_states) {
            state.kv_cache.Reset();
        }
    }
};

// ============================================================================
// Utility Functions
// ============================================================================

// Print tensor view for debugging
void PrintTensorView(const TensorView& view, const std::string& name);

// Print attention config
void PrintAttentionConfig(const AttentionConfig& config);

// Print KV cache state
void PrintKVCacheState(const KVCache& cache);

// Validate entire attention operation chain
bool ValidateAttentionChain(const AttentionConfig& config,
                            const std::vector<std::string>* expected_ops = nullptr);

} // namespace attention
} // namespace rawrxd
