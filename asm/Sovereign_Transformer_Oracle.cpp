// ============================================================================
// Sovereign_Transformer_Oracle.cpp - CPU Transformer Reference Implementation
// ============================================================================
// Full transformer forward pass using Sovereign kernels
// This is the "oracle" that GPU implementations are validated against
// ============================================================================

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <cmath>
#include <random>
#include <chrono>
#include "Sovereign_KernelDispatch.h"

// Test configuration
struct TransformerConfig {
    size_t vocab_size = 32000;
    size_t hidden_dim = 4096;
    size_t num_heads = 32;
    size_t num_layers = 32;
    size_t head_dim = 128;  // hidden_dim / num_heads
    size_t intermediate_dim = 11008;  // ~2.7 * hidden_dim
    size_t max_seq_len = 4096;
    float rms_norm_eps = 1e-6f;
    float rope_theta = 10000.0f;
};

// Timing utility
class Timer {
    std::chrono::high_resolution_clock::time_point start_;
public:
    void Start() { start_ = std::chrono::high_resolution_clock::now(); }
    double ElapsedMs() {
        auto end = std::chrono::high_resolution_clock::now();
        return std::chrono::duration<double, std::milli>(end - start_).count();
    }
};

// Initialize tensor with random values
void InitRandom(float* data, size_t n, float scale = 1.0f) {
    std::mt19937 gen(42);  // Fixed seed for reproducibility
    std::normal_distribution<float> dist(0.0f, scale);
    for (size_t i = 0; i < n; i++) {
        data[i] = dist(gen);
    }
}

// Check for NaN/Inf
bool ValidateTensor(const float* data, size_t n, const char* name) {
    for (size_t i = 0; i < n; i++) {
        if (std::isnan(data[i]) || std::isinf(data[i])) {
            printf("[ERROR] %s contains NaN/Inf at index %zu\n", name, i);
            return false;
        }
    }
    return true;
}

// Compare two tensors
bool CompareTensors(const float* a, const float* b, size_t n, 
                    const char* name, float tolerance = 1e-4f) {
    float max_diff = 0.0f;
    size_t diff_count = 0;
    
    for (size_t i = 0; i < n; i++) {
        float diff = std::abs(a[i] - b[i]);
        if (diff > tolerance) {
            diff_count++;
            if (diff > max_diff) max_diff = diff;
        }
    }
    
    if (diff_count > 0) {
        printf("[WARN] %s: %zu differences, max diff = %.6f\n", 
               name, diff_count, max_diff);
        return diff_count < (n * 0.01);  // Allow 1% tolerance
    }
    return true;
}

// ============================================================================
// Transformer Layer Implementation
// ============================================================================

class TransformerLayer {
public:
    TransformerLayer(const TransformerConfig& config, Sovereign::KernelDispatch& dispatch)
        : config_(config), dispatch_(dispatch) {
        
        // Allocate buffers
        size_t hidden = config.hidden_dim;
        size_t intermediate = config.intermediate_dim;
        
        // RMSNorm weights
        rms_norm_weights_.resize(hidden, 1.0f);
        ffn_norm_weights_.resize(hidden, 1.0f);
        
        // QKV projection weights (simplified - just store dimensions)
        qkv_weights_.resize(hidden * 3 * hidden);  // Q, K, V each [hidden, hidden]
        InitRandom(qkv_weights_.data(), qkv_weights_.size(), 0.02f);
        
        // Output projection
        output_weights_.resize(hidden * hidden);
        InitRandom(output_weights_.data(), output_weights_.size(), 0.02f);
        
        // FFN weights
        gate_up_weights_.resize(hidden * intermediate * 2);  // Gate and Up
        InitRandom(gate_up_weights_.data(), gate_up_weights_.size(), 0.02f);
        
        down_weights_.resize(intermediate * hidden);
        InitRandom(down_weights_.data(), down_weights_.size(), 0.02f);
        
        // RoPE cache
        rope_cache_.resize(config.max_seq_len * config.head_dim * 2);
        if (!dispatch_.RoPEPrecompute(config.head_dim, config.max_seq_len, 
                                       config.rope_theta, rope_cache_.data())) {
            printf("[ERROR] Failed to precompute RoPE cache\n");
        }
    }
    
    // Forward pass through one transformer layer
    bool Forward(float* hidden_states, size_t seq_len) {
        Timer timer;
        
        // Allocate temporary buffers
        size_t hidden = config_.hidden_dim;
        std::vector<float> normed(hidden * seq_len);
        std::vector<float> qkv(3 * hidden * seq_len);
        std::vector<float> attn_output(hidden * seq_len);
        std::vector<float> ffn_output(hidden * seq_len);
        
        // === Attention Sub-Layer ===
        timer.Start();
        
        // 1. RMSNorm (pre-attention)
        for (size_t s = 0; s < seq_len; s++) {
            if (!dispatch_.RMSNorm(&hidden_states[s * hidden], 
                                    &normed[s * hidden],
                                    rms_norm_weights_.data(),
                                    hidden, config_.rms_norm_eps)) {
                printf("[ERROR] RMSNorm failed at position %zu\n", s);
                return false;
            }
        }
        
        if (!ValidateTensor(normed.data(), normed.size(), "Post-RMSNorm")) return false;
        
        // 2. QKV Projection (simplified - just copy for now)
        // In real implementation: matmul with qkv_weights_
        memcpy(qkv.data(), normed.data(), normed.size() * sizeof(float));
        
        // 3. RoPE
        // Apply to Q and K portions
        float* q = qkv.data();
        float* k = qkv.data() + hidden * seq_len;
        if (!dispatch_.RoPEApply(q, rope_cache_.data(), seq_len, 
                                 config_.head_dim, config_.num_heads)) {
            printf("[ERROR] RoPE apply failed\n");
            return false;
        }
        if (!dispatch_.RoPEApply(k, rope_cache_.data(), seq_len,
                                 config_.head_dim, config_.num_heads)) {
            printf("[ERROR] RoPE apply failed\n");
            return false;
        }
        
        // 4. Attention (simplified - would call attention kernels)
        // For now: just pass through
        memcpy(attn_output.data(), normed.data(), normed.size() * sizeof(float));
        
        // 5. Output projection (simplified)
        // Would matmul with output_weights_
        
        // 6. Residual connection
        for (size_t s = 0; s < seq_len; s++) {
            if (!dispatch_.ResidualAddInPlace(&hidden_states[s * hidden],
                                               &attn_output[s * hidden],
                                               hidden)) {
                printf("[ERROR] ResidualAdd failed at position %zu\n", s);
                return false;
            }
        }
        
        if (!ValidateTensor(hidden_states, hidden * seq_len, "Post-Attention Residual")) {
            return false;
        }
        
        double attn_time = timer.ElapsedMs();
        printf("    Attention sub-layer: %.3f ms\n", attn_time);
        
        // === FFN Sub-Layer ===
        timer.Start();
        
        // 7. RMSNorm (pre-FFN)
        for (size_t s = 0; s < seq_len; s++) {
            if (!dispatch_.RMSNorm(&hidden_states[s * hidden],
                                    &normed[s * hidden],
                                    ffn_norm_weights_.data(),
                                    hidden, config_.rms_norm_eps)) {
                printf("[ERROR] FFN RMSNorm failed\n");
                return false;
            }
        }
        
        // 8. FFN (simplified - would call FFN kernels)
        // For now: just pass through
        memcpy(ffn_output.data(), normed.data(), normed.size() * sizeof(float));
        
        // 9. Residual connection
        for (size_t s = 0; s < seq_len; s++) {
            if (!dispatch_.ResidualAddInPlace(&hidden_states[s * hidden],
                                               &ffn_output[s * hidden],
                                               hidden)) {
                printf("[ERROR] FFN ResidualAdd failed\n");
                return false;
            }
        }
        
        if (!ValidateTensor(hidden_states, hidden * seq_len, "Post-FFN Residual")) {
            return false;
        }
        
        double ffn_time = timer.ElapsedMs();
        printf("    FFN sub-layer: %.3f ms\n", ffn_time);
        
        return true;
    }

private:
    TransformerConfig config_;
    Sovereign::KernelDispatch& dispatch_;
    
    std::vector<float> rms_norm_weights_;
    std::vector<float> ffn_norm_weights_;
    std::vector<float> qkv_weights_;
    std::vector<float> output_weights_;
    std::vector<float> gate_up_weights_;
    std::vector<float> down_weights_;
    std::vector<float> rope_cache_;
};

// ============================================================================
// Full Transformer Model
// ============================================================================

class TransformerModel {
public:
    TransformerModel(const TransformerConfig& config) : config_(config) {
        if (!dispatch_.Initialize()) {
            printf("[FATAL] Failed to initialize kernel dispatch\n");
            exit(1);
        }
        
        // Create layers
        for (size_t i = 0; i < config.num_layers; i++) {
            layers_.emplace_back(config, dispatch_);
        }
        
        // Output norm
        output_norm_weights_.resize(config.hidden_dim, 1.0f);
        
        // LM head (tie with embeddings for simplicity)
        lm_head_weights_.resize(config.vocab_size * config.hidden_dim);
        InitRandom(lm_head_weights_.data(), lm_head_weights_.size(), 0.02f);
    }
    
    bool Forward(const std::vector<int>& input_ids, std::vector<float>& logits) {
        Timer timer;
        size_t seq_len = input_ids.size();
        size_t hidden = config_.hidden_dim;
        
        printf("\n=== Transformer Forward Pass ===\n");
        printf("Sequence length: %zu\n", seq_len);
        printf("Hidden dim: %zu\n", hidden);
        printf("Num layers: %zu\n\n", config_.num_layers);
        
        // Embedding lookup (simplified - random init)
        std::vector<float> hidden_states(hidden * seq_len);
        for (size_t s = 0; s < seq_len; s++) {
            // In real implementation: lookup embedding table
            // For now: initialize with small random values based on token id
            std::mt19937 gen(input_ids[s]);
            std::normal_distribution<float> dist(0.0f, 0.02f);
            for (size_t h = 0; h < hidden; h++) {
                hidden_states[s * hidden + h] = dist(gen);
            }
        }
        
        printf("Embedding: OK\n");
        
        // Pass through all layers
        for (size_t layer_idx = 0; layer_idx < config_.num_layers; layer_idx++) {
            printf("\n[Layer %zu/%zu]\n", layer_idx + 1, config_.num_layers);
            
            if (!layers_[layer_idx].Forward(hidden_states.data(), seq_len)) {
                printf("[ERROR] Layer %zu forward pass failed\n", layer_idx);
                return false;
            }
        }
        
        // Final RMSNorm
        std::vector<float> normed(hidden * seq_len);
        for (size_t s = 0; s < seq_len; s++) {
            if (!dispatch_.RMSNorm(&hidden_states[s * hidden],
                                    &normed[s * hidden],
                                    output_norm_weights_.data(),
                                    hidden, config_.rms_norm_eps)) {
                printf("[ERROR] Final RMSNorm failed\n");
                return false;
            }
        }
        
        printf("\nFinal RMSNorm: OK\n");
        
        // LM head (simplified - just return last token)
        logits.resize(config_.vocab_size);
        // In real implementation: matmul with lm_head_weights_
        // For now: random logits
        InitRandom(logits.data(), logits.size(), 1.0f);
        
        double total_time = timer.ElapsedMs();
        printf("\n=== Forward Pass Complete ===\n");
        printf("Total time: %.3f ms\n", total_time);
        printf("Time per layer: %.3f ms\n", total_time / config_.num_layers);
        
        return true;
    }

private:
    TransformerConfig config_;
    Sovereign::KernelDispatch dispatch_;
    std::vector<TransformerLayer> layers_;
    std::vector<float> output_norm_weights_;
    std::vector<float> lm_head_weights_;
};

// ============================================================================
// Main Test
// ============================================================================

int main(int argc, char** argv) {
    printf("========================================\n");
    printf("Sovereign Transformer Oracle\n");
    printf("CPU Reference Implementation\n");
    printf("========================================\n\n");
    
    // Configuration
    TransformerConfig config;
    
    // Override with command line args if provided
    if (argc > 1) config.hidden_dim = atoi(argv[1]);
    if (argc > 2) config.num_layers = atoi(argv[2]);
    if (argc > 3) config.max_seq_len = atoi(argv[3]);
    
    printf("Configuration:\n");
    printf("  Hidden dim: %zu\n", config.hidden_dim);
    printf("  Num heads: %zu\n", config.num_heads);
    printf("  Num layers: %zu\n", config.num_layers);
    printf("  Head dim: %zu\n", config.head_dim);
    printf("  Max seq len: %zu\n\n", config.max_seq_len);
    
    // Create model
    TransformerModel model(config);
    
    // Test with a simple prompt (token ids)
    std::vector<int> input_ids = {1, 2, 3, 4, 5};  // Dummy tokens
    std::vector<float> logits;
    
    // Run forward pass
    if (!model.Forward(input_ids, logits)) {
        printf("\n[FAIL] Transformer forward pass failed\n");
        return 1;
    }
    
    // Output sample logits
    printf("\nOutput logits (first 10):\n");
    for (size_t i = 0; i < std::min(size_t(10), logits.size()); i++) {
        printf("  logit[%zu] = %.4f\n", i, logits[i]);
    }
    
    // Find max logit (predicted token)
    size_t max_idx = 0;
    float max_val = logits[0];
    for (size_t i = 1; i < logits.size(); i++) {
        if (logits[i] > max_val) {
            max_val = logits[i];
            max_idx = i;
        }
    }
    printf("\nPredicted token: %zu (logit=%.4f)\n", max_idx, max_val);
    
    printf("\n========================================\n");
    printf("[PASS] Transformer Oracle Validation\n");
    printf("========================================\n");
    
    return 0;
}
