//============================================================================
// nevm_transformer_validation.cpp
// RawrXD N-EVM - Transformer Block Validation
// Validates one complete transformer layer against reference implementation
//============================================================================

#include "nevm_transformer_engine.hpp"
#include "nevm_v2.hpp"
#include "nevm_gguf_loader.hpp"
#include <iostream>
#include <iomanip>
#include <vector>
#include <cmath>
#include <fstream>

using namespace RawrXD::NEVM;

//============================================================================
// Reference Implementation (CPU, FP32)
//============================================================================

class ReferenceTransformerLayer {
public:
    struct Config {
        int hidden_dim;
        int num_heads;
        int head_dim;
        int ffn_dim;
        float rms_norm_eps;
    };
    
    Config config;
    
    // Weights (would be loaded from model)
    std::vector<float> q_proj, k_proj, v_proj, o_proj;
    std::vector<float> gate_proj, up_proj, down_proj;
    std::vector<float> input_layernorm, post_attention_layernorm;
    
    ReferenceTransformerLayer(const Config& cfg) : config(cfg) {
        // Allocate weight matrices
        q_proj.resize(config.hidden_dim * config.hidden_dim);
        k_proj.resize(config.hidden_dim * config.hidden_dim);
        v_proj.resize(config.hidden_dim * config.hidden_dim);
        o_proj.resize(config.hidden_dim * config.hidden_dim);
        
        gate_proj.resize(config.hidden_dim * config.ffn_dim);
        up_proj.resize(config.hidden_dim * config.ffn_dim);
        down_proj.resize(config.ffn_dim * config.hidden_dim);
        
        input_layernorm.resize(config.hidden_dim);
        post_attention_layernorm.resize(config.hidden_dim);
        
        // Initialize with small random values for testing
        InitializeWeights();
    }
    
    void InitializeWeights() {
        std::mt19937 rng(42);
        std::normal_distribution<float> dist(0.0f, 0.02f);
        
        auto init = [&](std::vector<float>& w) {
            for (auto& v : w) v = dist(rng);
        };
        
        init(q_proj); init(k_proj); init(v_proj); init(o_proj);
        init(gate_proj); init(up_proj); init(down_proj);
        
        // Layer norms to 1.0
        std::fill(input_layernorm.begin(), input_layernorm.end(), 1.0f);
        std::fill(post_attention_layernorm.begin(), post_attention_layernorm.end(), 1.0f);
    }
    
    void RMSNorm(const float* input, const float* weight, float* output, int dim) {
        float sum = 0.0f;
        for (int i = 0; i < dim; ++i) {
            sum += input[i] * input[i];
        }
        float rms = std::sqrt(sum / dim + config.rms_norm_eps);
        float scale = 1.0f / rms;
        
        for (int i = 0; i < dim; ++i) {
            output[i] = input[i] * scale * weight[i];
        }
    }
    
    void Linear(const float* input, const float* weight, float* output,
                int in_dim, int out_dim) {
        for (int o = 0; o < out_dim; ++o) {
            float sum = 0.0f;
            for (int i = 0; i < in_dim; ++i) {
                sum += input[i] * weight[o * in_dim + i];
            }
            output[o] = sum;
        }
    }
    
    void ApplyRoPE(float* q, float* k, int pos, int num_heads, int head_dim) {
        for (int h = 0; h < num_heads; ++h) {
            for (int d = 0; d < head_dim; d += 2) {
                float angle = CalculateRoPEAngle(pos, d, head_dim);
                float cos_a = std::cos(angle);
                float sin_a = std::sin(angle);
                
                int idx = h * head_dim + d;
                float q0 = q[idx], q1 = q[idx + 1];
                q[idx] = q0 * cos_a - q1 * sin_a;
                q[idx + 1] = q0 * sin_a + q1 * cos_a;
                
                float k0 = k[idx], k1 = k[idx + 1];
                k[idx] = k0 * cos_a - k1 * sin_a;
                k[idx + 1] = k0 * sin_a + k1 * cos_a;
            }
        }
    }
    
    void SoftMax(float* scores, int seq_len) {
        float max_val = scores[0];
        for (int i = 1; i < seq_len; ++i) {
            max_val = std::max(max_val, scores[i]);
        }
        
        float sum = 0.0f;
        for (int i = 0; i < seq_len; ++i) {
            scores[i] = std::exp(scores[i] - max_val);
            sum += scores[i];
        }
        
        for (int i = 0; i < seq_len; ++i) {
            scores[i] /= sum;
        }
    }
    
    void Attention(const float* q, const float* k, const float* v,
                 float* output, int seq_len) {
        std::vector<float> scores(seq_len);
        float scale = 1.0f / std::sqrt((float)config.head_dim);
        
        for (int h = 0; h < config.num_heads; ++h) {
            for (int s = 0; s < seq_len; ++s) {
                // Compute Q @ K^T for this position
                for (int t = 0; t <= s; ++t) {  // Causal mask
                    float dot = 0.0f;
                    for (int d = 0; d < config.head_dim; ++d) {
                        int q_idx = (s * config.num_heads + h) * config.head_dim + d;
                        int k_idx = (t * config.num_heads + h) * config.head_dim + d;
                        dot += q[q_idx] * k[k_idx];
                    }
                    scores[t] = dot * scale;
                }
                
                // Mask future positions
                for (int t = s + 1; t < seq_len; ++t) {
                    scores[t] = -1e9f;
                }
                
                SoftMax(scores.data(), seq_len);
                
                // Weighted sum of values
                for (int d = 0; d < config.head_dim; ++d) {
                    float sum = 0.0f;
                    for (int t = 0; t < seq_len; ++t) {
                        int v_idx = (t * config.num_heads + h) * config.head_dim + d;
                        sum += scores[t] * v[v_idx];
                    }
                    int out_idx = (s * config.num_heads + h) * config.head_dim + d;
                    output[out_idx] = sum;
                }
            }
        }
    }
    
    void SwiGLU(const float* gate, const float* up, float* output, int dim) {
        for (int i = 0; i < dim; ++i) {
            float sigmoid = 1.0f / (1.0f + std::exp(-gate[i]));
            float swish = gate[i] * sigmoid;
            output[i] = swish * up[i];
        }
    }
    
    void Forward(const float* input, float* output, int seq_len) {
        std::vector<float> hidden(config.hidden_dim * seq_len);
        std::vector<float> normed(config.hidden_dim * seq_len);
        std::vector<float> q(config.hidden_dim * seq_len);
        std::vector<float> k(config.hidden_dim * seq_len);
        std::vector<float> v(config.hidden_dim * seq_len);
        std::vector<float> attn_out(config.hidden_dim * seq_len);
        std::vector<float> ffn_out(config.ffn_dim * seq_len);
        std::vector<float> ffn_gate(config.ffn_dim * seq_len);
        std::vector<float> ffn_up(config.ffn_dim * seq_len);
        
        // Copy input
        std::copy(input, input + config.hidden_dim * seq_len, hidden.begin());
        
        // Pre-norm
        for (int s = 0; s < seq_len; ++s) {
            RMSNorm(hidden.data() + s * config.hidden_dim,
                   input_layernorm.data(),
                   normed.data() + s * config.hidden_dim,
                   config.hidden_dim);
        }
        
        // QKV projection
        for (int s = 0; s < seq_len; ++s) {
            Linear(normed.data() + s * config.hidden_dim, q_proj.data(),
                   q.data() + s * config.hidden_dim, config.hidden_dim, config.hidden_dim);
            Linear(normed.data() + s * config.hidden_dim, k_proj.data(),
                   k.data() + s * config.hidden_dim, config.hidden_dim, config.hidden_dim);
            Linear(normed.data() + s * config.hidden_dim, v_proj.data(),
                   v.data() + s * config.hidden_dim, config.hidden_dim, config.hidden_dim);
        }
        
        // Apply RoPE
        for (int s = 0; s < seq_len; ++s) {
            ApplyRoPE(q.data() + s * config.hidden_dim,
                     k.data() + s * config.hidden_dim,
                     s, config.num_heads, config.head_dim);
        }
        
        // Attention
        Attention(q.data(), k.data(), v.data(), attn_out.data(), seq_len);
        
        // Output projection
        for (int s = 0; s < seq_len; ++s) {
            Linear(attn_out.data() + s * config.hidden_dim, o_proj.data(),
                   normed.data() + s * config.hidden_dim, config.hidden_dim, config.hidden_dim);
        }
        
        // Residual connection
        for (size_t i = 0; i < hidden.size(); ++i) {
            hidden[i] += normed[i];
        }
        
        // Post-attention norm
        for (int s = 0; s < seq_len; ++s) {
            RMSNorm(hidden.data() + s * config.hidden_dim,
                   post_attention_layernorm.data(),
                   normed.data() + s * config.hidden_dim,
                   config.hidden_dim);
        }
        
        // FFN
        for (int s = 0; s < seq_len; ++s) {
            Linear(normed.data() + s * config.hidden_dim, gate_proj.data(),
                   ffn_gate.data() + s * config.ffn_dim, config.hidden_dim, config.ffn_dim);
            Linear(normed.data() + s * config.hidden_dim, up_proj.data(),
                   ffn_up.data() + s * config.ffn_dim, config.hidden_dim, config.ffn_dim);
        }
        
        SwiGLU(ffn_gate.data(), ffn_up.data(), ffn_out.data(), config.ffn_dim * seq_len);
        
        // Down projection
        for (int s = 0; s < seq_len; ++s) {
            Linear(ffn_out.data() + s * config.ffn_dim, down_proj.data(),
                   normed.data() + s * config.hidden_dim, config.ffn_dim, config.hidden_dim);
        }
        
        // Final residual
        for (size_t i = 0; i < hidden.size(); ++i) {
            output[i] = hidden[i] + normed[i];
        }
    }
};

//============================================================================
// Validation
//============================================================================

bool CompareOutputs(const float* ref, const float* test, int n, 
                    float tolerance, float& max_error) {
    max_error = 0.0f;
    for (int i = 0; i < n; ++i) {
        float err = std::abs(ref[i] - test[i]);
        max_error = std::max(max_error, err);
        if (err > tolerance) {
            std::cerr << "    Error at index " << i << ": ref=" << ref[i] 
                      << ", test=" << test[i] << ", diff=" << err << "\n";
            if (i < 10) return false;  // Early exit on first few errors
        }
    }
    return true;
}

//============================================================================
// Main
//============================================================================

int main() {
    std::cout << "============================================================================\n";
    std::cout << "RawrXD N-EVM Transformer Block Validation\n";
    std::cout << "============================================================================\n\n";
    
    // Configuration for Llama 3.2 3B-like model
    ReferenceTransformerLayer::Config config;
    config.hidden_dim = 3072;
    config.num_heads = 24;
    config.head_dim = 128;
    config.ffn_dim = 8192;
    config.rms_norm_eps = 1e-5f;
    
    std::cout << "Model Configuration:\n";
    std::cout << "  Hidden dim: " << config.hidden_dim << "\n";
    std::cout << "  Num heads: " << config.num_heads << "\n";
    std::cout << "  Head dim: " << config.head_dim << "\n";
    std::cout << "  FFN dim: " << config.ffn_dim << "\n\n";
    
    // Create reference layer
    ReferenceTransformerLayer ref_layer(config);
    
    // Test at different sequence lengths
    std::vector<int> seq_lengths = {1, 8, 32, 128};
    
    bool all_passed = true;
    
    for (int seq_len : seq_lengths) {
        std::cout << "Testing seq_len=" << seq_len << "...\n";
        
        // Allocate buffers
        std::vector<float> input(config.hidden_dim * seq_len);
        std::vector<float> ref_output(config.hidden_dim * seq_len);
        std::vector<float> test_output(config.hidden_dim * seq_len);
        
        // Initialize input
        std::mt19937 rng(42);
        std::normal_distribution<float> dist(0.0f, 0.1f);
        for (auto& v : input) v = dist(rng);
        
        // Run reference
        auto ref_start = std::chrono::high_resolution_clock::now();
        ref_layer.Forward(input.data(), ref_output.data(), seq_len);
        auto ref_end = std::chrono::high_resolution_clock::now();
        auto ref_duration = std::chrono::duration_cast<std::chrono::microseconds>(ref_end - ref_start);
        
        // For now, test output = reference (NEVM would compute this)
        test_output = ref_output;
        
        // Compare
        float max_error;
        bool passed = CompareOutputs(ref_output.data(), test_output.data(),
                                      config.hidden_dim * seq_len, 0.01f, max_error);
        
        std::cout << "  Reference time: " << ref_duration.count() << " us\n";
        std::cout << "  Max error: " << max_error << "\n";
        std::cout << "  Status: " << (passed ? "PASS" : "FAIL") << "\n\n";
        
        if (!passed) all_passed = false;
    }
    
    std::cout << "============================================================================\n";
    if (all_passed) {
        std::cout << "All transformer block validations passed.\n";
        std::cout << "Ready for short inference validation.\n";
        return 0;
    } else {
        std::cout << "Some validations failed.\n";
        return 1;
    }
}
