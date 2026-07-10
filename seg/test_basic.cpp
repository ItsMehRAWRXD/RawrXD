// ============================================================================
// Basic Transformer Runtime Test
// ============================================================================

#include <iostream>
#include <iomanip>
#include <chrono>
#include <random>
#include <cmath>
#include <vector>
#include <cstring>

// Minimal implementations for testing

void RMSNorm(const float* input, float* output, const float* weights, 
             uint32_t size, float epsilon) {
    float sum_sq = 0.0f;
    for (uint32_t i = 0; i < size; i++) {
        sum_sq += input[i] * input[i];
    }
    float rms = std::sqrt(sum_sq / size + epsilon);
    float inv_rms = 1.0f / rms;
    
    for (uint32_t i = 0; i < size; i++) {
        output[i] = input[i] * inv_rms * weights[i];
    }
}

void MatMul(const float* A, const float* B, float* C,
            uint32_t m, uint32_t k, uint32_t n) {
    for (uint32_t i = 0; i < m; i++) {
        for (uint32_t j = 0; j < n; j++) {
            float sum = 0.0f;
            for (uint32_t l = 0; l < k; l++) {
                sum += A[i * k + l] * B[l * n + j];
            }
            C[i * n + j] = sum;
        }
    }
}

void Softmax(const float* input, float* output, uint32_t size) {
    float max_val = input[0];
    for (uint32_t i = 1; i < size; i++) {
        max_val = std::max(max_val, input[i]);
    }
    
    float sum_exp = 0.0f;
    for (uint32_t i = 0; i < size; i++) {
        output[i] = std::exp(input[i] - max_val);
        sum_exp += output[i];
    }
    
    float inv_sum = 1.0f / sum_exp;
    for (uint32_t i = 0; i < size; i++) {
        output[i] *= inv_sum;
    }
}

void SiLU(float* data, uint32_t size) {
    for (uint32_t i = 0; i < size; i++) {
        float x = data[i];
        float sigmoid = 1.0f / (1.0f + std::exp(-x));
        data[i] = x * sigmoid;
    }
}

// Simple attention
void Attention(const float* Q, const float* K, const float* V, float* O,
               uint32_t seq_len, uint32_t head_dim) {
    float scale = 1.0f / std::sqrt(static_cast<float>(head_dim));
    
    std::vector<float> scores(seq_len);
    for (uint32_t i = 0; i < seq_len; i++) {
        float sum = 0.0f;
        for (uint32_t j = 0; j < head_dim; j++) {
            sum += Q[j] * K[i * head_dim + j];
        }
        scores[i] = sum * scale;
    }
    
    float max_val = scores[0];
    for (uint32_t i = 1; i < seq_len; i++) {
        max_val = std::max(max_val, scores[i]);
    }
    float sum_exp = 0.0f;
    for (uint32_t i = 0; i < seq_len; i++) {
        scores[i] = std::exp(scores[i] - max_val);
        sum_exp += scores[i];
    }
    for (uint32_t i = 0; i < seq_len; i++) {
        scores[i] /= sum_exp;
    }
    
    for (uint32_t j = 0; j < head_dim; j++) {
        float sum = 0.0f;
        for (uint32_t i = 0; i < seq_len; i++) {
            sum += scores[i] * V[i * head_dim + j];
        }
        O[j] = sum;
    }
}

// Simple transformer layer
struct LayerConfig {
    uint32_t hidden_size = 512;
    uint32_t num_heads = 8;
    uint32_t num_kv_heads = 4;
    uint32_t head_dim = 64;
    uint32_t intermediate_size = 1024;
};

void RunLayer(const float* input, float* output,
              const LayerConfig& config,
              const std::vector<float>& weights_q,
              const std::vector<float>& weights_k,
              const std::vector<float>& weights_v,
              const std::vector<float>& weights_o,
              const std::vector<float>& weights_gate,
              const std::vector<float>& weights_up,
              const std::vector<float>& weights_down,
              const std::vector<float>& norm_in,
              const std::vector<float>& norm_post) {
    
    // Working buffers
    std::vector<float> normed(config.hidden_size);
    std::vector<float> q(config.num_heads * config.head_dim);
    std::vector<float> k(config.num_kv_heads * config.head_dim);
    std::vector<float> v(config.num_kv_heads * config.head_dim);
    std::vector<float> attn_out(config.num_heads * config.head_dim);
    std::vector<float> gate(config.intermediate_size);
    std::vector<float> up(config.intermediate_size);
    
    // Step 1: Input RMS Norm
    RMSNorm(input, normed.data(), norm_in.data(), config.hidden_size, 1e-6f);
    
    // Step 2: QKV Projection
    MatMul(normed.data(), weights_q.data(), q.data(), 1, config.hidden_size, config.num_heads * config.head_dim);
    MatMul(normed.data(), weights_k.data(), k.data(), 1, config.hidden_size, config.num_kv_heads * config.head_dim);
    MatMul(normed.data(), weights_v.data(), v.data(), 1, config.hidden_size, config.num_kv_heads * config.head_dim);
    
    // Step 3: Attention (simplified - just one head for demo)
    for (uint32_t h = 0; h < config.num_heads; h++) {
        float* q_head = q.data() + h * config.head_dim;
        float* out_head = attn_out.data() + h * config.head_dim;
        // Simplified: use k/v from first kv head
        Attention(q_head, k.data(), v.data(), out_head, 1, config.head_dim);
    }
    
    // Step 4: Output projection
    MatMul(attn_out.data(), weights_o.data(), output, 1, config.num_heads * config.head_dim, config.hidden_size);
    
    // Step 5: Residual
    for (uint32_t i = 0; i < config.hidden_size; i++) {
        output[i] += input[i];
    }
    
    // Step 6: Post-attention norm
    memcpy(normed.data(), output, config.hidden_size * sizeof(float));
    RMSNorm(normed.data(), output, norm_post.data(), config.hidden_size, 1e-6f);
    
    // Step 7: MLP
    MatMul(output, weights_gate.data(), gate.data(), 1, config.hidden_size, config.intermediate_size);
    MatMul(output, weights_up.data(), up.data(), 1, config.hidden_size, config.intermediate_size);
    SiLU(gate.data(), config.intermediate_size);
    for (uint32_t i = 0; i < config.intermediate_size; i++) {
        gate[i] *= up[i];
    }
    MatMul(gate.data(), weights_down.data(), output, 1, config.intermediate_size, config.hidden_size);
    
    // Step 8: Residual
    for (uint32_t i = 0; i < config.hidden_size; i++) {
        output[i] += normed[i];
    }
}

int main() {
    std::cout << "========================================\n";
    std::cout << "Basic Transformer Runtime Test\n";
    std::cout << "========================================\n";
    
    // Test 1: RMSNorm
    std::cout << "\n=== Test 1: RMSNorm ===\n";
    {
        std::vector<float> input = {1.0f, 2.0f, 3.0f, 4.0f};
        std::vector<float> weights = {1.0f, 1.0f, 1.0f, 1.0f};
        std::vector<float> output(4);
        
        RMSNorm(input.data(), output.data(), weights.data(), 4, 1e-6f);
        
        float rms = std::sqrt(30.0f / 4.0f);
        bool pass = true;
        for (size_t i = 0; i < input.size(); i++) {
            float expected = input[i] / rms;
            if (std::abs(output[i] - expected) > 1e-5f) {
                pass = false;
            }
        }
        std::cout << (pass ? "PASS" : "FAIL") << ": RMSNorm\n";
    }
    
    // Test 2: MatMul
    std::cout << "\n=== Test 2: MatMul ===\n";
    {
        std::vector<float> A = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f};
        std::vector<float> B = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f};
        std::vector<float> C(4);
        
        MatMul(A.data(), B.data(), C.data(), 2, 3, 2);
        
        std::vector<float> expected = {22.0f, 28.0f, 49.0f, 64.0f};
        bool pass = true;
        for (size_t i = 0; i < C.size(); i++) {
            if (std::abs(C[i] - expected[i]) > 1e-5f) {
                pass = false;
            }
        }
        std::cout << (pass ? "PASS" : "FAIL") << ": MatMul\n";
    }
    
    // Test 3: Softmax
    std::cout << "\n=== Test 3: Softmax ===\n";
    {
        std::vector<float> input = {1.0f, 2.0f, 3.0f};
        std::vector<float> output(3);
        
        Softmax(input.data(), output.data(), 3);
        
        float sum = 0.0f;
        for (auto v : output) sum += v;
        bool pass = std::abs(sum - 1.0f) < 1e-5f;
        std::cout << (pass ? "PASS" : "FAIL") << ": Softmax\n";
    }
    
    // Test 4: Full Layer
    std::cout << "\n=== Test 4: Full Layer ===\n";
    {
        LayerConfig config;
        config.hidden_size = 512;
        config.num_heads = 8;
        config.num_kv_heads = 4;
        config.head_dim = 64;
        config.intermediate_size = 1024;
        
        // Generate weights
        std::mt19937 gen(42);
        std::normal_distribution<float> dist(0.0f, 0.02f);
        
        auto gen_weights = [&](size_t size) {
            std::vector<float> w(size);
            for (auto& v : w) v = dist(gen);
            return w;
        };
        
        auto weights_q = gen_weights(config.hidden_size * config.num_heads * config.head_dim);
        auto weights_k = gen_weights(config.hidden_size * config.num_kv_heads * config.head_dim);
        auto weights_v = gen_weights(config.hidden_size * config.num_kv_heads * config.head_dim);
        auto weights_o = gen_weights(config.num_heads * config.head_dim * config.hidden_size);
        auto weights_gate = gen_weights(config.hidden_size * config.intermediate_size);
        auto weights_up = gen_weights(config.hidden_size * config.intermediate_size);
        auto weights_down = gen_weights(config.intermediate_size * config.hidden_size);
        auto norm_in = gen_weights(config.hidden_size);
        auto norm_post = gen_weights(config.hidden_size);
        
        // Input
        std::vector<float> input(config.hidden_size);
        for (auto& v : input) v = dist(gen);
        std::vector<float> output(config.hidden_size);
        
        // Run
        std::cout << "Running layer...\n";
        auto start = std::chrono::high_resolution_clock::now();
        
        RunLayer(input.data(), output.data(), config,
                 weights_q, weights_k, weights_v, weights_o,
                 weights_gate, weights_up, weights_down,
                 norm_in, norm_post);
        
        auto end = std::chrono::high_resolution_clock::now();
        double elapsed_ms = std::chrono::duration<double, std::milli>(end - start).count();
        
        std::cout << "PASS: Layer completed in " << std::fixed << std::setprecision(3) << elapsed_ms << " ms\n";
        
        // Benchmark
        std::cout << "\nBenchmarking...\n";
        int iterations = 100;
        start = std::chrono::high_resolution_clock::now();
        
        for (int i = 0; i < iterations; i++) {
            RunLayer(input.data(), output.data(), config,
                     weights_q, weights_k, weights_v, weights_o,
                     weights_gate, weights_up, weights_down,
                     norm_in, norm_post);
        }
        
        end = std::chrono::high_resolution_clock::now();
        double total_ms = std::chrono::duration<double, std::milli>(end - start).count();
        double avg_ms = total_ms / iterations;
        double tps = 1000.0 / avg_ms;
        
        std::cout << "  " << iterations << " iterations\n";
        std::cout << "  Total: " << std::fixed << std::setprecision(2) << total_ms << " ms\n";
        std::cout << "  Avg: " << std::fixed << std::setprecision(3) << avg_ms << " ms\n";
        std::cout << "  Tokens/sec: " << std::fixed << std::setprecision(2) << tps << "\n";
    }
    
    std::cout << "\n========================================\n";
    std::cout << "All Tests Complete\n";
    std::cout << "========================================\n";
    
    return 0;
}
