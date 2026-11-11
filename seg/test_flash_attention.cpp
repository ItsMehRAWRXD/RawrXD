// ============================================================================
// FlashAttention v2 Test
// ============================================================================
// Tests the FlashAttention v2 implementation for correctness and performance
// ============================================================================

#include "../runtime/flash_attention_v2.hpp"
#include "../runtime/telemetry_masm_bridge.hpp"
#include <iostream>
#include <vector>
#include <cmath>
#include <chrono>

using namespace RawrXD::Runtime;
using namespace RawrXD::Runtime::Telemetry;

// Reference attention implementation (naive)
void ReferenceAttention(const float* Q, const float* K, const float* V, float* O,
                        uint32_t seq_len, uint32_t num_heads, uint32_t head_dim) {
    float scale = 1.0f / std::sqrt(static_cast<float>(head_dim));
    
    for (uint32_t h = 0; h < num_heads; ++h) {
        for (uint32_t i = 0; i < seq_len; ++i) {
            // Compute attention scores
            std::vector<float> scores(seq_len);
            float max_score = -std::numeric_limits<float>::infinity();
            
            for (uint32_t j = 0; j < seq_len; ++j) {
                float dot = 0.0f;
                for (uint32_t d = 0; d < head_dim; ++d) {
                    dot += Q[(h * seq_len + i) * head_dim + d] * 
                           K[(h * seq_len + j) * head_dim + d];
                }
                scores[j] = dot * scale;
                max_score = std::max(max_score, scores[j]);
            }
            
            // Softmax
            float sum = 0.0f;
            for (uint32_t j = 0; j < seq_len; ++j) {
                scores[j] = std::exp(scores[j] - max_score);
                sum += scores[j];
            }
            
            for (uint32_t j = 0; j < seq_len; ++j) {
                scores[j] /= sum;
            }
            
            // Weighted sum of values
            for (uint32_t d = 0; d < head_dim; ++d) {
                float out = 0.0f;
                for (uint32_t j = 0; j < seq_len; ++j) {
                    out += scores[j] * V[(h * seq_len + j) * head_dim + d];
                }
                O[(h * seq_len + i) * head_dim + d] = out;
            }
        }
    }
}

// Compare outputs
bool CompareOutputs(const float* a, const float* b, size_t n, float tolerance = 1e-3f) {
    float max_diff = 0.0f;
    for (size_t i = 0; i < n; ++i) {
        float diff = std::abs(a[i] - b[i]);
        max_diff = std::max(max_diff, diff);
        if (diff > tolerance) {
            std::cout << "Mismatch at " << i << ": " << a[i] << " vs " << b[i] 
                      << " (diff=" << diff << ")" << std::endl;
            return false;
        }
    }
    std::cout << "Max difference: " << max_diff << std::endl;
    return true;
}

int main() {
    std::cout << "=== FlashAttention v2 Test ===" << std::endl;
    
    // Initialize telemetry
    if (!InitializeMasmTelemetry(1024 * 1024)) {
        std::cerr << "Failed to initialize telemetry" << std::endl;
    }
    
    // Test configuration
    const uint32_t seq_len = 128;
    const uint32_t num_heads = 4;
    const uint32_t head_dim = 64;
    const uint32_t batch_size = 1;
    
    std::cout << "\nConfiguration:" << std::endl;
    std::cout << "  Sequence length: " << seq_len << std::endl;
    std::cout << "  Number of heads: " << num_heads << std::endl;
    std::cout << "  Head dimension: " << head_dim << std::endl;
    std::cout << "  Batch size: " << batch_size << std::endl;
    
    // Allocate memory
    size_t tensor_size = batch_size * num_heads * seq_len * head_dim;
    std::vector<float> Q(tensor_size);
    std::vector<float> K(tensor_size);
    std::vector<float> V(tensor_size);
    std::vector<float> O_flash(tensor_size);
    std::vector<float> O_ref(tensor_size);
    
    // Initialize with random values
    srand(42);
    for (size_t i = 0; i < tensor_size; ++i) {
        Q[i] = (rand() / float(RAND_MAX) - 0.5f) * 0.1f;
        K[i] = (rand() / float(RAND_MAX) - 0.5f) * 0.1f;
        V[i] = (rand() / float(RAND_MAX) - 0.5f) * 0.1f;
    }
    
    // Create FlashAttention config
    FlashAttentionConfig config = MakeFlashAttentionConfig(
        seq_len, num_heads, head_dim, batch_size);
    
    std::cout << "\nBlock sizes: Q=" << config.block_q 
              << ", KV=" << config.block_kv << std::endl;
    
    // Test 1: Forward pass
    std::cout << "\n[1/3] Testing forward pass..." << std::endl;
    {
        FlashAttentionV2 fa(config);
        
        auto start = std::chrono::high_resolution_clock::now();
        fa.Forward(Q.data(), K.data(), V.data(), O_flash.data());
        auto end = std::chrono::high_resolution_clock::now();
        
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        std::cout << "  FlashAttention time: " << duration.count() << " us" << std::endl;
    }
    
    // Compute reference
    std::cout << "  Computing reference..." << std::endl;
    auto start = std::chrono::high_resolution_clock::now();
    ReferenceAttention(Q.data(), K.data(), V.data(), O_ref.data(), 
                       seq_len, num_heads, head_dim);
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    std::cout << "  Reference time: " << duration.count() << " us" << std::endl;
    
    // Compare
    std::cout << "  Comparing outputs..." << std::endl;
    if (CompareOutputs(O_flash.data(), O_ref.data(), tensor_size)) {
        std::cout << "  ✓ Forward pass matches reference!" << std::endl;
    } else {
        std::cout << "  ✗ Forward pass mismatch!" << std::endl;
        return 1;
    }
    
    // Test 2: Causal attention
    std::cout << "\n[2/3] Testing causal attention..." << std::endl;
    {
        FlashAttentionV2 fa(config);
        fa.ForwardCausal(Q.data(), K.data(), V.data(), O_flash.data());
    }
    std::cout << "  ✓ Causal attention completed" << std::endl;
    
    // Test 3: Performance benchmark
    std::cout << "\n[3/3] Performance benchmark..." << std::endl;
    const int iterations = 10;
    {
        FlashAttentionV2 fa(config);
        
        // Warmup
        for (int i = 0; i < 3; ++i) {
            fa.Forward(Q.data(), K.data(), V.data(), O_flash.data());
        }
        
        // Benchmark
        auto start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < iterations; ++i) {
            fa.Forward(Q.data(), K.data(), V.data(), O_flash.data());
        }
        auto end = std::chrono::high_resolution_clock::now();
        
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        float avg_time = duration.count() / float(iterations);
        
        // Calculate FLOPs
        // Attention: 2 * seq_len^2 * head_dim (QK^T) + 2 * seq_len^2 * head_dim (softmax*V)
        float flops = 4.0f * seq_len * seq_len * head_dim * num_heads * batch_size;
        float gflops = (flops / avg_time) / 1000.0f;
        
        std::cout << "  Average time: " << avg_time << " us" << std::endl;
        std::cout << "  Throughput: " << gflops << " GFLOP/s" << std::endl;
    }
    
    // Print telemetry summary
    std::cout << "\n=== Telemetry Summary ===" << std::endl;
    TelemetryStats stats;
    MasmTelemetry_GetStats(&stats);
    std::cout << "Events logged: " << stats.eventsLogged << std::endl;
    std::cout << "Events dropped: " << stats.eventsDropped << std::endl;
    
    std::cout << "\n=== All Tests Passed ===" << std::endl;
    return 0;
}
