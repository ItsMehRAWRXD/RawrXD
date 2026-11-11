// ============================================================================
// Minimal Transformer Runtime Test
// ============================================================================

#include "transformer_layer_runtime.hpp"
#include <iostream>
#include <iomanip>
#include <chrono>
#include <random>
#include <cmath>

using namespace transformer;

int main() {
    std::cout << "========================================\n";
    std::cout << "Minimal Transformer Runtime Test\n";
    std::cout << "========================================\n";
    
    // Test 1: CPU Backend
    std::cout << "\n=== Test 1: CPU Backend ===\n";
    {
        auto backend = CreateCPUBackend();
        if (!backend->Initialize()) {
            std::cerr << "FAIL: Backend initialization\n";
            return 1;
        }
        std::cout << "PASS: Backend initialized\n";
        
        // Test RMSNorm
        std::vector<float> input = {1.0f, 2.0f, 3.0f, 4.0f};
        std::vector<float> weights = {1.0f, 1.0f, 1.0f, 1.0f};
        std::vector<float> output(4);
        
        backend->RMSNorm(input.data(), output.data(), weights.data(), 4, 1e-6f);
        
        float rms = std::sqrt(30.0f / 4.0f);
        bool pass = true;
        for (size_t i = 0; i < input.size(); i++) {
            float expected = input[i] / rms;
            if (std::abs(output[i] - expected) > 1e-5f) {
                pass = false;
            }
        }
        std::cout << (pass ? "PASS" : "FAIL") << ": RMSNorm\n";
        
        // Test MatMul
        std::vector<float> A = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f};
        std::vector<float> B = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f};
        std::vector<float> C(4);
        
        backend->MatMul(A.data(), B.data(), C.data(), 2, 3, 2);
        
        std::vector<float> expected = {22.0f, 28.0f, 49.0f, 64.0f};
        pass = true;
        for (size_t i = 0; i < C.size(); i++) {
            if (std::abs(C[i] - expected[i]) > 1e-5f) {
                pass = false;
            }
        }
        std::cout << (pass ? "PASS" : "FAIL") << ": MatMul\n";
        
        // Test Softmax
        std::vector<float> S_input = {1.0f, 2.0f, 3.0f};
        std::vector<float> S_output(3);
        
        backend->Softmax(S_input.data(), S_output.data(), 3);
        
        float sum = 0.0f;
        for (auto v : S_output) sum += v;
        pass = std::abs(sum - 1.0f) < 1e-5f;
        std::cout << (pass ? "PASS" : "FAIL") << ": Softmax\n";
        
        backend->Cleanup();
    }
    
    // Test 2: KV Cache
    std::cout << "\n=== Test 2: KV Cache ===\n";
    {
        KVCacheEntry cache;
        cache.Resize(4096, 8, 128);
        
        if (cache.key_cache.size() == 4096 * 8 * 128 && 
            cache.value_cache.size() == 4096 * 8 * 128) {
            std::cout << "PASS: KV Cache resized correctly\n";
        } else {
            std::cout << "FAIL: KV Cache size mismatch\n";
        }
        
        cache.Reset();
        if (cache.seq_len == 0) {
            std::cout << "PASS: KV Cache reset\n";
        } else {
            std::cout << "FAIL: KV Cache not reset\n";
        }
    }
    
    // Test 3: Layer Initialization (small config)
    std::cout << "\n=== Test 3: Layer Initialization ===\n";
    {
        TransformerConfig config;
        config.hidden_size = 512;
        config.num_heads = 8;
        config.num_kv_heads = 4;
        config.head_dim = 64;
        config.intermediate_size = 1024;
        config.num_layers = 1;
        config.max_seq_len = 1024;
        config.vocab_size = 1000;
        
        LayerWeights weights;
        weights.q_proj.resize(config.hidden_size * config.num_heads * config.head_dim, 0.01f);
        weights.k_proj.resize(config.hidden_size * config.num_kv_heads * config.head_dim, 0.01f);
        weights.v_proj.resize(config.hidden_size * config.num_kv_heads * config.head_dim, 0.01f);
        weights.o_proj.resize(config.num_heads * config.head_dim * config.hidden_size, 0.01f);
        weights.gate_proj.resize(config.hidden_size * config.intermediate_size, 0.01f);
        weights.up_proj.resize(config.hidden_size * config.intermediate_size, 0.01f);
        weights.down_proj.resize(config.intermediate_size * config.hidden_size, 0.01f);
        weights.input_layernorm.resize(config.hidden_size, 1.0f);
        weights.post_attn_layernorm.resize(config.hidden_size, 1.0f);
        
        TransformerLayerRuntime layer;
        if (layer.Initialize(config, weights)) {
            std::cout << "PASS: Layer initialized\n";
            
            // Test forward pass
            std::vector<float> input(config.hidden_size, 0.5f);
            std::vector<float> output(config.hidden_size);
            KVCacheEntry kv_cache;
            kv_cache.Resize(config.max_seq_len, config.num_kv_heads, config.head_dim);
            
            TensorViewF32 input_view(input.data(), {config.hidden_size});
            TensorViewF32 output_view(output.data(), {config.hidden_size});
            
            std::cout << "Running forward pass...\n";
            auto start = std::chrono::high_resolution_clock::now();
            
            layer.Forward(input_view, output_view, kv_cache, 0);
            
            auto end = std::chrono::high_resolution_clock::now();
            double elapsed_ms = std::chrono::duration<double, std::milli>(end - start).count();
            
            std::cout << "PASS: Forward pass completed in " << std::fixed << std::setprecision(3) << elapsed_ms << " ms\n";
            
            layer.Cleanup();
        } else {
            std::cout << "FAIL: Layer initialization failed\n";
        }
    }
    
    std::cout << "\n========================================\n";
    std::cout << "All Tests Complete\n";
    std::cout << "========================================\n";
    
    return 0;
}
