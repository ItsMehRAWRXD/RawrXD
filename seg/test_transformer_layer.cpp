// ============================================================================
// Test: Transformer Layer with Real Weights
// ============================================================================

#include "transformer_layer_inference.hpp"
#include "../runtime/streaming_gguf_loader_v2.hpp"
#include "../runtime/tensor_view.hpp"
#include <iostream>
#include <iomanip>
#include <chrono>

using namespace RawrXD;

// F16 to F32 conversion helper
inline float F16ToF32(uint16_t f16) {
    uint32_t sign = (f16 >> 15) & 0x1;
    uint32_t exp = (f16 >> 10) & 0x1F;
    uint32_t mant = f16 & 0x3FF;
    
    if (exp == 0) {
        if (mant == 0) return sign ? -0.0f : 0.0f;
        // Subnormal
        float val = mant / 1024.0f;
        return (sign ? -1.0f : 1.0f) * val * std::pow(2.0f, -14);
    }
    if (exp == 31) {
        if (mant == 0) return sign ? -INFINITY : INFINITY;
        return NAN;
    }
    
    // Normal
    float val = 1.0f + mant / 1024.0f;
    int32_t exp32 = exp - 15 + 127;
    uint32_t f32 = (sign << 31) | (exp32 << 23) | (mant << 13);
    float result;
    std::memcpy(&result, &f32, sizeof(result));
    return result;
}

// Dequantize Q4_0 to float
std::vector<float> DequantizeQ4_0(const uint8_t* data, size_t num_weights) {
    std::vector<float> result;
    result.reserve(num_weights);
    
    size_t blocks = num_weights / 32;
    for (size_t b = 0; b < blocks; b++) {
        // Read scale (F16)
        uint16_t scale_f16 = *reinterpret_cast<const uint16_t*>(data + b * 18);
        float scale = F16ToF32(scale_f16);
        
        // Read 32 nibbles (16 bytes)
        for (int i = 0; i < 16; i++) {
            uint8_t byte = data[b * 18 + 2 + i];
            int8_t nibble0 = (byte & 0x0F) - 8;
            int8_t nibble1 = ((byte >> 4) & 0x0F) - 8;
            result.push_back(nibble0 * scale);
            result.push_back(nibble1 * scale);
        }
    }
    return result;
}

// Dequantize Q4_K to float
std::vector<float> DequantizeQ4_K(const uint8_t* data, size_t num_weights) {
    std::vector<float> result;
    result.reserve(num_weights);
    
    size_t blocks = num_weights / 256;
    for (size_t b = 0; b < blocks; b++) {
        const uint8_t* block = data + b * 144;
        
        // Read scales and mins
        uint16_t scale_f16 = *reinterpret_cast<const uint16_t*>(block);
        uint16_t min_f16 = *reinterpret_cast<const uint16_t*>(block + 2);
        float scale = F16ToF32(scale_f16);
        float min_val = F16ToF32(min_f16);
        
        // Read 128 nibbles (64 bytes)
        for (int i = 0; i < 64; i++) {
            uint8_t byte = block[4 + i];
            int8_t nibble0 = (byte & 0x0F);
            int8_t nibble1 = ((byte >> 4) & 0x0F);
            result.push_back(nibble0 * scale + min_val);
            result.push_back(nibble1 * scale + min_val);
        }
    }
    return result;
}

int main() {
    std::cout << "=== Transformer Layer Test (Real Weights) ===\n\n";
    
    // Configuration for ministral3
    Inference::TransformerConfig config;
    config.hidden_size = 4096;
    config.num_heads = 32;
    config.num_kv_heads = 8;  // GQA
    config.head_dim = 128;
    config.intermediate_size = 14336;
    config.rms_norm_eps = 1e-5f;
    
    // Load model
    Runtime::StreamingGGUFLoader loader;
    if (!loader.Open("D:\\ministral3_q4_0.gguf")) {
        std::cerr << "Failed to load model\n";
        return 1;
    }
    
    std::cout << "Model loaded: " << loader.GetTensorCount() << " tensors\n\n";
    
    // Load layer 0 weights
    std::cout << "Loading Layer 0 weights...\n";
    
    // Attention weights
    Runtime::TensorInfo q_w, k_w, v_w, o_w, attn_n;
    Runtime::TensorInfo ffn_g, ffn_u, ffn_d, ffn_n;
    
    if (!loader.GetTensor("blk.0.attn_q.weight", q_w) ||
        !loader.GetTensor("blk.0.attn_k.weight", k_w) ||
        !loader.GetTensor("blk.0.attn_v.weight", v_w) ||
        !loader.GetTensor("blk.0.attn_output.weight", o_w) ||
        !loader.GetTensor("blk.0.attn_norm.weight", attn_n) ||
        !loader.GetTensor("blk.0.ffn_gate.weight", ffn_g) ||
        !loader.GetTensor("blk.0.ffn_up.weight", ffn_u) ||
        !loader.GetTensor("blk.0.ffn_down.weight", ffn_d) ||
        !loader.GetTensor("blk.0.ffn_norm.weight", ffn_n)) {
        std::cerr << "Failed to load some weights\n";
        return 1;
    }
    
    // Dequantize weights (ministral3 is Q4_0)
    std::cout << "Dequantizing weights...\n";
    auto start = std::chrono::high_resolution_clock::now();
    
    auto q_f32 = DequantizeQ4_0(loader.GetTensorData(q_w), q_w.NumElements());
    auto k_f32 = DequantizeQ4_0(loader.GetTensorData(k_w), k_w.NumElements());
    auto v_f32 = DequantizeQ4_0(loader.GetTensorData(v_w), v_w.NumElements());
    auto o_f32 = DequantizeQ4_0(loader.GetTensorData(o_w), o_w.NumElements());
    auto attn_n_f32 = DequantizeQ4_0(loader.GetTensorData(attn_n), attn_n.NumElements());
    auto ffn_g_f32 = DequantizeQ4_0(loader.GetTensorData(ffn_g), ffn_g.NumElements());
    auto ffn_u_f32 = DequantizeQ4_0(loader.GetTensorData(ffn_u), ffn_u.NumElements());
    auto ffn_d_f32 = DequantizeQ4_0(loader.GetTensorData(ffn_d), ffn_d.NumElements());
    auto ffn_n_f32 = DequantizeQ4_0(loader.GetTensorData(ffn_n), ffn_n.NumElements());
    
    auto end = std::chrono::high_resolution_clock::now();
    auto dequant_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    std::cout << "Dequantization: " << dequant_ms << " ms\n\n";
    
    // Create layer
    Inference::TransformerLayer layer(config);
    layer.LoadWeights(q_f32.data(), k_f32.data(), v_f32.data(), o_f32.data(),
                      attn_n_f32.data(), ffn_g_f32.data(), ffn_u_f32.data(),
                      ffn_d_f32.data(), ffn_n_f32.data());
    
    // Create KV cache
    Inference::KVCache kv_cache;
    kv_cache.k_cache.resize(4096 * config.num_kv_heads * config.head_dim);
    kv_cache.v_cache.resize(4096 * config.num_kv_heads * config.head_dim);
    kv_cache.cache_len = 0;
    
    // Create input (simulated embedding output)
    std::vector<float> input(config.hidden_size);
    std::vector<float> output(config.hidden_size);
    
    // Initialize with small random values
    for (uint32_t i = 0; i < config.hidden_size; i++) {
        input[i] = (static_cast<float>(i % 100) - 50.0f) / 1000.0f;
    }
    
    std::cout << "Running transformer layer forward pass...\n";
    std::cout << "Input sample: " << std::fixed << std::setprecision(4);
    for (int i = 0; i < 5; i++) {
        std::cout << input[i] << " ";
    }
    std::cout << "\n\n";
    
    // Run forward pass
    start = std::chrono::high_resolution_clock::now();
    
    bool success = layer.Forward(input.data(), output.data(), kv_cache, 0);
    
    end = std::chrono::high_resolution_clock::now();
    auto forward_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    
    if (!success) {
        std::cerr << "Forward pass failed\n";
        return 1;
    }
    
    std::cout << "Forward pass completed in " << forward_ms << " ms\n";
    std::cout << "KV cache length: " << kv_cache.cache_len << "\n\n";
    
    // Output sample
    std::cout << "Output sample:\n";
    for (int i = 0; i < 10; i++) {
        std::cout << "  [" << i << "] " << output[i] << "\n";
    }
    std::cout << "\n";
    
    // Statistics
    float min_val = output[0], max_val = output[0], sum = 0.0f;
    for (uint32_t i = 0; i < config.hidden_size; i++) {
        min_val = std::min(min_val, output[i]);
        max_val = std::max(max_val, output[i]);
        sum += output[i];
    }
    float mean = sum / config.hidden_size;
    
    std::cout << "Output statistics:\n";
    std::cout << "  Min:  " << min_val << "\n";
    std::cout << "  Max:  " << max_val << "\n";
    std::cout << "  Mean: " << mean << "\n";
    std::cout << "\n";
    
    // Test second token (with KV cache)
    std::cout << "=== Second Token (with KV cache) ===\n";
    
    // New input
    for (uint32_t i = 0; i < config.hidden_size; i++) {
        input[i] = (static_cast<float>((i + 1) % 100) - 50.0f) / 1000.0f;
    }
    
    start = std::chrono::high_resolution_clock::now();
    success = layer.Forward(input.data(), output.data(), kv_cache, 1);
    end = std::chrono::high_resolution_clock::now();
    forward_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    
    if (!success) {
        std::cerr << "Second forward pass failed\n";
        return 1;
    }
    
    std::cout << "Second token forward: " << forward_ms << " ms\n";
    std::cout << "KV cache length: " << kv_cache.cache_len << "\n";
    std::cout << "Output sample: ";
    for (int i = 0; i < 5; i++) {
        std::cout << output[i] << " ";
    }
    std::cout << "\n\n";
    
    std::cout << "=== SUCCESS: Full transformer layer working! ===\n";
    return 0;
}
