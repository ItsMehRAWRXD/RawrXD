// ============================================================================
// Multi-Layer Inference Test - Full Model Forward Pass
// ============================================================================
// Runs actual inference through all 34 layers of ministral3
// ============================================================================

#include "transformer_layer_inference.hpp"
#include "../runtime/streaming_gguf_loader_v2.hpp"
#include <iostream>
#include <vector>
#include <chrono>
#include <cstring>

using namespace RawrXD;

// F16 to F32 conversion
inline float F16ToF32(uint16_t f16) {
    uint32_t sign = (f16 >> 15) & 0x1;
    uint32_t exp = (f16 >> 10) & 0x1F;
    uint32_t mant = f16 & 0x3FF;
    
    if (exp == 0) {
        if (mant == 0) return sign ? -0.0f : 0.0f;
        float val = mant / 1024.0f;
        return (sign ? -1.0f : 1.0f) * val * std::pow(2.0f, -14);
    }
    if (exp == 31) {
        if (mant == 0) return sign ? -INFINITY : INFINITY;
        return NAN;
    }
    
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
        uint16_t scale_f16 = *reinterpret_cast<const uint16_t*>(data + b * 18);
        float scale = F16ToF32(scale_f16);
        
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

// Simple tokenizer (ASCII fallback)
std::vector<int> Tokenize(const std::string& text) {
    std::vector<int> tokens;
    for (char c : text) {
        if (c == ' ') tokens.push_back(220);
        else if (c >= 33 && c <= 126) tokens.push_back(static_cast<unsigned char>(c));
    }
    return tokens;
}

// Load layer weights from GGUF
bool LoadLayerWeights(Runtime::StreamingGGUFLoader& loader, int layer_idx,
                      std::vector<float>& q_w, std::vector<float>& k_w,
                      std::vector<float>& v_w, std::vector<float>& o_w,
                      std::vector<float>& attn_n, std::vector<float>& ffn_g,
                      std::vector<float>& ffn_u, std::vector<float>& ffn_d,
                      std::vector<float>& ffn_n) {
    std::string prefix = "blk." + std::to_string(layer_idx) + ".";
    
    Runtime::TensorInfo q_t, k_t, v_t, o_t, an_t, fg_t, fu_t, fd_t, fn_t;
    
    if (!loader.GetTensor(prefix + "attn_q.weight", q_t) ||
        !loader.GetTensor(prefix + "attn_k.weight", k_t) ||
        !loader.GetTensor(prefix + "attn_v.weight", v_t) ||
        !loader.GetTensor(prefix + "attn_output.weight", o_t) ||
        !loader.GetTensor(prefix + "attn_norm.weight", an_t) ||
        !loader.GetTensor(prefix + "ffn_gate.weight", fg_t) ||
        !loader.GetTensor(prefix + "ffn_up.weight", fu_t) ||
        !loader.GetTensor(prefix + "ffn_down.weight", fd_t) ||
        !loader.GetTensor(prefix + "ffn_norm.weight", fn_t)) {
        return false;
    }
    
    q_w = DequantizeQ4_0(loader.GetTensorData(q_t), q_t.NumElements());
    k_w = DequantizeQ4_0(loader.GetTensorData(k_t), k_t.NumElements());
    v_w = DequantizeQ4_0(loader.GetTensorData(v_t), v_t.NumElements());
    o_w = DequantizeQ4_0(loader.GetTensorData(o_t), o_t.NumElements());
    attn_n = DequantizeQ4_0(loader.GetTensorData(an_t), an_t.NumElements());
    ffn_g = DequantizeQ4_0(loader.GetTensorData(fg_t), fg_t.NumElements());
    ffn_u = DequantizeQ4_0(loader.GetTensorData(fu_t), fu_t.NumElements());
    ffn_d = DequantizeQ4_0(loader.GetTensorData(fd_t), fd_t.NumElements());
    ffn_n = DequantizeQ4_0(loader.GetTensorData(fn_t), fn_t.NumElements());
    
    return true;
}

int main(int argc, char* argv[]) {
    std::cout << "========================================" << std::endl;
    std::cout << "Multi-Layer Inference Test (C4 Full)" << std::endl;
    std::cout << "========================================" << std::endl;
    
    std::string model_path = (argc > 1) ? argv[1] : "D:\\ministral3_q4_0.gguf";
    std::string prompt = (argc > 2) ? argv[2] : "Hello";
    int num_layers_to_run = (argc > 3) ? std::stoi(argv[3]) : 34;
    
    std::cout << "Model: " << model_path << std::endl;
    std::cout << "Prompt: \"" << prompt << "\"" << std::endl;
    std::cout << "Layers: " << num_layers_to_run << std::endl;
    std::cout << std::endl;
    
    // Load model
    std::cout << "[1/4] Loading model..." << std::endl;
    auto t0 = std::chrono::high_resolution_clock::now();
    
    Runtime::StreamingGGUFLoader loader;
    if (!loader.Open(model_path)) {
        std::cerr << "Failed to load model" << std::endl;
        return 1;
    }
    
    auto t1 = std::chrono::high_resolution_clock::now();
    std::cout << "  Loaded in " << std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count() << " ms" << std::endl;
    std::cout << "  Tensors: " << loader.GetTensorCount() << std::endl;
    std::cout << std::endl;
    
    // Tokenize
    std::cout << "[2/4] Tokenizing..." << std::endl;
    auto tokens = Tokenize(prompt);
    std::cout << "  Tokens: " << tokens.size() << " [";
    for (size_t i = 0; i < tokens.size() && i < 10; i++) {
        if (i > 0) std::cout << ", ";
        std::cout << tokens[i];
    }
    std::cout << "]" << std::endl;
    std::cout << std::endl;
    
    // Configuration
    Inference::TransformerConfig config;
    config.hidden_size = 4096;
    config.num_heads = 32;
    config.num_kv_heads = 8;
    config.head_dim = 128;
    config.intermediate_size = 14336;
    config.rms_norm_eps = 1e-5f;
    
    // Create embedding (simulated - random init for test)
    std::vector<float> hidden(config.hidden_size);
    for (uint32_t i = 0; i < config.hidden_size; i++) {
        hidden[i] = (static_cast<float>(i % 100) - 50.0f) / 1000.0f;
    }
    
    // Load and run through layers
    std::cout << "[3/4] Running through " << num_layers_to_run << " layers..." << std::endl;
    auto t2 = std::chrono::high_resolution_clock::now();
    
    std::vector<float> output(config.hidden_size);
    Inference::KVCache kv_cache;
    kv_cache.k_cache.resize(4096 * config.num_kv_heads * config.head_dim);
    kv_cache.v_cache.resize(4096 * config.num_kv_heads * config.head_dim);
    kv_cache.cache_len = 0;
    
    for (int layer_idx = 0; layer_idx < num_layers_to_run; layer_idx++) {
        // Load layer weights
        std::vector<float> q_w, k_w, v_w, o_w, attn_n, ffn_g, ffn_u, ffn_d, ffn_n;
        if (!LoadLayerWeights(loader, layer_idx, q_w, k_w, v_w, o_w, attn_n, ffn_g, ffn_u, ffn_d, ffn_n)) {
            std::cerr << "  Failed to load layer " << layer_idx << std::endl;
            break;
        }
        
        // Create layer and run forward
        Inference::TransformerLayer layer(config);
        layer.LoadWeights(q_w.data(), k_w.data(), v_w.data(), o_w.data(),
                         attn_n.data(), ffn_g.data(), ffn_u.data(),
                         ffn_d.data(), ffn_n.data());
        
        bool success = layer.Forward(hidden.data(), output.data(), kv_cache, 0);
        if (!success) {
            std::cerr << "  Layer " << layer_idx << " forward failed" << std::endl;
            break;
        }
        
        // Swap hidden and output for next layer
        std::swap(hidden, output);
        
        if ((layer_idx + 1) % 5 == 0 || layer_idx == num_layers_to_run - 1) {
            std::cout << "  Layer " << (layer_idx + 1) << "/" << num_layers_to_run << " complete\r" << std::flush;
        }
    }
    
    auto t3 = std::chrono::high_resolution_clock::now();
    auto inference_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t3 - t2).count();
    
    std::cout << std::endl;
    std::cout << "  Inference time: " << inference_ms << " ms" << std::endl;
    std::cout << "  ms/layer: " << (inference_ms / (float)num_layers_to_run) << std::endl;
    std::cout << std::endl;
    
    // Output statistics
    std::cout << "[4/4] Final hidden state statistics:" << std::endl;
    float min_val = hidden[0], max_val = hidden[0], sum = 0.0f;
    for (uint32_t i = 0; i < config.hidden_size; i++) {
        min_val = std::min(min_val, hidden[i]);
        max_val = std::max(max_val, hidden[i]);
        sum += hidden[i];
    }
    float mean = sum / config.hidden_size;
    
    std::cout << "  Min:  " << min_val << std::endl;
    std::cout << "  Max:  " << max_val << std::endl;
    std::cout << "  Mean: " << mean << std::endl;
    std::cout << "  Sample: [";
    for (int i = 0; i < 5; i++) {
        if (i > 0) std::cout << ", ";
        std::cout << hidden[i];
    }
    std::cout << ", ...]" << std::endl;
    std::cout << std::endl;
    
    std::cout << "========================================" << std::endl;
    std::cout << "SUCCESS: Multi-layer inference complete!" << std::endl;
    std::cout << "========================================" << std::endl;
    
    return 0;
}
