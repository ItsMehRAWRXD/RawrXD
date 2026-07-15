// ============================================================================
// Real Forward Pass Test - Actual Dequantization + Matmul
// ============================================================================
// Loads real Q4_0 weights, dequantizes, and runs simple forward pass
// ============================================================================

#include <iostream>
#include <vector>
#include <cstring>
#include <chrono>
#include <cmath>

// Include components
#include "../runtime/streaming_gguf_loader_v2.hpp"

using namespace RawrXD::Runtime;

// Q4_0 block structure
struct BlockQ4_0 {
    uint16_t d;      // F16 scale
    uint8_t qs[16];  // 4-bit weights (32 nibbles packed)
};

// F16 to F32 conversion
float F16ToF32(uint16_t f16) {
    uint32_t sign = (f16 >> 15) & 0x1;
    uint32_t exp = (f16 >> 10) & 0x1F;
    uint32_t mant = f16 & 0x3FF;
    
    uint32_t f32;
    if (exp == 0) {
        if (mant == 0) {
            f32 = sign << 31;
        } else {
            exp = 1;
            while ((mant & 0x400) == 0) {
                mant <<= 1;
                exp--;
            }
            mant &= 0x3FF;
            f32 = (sign << 31) | ((exp + 112) << 23) | (mant << 13);
        }
    } else if (exp == 31) {
        f32 = (sign << 31) | (0xFF << 23) | (mant << 13);
    } else {
        f32 = (sign << 31) | ((exp + 112) << 23) | (mant << 13);
    }
    
    float result;
    std::memcpy(&result, &f32, sizeof(result));
    return result;
}

// Dequantize Q4_0 tensor to F32
std::vector<float> DequantizeQ4_0(const uint8_t* data, uint64_t num_elements) {
    std::vector<float> result;
    result.reserve(num_elements);
    
    const BlockQ4_0* blocks = reinterpret_cast<const BlockQ4_0*>(data);
    uint64_t num_blocks = (num_elements + 31) / 32;
    
    for (uint64_t b = 0; b < num_blocks && result.size() < num_elements; b++) {
        const BlockQ4_0& block = blocks[b];
        float d = F16ToF32(block.d);
        
        // Dequantize 32 values
        for (int j = 0; j < 32 && result.size() < num_elements; j++) {
            int byte_idx = j / 2;
            int nibble = j % 2;
            uint8_t q = (nibble == 0) ? (block.qs[byte_idx] & 0x0F) : (block.qs[byte_idx] >> 4);
            result.push_back(d * (q - 8));  // Center around 0: -8 to +7
        }
    }
    
    return result;
}

// Simple matmul: C = A * B (A is MxK, B is KxN, C is MxN)
void MatMul(const float* A, const float* B, float* C, int M, int K, int N) {
    for (int m = 0; m < M; m++) {
        for (int n = 0; n < N; n++) {
            float sum = 0.0f;
            for (int k = 0; k < K; k++) {
                sum += A[m * K + k] * B[k * N + n];
            }
            C[m * N + n] = sum;
        }
    }
}

// Simple attention forward pass
void AttentionForward(const float* Q, const float* K, const float* V, 
                      float* output, int batch_size, int num_heads, int seq_len, int head_dim) {
    // Simplified: just compute Q*K^T and softmax (omitted for brevity)
    // For now, just copy Q to output as placeholder
    std::memcpy(output, Q, batch_size * num_heads * seq_len * head_dim * sizeof(float));
}

int main(int argc, char* argv[]) {
    std::string model_path = (argc > 1) ? argv[1] : "d:\\ministral3_q4_0.gguf";
    
    std::cout << "========================================" << std::endl;
    std::cout << "Real Forward Pass Test" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Model: " << model_path << std::endl << std::endl;
    
    // Load model
    std::cout << "[1/4] Loading model..." << std::endl;
    auto t0 = std::chrono::high_resolution_clock::now();
    
    StreamingGGUFLoader loader;
    if (!loader.Open(model_path)) {
        std::cerr << "Failed to load model" << std::endl;
        return 1;
    }
    
    auto t1 = std::chrono::high_resolution_clock::now();
    std::cout << "  Loaded in " << std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count() << " ms" << std::endl;
    std::cout << "  Tensors: " << loader.GetTensorCount() << std::endl;
    std::cout << "  Data offset: " << loader.GetTensorDataOffset() << std::endl << std::endl;
    
    // Load and dequantize Q weights from layer 0
    std::cout << "[2/4] Loading and dequantizing weights..." << std::endl;
    
    TensorInfo q_info, k_info, v_info;
    if (!loader.GetTensor("blk.0.attn_q.weight", q_info)) {
        std::cerr << "Failed to get Q weights" << std::endl;
        return 1;
    }
    if (!loader.GetTensor("blk.0.attn_k.weight", k_info)) {
        std::cerr << "Failed to get K weights" << std::endl;
        return 1;
    }
    if (!loader.GetTensor("blk.0.attn_v.weight", v_info)) {
        std::cerr << "Failed to get V weights" << std::endl;
        return 1;
    }
    
    std::cout << "  Q weight: [" << q_info.shape[0] << ", " << q_info.shape[1] << "]" << std::endl;
    std::cout << "  K weight: [" << k_info.shape[0] << ", " << k_info.shape[1] << "]" << std::endl;
    std::cout << "  V weight: [" << v_info.shape[0] << ", " << v_info.shape[1] << "]" << std::endl;
    
    // Get raw data pointers
    const uint8_t* q_data = loader.GetTensorData(q_info);
    const uint8_t* k_data = loader.GetTensorData(k_info);
    const uint8_t* v_data = loader.GetTensorData(v_info);
    
    // Dequantize
    auto t2 = std::chrono::high_resolution_clock::now();
    
    std::cout << "\n  Dequantizing Q weights..." << std::endl;
    auto q_dequant = DequantizeQ4_0(q_data, q_info.shape[0] * q_info.shape[1]);
    
    std::cout << "  Dequantizing K weights..." << std::endl;
    auto k_dequant = DequantizeQ4_0(k_data, k_info.shape[0] * k_info.shape[1]);
    
    std::cout << "  Dequantizing V weights..." << std::endl;
    auto v_dequant = DequantizeQ4_0(v_data, v_info.shape[0] * v_info.shape[1]);
    
    auto t3 = std::chrono::high_resolution_clock::now();
    std::cout << "  Dequantized in " << std::chrono::duration_cast<std::chrono::milliseconds>(t3 - t2).count() << " ms" << std::endl;
    std::cout << "  Q dequantized size: " << q_dequant.size() << " floats" << std::endl;
    std::cout << "  K dequantized size: " << k_dequant.size() << " floats" << std::endl;
    std::cout << "  V dequantized size: " << v_dequant.size() << " floats" << std::endl;
    
    // Show sample values
    std::cout << "\n  Sample Q values (first 8): ";
    for (int i = 0; i < 8 && i < q_dequant.size(); i++) {
        std::cout << q_dequant[i] << " ";
    }
    std::cout << std::endl;
    
    // Run simple forward pass
    std::cout << "\n[3/4] Running forward pass..." << std::endl;
    
    // Create dummy input (1 token, 4096 dims)
    std::vector<float> input(4096, 1.0f);
    
    // Project input to Q, K, V
    std::vector<float> q_proj(4096);
    std::vector<float> k_proj(1024);
    std::vector<float> v_proj(1024);
    
    auto t4 = std::chrono::high_resolution_clock::now();
    
    // Q projection: input [1, 4096] * Q_weight [4096, 4096] = [1, 4096]
    MatMul(input.data(), q_dequant.data(), q_proj.data(), 1, 4096, 4096);
    
    // K projection: input [1, 4096] * K_weight [4096, 1024] = [1, 1024]
    MatMul(input.data(), k_dequant.data(), k_proj.data(), 1, 4096, 1024);
    
    // V projection: input [1, 4096] * V_weight [4096, 1024] = [1, 1024]
    MatMul(input.data(), v_dequant.data(), v_proj.data(), 1, 4096, 1024);
    
    auto t5 = std::chrono::high_resolution_clock::now();
    auto matmul_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t5 - t4).count();
    
    std::cout << "  Matmul completed in " << matmul_ms << " ms" << std::endl;
    std::cout << "  Q projection (first 8): ";
    for (int i = 0; i < 8 && i < q_proj.size(); i++) {
        std::cout << q_proj[i] << " ";
    }
    std::cout << std::endl;
    
    // Results
    std::cout << "\n========================================" << std::endl;
    std::cout << "Results" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Model: ministral3_q4_0.gguf" << std::endl;
    std::cout << "Layers loaded: 1 (layer 0)" << std::endl;
    std::cout << "Weights dequantized: Q, K, V" << std::endl;
    std::cout << "Forward pass: Q/K/V projections" << std::endl;
    std::cout << std::endl;
    std::cout << "Performance:" << std::endl;
    std::cout << "  Model load:     " << std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count() << " ms" << std::endl;
    std::cout << "  Dequantization: " << std::chrono::duration_cast<std::chrono::milliseconds>(t3 - t2).count() << " ms" << std::endl;
    std::cout << "  Matmul (3x):    " << matmul_ms << " ms" << std::endl;
    std::cout << "  Total:          " << std::chrono::duration_cast<std::chrono::milliseconds>(t5 - t0).count() << " ms" << std::endl;
    std::cout << "========================================" << std::endl;
    
    return 0;
}
