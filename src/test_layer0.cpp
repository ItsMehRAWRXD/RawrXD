#include "Deep2Engine.hpp"
#include <iostream>
#include <vector>
#include <xmmintrin.h>
#include <pmmintrin.h>

int main(int argc, char* argv[]) {
    _mm_setcsr(_mm_getcsr() | 0x8040);
    
    if (argc < 2) {
        std::cerr << "Usage: test_move10_simple <model.gguf>\n";
        return 1;
    }
    
    Deep2Engine engine;
    if (!engine.Initialize(argv[1])) {
        std::cerr << "Failed to initialize engine\n";
        return 1;
    }
    
    std::cout << "=== Simple Layer 0 Test ===\n";
    
    // Test just the first layer's QKV dequantization
    auto qkv = engine.rom.findTensor("blk.0.attn_qkv.weight");
    if (!qkv) {
        std::cerr << "QKV tensor not found\n";
        return 1;
    }
    
    deep2::DequantizedTensor qkvDq;
    if (!engine.dequantTensor(*qkv, qkvDq)) {
        std::cerr << "Failed to dequantize QKV\n";
        return 1;
    }
    
    std::cout << "QKV dequantized: " << qkvDq.rows << "x" << qkvDq.cols << "\n";
    
    // Test gemvFloat
    std::vector<float> x(qkvDq.cols, 1.0f);
    std::vector<float> y(qkvDq.rows, 0.0f);
    engine.gemvFloat(qkvDq.data.data(), x.data(), y.data(), qkvDq.rows, qkvDq.cols);
    
    float sum = 0;
    for (float v : y) sum += v;
    std::cout << "gemvFloat sum: " << sum << "\n";
    
    std::cout << "Test passed!\n";
    return 0;
}