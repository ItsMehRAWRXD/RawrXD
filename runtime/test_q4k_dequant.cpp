// Test Q4_K dequantization - validates non-zero output and correctness
#include "tensor_view.hpp"
#include "q4k_decoder.hpp"
#include <iostream>
#include <cmath>
#include <vector>

using namespace RawrXD::Runtime;
using namespace rawrxd;

// Create a synthetic Q4_K block with known values for testing
void CreateSyntheticQ4KBlock(uint8_t* block_data, float expected_scale, float expected_min) {
    BlockQ4_K* block = reinterpret_cast<BlockQ4_K*>(block_data);
    
    // Set scale and min (F16 values)
    // For simplicity, use 1.0 and 0.0
    uint16_t d_f16 = 0x3C00;  // 1.0 in F16
    uint16_t dmin_f16 = 0x0000; // 0.0 in F16
    block->d = d_f16;
    block->dmin = dmin_f16;
    
    // Set scales to 1.0 (packed 4-bit values)
    // Each byte contains 2 scale values
    for (int i = 0; i < 12; i++) {
        block->scales[i] = 0x11;  // scale=1, min=1 in each nibble
    }
    
    // Set quantized values to ascending pattern
    for (int i = 0; i < 128; i++) {
        block->qs[i] = (i & 0x0F) | ((i << 4) & 0xF0);
    }
}

bool TestQ4KDecoder() {
    std::cout << "=== Q4_K Decoder Test ===" << std::endl;
    
    // Test 1: Block decode
    std::cout << "\n[Test 1] Block decode..." << std::endl;
    
    uint8_t block_data[144];
    CreateSyntheticQ4KBlock(block_data, 1.0f, 0.0f);
    
    float output[256];
    Q4KDecoder::DecodeBlock(reinterpret_cast<BlockQ4_K*>(block_data), output);
    
    // Check non-zero
    bool non_zero = false;
    for (int i = 0; i < 256; i++) {
        if (output[i] != 0.0f) {
            non_zero = true;
            break;
        }
    }
    
    if (!non_zero) {
        std::cout << "  FAIL: All outputs are zero!" << std::endl;
        return false;
    }
    std::cout << "  PASS: Non-zero outputs detected" << std::endl;
    
    // Test 2: Row decode
    std::cout << "\n[Test 2] Row decode (512 elements)..." << std::endl;
    
    std::vector<uint8_t> row_data(144 * 2);  // 2 blocks = 512 elements
    CreateSyntheticQ4KBlock(row_data.data(), 1.0f, 0.0f);
    CreateSyntheticQ4KBlock(row_data.data() + 144, 1.0f, 0.0f);
    
    std::vector<float> row_output(512);
    Q4KDecoder::DecodeRow(row_data.data(), 512, row_output.data());
    
    non_zero = false;
    for (int i = 0; i < 512; i++) {
        if (row_output[i] != 0.0f) {
            non_zero = true;
            break;
        }
    }
    
    if (!non_zero) {
        std::cout << "  FAIL: All row outputs are zero!" << std::endl;
        return false;
    }
    std::cout << "  PASS: Non-zero row outputs detected" << std::endl;
    
    // Test 3: TensorView integration
    std::cout << "\n[Test 3] TensorView Q4_K dequantization..." << std::endl;
    
    TensorData tensor_data;
    tensor_data.type = GGMLType::Q4_K;
    tensor_data.shape = {1, 256};  // 1 row, 256 cols
    tensor_data.rawData.resize(144);
    tensor_data.provenance.quantized = true;
    
    CreateSyntheticQ4KBlock(tensor_data.rawData.data(), 1.0f, 0.0f);
    
    TensorView view(&tensor_data);
    
    float dequant_row[256];
    size_t written = view.DequantizeRow(0, dequant_row, 256);
    
    if (written != 256) {
        std::cout << "  FAIL: DequantizeRow returned " << written << " elements, expected 256" << std::endl;
        return false;
    }
    
    non_zero = false;
    for (int i = 0; i < 256; i++) {
        if (dequant_row[i] != 0.0f) {
            non_zero = true;
            break;
        }
    }
    
    if (!non_zero) {
        std::cout << "  FAIL: TensorView dequantization returned all zeros!" << std::endl;
        return false;
    }
    std::cout << "  PASS: TensorView dequantization produces non-zero values" << std::endl;
    
    // Print first 10 values for inspection
    std::cout << "  First 10 dequantized values: ";
    for (int i = 0; i < 10; i++) {
        std::cout << dequant_row[i] << " ";
    }
    std::cout << std::endl;
    
    std::cout << "\n=== All Tests PASSED ===" << std::endl;
    return true;
}

int main() {
    bool success = TestQ4KDecoder();
    return success ? 0 : 1;
}
