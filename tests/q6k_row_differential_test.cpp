/**
 * @file q6k_row_differential_test.cpp
 * @brief Find first divergent row between LinearW path and direct kernel call for Q6_K
 */

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#include "deep2/QuantKernelRegistry.hpp"
#include <iostream>
#include <fstream>
#include <vector>
#include <cmath>
#include <cstring>
#include <iomanip>

using namespace Deep2;

// Copy of kernel's FP16 to float conversion
static inline float kernel_q6k_f16(uint16_t f16) {
    uint32_t sign = (f16 >> 15) & 1;
    uint32_t exp = (f16 >> 10) & 0x1F;
    uint32_t frac = f16 & 0x3FF;
    if (exp == 0) {
        if (frac == 0) return sign ? -0.0f : 0.0f;
        while ((frac & 0x400) == 0) {
            frac <<= 1;
            exp--;
        }
        exp++;
        frac &= 0x3FF;
    }
    if (exp == 31) {
        uint32_t bits = sign | 0x7F800000 | (frac << 13);
        return reinterpret_cast<float&>(bits);
    }
    uint32_t bits = sign | ((exp + 127 - 15) << 23) | (frac << 13);
    return reinterpret_cast<float&>(bits);
}

// Copy of kernel's Q6_K dequantization for comparison
static inline bool kernel_q6k_dequant_block(const uint8_t* block, float* dst) {
    if (!block || !dst) return false;
    uint16_t d16; std::memcpy(&d16, block + 208, sizeof(d16));
    const float d = kernel_q6k_f16(d16);
    if (!std::isfinite(d)) return false;

    const uint8_t* ql = block + 0;
    const uint8_t* qh = block + 128;
    const int8_t* scales = reinterpret_cast<const int8_t*>(block + 192);

    for (int j = 0; j < 16; ++j) {
        const float d_scales = d * static_cast<float>(scales[j]);
        for (int l = 0; l < 16; ++l) {
            const int idx = j * 16 + l;
            const int ql_idx = idx / 2;
            const int qh_idx = idx / 4;
            const int shift = (idx % 2) * 4;
            const int ql_val = (ql[ql_idx] >> shift) & 0xF;
            const int qh_val = (qh[qh_idx] >> ((idx % 4) * 2)) & 0x3;
            const int8_t q = static_cast<int8_t>((ql_val | (qh_val << 4)) - 32);
            dst[idx] = d_scales * static_cast<float>(q);
        }
    }
    return true;
}

// Reference Q6_K dequantization matching llama.cpp exactly
static inline bool q6k_dequant_reference(const uint8_t* block, float* dst) {
    if (!block || !dst) return false;
    
    // block_q6_K layout per llama.cpp: ql[128], qh[64], scales[16], d[2 bytes]
    uint16_t d16; std::memcpy(&d16, block + 208, sizeof(d16));
    
    // Convert FP16 to float
    uint32_t bits = ((d16 & 0x8000) << 16) | (((d16 & 0x7C00) + 0x1C000) << 13) | ((d16 & 0x03FF) << 13);
    float d = *reinterpret_cast<float*>(&bits);
    if (!std::isfinite(d)) return false;

    const uint8_t* ql = block + 0;
    const uint8_t* qh = block + 128;
    const int8_t* scales = reinterpret_cast<const int8_t*>(block + 192);

    // llama.cpp dequantize_row_q6_K: 16 scale groups × 16 values
    for (int j = 0; j < 16; ++j) {
        float d_scales = d * static_cast<float>(scales[j]);
        for (int l = 0; l < 16; ++l) {
            int idx = j * 16 + l;
            int ql_idx = idx / 2;
            int qh_idx = idx / 4;
            int shift = (idx % 2) * 4;
            int ql_val = (ql[ql_idx] >> shift) & 0xF;
            int qh_val = (qh[qh_idx] >> (shift * 2)) & 0x3;
            int8_t q = static_cast<int8_t>((ql_val | (qh_val << 4)) - 32);
            dst[idx] = d_scales * static_cast<float>(q);
        }
    }
    return true;
}

// Reference FP32 dot product
static inline float fp32_dot(const float* w, const float* x, size_t cols) {
    double sum = 0.0;
    for (size_t i = 0; i < cols; ++i) {
        sum += static_cast<double>(w[i]) * static_cast<double>(x[i]);
    }
    return static_cast<float>(sum);
}

// Compare two kernel implementations row by row
int main(int argc, char** argv) {
    // Load the model to get actual Q6_K weights
    const char* modelPath = "F:\\rawrxd\\model_solo\\tinyllama_fresh.gguf";
    
    // For now, create a minimal test with known Q6_K weight pattern
    // We'll test the kernel implementations directly
    
    std::cout << "=== Q6_K Row-Level Differential Test ===\n\n";
    
    // Test case: 256 cols (exactly 1 block)
    size_t rows = 4;
    size_t cols = 256;
    size_t blocksPerRow = 1;
    
    // Create synthetic Q6_K weight data
    std::vector<uint8_t> weightData(rows * 210);
    std::vector<float> input(cols);
    
    // Initialize with known pattern
    for (size_t r = 0; r < rows; ++r) {
        uint8_t* block = weightData.data() + r * 210;
        // ql: 128 bytes
        for (int i = 0; i < 128; ++i) block[i] = static_cast<uint8_t>((r * 128 + i) & 0xFF);
        // qh: 64 bytes
        for (int i = 0; i < 64; ++i) block[128 + i] = static_cast<uint8_t>((r * 64 + i) & 0xFF);
        // scales: 16 int8
        for (int i = 0; i < 16; ++i) block[192 + i] = static_cast<int8_t>(i + 1);
        // d: FP16 value (1.0)
        uint16_t d16 = 0x3C00; // FP16 1.0
        std::memcpy(block + 208, &d16, 2);
    }
    
    // Initialize input
    for (size_t i = 0; i < cols; ++i) input[i] = static_cast<float>(i) * 0.01f;
    
    // Get kernels
    auto& reg = QuantKernelRegistry::Instance();
    if (reg.GetRegisteredCount() == 0) reg.Initialize();
    
    auto scalarKernel = reg.GetGEMV((int)GGMLType::GGML_TYPE_Q6_K);
    
    if (!scalarKernel) {
        std::cerr << "ERROR: No Q6_K kernel registered\n";
        return 1;
    }
    
    // Test 1: Direct kernel call (full tensor)
    std::cout << "Test 1: Direct kernel call (full tensor)\n";
    std::vector<float> outputDirect(rows);
    scalarKernel(weightData.data(), input.data(), outputDirect.data(), rows, cols);
    
    // DEBUG: Compare dequantization
    std::cout << "\nDEBUG: Dequantization comparison for row 0:\n";
    std::vector<float> dequantKernel(256), dequantRef(256);
    kernel_q6k_dequant_block(weightData.data(), dequantKernel.data());
    q6k_dequant_reference(weightData.data(), dequantRef.data());
    for (int i = 0; i < 16; ++i) {
        if (dequantKernel[i] != dequantRef[i]) {
            std::cout << "  [" << i << "] kernel=" << dequantKernel[i] << " ref=" << dequantRef[i] << " DIFF\n";
        }
    }
    for (int i = 240; i < 256; ++i) {
        if (dequantKernel[i] != dequantRef[i]) {
            std::cout << "  [" << i << "] kernel=" << dequantKernel[i] << " ref=" << dequantRef[i] << " DIFF\n";
        }
    }
    
    std::cout << "Direct kernel output:\n";
    for (size_t r = 0; r < rows; ++r) {
        std::cout << "  Row " << r << ": " << outputDirect[r] << "\n";
    }
    
    // Test 2: Reference dequant + FP32 dot
    std::cout << "\nTest 2: Reference dequant + FP32 dot (per row)\n";
    std::vector<float> outputRef(rows);
    std::vector<float> dequant(256);
    
    for (size_t r = 0; r < rows; ++r) {
        const uint8_t* block = weightData.data() + r * 210;
        q6k_dequant_reference(block, dequant.data());
        outputRef[r] = fp32_dot(dequant.data(), input.data(), cols);
        std::cout << "  Row " << r << ": " << outputRef[r] << " (diff: " << std::abs(outputDirect[r] - outputRef[r]) << ")\n";
    }
    
    // Test 3: Scalar kernel with row slicing (simulating LinearW_Range)
    std::cout << "\nTest 3: Scalar kernel with row slicing (LinearW_Range style)\n";
    for (size_t startRow = 0; startRow < rows; ++startRow) {
        for (size_t endRow = startRow + 1; endRow <= rows; ++endRow) {
            size_t testRows = endRow - startRow;
            std::vector<float> outputSlice(testRows);
            
            // Calculate row bytes for Q6_K
            size_t blockSize = 210; // Q6_K block size
            size_t elemsPerBlock = 256;
            size_t blocksPerRow = (cols + elemsPerBlock - 1) / elemsPerBlock;
            size_t rowBytes = blocksPerRow * blockSize;
            
            const uint8_t* rowWeights = weightData.data() + startRow * rowBytes;
            
            scalarKernel(rowWeights, input.data(), outputSlice.data(), testRows, cols);
            
            std::cout << "  Rows [" << startRow << ":" << endRow << "): ";
            for (size_t i = 0; i < testRows; ++i) {
                float expected = outputRef[startRow + i];
                float diff = std::abs(outputSlice[i] - expected);
                std::cout << "Row " << (startRow + i) << "=" << outputSlice[i] 
                          << " (exp=" << expected << " diff=" << diff << ") ";
            }
            std::cout << "\n";
        }
    }
    
    // Test 4: Compare LinearW_Range geometry calculations
    std::cout << "\nTest 4: Geometry verification\n";
    size_t blockSize = 210;
    size_t elemsPerBlock = 256;
    size_t blocksPerRow4 = (cols + elemsPerBlock - 1) / elemsPerBlock;
    size_t rowBytes = blocksPerRow4 * blockSize;
    
    std::cout << "  cols=" << cols << "\n";
    std::cout << "  blockSize=" << blockSize << "\n";
    std::cout << "  elemsPerBlock=" << elemsPerBlock << "\n";
    std::cout << "  blocksPerRow=" << blocksPerRow4 << "\n";
    std::cout << "  rowBytes=" << rowBytes << "\n";
    std::cout << "  total weight bytes=" << weightData.size() << "\n";
    std::cout << "  expected total=" << (rows * rowBytes) << "\n";
    
    // Verify block geometry from registry
    auto geom = reg.GetGeometry((int)GGMLType::GGML_TYPE_Q6_K);
    std::cout << "  Registry geom: blockSize=" << geom.blockSize 
              << " elemsPerBlock=" << geom.elemsPerBlock << "\n";
    
    return 0;
}