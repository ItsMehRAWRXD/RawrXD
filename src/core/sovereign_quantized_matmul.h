// =============================================================================
// sovereign_quantized_matmul.h
// Quantized Matrix Multiplication Kernels
// Performs matmul directly on quantized weights without full dequantization
// =============================================================================

#ifndef SOVEREIGN_QUANTIZED_MATMUL_H
#define SOVEREIGN_QUANTIZED_MATMUL_H

#include <cstdint>
#include <memory>
#include <string>

namespace Sovereign {

// =============================================================================
// Quantized Weight Structure
// =============================================================================

struct QuantizedWeights {
    uint8_t* data;           // Raw quantized bytes
    uint64_t size;           // Size in bytes
    uint32_t n_elements;     // Number of elements
    uint32_t rows;           // Matrix rows
    uint32_t cols;           // Matrix cols
    int quant_type;          // 0=Q3_K, 1=Q6_K, etc.
};

// =============================================================================
// Quantized Matrix Operations
// =============================================================================

// Matrix-vector multiplication: y = weights * x
// weights: quantized [rows x cols]
// x: float input [cols]
// y: float output [rows]
void QuantizedMatVecMul(
    const QuantizedWeights& weights,
    const float* x,
    float* y
);

// Matrix-matrix multiplication: C = A * B
// A: quantized [M x K]
// B: float [K x N]
// C: float [M x N]
void QuantizedMatMul(
    const QuantizedWeights& A,
    const float* B,
    float* C,
    uint32_t M, uint32_t K, uint32_t N
);

// =============================================================================
// Q3_K_S Specific Operations
// =============================================================================

// Dequantize and multiply a single block
// block: 98 bytes of Q3_K_S data
// x: input vector segment (256 elements)
// result: accumulator for output
void Q3_K_S_BlockMatVec(
    const uint8_t* block,
    const float* x,
    float* result
);

// =============================================================================
// Q4_0 Specific Operations
// =============================================================================

// Matrix-vector multiplication for Q4_0 quantized weights
// weights: Q4_0 quantized data [rows x cols]
// x: float input [cols]
// y: float output [rows]
// rows: number of output rows
// cols: number of input columns
void QuantizedMatVecMul_Q4_0(
    const QuantizedWeights& weights,
    const float* x,
    float* y,
    uint32_t rows,
    uint32_t cols
);

// =============================================================================
// Q6_K Specific Operations
// =============================================================================

// Matrix-vector multiplication for Q6_K quantized weights
// weights: Q6_K quantized data [rows x cols]
// x: float input [cols]
// y: float output [rows]
// rows: number of output rows
// cols: number of input columns
void QuantizedMatVecMul_Q6_K(
    const QuantizedWeights& weights,
    const float* x,
    float* y,
    uint32_t rows,
    uint32_t cols
);

// =============================================================================
// Memory-Efficient Weight Storage
// =============================================================================

class QuantizedWeightBank {
public:
    QuantizedWeightBank();
    ~QuantizedWeightBank();
    
    // Add a quantized tensor
    bool AddTensor(
        const std::string& name,
        const uint8_t* data,
        uint64_t size,
        uint32_t rows,
        uint32_t cols,
        int quant_type
    );
    
    // Get quantized weights for operation
    const QuantizedWeights* GetWeights(const std::string& name) const;
    
    // Compute matvec: y = W * x
    bool ComputeMatVec(
        const std::string& weight_name,
        const float* x,
        float* y
    ) const;
    
    // Clear all weights
    void Clear();
    
    // Get total memory usage
    uint64_t GetTotalMemory() const;
    
private:
    struct Impl;
    std::unique_ptr<Impl> pImpl;
};

} // namespace Sovereign

#endif // SOVEREIGN_QUANTIZED_MATMUL_H
