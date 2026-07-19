/*===========================================================================
 * Deep2_Q4KM.hpp
 * 
 * Q4_K_M quantized matrix operations for Deep2Bridge
 * 
 * Integrates Sovereign_Q4K_Dequant.asm kernels with Deep2 inference pipeline
 * 
 * Performance targets:
 *   - Dequantization: ~50-100 GB/s memory bandwidth
 *   - Fused Q4xFP32 GEMV: 15-25 TPS (vs 4 TPS FP32)
 *   - With threading: 30-60 TPS
 *===========================================================================*/

#pragma once

#include <cstdint>
#include <cstddef>

// External MASM functions
extern "C" {

/**
 * Dequantize Q4_K_M blocks to FP32
 * @param pBlocks Array of Q4_K_M blocks (144 bytes each)
 * @param pDest Destination buffer (must hold num_blocks * 256 floats)
 * @param num_blocks Number of blocks to dequantize
 * @return Number of values dequantized (num_blocks * 256)
 */
uint64_t Sovereign_Q4KM_DequantRange(
    const uint8_t* pBlocks,
    float* pDest,
    uint64_t num_blocks
);

/**
 * Dequantize single block (AVX-512 optimized)
 * @param pBlock Single Q4_K_M block (144 bytes)
 * @param pDest Destination buffer (256 floats)
 * @return 256 (values processed)
 */
uint64_t Sovereign_Q4KM_DequantBlock_AVX512(
    const uint8_t* pBlock,
    float* pDest
);

/**
 * Dequantize single block (AVX2 optimized)
 */
uint64_t Sovereign_Q4KM_DequantBlock_AVX2(
    const uint8_t* pBlock,
    float* pDest
);

/**
 * Extract single sub-block (16 values) - scalar fallback
 */
void Sovereign_Q4KM_ExtractSubBlock_Scalar(
    const uint8_t* pBlock,
    float* pDest,
    uint64_t sub_block_index
);

} // extern "C"

namespace RawrXD {
namespace Deep2 {

/*===========================================================================
 * Q4_K_M Block Structure (GGUF format)
 *===========================================================================*/
struct Q4KMBlock {
    // 32 bytes of scales/mins (16 sub-blocks * 2 bytes each)
    // Layout: [scale0, min0, scale1, min1, ... scale15, min15]
    uint8_t scales_mins[32];
    
    // 128 bytes of quantized values (4 bits per value, 256 values total)
    // Each byte contains 2 nibbles: [high_nibble, low_nibble]
    // 16 sub-blocks * 8 bytes per sub-block = 128 bytes
    uint8_t qvalues[128];
    
    static constexpr size_t BLOCK_SIZE = 256;       // Values per block
    static constexpr size_t SUBBLOCK_SIZE = 16;     // Values per sub-block
    static constexpr size_t NUM_SUBBLOCKS = 16;     // Sub-blocks per block
    static constexpr size_t BYTES_PER_BLOCK = 144;  // Total bytes
    
    // Extract scale and min for a sub-block
    inline float GetScale(size_t sub_block) const {
        return static_cast<float>(scales_mins[sub_block * 2]);
    }
    
    inline float GetMin(size_t sub_block) const {
        return static_cast<float>(scales_mins[sub_block * 2 + 1]);
    }
};

static_assert(sizeof(Q4KMBlock) == 144, "Q4KMBlock must be 144 bytes");

/*===========================================================================
 * Quantized Tensor View
 * Non-owning view into GGUF-mapped Q4_K_M data
 *===========================================================================*/
class Q4KMTensorView {
public:
    Q4KMTensorView() = default;
    Q4KMTensorView(const uint8_t* data, size_t num_blocks, size_t rows, size_t cols)
        : data_(data), num_blocks_(num_blocks), rows_(rows), cols_(cols) {}
    
    // Get block at index
    const Q4KMBlock* GetBlock(size_t index) const {
        if (index >= num_blocks_) return nullptr;
        return reinterpret_cast<const Q4KMBlock*>(data_ + index * sizeof(Q4KMBlock));
    }
    
    // Get number of blocks
    size_t NumBlocks() const { return num_blocks_; }
    
    // Get dimensions
    size_t Rows() const { return rows_; }
    size_t Cols() const { return cols_; }
    
    // Check if valid
    bool IsValid() const { return data_ != nullptr && num_blocks_ > 0; }
    
    // Raw data access
    const uint8_t* Data() const { return data_; }

private:
    const uint8_t* data_ = nullptr;
    size_t num_blocks_ = 0;
    size_t rows_ = 0;
    size_t cols_ = 0;
};

/*===========================================================================
 * Dequantization Buffers
 * Aligned memory for dequantized weights
 *===========================================================================*/
class DequantBuffer {
public:
    explicit DequantBuffer(size_t num_floats);
    ~DequantBuffer();
    
    // Non-copyable
    DequantBuffer(const DequantBuffer&) = delete;
    DequantBuffer& operator=(const DequantBuffer&) = delete;
    
    // Movable
    DequantBuffer(DequantBuffer&& other) noexcept;
    DequantBuffer& operator=(DequantBuffer&& other) noexcept;
    
    float* Data() { return data_; }
    const float* Data() const { return data_; }
    size_t Size() const { return size_; }
    bool IsValid() const { return data_ != nullptr; }
    
    // Resize (reallocates if needed)
    bool Resize(size_t num_floats);

private:
    float* data_ = nullptr;
    size_t size_ = 0;
    size_t capacity_ = 0;
};

/*===========================================================================
 * Q4_K_M Linear Layer
 * Replaces FP32 matrix-vector multiplication with Q4_K_M + dequant
 *===========================================================================*/
class Q4KMLinear {
public:
    Q4KMLinear() = default;
    
    // Initialize with quantized weights
    // weight_data: GGUF-mapped Q4_K_M blocks
    // in_features: Input dimension
    // out_features: Output dimension
    bool Initialize(const uint8_t* weight_data, size_t in_features, size_t out_features);
    
    // Matrix-vector multiplication: y = weights * x
    // x: Input vector (in_features elements)
    // y: Output vector (out_features elements)
    // Uses fused dequant + GEMV for performance
    bool Forward(const float* x, float* y);
    
    // Get dimensions
    size_t InFeatures() const { return in_features_; }
    size_t OutFeatures() const { return out_features_; }
    bool IsInitialized() const { return weights_.IsValid(); }
    
    // Performance telemetry
    struct Stats {
        uint64_t forward_calls;
        uint64_t total_cycles;
        double avg_cycles_per_call;
        uint64_t cache_hits;
        uint64_t cache_misses;
    };
    Stats GetStats() const { return stats_; }
    void ResetStats() { stats_ = Stats{}; }

private:
    Q4KMTensorView weights_;
    size_t in_features_ = 0;
    size_t out_features_ = 0;
    
    // Scratch buffer for dequantized row
    DequantBuffer row_buffer_;
    
    // Stats
    Stats stats_ = {};
    
    // Internal forward implementations
    bool Forward_Fused(const float* x, float* y);
    bool Forward_DequantThenGEMV(const float* x, float* y);
};

/*===========================================================================
 * Kernel Dispatch
 * Automatically selects best implementation based on CPU features
 *===========================================================================*/
enum class Q4KMKernelType {
    Auto,           // Select based on CPU features
    AVX512,         // AVX-512 optimized
    AVX2,           // AVX2 optimized
    Scalar          // Scalar fallback
};

class Q4KMDispatch {
public:
    static Q4KMDispatch& Instance();
    
    // Initialize dispatch table
    void Initialize();
    
    // Check CPU features
    bool HasAVX512() const;
    bool HasAVX2() const;
    
    // Get best kernel type
    Q4KMKernelType GetBestKernelType() const;
    
    // Dequantize blocks using best available kernel
    void Dequantize(const uint8_t* blocks, float* dest, size_t num_blocks);
    
    // Fused Q4xFP32 GEMV
    // weights: Q4_K_M quantized weights
    // x: FP32 input vector
    // y: FP32 output vector
    // len: Vector length
    void FusedGEMV(const Q4KMBlock* weights, const float* x, float* y, size_t len);

private:
    Q4KMDispatch() = default;
    
    bool has_avx512_ = false;
    bool has_avx2_ = false;
    bool initialized_ = false;
};

} // namespace Deep2
} // namespace RawrXD
