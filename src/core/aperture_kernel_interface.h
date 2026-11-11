/**
 * @file aperture_kernel_interface.h
 * @brief Aperture AVX-512 Kernel Interface
 * @version 1.0.0
 * 
 * Defines the bridge between GGUF tensor data and AVX-512 compute kernels.
 * Zero-copy pipeline: GGUF mmap -> Aperture Kernel -> Output buffer
 * 
 * @copyright (c) 2025 RawrXD Project
 */

#pragma once

#include <cstdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// VERSION AND CAPABILITY
// ============================================================================

#define APERTURE_KERNEL_VERSION_MAJOR 1
#define APERTURE_KERNEL_VERSION_MINOR 0
#define APERTURE_KERNEL_VERSION_PATCH 0

#define APERTURE_KERNEL_VERSION_STRING "1.0.0"

// Capability flags returned by Aperture_GetCapabilities()
#define APERTURE_CAP_AVX512F      (1ULL << 0)   // AVX-512 Foundation
#define APERTURE_CAP_AVX512DQ     (1ULL << 1)   // AVX-512 Double/Quad
#define APERTURE_CAP_AVX512BW     (1ULL << 2)   // AVX-512 Byte/Word
#define APERTURE_CAP_AVX512VL     (1ULL << 3)   // AVX-512 Vector Length
#define APERTURE_CAP_AVX512BF16   (1ULL << 4)   // AVX-512 BFloat16
#define APERTURE_CAP_AVX512_VNNI  (1ULL << 5)   // AVX-512 VNNI

// ============================================================================
// DATA TYPES
// ============================================================================

/**
 * @brief Quantization types supported by Aperture kernels
 */
typedef enum {
    APERTURE_Q4_0 = 0,   // 4-bit quantization, type 0
    APERTURE_Q4_1,       // 4-bit quantization, type 1
    APERTURE_Q5_0,       // 5-bit quantization, type 0
    APERTURE_Q5_1,       // 5-bit quantization, type 1
    APERTURE_Q8_0,       // 8-bit quantization, type 0
    APERTURE_Q8_1,       // 8-bit quantization, type 1
    APERTURE_F16,        // 16-bit float (half precision)
    APERTURE_BF16,       // 16-bit bfloat
    APERTURE_F32,        // 32-bit float (single precision)
    APERTURE_COUNT       // Number of quantization types
} ApertureQuantType;

/**
 * @brief Kernel operation types
 */
typedef enum {
    APERTURE_OP_DEQUANT = 0,     // Dequantization only
    APERTURE_OP_DEQUANT_MUL,     // Dequantize + multiply
    APERTURE_OP_DEQUANT_ADD,     // Dequantize + add
    APERTURE_OP_GEMM,            // General matrix multiply
    APERTURE_OP_ATTENTION,       // Attention mechanism
    APERTURE_OP_SOFTMAX,         // Softmax normalization
    APERTURE_OP_LAYERNORM,       // Layer normalization
    APERTURE_OP_COUNT
} ApertureOpType;

/**
 * @brief Execution flags
 */
typedef enum {
    APERTURE_FLAG_NONE          = 0,
    APERTURE_FLAG_ASYNC         = (1 << 0),   // Asynchronous execution
    APERTURE_FLAG_PREFETCH      = (1 << 1),   // Enable prefetching
    APERTURE_FLAG_STREAMING     = (1 << 2),   // Streaming mode (low latency)
    APERTURE_FLAG_ACCUMULATE    = (1 << 3),   // Accumulate to output
} ApertureFlags;

/**
 * @brief Status codes
 */
typedef enum {
    APERTURE_OK = 0,
    APERTURE_ERROR_INVALID_PARAM = -1,
    APERTURE_ERROR_UNSUPPORTED_TYPE = -2,
    APERTURE_ERROR_ALIGNMENT = -3,
    APERTURE_ERROR_BUFFER_TOO_SMALL = -4,
    APERTURE_ERROR_NO_AVX512 = -5,
    APERTURE_ERROR_EXECUTION = -6,
} ApertureStatus;

// ============================================================================
// TENSOR DESCRIPTOR
// ============================================================================

/**
 * @brief Tensor descriptor for Aperture kernels
 * 
 * Describes a tensor's memory layout and quantization format.
 * Used for zero-copy operations from GGUF-mapped memory.
 */
typedef struct {
    void* data;                    // Pointer to tensor data (from GGUF mmap)
    ApertureQuantType quant_type;  // Quantization format
    uint32_t num_dims;             // Number of dimensions (1-4)
    uint32_t dims[4];              // Dimension sizes (up to 4D)
    uint32_t strides[4];           // Strides in elements
    size_t byte_offset;            // Offset from data pointer
    size_t byte_size;              // Total size in bytes
} ApertureTensorDesc;

/**
 * @brief Kernel execution context
 * 
 * Holds state for async operations and performance monitoring.
 */
typedef struct {
    void* internal_state;          // Opaque pointer to kernel state
    uint64_t execution_id;         // Unique execution ID
    uint64_t start_cycles;         // Cycle counter at start
    uint64_t end_cycles;           // Cycle counter at end
    ApertureStatus status;         // Execution status
} ApertureContext;

// ============================================================================
// CAPABILITY QUERY
// ============================================================================

/**
 * @brief Get Aperture kernel version string
 * @return Version string (e.g., "1.0.0")
 */
const char* __cdecl Aperture_GetVersion(void);

/**
 * @brief Get CPU capability flags
 * @return Bitmask of APERTURE_CAP_* flags
 */
uint64_t __cdecl Aperture_GetCapabilities(void);

/**
 * @brief Check if specific quantization type is supported
 * @param type Quantization type to check
 * @return 1 if supported, 0 otherwise
 */
int __cdecl Aperture_IsQuantTypeSupported(ApertureQuantType type);

/**
 * @brief Check if specific operation is supported
 * @param op Operation type to check
 * @return 1 if supported, 0 otherwise
 */
int __cdecl Aperture_IsOpSupported(ApertureOpType op);

/**
 * @brief Get optimal block size for quantization type
 * @param type Quantization type
 * @return Optimal block size in elements, 0 if unsupported
 */
uint32_t __cdecl Aperture_GetOptimalBlockSize(ApertureQuantType type);

// ============================================================================
// TENSOR OPERATIONS
// ============================================================================

/**
 * @brief Dequantize tensor to float32
 * 
 * Converts quantized tensor data to float32 output.
 * Zero-copy: input comes directly from GGUF mmap.
 * 
 * @param input Input tensor descriptor (from GGUF)
 * @param output Output buffer (float32)
 * @param output_size Size of output buffer in bytes
 * @param flags Execution flags
 * @return APERTURE_OK on success, error code otherwise
 * 
 * Example:
 * @code
 *   ApertureTensorDesc input = {
 *       .data = gguf_mmap + tensor_offset,
 *       .quant_type = APERTURE_Q4_0,
 *       .num_dims = 2,
 *       .dims = {4096, 4096},
 *       .byte_size = tensor_size
 *   };
 *   float output[4096 * 4096];
 *   Aperture_Dequantize(&input, output, sizeof(output), APERTURE_FLAG_NONE);
 * @endcode
 */
ApertureStatus __cdecl Aperture_Dequantize(const ApertureTensorDesc* input,
                                            float* output,
                                            size_t output_size,
                                            uint32_t flags);

/**
 * @brief Dequantize and multiply
 * 
 * Dequantizes input and multiplies by scale factor.
 * Used for weight dequantization with scaling.
 * 
 * @param input Input tensor descriptor
 * @param scale Scale factor (per-block or global)
 * @param scale_type 0=global, 1=per-block
 * @param output Output buffer
 * @param output_size Size of output buffer
 * @param flags Execution flags
 * @return Status code
 */
ApertureStatus __cdecl Aperture_DequantizeMul(const ApertureTensorDesc* input,
                                               const float* scale,
                                               int scale_type,
                                               float* output,
                                               size_t output_size,
                                               uint32_t flags);

/**
 * @brief General matrix multiply (GEMM)
 * 
 * Performs C = A * B + C (if APERTURE_FLAG_ACCUMULATE)
 * or C = A * B (otherwise)
 * 
 * @param A Input matrix A descriptor
 * @param B Input matrix B descriptor
 * @param C Output matrix C descriptor
 * @param M Rows in A and C
 * @param N Columns in B and C
 * @param K Columns in A, rows in B
 * @param flags Execution flags
 * @return Status code
 */
ApertureStatus __cdecl Aperture_GEMM(const ApertureTensorDesc* A,
                                      const ApertureTensorDesc* B,
                                      float* C,
                                      uint32_t M, uint32_t N, uint32_t K,
                                      uint32_t flags);

/**
 * @brief Attention mechanism (Q @ K^T @ V)
 * 
 * Computes scaled dot-product attention.
 * Optimized for transformer inference.
 * 
 * @param Q Query tensor [batch, heads, seq_len, head_dim]
 * @param K Key tensor [batch, heads, seq_len, head_dim]
 * @param V Value tensor [batch, heads, seq_len, head_dim]
 * @param output Output tensor
 * @param batch_size Batch dimension
 * @param num_heads Number of attention heads
 * @param seq_len Sequence length
 * @param head_dim Head dimension
 * @param flags Execution flags
 * @return Status code
 */
ApertureStatus __cdecl Aperture_Attention(const ApertureTensorDesc* Q,
                                           const ApertureTensorDesc* K,
                                           const ApertureTensorDesc* V,
                                           float* output,
                                           uint32_t batch_size,
                                           uint32_t num_heads,
                                           uint32_t seq_len,
                                           uint32_t head_dim,
                                           uint32_t flags);

/**
 * @brief Softmax normalization
 * 
 * Computes softmax along last dimension.
 * Optimized for attention scores.
 * 
 * @param input Input tensor
 * @param output Output buffer
 * @param num_rows Number of rows
 * @param row_size Elements per row
 * @param flags Execution flags
 * @return Status code
 */
ApertureStatus __cdecl Aperture_Softmax(const ApertureTensorDesc* input,
                                         float* output,
                                         uint32_t num_rows,
                                         uint32_t row_size,
                                         uint32_t flags);

/**
 * @brief Layer normalization
 * 
 * Computes layer norm: (x - mean) / sqrt(var + eps) * gamma + beta
 * 
 * @param input Input tensor
 * @param gamma Scale parameter
 * @param beta Shift parameter
 * @param epsilon Small constant for numerical stability
 * @param output Output buffer
 * @param num_elements Total elements
 * @param flags Execution flags
 * @return Status code
 */
ApertureStatus __cdecl Aperture_LayerNorm(const ApertureTensorDesc* input,
                                           const float* gamma,
                                           const float* beta,
                                           float epsilon,
                                           float* output,
                                           uint32_t num_elements,
                                           uint32_t flags);

// ============================================================================
// ASYNC OPERATIONS
// ============================================================================

/**
 * @brief Initialize async execution context
 * 
 * Must be called before any async operations.
 * 
 * @param context Pointer to context structure
 * @return APERTURE_OK on success
 */
ApertureStatus __cdecl Aperture_InitContext(ApertureContext* context);

/**
 * @brief Dequantize asynchronously
 * 
 * Non-blocking dequantization. Check completion with Aperture_Wait().
 * 
 * @param input Input tensor descriptor
 * @param output Output buffer
 * @param output_size Size of output buffer
 * @param flags Must include APERTURE_FLAG_ASYNC
 * @param context Execution context
 * @return APERTURE_OK if submitted, error otherwise
 */
ApertureStatus __cdecl Aperture_DequantizeAsync(const ApertureTensorDesc* input,
                                                 float* output,
                                                 size_t output_size,
                                                 uint32_t flags,
                                                 ApertureContext* context);

/**
 * @brief Wait for async operation completion
 * 
 * @param context Execution context
 * @param timeout_ms Timeout in milliseconds (0 = infinite)
 * @return APERTURE_OK on completion, error on timeout/failure
 */
ApertureStatus __cdecl Aperture_Wait(ApertureContext* context, uint32_t timeout_ms);

/**
 * @brief Check if async operation is complete
 * 
 * @param context Execution context
 * @return 1 if complete, 0 if still running
 */
int __cdecl Aperture_IsComplete(const ApertureContext* context);

// ============================================================================
// PERFORMANCE MONITORING
// ============================================================================

/**
 * @brief Performance metrics for kernel execution
 */
typedef struct {
    uint64_t cycles_elapsed;       // CPU cycles elapsed
    uint64_t instructions_retired; // Instructions retired
    uint64_t cache_misses;         // L3 cache misses
    uint64_t cache_references;     // L3 cache references
    double throughput_gbps;        // Effective throughput GB/s
    double utilization;            // CPU utilization (0.0 - 1.0)
} AperturePerfMetrics;

/**
 * @brief Enable performance monitoring
 * 
 * Enables hardware performance counters.
 * May have slight overhead.
 * 
 * @return APERTURE_OK on success
 */
ApertureStatus __cdecl Aperture_EnablePerfMonitoring(void);

/**
 * @brief Disable performance monitoring
 */
void __cdecl Aperture_DisablePerfMonitoring(void);

/**
 * @brief Get performance metrics from last execution
 * 
 * @param context Execution context
 * @param metrics Output metrics structure
 * @return APERTURE_OK on success
 */
ApertureStatus __cdecl Aperture_GetPerfMetrics(const ApertureContext* context,
                                                AperturePerfMetrics* metrics);

/**
 * @brief Reset performance counters
 */
void __cdecl Aperture_ResetPerfCounters(void);

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Get error string for status code
 * 
 * @param status Status code
 * @return Human-readable error message
 */
const char* __cdecl Aperture_GetErrorString(ApertureStatus status);

/**
 * @brief Get size of dequantized tensor
 * 
 * Calculates output size needed for dequantization.
 * 
 * @param input Input tensor descriptor
 * @return Size in bytes needed for float32 output
 */
size_t __cdecl Aperture_GetDequantizedSize(const ApertureTensorDesc* input);

/**
 * @brief Validate tensor descriptor
 * 
 * Checks alignment, dimensions, and sizes.
 * 
 * @param desc Tensor descriptor to validate
 * @return APERTURE_OK if valid, error code otherwise
 */
ApertureStatus __cdecl Aperture_ValidateTensorDesc(const ApertureTensorDesc* desc);

/**
 * @brief Prefetch tensor data into cache
 * 
 * Hints CPU to load data before computation.
 * 
 * @param desc Tensor descriptor
 * @param offset Byte offset to start prefetch
 * @param size Bytes to prefetch
 */
void __cdecl Aperture_Prefetch(const ApertureTensorDesc* desc, 
                                size_t offset, 
                                size_t size);

// ============================================================================
// BATCH OPERATIONS
// ============================================================================

/**
 * @brief Batch dequantization
 * 
 * Dequantizes multiple tensors in one call.
 * More efficient than individual calls.
 * 
 * @param inputs Array of input descriptors
 * @param outputs Array of output buffers
 * @param output_sizes Array of output sizes
 * @param count Number of tensors
 * @param flags Execution flags
 * @return APERTURE_OK if all succeeded
 */
ApertureStatus __cdecl Aperture_DequantizeBatch(const ApertureTensorDesc** inputs,
                                                 float** outputs,
                                                 const size_t* output_sizes,
                                                 uint32_t count,
                                                 uint32_t flags);

/**
 * @brief Fused attention + softmax
 * 
 * Computes attention and applies softmax in one kernel.
 * Reduces memory bandwidth.
 * 
 * @param Q Query tensor
 * @param K Key tensor
 * @param V Value tensor
 * @param output Output buffer
 * @param batch_size Batch dimension
 * @param num_heads Number of heads
 * @param seq_len Sequence length
 * @param head_dim Head dimension
 * @param flags Execution flags
 * @return Status code
 */
ApertureStatus __cdecl Aperture_FusedAttentionSoftmax(const ApertureTensorDesc* Q,
                                                       const ApertureTensorDesc* K,
                                                       const ApertureTensorDesc* V,
                                                       float* output,
                                                       uint32_t batch_size,
                                                       uint32_t num_heads,
                                                       uint32_t seq_len,
                                                       uint32_t head_dim,
                                                       uint32_t flags);

#ifdef __cplusplus
} // extern "C"
#endif

// ============================================================================
// C++ WRAPPER (Optional)
// ============================================================================

#ifdef __cplusplus

#include <stdexcept>
#include <string>

namespace Aperture {

/**
 * @brief C++ exception for Aperture errors
 */
class ApertureError : public std::runtime_error {
public:
    explicit ApertureError(ApertureStatus status)
        : std::runtime_error(Aperture_GetErrorString(status))
        , status_(status) {}
    
    ApertureStatus GetStatus() const { return status_; }
    
private:
    ApertureStatus status_;
};

/**
 * @brief Check status and throw on error
 */
inline void CheckStatus(ApertureStatus status) {
    if (status != APERTURE_OK) {
        throw ApertureError(status);
    }
}

/**
 * @brief RAII wrapper for tensor descriptor
 */
class Tensor {
public:
    Tensor(void* data, ApertureQuantType type, 
           const uint32_t* dims, uint32_t num_dims);
    
    ApertureTensorDesc* GetDesc() { return &desc_; }
    const ApertureTensorDesc* GetDesc() const { return &desc_; }
    
    size_t GetDequantizedSize() const {
        return Aperture_GetDequantizedSize(&desc_);
    }
    
private:
    ApertureTensorDesc desc_;
};

/**
 * @brief High-level dequantization function
 */
inline void Dequantize(const Tensor& input, float* output, size_t output_size,
                       uint32_t flags = APERTURE_FLAG_NONE) {
    CheckStatus(Aperture_Dequantize(input.GetDesc(), output, output_size, flags));
}

/**
 * @brief High-level GEMM function
 */
inline void GEMM(const Tensor& A, const Tensor& B, float* C,
                 uint32_t M, uint32_t N, uint32_t K,
                 uint32_t flags = APERTURE_FLAG_NONE) {
    CheckStatus(Aperture_GEMM(A.GetDesc(), B.GetDesc(), C, M, N, K, flags));
}

} // namespace Aperture

#endif // __cplusplus
