/**
 * @file rawrxd_masm_tensor.h
 * @brief C/C++ Header for Pure MASM Tensor Operations
 * Zero dependencies on GGML - uses pure x64 MASM kernels
 */

#pragma once

#include <cstdint>
#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// TENSOR TYPE DEFINITIONS (match MASM constants)
// ============================================================================
#define RAWRXD_TYPE_F32     0
#define RAWRXD_TYPE_F16     1
#define RAWRXD_TYPE_Q4_0    2
#define RAWRXD_TYPE_Q4_1    3
#define RAWRXD_TYPE_Q5_0    6
#define RAWRXD_TYPE_Q5_1    7
#define RAWRXD_TYPE_Q8_0    8
#define RAWRXD_TYPE_Q2_K    14
#define RAWRXD_TYPE_Q3_K    15
#define RAWRXD_TYPE_Q4_K    16
#define RAWRXD_TYPE_Q5_K    17
#define RAWRXD_TYPE_Q6_K    18

// Q4_K_M block structure
#define Q4K_BLOCK_SIZE      144
#define Q4K_SUPERBLOCK_SIZE 256

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Q4_K_M quantization block
 * 256 weights compressed to 144 bytes
 */
#pragma pack(push, 1)
typedef struct {
    uint16_t scales[32];    // 64 bytes - f16 scales for 8 groups of 32
    uint16_t mins[32];      // 64 bytes - f16 mins for 8 groups
    uint8_t  qs[16];        // 16 bytes - packed 4-bit weights (32 nibbles)
} q4k_block_t;
#pragma pack(pop)

/**
 * @brief Tensor descriptor
 */
typedef struct {
    void*    data;          // Pointer to data
    int      type;          // RAWRXD_TYPE_*
    int64_t  ne[4];         // Dimensions [ne0, ne1, ne2, ne3]
    size_t   nb[4];         // Byte strides [nb0, nb1, nb2, nb3]
    char     name[64];      // Tensor name
} rawrxd_tensor_t;

/**
 * @brief Context for tensor operations
 */
typedef struct {
    void*    scratch;       // Scratch buffer pointer
    size_t   scratch_size;  // Scratch buffer size
    int      n_threads;     // Number of threads to use
    uint32_t flags;         // Context flags
} rawrxd_tensor_ctx_t;

/**
 * @brief KV Cache entry
 */
typedef struct {
    float*   k_ptr;         // Key cache pointer
    float*   v_ptr;         // Value cache pointer
    int      seq_len;       // Current sequence length
    int      max_len;       // Maximum sequence length
} rawrxd_kv_cache_entry_t;

// ============================================================================
// MATH OPERATIONS
// ============================================================================

/**
 * @brief F32 dot product
 * @param a First array
 * @param b Second array
 * @param n Number of elements
 * @return Dot product result
 */
float rawrxd_dot_f32(const float* a, const float* b, size_t n);

/**
 * @brief F32 matrix-vector multiply: out = mat @ vec
 * @param mat Matrix [rows][cols]
 * @param vec Vector [cols]
 * @param out Output [rows]
 * @param rows Number of rows
 * @param cols Number of columns
 */
void rawrxd_matvec_f32(const float* mat, const float* vec, float* out,
                       size_t rows, size_t cols);

/**
 * @brief F32 matrix-matrix multiply: C = A @ B^T
 * @param A Matrix A [M][K]
 * @param B Matrix B [N][K] (transposed)
 * @param C Output [M][N]
 * @param M Rows in A
 * @param N Rows in B
 * @param K Columns in A/B
 */
void rawrxd_matmul_f32(const float* A, const float* B, float* C,
                       size_t M, size_t N, size_t K);

/**
 * @brief RMS normalization
 * @param out Output array
 * @param in Input array
 * @param weight Weight array
 * @param n Number of elements
 * @param eps Epsilon for numerical stability
 */
void rawrxd_rms_norm_f32(float* out, const float* in, const float* weight,
                         int n, float eps);

/**
 * @brief Layer normalization
 * @param out Output array
 * @param in Input array
 * @param weight Weight array
 * @param bias Bias array (can be NULL)
 * @param n Number of elements
 * @param eps Epsilon for numerical stability
 */
void rawrxd_layer_norm_f32(float* out, const float* in, const float* weight,
                           const float* bias, int n, float eps);

/**
 * @brief Softmax over last dimension
 * @param out Output array
 * @param in Input array
 * @param n Number of elements
 */
void rawrxd_softmax_f32(float* out, const float* in, int n);

/**
 * @brief SiLU activation: silu(x) = x * sigmoid(x)
 * @param out Output array (can be same as in)
 * @param in Input array
 * @param n Number of elements
 */
void rawrxd_silu_f32(float* out, const float* in, int n);

/**
 * @brief GELU activation
 * @param out Output array
 * @param in Input array
 * @param n Number of elements
 */
void rawrxd_gelu_f32(float* out, const float* in, int n);

/**
 * @brief Element-wise addition: c = a + b
 * @param c Output array
 * @param a First input
 * @param b Second input
 * @param n Number of elements
 */
void rawrxd_add_f32(float* c, const float* a, const float* b, int n);

/**
 * @brief Element-wise multiplication: c = a * b
 * @param c Output array
 * @param a First input
 * @param b Second input
 * @param n Number of elements
 */
void rawrxd_mul_f32(float* c, const float* a, const float* b, int n);

/**
 * @brief Element-wise scaling: out = in * scale
 * @param out Output array
 * @param in Input array
 * @param scale Scale factor
 * @param n Number of elements
 */
void rawrxd_scale_f32(float* out, const float* in, float scale, int n);

/**
 * @brief Element-wise copy
 * @param dst Destination
 * @param src Source
 * @param n Number of elements
 */
void rawrxd_copy_f32(float* dst, const float* src, int n);

// ============================================================================
// QUANTIZATION OPERATIONS
// ============================================================================

/**
 * @brief Dequantize Q4_K block to f32
 * @param block Q4_K block pointer
 * @param out Output float array (256 elements)
 * @param n Number of elements (must be multiple of 256)
 */
void rawrxd_dequantize_q4k(const void* block, float* out, int n);

/**
 * @brief Dequantize Q4_K row (optimized for single row)
 * @param row Row pointer
 * @param out Output array
 * @param n_embd Number of embeddings (must be multiple of 256)
 */
void rawrxd_dequantize_q4k_row(const void* row, float* out, int n_embd);

/**
 * @brief Matrix-vector multiply with Q4_K weights (fused dequantize + matvec)
 * @param mat Q4_K quantized matrix
 * @param vec f32 input vector
 * @param out f32 output
 * @param rows Number of rows
 * @param cols Number of columns (must be multiple of 256)
 */
void rawrxd_matvec_q4k(const void* mat, const float* vec, float* out,
                       int rows, int cols);

/**
 * @brief Fused Q4_K matvec + SwiGLU for FFN layers
 * @param w1 Gate weights (Q4_K)
 * @param w3 Up weights (Q4_K)
 * @param x Input
 * @param gate Gate output
 * @param up Up output
 * @param n_embd Embedding dimension
 * @param n_ff FFN dimension
 */
void rawrxd_matvec_q4k_fused(const void* w1, const void* w3,
                              const float* x, float* gate, float* up,
                              int n_embd, int n_ff);

// ============================================================================
// TRANSFORMER OPERATIONS
// ============================================================================

/**
 * @brief Transformer layer forward pass
 * @param hidden Input/output hidden state [n_embd]
 * @param wq Query weights [n_embd][n_embd]
 * @param wk Key weights [n_embd][n_embd]
 * @param wv Value weights [n_embd][n_embd]
 * @param wo Output weights [n_embd][n_embd]
 * @param w1 FFN gate weights [n_embd][n_ff]
 * @param w2 FFN down weights [n_ff][n_embd]
 * @param w3 FFN up weights [n_embd][n_ff]
 * @param norm1 Attention norm weights [n_embd]
 * @param norm2 FFN norm weights [n_embd]
 * @param kv_cache_k K cache pointer
 * @param kv_cache_v V cache pointer
 * @param n_embd Embedding dimension
 * @param n_head Number of attention heads
 * @param n_ff FFN dimension
 * @param n_rot Rotation dimension for RoPE
 * @param n_past Current position in sequence
 * @param scratch Scratch buffer [n_embd*6 + n_ff*2]
 */
void rawrxd_transformer_layer(float* hidden,
                               const float* wq, const float* wk, const float* wv,
                               const float* wo,
                               const float* w1, const float* w2, const float* w3,
                               const float* norm1, const float* norm2,
                               float* kv_cache_k, float* kv_cache_v,
                               int n_embd, int n_head, int n_ff, int n_rot,
                               int n_past, float* scratch);

/**
 * @brief Apply RoPE (Rotary Position Embedding)
 * @param q Query tensor [n_head][head_dim]
 * @param k Key tensor [n_head][head_dim]
 * @param n_head Number of heads
 * @param head_dim Dimension per head
 * @param n_past Current position
 * @param theta Base frequency (typically 10000.0)
 */
void rawrxd_rope_f32(float* q, float* k, int n_head, int head_dim,
                       int n_past, float theta);

/**
 * @brief Attention forward pass
 * @param q Query tensor
 * @param k Key tensor (cached)
 * @param v Value tensor (cached)
 * @param out Output tensor
 * @param n_head Number of heads
 * @param head_dim Dimension per head
 * @param n_past Number of past positions
 */
void rawrxd_attention_fwd(const float* q, const float* k, const float* v,
                          float* out, int n_head, int head_dim, int n_past);

/**
 * @brief FFN SwiGLU: out = silu(gate) * up
 * @param gate Gate values (input/output)
 * @param up Up values
 * @param n Number of elements
 */
void rawrxd_ffn_swiglu(float* gate, const float* up, int n);

/**
 * @brief Update KV cache with new K,V values
 * @param cache_k K cache pointer
 * @param cache_v V cache pointer
 * @param k New K values
 * @param v New V values
 * @param layer Layer index
 * @param pos Position in sequence
 * @param n_embd Embedding dimension
 */
void rawrxd_kv_cache_update(float* cache_k, float* cache_v,
                            const float* k, const float* v,
                            int layer, int pos, int n_embd);

/**
 * @brief Retrieve K,V from cache for attention
 * @param cache_k K cache
 * @param cache_v V cache
 * @param out_k Output K
 * @param out_v Output V
 * @param layer Layer index
 * @param pos_start Start position
 * @param pos_end End position
 * @param n_embd Embedding dimension
 */
void rawrxd_kv_cache_retrieve(const float* cache_k, const float* cache_v,
                              float* out_k, float* out_v,
                              int layer, int pos_start, int pos_end, int n_embd);

// ============================================================================
// SAMPLING OPERATIONS
// ============================================================================

/**
 * @brief Argmax sampling: return index of maximum value
 * @param logits Logit array
 * @param n_vocab Vocabulary size
 * @return Index of maximum logit
 */
int rawrxd_sample_argmax(const float* logits, int n_vocab);

/**
 * @brief Top-k sampling
 * @param logits Logit array
 * @param n_vocab Vocabulary size
 * @param k Top k value
 * @param temperature Temperature for softmax
 * @return Sampled token index
 */
int rawrxd_sample_topk(float* logits, int n_vocab, int k, float temperature);

/**
 * @brief Top-p (nucleus) sampling
 * @param logits Logit array
 * @param n_vocab Vocabulary size
 * @param p Cumulative probability threshold
 * @param temperature Temperature for softmax
 * @return Sampled token index
 */
int rawrxd_sample_topp(float* logits, int n_vocab, float p, float temperature);

/**
 * @brief Apply temperature to logits
 * @param logits Logit array (modified in-place)
 * @param n_vocab Vocabulary size
 * @param temperature Temperature value
 */
void rawrxd_sample_temperature(float* logits, int n_vocab, float temperature);

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Initialize tensor context
 * @param ctx Context to initialize
 * @param scratch_size Size of scratch buffer to allocate
 * @return 0 on success, non-zero on error
 */
int rawrxd_tensor_ctx_init(rawrxd_tensor_ctx_t* ctx, size_t scratch_size);

/**
 * @brief Cleanup tensor context
 * @param ctx Context to cleanup
 */
void rawrxd_tensor_ctx_cleanup(rawrxd_tensor_ctx_t* ctx);

/**
 * @brief Get last error message
 * @return Error string
 */
const char* rawrxd_get_last_error(void);

#ifdef __cplusplus
} // extern "C"
#endif
