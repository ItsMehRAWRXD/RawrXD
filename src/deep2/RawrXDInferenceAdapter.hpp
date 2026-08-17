// ============================================================================
// RawrXDInferenceAdapter.hpp — Native Deep2 → MASM Runtime Adapter
// Bridges Deep2Bridge to the MASM inference engine kernels
// ============================================================================

#ifndef RAWRXD_INFERENCE_ADAPTER_HPP
#define RAWRXD_INFERENCE_ADAPTER_HPP

#include <cstdint>
#include <cstddef>
#include <functional>
#include <string>

// Include Deep2Bridge for backend selection enum
#include "Deep2Bridge.hpp"

namespace rawr {

// ============================================================================
// Q4_0 Block (matches MASM layout)
// ============================================================================
struct alignas(16) Q4_0_Block {
    float scale;        // FP32 scale
    uint8_t qs[16];     // 32 nibbles (4-bit each)
};

// ============================================================================
// GGUF Tensor Info
// ============================================================================
struct GGUFTensorInfo {
    std::string name;
    uint32_t nDims;
    uint64_t ne[4];
    uint64_t offset;
    uint32_t type;  // GGML type enum
};

// ============================================================================
// Token Stream Callback
// ============================================================================
using TokenStreamCallback = std::function<void(const char* token, uint32_t index)>;

// ============================================================================
// MASM Kernel Extern Declarations
// ============================================================================
extern "C" {
    // Real MASM Q4_K GEMV kernel (sovereign_q4k_gemv.asm)
    void Sovereign_Q4K_GEMV_AVX2(const void* q4, const float* x, float* y,
                                  uint32_t num_blocks, uint32_t rows);
    void Sovereign_Q4K_GEMV_AVX2_T(const void* q4, const float* x, float* y,
                                    uint32_t num_blocks, uint32_t rows,
                                    uint32_t row_stride_bytes);

    // Real MASM Deep2 kernels (sovereign_deep2_kernels.asm)
    float Deep2_VecDotProduct_AVX2(const float* a, const float* b, float* out, size_t n);
    void  Deep2_SwiGLU_AVX2(const float* x, const float* y, float* out, size_t n);
    void  Deep2_RMSNorm_AVX2(const float* x, float* out, size_t n, float eps);

    // Stub kernels (sovereign_kernel_stubs.asm)
    void ggml_gemm_q4_0(int M, int N, int K, const float* A, const uint8_t* Bq4, float scale, float* C);
    void Dequant_Q4_0_AVX2(void* blocks, uint64_t num_blocks, void* output, float* scale_override);
    void rmsnorm_forward_avx2(const float* input, float* output, uint32_t n, float eps);
    void softmax_forward_avx2(const float* input, float* output, uint32_t n);
    void silu_activation_avx512(const float* input, float* output, uint32_t n);
    void flash_attn_asm_avx2(const float* Q, const float* K, const float* V, float* O,
                             uint32_t seqLen, uint32_t headDim, float scale);
    void bpe_encode(const char* text, uint32_t* tokens, uint32_t* count, uint32_t maxTokens);
    void* gguf_reader_open(const char* path);
    void  gguf_reader_close(void* handle);
    uint32_t gguf_reader_num_tensors(void* handle);
}

// ============================================================================
// RawrXDInferenceAdapter — High-level adapter
// ============================================================================
class RawrXDInferenceAdapter {
public:
    static RawrXDInferenceAdapter& Get();

    bool Initialize(InferenceBackend backend = InferenceBackend::Deep2Engine);
    void Shutdown();

    // Model lifecycle
    bool LoadModel(const char* ggufPath);
    void UnloadModel();
    bool IsModelLoaded() const { return m_modelLoaded; }

    // Generation
    bool Generate(const char* prompt, TokenStreamCallback onToken);
    void CancelGeneration() { m_cancelled = true; }
    bool IsGenerating() const { return m_generating; }

    // Direct kernel access (for benchmarking)
    void GemmQ4_0(int M, int N, int K, const float* A, const uint8_t* Bq4, float scale, float* C);
    void DequantQ4_0(void* blocks, uint64_t numBlocks, void* output, float* scaleOverride);
    void RMSNorm(const float* input, float* output, uint32_t n, float eps);
    void Softmax(const float* input, float* output, uint32_t n);
    void SiLU(const float* input, float* output, uint32_t n);
    void FlashAttn(const float* Q, const float* K, const float* V, float* O,
                   uint32_t seqLen, uint32_t headDim, float scale);

    // Stats
    struct Stats {
        uint64_t totalTokens = 0;
        uint64_t totalTimeUs = 0;
        double tokensPerSecond = 0.0;
    };
    const Stats& GetStats() const { return m_stats; }

private:
    RawrXDInferenceAdapter() = default;
    ~RawrXDInferenceAdapter() = default;
    RawrXDInferenceAdapter(const RawrXDInferenceAdapter&) = delete;
    RawrXDInferenceAdapter& operator=(const RawrXDInferenceAdapter&) = delete;

    bool m_modelLoaded = false;
    bool m_generating = false;
    bool m_cancelled = false;
    Stats m_stats;

    // Model data (simplified — real impl uses GGUF loader)
    void* m_ggufHandle = nullptr;
    float* m_weights = nullptr;
    uint64_t m_weightSize = 0;
};

} // namespace rawr

#endif // RAWRXD_INFERENCE_ADAPTER_HPP
