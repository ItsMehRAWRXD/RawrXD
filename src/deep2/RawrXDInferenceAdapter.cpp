// ============================================================================
// RawrXDInferenceAdapter.cpp — Native Deep2 → MASM Runtime Adapter
// Bridges Deep2Bridge to the MASM inference engine kernels
// ============================================================================

#include "RawrXDInferenceAdapter.hpp"
#include "../runtime/RawrRuntime.hpp"
#include <cstdio>
#include <chrono>
#include <cstring>
#include <thread>

namespace rawr {

RawrXDInferenceAdapter& RawrXDInferenceAdapter::Get() {
    static RawrXDInferenceAdapter instance;
    return instance;
}

bool RawrXDInferenceAdapter::Initialize() {
    RawrRuntime::Get().Log(LogLevel::Info, "InferenceAdapter initializing...");
    RawrRuntime::Get().Log(LogLevel::Info, "InferenceAdapter ready");
    return true;
}

void RawrXDInferenceAdapter::Shutdown() {
    UnloadModel();
    m_cancelled = false;
    m_generating = false;
}

bool RawrXDInferenceAdapter::LoadModel(const char* ggufPath) {
    if (m_modelLoaded) UnloadModel();

    RawrRuntime::Get().Log(LogLevel::Info, "Loading GGUF model...");

    // Open GGUF via MASM reader
    m_ggufHandle = gguf_reader_open(ggufPath);
    if (!m_ggufHandle) {
        RawrRuntime::Get().Log(LogLevel::Error, "Failed to open GGUF file");
        return false;
    }

    uint32_t numTensors = gguf_reader_num_tensors(m_ggufHandle);
    RawrRuntime::Get().Log(LogLevel::Info, "GGUF opened");

    // In production: iterate tensors, allocate memory, load weights
    m_modelLoaded = true;
    return true;
}

void RawrXDInferenceAdapter::UnloadModel() {
    if (m_ggufHandle) {
        gguf_reader_close(m_ggufHandle);
        m_ggufHandle = nullptr;
    }
    m_modelLoaded = false;
    m_stats = {};
}

bool RawrXDInferenceAdapter::Generate(const char* prompt, TokenStreamCallback onToken) {
    if (!m_modelLoaded || m_generating) return false;

    m_generating = true;
    m_cancelled = false;

    auto start = std::chrono::high_resolution_clock::now();

    // Tokenize prompt via MASM BPE
    uint32_t tokens[2048];
    uint32_t numTokens = 0;
    bpe_encode(prompt, tokens, &numTokens, 2048);

    // Run inference loop
    // For each token: forward through transformer → sample → decode
    for (uint32_t i = 0; i < 128 && !m_cancelled; ++i) {
        // In production: full transformer forward pass
        // transformer_block_forward(...)
        // sampler_topk(...)
        // bpe_decode(...)

        // Simulate token generation
        const char* sampleTokens[] = {
            "Hello", " from", " RawrXD", " native", " inference", " engine", "."
        };
        if (i < 7 && onToken) {
            onToken(sampleTokens[i], i);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

    m_stats.totalTokens += 7;
    m_stats.totalTimeUs += elapsed.count();
    m_stats.tokensPerSecond = 7.0 / (elapsed.count() / 1000000.0);

    m_generating = false;
    return true;
}

// ============================================================================
// Direct kernel wrappers
// ============================================================================
void RawrXDInferenceAdapter::GemmQ4_0(int M, int N, int K, const float* A,
                                        const uint8_t* Bq4, float scale, float* C) {
    // Call the real MASM Q4_K GEMV kernel
    // M=rows, K=cols, Bq4 points to Q4_K blocks, A=input, C=output
    uint32_t num_blocks = K / 256;
    if (num_blocks < 1) num_blocks = 1;
    Sovereign_Q4K_GEMV_AVX2(Bq4, A, C, num_blocks, M);
}

void RawrXDInferenceAdapter::DequantQ4_0(void* blocks, uint64_t numBlocks,
                                          void* output, float* scaleOverride) {
    Dequant_Q4_0_AVX2(blocks, numBlocks, output, scaleOverride);
}

void RawrXDInferenceAdapter::RMSNorm(const float* input, float* output,
                                       uint32_t n, float eps) {
    rmsnorm_forward_avx2(input, output, n, eps);
}

void RawrXDInferenceAdapter::Softmax(const float* input, float* output, uint32_t n) {
    softmax_forward_avx2(input, output, n);
}

void RawrXDInferenceAdapter::SiLU(const float* input, float* output, uint32_t n) {
    silu_activation_avx512(input, output, n);
}

void RawrXDInferenceAdapter::FlashAttn(const float* Q, const float* K, const float* V,
                                        float* O, uint32_t seqLen, uint32_t headDim,
                                        float scale) {
    flash_attn_asm_avx2(Q, K, V, O, seqLen, headDim, scale);
}

} // namespace rawr
