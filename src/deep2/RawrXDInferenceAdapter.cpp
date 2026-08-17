// ============================================================================
// RawrXDInferenceAdapter.cpp — Native Deep2 → MASM Runtime Adapter
// Bridges Deep2Bridge to the MASM inference engine kernels
// ============================================================================

#include "RawrXDInferenceAdapter.hpp"
#include "Deep2Bridge.hpp"
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

    // Initialize the real Deep2Bridge backend
    EngineConfig cfg{};
    cfg.contextSize = 2048;
    cfg.useKVCache = true;
    if (!Deep2Bridge::Get().Initialize(cfg)) {
        RawrRuntime::Get().Log(LogLevel::Error, "Deep2Bridge initialization failed");
        return false;
    }

    m_modelLoaded = false;
    m_cancelled = false;
    m_generating = false;

    RawrRuntime::Get().Log(LogLevel::Info, "InferenceAdapter runtime ready");
    return true;
}

void RawrXDInferenceAdapter::Shutdown() {
    UnloadModel();
    Deep2Bridge::Get().Shutdown();
    m_cancelled = false;
    m_generating = false;
}

bool RawrXDInferenceAdapter::LoadModel(const char* ggufPath) {
    if (m_modelLoaded) UnloadModel();

    RawrRuntime::Get().Log(LogLevel::Info, "Loading GGUF model...");

    if (!Deep2Bridge::Get().LoadModel(ggufPath)) {
        RawrRuntime::Get().Log(LogLevel::Error, "Deep2Bridge failed to load model");
        return false;
    }

    m_modelLoaded = true;
    RawrRuntime::Get().Log(LogLevel::Info, "Model loaded via Deep2Bridge");
    return true;
}

void RawrXDInferenceAdapter::UnloadModel() {
    Deep2Bridge::Get().UnloadModel();
    m_modelLoaded = false;
    m_stats = {};
}

bool RawrXDInferenceAdapter::Generate(const char* prompt, TokenStreamCallback onToken) {
    if (!m_modelLoaded || m_generating) {
        RawrRuntime::Get().Log(LogLevel::Warn,
            "Generate requested without a GGUF model bound to the adapter");
        return false;
    }

    m_generating = true;
    m_cancelled = false;

    auto start = std::chrono::high_resolution_clock::now();

    // Delegate generation to Deep2Bridge, which drives the real Deep2Engine
    auto& bridge = Deep2Bridge::Get();
    uint32_t tokenIndex = 0;
    bool receivedAny = false;

    bool ok = bridge.Generate(
        prompt,
        [&](const char* token, uint32_t /*index*/) {
            receivedAny = true;
            if (onToken) onToken(token, tokenIndex++);
        },
        [&](const char* msg) {
            RawrRuntime::Get().Log(LogLevel::Error, msg);
        }
    );

    auto end = std::chrono::high_resolution_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

    // Pull metrics from the bridge so stats reflect real engine output
    auto bridgeMetrics = bridge.GetMetrics();
    m_stats.totalTokens += bridgeMetrics.totalTokens;
    m_stats.totalTimeUs += elapsed.count();
    if (elapsed.count() > 0) {
        m_stats.tokensPerSecond = static_cast<double>(bridgeMetrics.totalTokens)
                                    / (elapsed.count() / 1000000.0);
    }

    m_generating = false;
    return ok && receivedAny;
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
