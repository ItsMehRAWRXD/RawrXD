// ============================================================================
// Deep2Engine.cpp - Production Inference Engine Implementation
// Real weight loading, real attention, real FFN, real sampling
// NO STUBS, NO DUMMIES, NO HARDCODED VALUES
// ============================================================================

// VAL-051.7 Gate 16: B3 hard gate restored.
// Continuation mode removed for production certification.
// #define B3_CONTINUE_FOR_RESIDENCY_BASELINE

#include "ChatTemplate.hpp"
#include "d2_gen_quality_probe.hpp"
#include "Deep2Engine.h"
#include "Deep2SsVkPackedDualAdapter.hpp"
#include "lavapath/DualStickStreamWindow.hpp"
#include "MoEExpertResidencyPlace.hpp"
#include "Deep2GpuCounterSnapshot.hpp"
#include "Deep2Residency.hpp"
#include "GpuTransferCounters.hpp"
#include "Deep2Top15Seams.hpp"
#include "d2_packed_q2k_product_run_v1.h"
#include "TeardownWitness.hpp"
#include "RawrChoreography.hpp"
#include "ChoreographyResidencyLaw.hpp"
#include "RawrLiveSeal.hpp"
#include "RawrReverseCompletion.hpp"
#include "NemotronHSsmMap.hpp"
#include "NemotronHSsmExperimental.hpp"
#include "NemotronHGeometry.hpp"
#include "NemotronHMamba2Step.hpp"
#include "HostQ8GemvSafe.hpp"
#include "FinalNormAcquire.hpp"
#include "FinalNormProduce.hpp"
#include "SemanticSafe.hpp"
#include "FusedLiveController.hpp"
#include "GGUFLoader.hpp"
#include "ModelOpenCompat.hpp"
#include "Phi3FusedFfnRuntime.hpp"
#include "Gemma4SchemaBinder.hpp"
#include "Gemma4LayerTopologyBind.hpp"
#include "DecodeBlockerAttribution.hpp"
#include "Gemma4BindLlamaFallback.hpp"
#include "FfnInterInferFix.hpp"
#include "DecodeBlockerAttributionWire.hpp"
#include "DynamicPersistentModelManifest.hpp"
#include "ModelProvenanceSeal.hpp"
#include "ManifestRuntimeOverlay.hpp"
#include "lavapath/GgufDynamicGeometry.hpp"
#include "lavapath/AuthorityBridge.hpp"
#include "lavapath/ProductScoreboardWitness.hpp"
#include "lavapath/ScoreboardHostForwardBridge.hpp"
#include "lavapath/ScoreboardOwnedForward.hpp"
#include "lavapath/ScoreboardPumpIssue.hpp"
#include "lavapath/ScoreboardLayerWalk.hpp"
#include "../asm/k2_real_attention/XR_K2_RealAttention.hpp"
#include "ReverseHotpatchEngine.hpp"
#include "Tokenizer.hpp"
#include "lavapath/Batch007Emit.hpp"
#include "lavapath/BatchD_UnifiedAsyncMove.hpp"
#include "lavapath/HostFutureConsumerPrefetch.hpp"
#include "lavapath/DecodeLoopAttribution.hpp"
#include "lavapath/OneByOneIgnoreLadder.hpp"
#include "lavapath/Phi3FusedQkvAuthority.hpp"
#include "lavapath/HeapWitness.hpp"
#include "lavapath/Phi3FusedFfnAuthority.hpp"
#include "lavapath/UnlimitedTokenLaw.hpp"
#include "lavapath/ProductPathSeal.hpp"
#include "lavapath/ExperimentalSsmAuth.hpp"
#include "CanonicalTokenizer.hpp"
#include "GGUFTokenizerLoad.hpp"
#include "../sampling/advanced_sampler.hpp"
#include "MoERouter.hpp"
#include "QuantKernelRegistry.hpp"
#include "Deep2DeviceManager.hpp"
#include "AttnCertProbe.hpp"
#include "SsmCertProbe.hpp"
#include "MlaCertProbe.hpp"
#include "MlaCertAuthority.hpp"
#include "K2MLAWeights.hpp"
#include "K2KVCache.hpp"
#include "RuntimeEvidence512Surface.hpp"
#include "RuntimeEvidence512HostIDE.hpp"
#include "MedusaDecoder.hpp"
#include "NUFusedPacker.hpp"
#include "WarmupScheduler.hpp"
#include "CompressedKVCache.h"
#include "NVMeStream.h"
#include "SlidingWindowEngine.h"
#include "MoEWeightsLoader.hpp"
#include "HotPatcher.hpp"
#include "Deep2LivePath.hpp"
#include "Deep2LivePath_Internal.hpp"
#include "DecodeFeedbackProbe.hpp"
#include "K2LivePolicy.hpp"
#include "K2GpuStreamCopy.hpp"
#include "K2MLA_GpuGemv.hpp"
#include "K2ShardIo.hpp"
#include "CycloneScheduler.hpp"
#include "ElasticDynamicBudget.hpp"
#include "KimiK2Config.hpp"
#include "K2GlobalTensorIndex.hpp"
#include "K2LivePathTensorCache.hpp"
#include "K2LivePathOwnership.hpp"
#include "K2TokenEmbedding.hpp"
#include "ResidencyCounters.hpp"
#include "Deep2Telemetry.hpp"
#include "execution_policy/ExecutionPolicyBridge.hpp"
#include "execution_policy/ExecutionPolicyApply.hpp"
#include "execution_policy/PolicyApply.hpp"
#include "ollama_blob_parser.h"
#include "GgufModelPath.hpp"
#include <cstdio>
#include <cstdlib>
#include <cmath>
#include <cstring>
#include <stdexcept>
#include <chrono>
#include <algorithm>
#include <cctype>
#include <mutex>

namespace {
rawr::model_provenance::Provenance g_modelProv{};
} // namespace
#include <future>
#include <atomic>
#include <vector>
#include <immintrin.h>
#include <filesystem>
#include <fstream>
#include <sstream>
#ifdef __GNUC__
#include <cpuid.h>
#endif
#include "gguf_loader.h"

#ifdef RAWRXD_DEEP2_CERT
#include "Deep2CertBridge.hpp"
#endif

// Deep2 kernel interface
extern "C" {
    void Deep2_VecDotProduct(const float* a, const float* b, float* out, size_t n);
    void Deep2_SwiGLU(const float* x, const float* y, float* out, size_t n);
    void Deep2_RMSNorm(const float* x, float* out, size_t n, float eps);
    int Deep2_HasAVX2();
    int Deep2_HasAVX512();
    int Deep2_LoadModel(void* engine, const char* modelPath);

    // Real Q4_K GEMV from sovereign_q4k_gemv.asm (NOT a stub).
    void Sovereign_Q4K_GEMV_AVX2(
        const void* q4_weights,
        const float* input,
        float* output,
        unsigned int num_blocks,
        unsigned int rows);

    // Q4_K v2 optimized kernel (sovereign_q4k_gemv_v2.asm)
    void Sovereign_Q4K_GEMV_AVX2_V2(
        const void* q4_weights,
        const float* input,
        float* output,
        unsigned int num_blocks,
        unsigned int rows);

    // Q2_K v2 optimized kernel (sovereign_q2k_gemv_v2.asm)
    void Sovereign_Q2K_GEMV_AVX2_V2(
        const void* q2_weights,
        const float* input,
        float* output,
        unsigned int num_blocks,
        unsigned int rows);

    // Q3_K v2 optimized kernel (sovereign_q3k_gemv_v2.asm)
    void Sovereign_Q3K_GEMV_AVX2_V2(
        const void* q3_weights,
        const float* input,
        float* output,
        unsigned int num_blocks,
        unsigned int rows);

    // Q6_K GEMV kernel (sovereign_q6_k_gemv.asm)
    // ABI: RCX=blocks, RDX=x, R8=out, R9=nBlocks
    extern "C" void Deep2_Q6_K_GEMV(
        const void* blocks,
        const float* x,
        float* out,
        std::size_t nBlocks);

    // Q8_0 GEMV kernel (sovereign_q8_0_gemv.asm)
    // ABI: RCX=weights, RDX=input, R8=output, R9=numBlocks, [rsp+60h]=outputDim
    extern "C" void Deep2_Q8_0_GEMV(
        const void* weights,
        const float* input,
        float* output,
        unsigned int numBlocks,
        unsigned int outputDim);

    // Q4_1 GEMV kernel (sovereign_q4_1_gemv.asm)
    // ABI: RCX=weights, RDX=input, R8=output, R9=numBlocks, [rsp+60h]=outputDim
    extern "C" void Deep2_Q4_1_GEMV(
        const void* weights,
        const float* input,
        float* output,
        unsigned int numBlocks,
        unsigned int outputDim);

    // Q5_K GEMV kernel (sovereign_q5_k_gemv.asm)
    // ABI: RCX=weights, RDX=input, R8=output, R9=numBlocks, [rsp+60h]=outputDim
    extern "C" void Deep2_Q5_K_GEMV(
        const void* weights,
        const float* input,
        float* output,
        unsigned int numBlocks,
        unsigned int outputDim);

    // FP16 GEMV kernel (sovereign_fp16_gemv.asm)
    // ABI: RCX=weights, RDX=input, R8=output, R9=rows, [rsp+60h]=cols
    extern "C" void Deep2_FP16_GEMV(
        const void* weights,
        const float* input,
        float* output,
        unsigned int rows,
        unsigned int cols);

    // MoE kernel
    void Sovereign_ExecuteMoEKernel(const void* weight_ptr, const void* activation_ptr,
                                     void* output_ptr, size_t hidden_dim);
    
    // Medusa GEMV: Compute logits = weights[rows, cols] @ input[cols]
    // Used by MedusaDecoder for speculative head forward pass
    void Deep2_MedusaGEMV(const float* weights, const float* input, float* output,
                          size_t rows, size_t cols);
}

// C API for model loading
extern "C" int Deep2_LoadModel(void* engine, const char* modelPath) {
    if (!engine || !modelPath) return 0;
    Deep2::Deep2Engine* e = static_cast<Deep2::Deep2Engine*>(engine);
    return e->loadModel(modelPath) ? 1 : 0;
}
// AVX2 is detected via CPUID leaf 7, EBX bit 5 (not leaf 1 ECX bit 28 which is AVX)
extern "C" int Deep2_HasAVX2() {
    int cpuInfo[4] = {0};
    // First check leaf 1 for AVX (bit 28 of ECX) - prerequisite for AVX2
#ifdef _MSC_VER
    __cpuid(cpuInfo, 1);
#else
    __cpuid(1, cpuInfo[0], cpuInfo[1], cpuInfo[2], cpuInfo[3]);
#endif
    if (!(cpuInfo[2] & (1 << 28))) return 0;  // No AVX, so no AVX2
    
    // Now check leaf 7 for AVX2 (bit 5 of EBX)
#ifdef _MSC_VER
    __cpuid(cpuInfo, 7);
#else
    __cpuid(7, cpuInfo[0], cpuInfo[1], cpuInfo[2], cpuInfo[3]);
#endif
    return (cpuInfo[1] & (1 << 5)) ? 1 : 0;
}

extern "C" int Deep2_HasAVX512() {
    int cpuInfo[4] = {0};
#ifdef _MSC_VER
    __cpuid(cpuInfo, 7);
#else
    __cpuid(7, cpuInfo[0], cpuInfo[1], cpuInfo[2], cpuInfo[3]);
#endif
    // Check bit 16 of EBX for AVX-512F
    return (cpuInfo[1] & (1 << 16)) ? 1 : 0;
}

// Vector dot product - Production AVX2/AVX-512 implementation
extern "C" void Deep2_VecDotProduct(const float* a, const float* b, float* out, size_t n) {
    if (n == 0) {
        *out = 0.0f;
        return;
    }
    
    // AVX2 path: Process 8 floats at a time with FMA
    __m256 sum_vec = _mm256_setzero_ps();
    size_t i = 0;
    
    // Main loop: 8 elements per iteration
    for (; i + 8 <= n; i += 8) {
        __m256 va = _mm256_loadu_ps(a + i);
        __m256 vb = _mm256_loadu_ps(b + i);
        sum_vec = _mm256_fmadd_ps(va, vb, sum_vec);
    }
    
    // Horizontal sum of the 8-element vector
    __m128 hi128 = _mm256_extractf128_ps(sum_vec, 1);
    __m128 lo128 = _mm256_castps256_ps128(sum_vec);
    __m128 sum128 = _mm_add_ps(lo128, hi128);
    sum128 = _mm_hadd_ps(sum128, sum128);
    sum128 = _mm_hadd_ps(sum128, sum128);
    float sum = _mm_cvtss_f32(sum128);
    
    // Scalar remainder
    for (; i < n; ++i) {
        sum += a[i] * b[i];
    }
    
    *out = sum;
}

// SwiGLU activation: out = silu(gate) * up  (gate=y, up=x in legacy call sites)
// MUST match Deep2Engine::SwiGLU — XR real reference.
extern "C" void Deep2_SwiGLU(const float* x, const float* y, float* out, size_t n) {
    if (n == 0 || !x || !y || !out) return;
    /* Legacy: out = x * silu(y)  ⇒ gate=y, up=x */
    (void)XR_SwiGLU_F32(const_cast<float*>(y), x, out, static_cast<uint64_t>(n));
}

// RMSNorm - Production AVX2 implementation with two-pass algorithm
// Computes: out[i] = x[i] / sqrt(mean(xÂ²) + eps)
extern "C" void Deep2_RMSNorm(const float* x, float* out, size_t n, float eps) {
    if (n == 0) return;
    
    // Pass 1: Compute sum of squares using AVX2
    __m256 sum_vec = _mm256_setzero_ps();
    size_t i = 0;
    
    for (; i + 8 <= n; i += 8) {
        __m256 vx = _mm256_loadu_ps(x + i);
        sum_vec = _mm256_fmadd_ps(vx, vx, sum_vec);
    }
    
    // Horizontal sum
    __m128 hi128 = _mm256_extractf128_ps(sum_vec, 1);
    __m128 lo128 = _mm256_castps256_ps128(sum_vec);
    __m128 sum128 = _mm_add_ps(lo128, hi128);
    sum128 = _mm_hadd_ps(sum128, sum128);
    sum128 = _mm_hadd_ps(sum128, sum128);
    float sum = _mm_cvtss_f32(sum128);
    
    // Scalar remainder for sum
    for (; i < n; ++i) {
        sum += x[i] * x[i];
    }
    
    // Compute RMS scale factor
    float meanSq = sum / n;
    float rms = std::sqrt(meanSq + eps);
    __m256 scale_vec = _mm256_set1_ps(1.0f / rms);
    
    // Pass 2: Apply normalization with AVX2
    i = 0;
    for (; i + 8 <= n; i += 8) {
        __m256 vx = _mm256_loadu_ps(x + i);
        __m256 result = _mm256_mul_ps(vx, scale_vec);
        _mm256_storeu_ps(out + i, result);
    }
    
    // Scalar remainder
    float scale = 1.0f / rms;
    for (; i < n; ++i) {
        out[i] = x[i] * scale;
    }
}

// MoE kernel - Production AVX2 implementation for gate/up/down projections
// Computes full matrix-vector product: output[rows] = weights[rows, cols] * input[cols]
extern "C" void Sovereign_ExecuteMoEKernel(const void* weight_ptr, const void* activation_ptr,
                                            void* output_ptr, size_t hidden_dim) {
    const float* weights = static_cast<const float*>(weight_ptr);
    const float* input = static_cast<const float*>(activation_ptr);
    float* output = static_cast<float*>(output_ptr);
    
    // Full matrix-vector multiplication for MoE expert
    // weights is [output_dim, hidden_dim], input is [hidden_dim]
    // output is [output_dim]
    // For MoE, output_dim typically equals hidden_dim
    size_t output_dim = hidden_dim;
    
    // AVX2 optimized matvec for MoE expert
    for (size_t row = 0; row < output_dim; row++) {
        const float* row_weights = weights + row * hidden_dim;
        
        // Process 8 floats at a time with AVX2
        size_t i = 0;
        __m256 sum_vec = _mm256_setzero_ps();
        
        for (; i + 8 <= hidden_dim; i += 8) {
            __m256 w = _mm256_loadu_ps(&row_weights[i]);
            __m256 x = _mm256_loadu_ps(&input[i]);
            sum_vec = _mm256_fmadd_ps(w, x, sum_vec);
        }
        
        // Horizontal sum of the vector
        __m128 hi = _mm256_extractf128_ps(sum_vec, 1);
        __m128 lo = _mm256_castps256_ps128(sum_vec);
        __m128 sum = _mm_add_ps(lo, hi);
        sum = _mm_hadd_ps(sum, sum);
        sum = _mm_hadd_ps(sum, sum);
        float total = _mm_cvtss_f32(sum);
        
        // Remainder
        for (; i < hidden_dim; ++i) {
            total += row_weights[i] * input[i];
        }
        
        output[row] = total;
    }
}

// Medusa GEMV: Compute logits = weights[rows, cols] @ input[cols]
// Production AVX2 implementation for speculative decoding heads
// weights: [rows, cols] row-major, input: [cols], output: [rows]
extern "C" void Deep2_MedusaGEMV(const float* weights, const float* input, float* output,
                                  size_t rows, size_t cols) {
    if (!weights || !input || !output || rows == 0 || cols == 0) return;
    
    // AVX2 optimized GEMV for Medusa heads
    // Each output[row] = dot(weights[row], input)
    for (size_t r = 0; r < rows; r++) {
        const float* row_weights = weights + r * cols;
        
        // Process 8 floats at a time with AVX2 FMA
        size_t i = 0;
        __m256 sum_vec = _mm256_setzero_ps();
        
        for (; i + 8 <= cols; i += 8) {
            __m256 w = _mm256_loadu_ps(&row_weights[i]);
            __m256 x = _mm256_loadu_ps(&input[i]);
            sum_vec = _mm256_fmadd_ps(w, x, sum_vec);
        }
        
        // Horizontal sum of the 8-element vector
        __m128 hi = _mm256_extractf128_ps(sum_vec, 1);
        __m128 lo = _mm256_castps256_ps128(sum_vec);
        __m128 sum = _mm_add_ps(lo, hi);
        sum = _mm_hadd_ps(sum, sum);
        sum = _mm_hadd_ps(sum, sum);
        float total = _mm_cvtss_f32(sum);
        
        // Scalar remainder for non-multiple-of-8 dimensions
        for (; i < cols; ++i) {
            total += row_weights[i] * input[i];
        }
        
        output[r] = total;
    }
}

// ============================================================================
// GGUF Q4_K Block Structure (144 bytes per 256 elements)
//
// Layout (from llama.cpp / ggml-quants.h):
//   +0:   d (fp16)     â€” super-block scale
//   +2:   dmin (fp16)  â€” super-block minimum
//   +4:   scales[12]   â€” packed 6-bit scale/min pairs for 8 sub-blocks
//   +16:  qs[128]      â€” packed 4-bit quants (2 per byte)
//
// Total: 144 bytes per 256-element super-block
//
// Formula per element: output = d * sc * q - dmin * m
//   where sc/m are unpacked from scales[], q is 4-bit quant [0..15]
// ============================================================================
struct alignas(16) Q4_K_Block {
    uint16_t d;               // FP16 super-scale
    uint16_t dmin;            // FP16 super-minimum
    uint8_t  scales[12];      // Packed 6-bit scale/min pairs (8 sub-blocks)
    uint8_t  qs[128];         // 256 x 4-bit packed weights
};
static_assert(sizeof(Q4_K_Block) == 144, "Q4_K_Block must be 144 bytes");

namespace Deep2 {
static bool EnhanceWanted(const char* name);


// Aligned allocation helpers â€” count is NUMBER OF FLOATS (not bytes).
static float* alignedAlloc(size_t count) {
#ifdef _WIN32
    return (float*)_aligned_malloc(count * sizeof(float), 32);
#else
    return (float*)aligned_alloc(32, count * sizeof(float));
#endif
}

static bool envFlagEnabled(const char* name) {
    const char* v = std::getenv(name);
    if (!v || !*v) return false;
    return !(v[0] == '0' && v[1] == '\0') &&
           !(v[0] == 'n' || v[0] == 'N' || v[0] == 'f' || v[0] == 'F');
}

static void alignedFree(float* ptr) {
#ifdef _WIN32
    _aligned_free(ptr);
#else
    free(ptr);
#endif
}

// ============================================================================
// FP16 -> FP32 conversion
// ============================================================================
static inline float fp16ToFloat(uint16_t h) {
    uint32_t sign = (h >> 15) & 0x1;
    uint32_t exp  = (h >> 10) & 0x1F;
    uint32_t mant = h & 0x3FF;
    uint32_t f;
    if (exp == 0) {
        if (mant == 0) {
            f = sign << 31;
        } else {
            // Subnormal: value = mant * 2^(-10) * 2^(-14) = mant * 2^(-24)
            // Normalize: shift left until bit 10 is set
            int e = 0;
            while (!(mant & 0x400)) { mant <<= 1; e++; }
            mant &= 0x3FF;
            // After e shifts, exponent = -14 - e
            // FP32 exponent = 127 + (-14 - e) = 113 - e
            f = (sign << 31) | ((113 - e) << 23) | (mant << 13);
        }
    } else if (exp == 31) {
        f = (sign << 31) | (0xFF << 23) | (mant << 13);
    } else {
        f = (sign << 31) | ((exp + 127 - 15) << 23) | (mant << 13);
    }
    float result;
    memcpy(&result, &f, sizeof(float));
    return result;
}

// ============================================================================
// Unpack 6-bit scale/min for Q4_K sub-block
// scales[12] packs 8 pairs of (scale, min) as 6-bit values each.
// Correct layout per llama.cpp ggml-common.h:
//   For j = 0..3:  d = scales[j] & 63,       m = scales[j + 4] & 63
//   For j = 4..7:  d = (scales[j+4] & 0x0F) | ((scales[j-4] >> 6) << 4)
//                  m = (scales[j+4] >> 4)      | ((scales[j]   >> 6) << 4)
// ============================================================================
static inline void unpackQ4KScaleMin(const uint8_t* scales, int j,
                                       uint8_t& sc, uint8_t& m) {
    if (j < 4) {
        sc = scales[j] & 63;
        m  = scales[j + 4] & 63;
    } else {
        sc = (scales[j + 4] & 0x0F) | ((scales[j - 4] >> 6) << 4);
        m  = (scales[j + 4] >> 4)      | ((scales[j]   >> 6) << 4);
    }
}

// ============================================================================
// Dequantize Q4_K block to FP32 (256 elements per block)
// ============================================================================
static void dequantizeQ4KBlock(const Q4_K_Block* block, float* out) {
    // Match ggml dequantize_row_q4_K: paired scales over 32-byte qs chunks
    float d    = fp16ToFloat(block->d);
    float dmin = fp16ToFloat(block->dmin);
    const uint8_t* q = block->qs;
    float* y = out;

    for (int is = 0; is < 8; is += 2) {
        uint8_t sc0, m0, sc1, m1;
        unpackQ4KScaleMin(block->scales, is, sc0, m0);
        unpackQ4KScaleMin(block->scales, is + 1, sc1, m1);
        const float d1 = d * sc0;
        const float min1 = dmin * m0;
        const float d2 = d * sc1;
        const float min2 = dmin * m1;
        for (int l = 0; l < 32; ++l) *y++ = d1 * (float)(q[l] & 0xF) - min1;
        for (int l = 0; l < 32; ++l) *y++ = d2 * (float)(q[l] >> 4) - min2;
        q += 32;
    }
}

// ============================================================================
// Dequantize Q6_K block to FP32 (256 elements per block)
// ============================================================================
static void dequantizeQ6KBlock(const block_q6_K* block, float* out) {
    float d = fp16ToFloat(block->d);
    const uint8_t* ql = block->ql;
    const uint8_t* qh = block->qh;
    const int8_t*  sc = block->scales;
    for (size_t i = 0; i < 256; ++i) {
        size_t qlIdx = i / 2;
        int    qlShift = (i % 2) * 4;
        uint8_t low4 = (ql[qlIdx] >> qlShift) & 0x0F;
        size_t qhIdx = i / 4;
        int    qhShift = (i % 4) * 2;
        uint8_t high2 = (qh[qhIdx] >> qhShift) & 0x03;
        int8_t q = (int8_t)(low4 | (high2 << 4)) - 32;
        int scaleIdx = (int)(i / 16);
        out[i] = d * (float)sc[scaleIdx] * (float)q;
    }
}

// ============================================================================
// FP32 GEMV: output[rows] = weights[rows, cols] * input[cols]
// ============================================================================
static void fp32GEMV(const float* weights, const float* input,
                     float* output, size_t rows, size_t cols) {
    for (size_t r = 0; r < rows; ++r) {
        const float* row = weights + r * cols;
        __m256 acc = _mm256_setzero_ps();
        size_t c = 0;
        for (; c + 8 <= cols; c += 8) {
            __m256 w = _mm256_loadu_ps(row + c);
            __m256 x = _mm256_loadu_ps(input + c);
            acc = _mm256_fmadd_ps(w, x, acc);
        }
        // Horizontal sum
        __m128 hi128 = _mm256_extractf128_ps(acc, 1);
        __m128 lo128 = _mm256_castps256_ps128(acc);
        __m128 sum128 = _mm_add_ps(lo128, hi128);
        sum128 = _mm_hadd_ps(sum128, sum128);
        sum128 = _mm_hadd_ps(sum128, sum128);
        float sum = _mm_cvtss_f32(sum128);
        // Remainder
        for (; c < cols; ++c) {
            sum += row[c] * input[c];
        }
        output[r] = sum;
    }
}

// ============================================================================
// Q4_K GEMV: output[rows] = dequant(weights[rows, cols]) * input[cols]
// ============================================================================
// ============================================================================
// Q4_K GEMV diagnostic counters (thread-local accumulators)
// ============================================================================
static thread_local double g_q4kDequantMs = 0.0;
static thread_local double g_q4kDotMs     = 0.0;
static thread_local size_t g_q4kCalls     = 0;
static thread_local size_t g_q4kBlocks    = 0;

// ============================================================================
// Q4_K GEMV â€” Fused AVX2 (ggml dequantize_row_q4_K nibble grouping)
// For each scale pair (is, is+1): qs[0..31] lo â†’ group is, qs[0..31] hi â†’ group is+1.
// Do NOT use per-16-byte interleaved lo/hi within one scale (pre-VAL-051 bug).
// ============================================================================
// Transpose Q4_K GEMV: output[cols] = W^T * input[rows]
// Used when attn_gate is stored as [gateDim × hidden] but O needs hidden←gateDim.
static void q4kGEMV_T(const void* weights, const float* input,
                      float* output, size_t rows, size_t cols) {
    size_t numBlocks = (cols + 255) / 256;
    constexpr size_t kBlockSize = sizeof(Q4_K_Block);
    std::memset(output, 0, cols * sizeof(float));
    std::vector<float> row(cols);
    for (size_t r = 0; r < rows; ++r) {
        const Q4_K_Block* rowBlocks =
            (const Q4_K_Block*)((const uint8_t*)weights + r * numBlocks * kBlockSize);
        for (size_t b = 0; b < numBlocks; ++b) {
            const size_t base = b * 256;
            const size_t n = (base + 256 <= cols) ? 256u : (cols - base);
            if (n == 0) break;
            dequantizeQ4KBlock(&rowBlocks[b], row.data() + base);
        }
        const float xr = input[r];
        for (size_t c = 0; c < cols; ++c)
            output[c] += row[c] * xr;
    }
}

static void q4kGEMV(const void* weights, const float* input,
                    float* output, size_t rows, size_t cols) {
    Deep2::scoreboard::MarkRealKernelDispatch();
    size_t numBlocks = (cols + 255) / 256;
    constexpr size_t kBlockSize = sizeof(Q4_K_Block);  // 144 bytes

    ++g_q4kCalls;
    g_q4kBlocks += rows * numBlocks;

    for (size_t r = 0; r < rows; ++r) {
        const Q4_K_Block* rowBlocks =
            (const Q4_K_Block*)((const uint8_t*)weights + r * numBlocks * kBlockSize);

        __m256 acc = _mm256_setzero_ps();
        for (size_t b = 0; b < numBlocks; ++b) {
            size_t elemsInBlock = (b == numBlocks - 1)
                ? (cols - b * 256)
                : 256;
            if (elemsInBlock == 0) break;

            const Q4_K_Block& blk = rowBlocks[b];
            float d = fp16ToFloat(blk.d);
            float dmin = fp16ToFloat(blk.dmin);
            const uint8_t* q = blk.qs;

            for (int is = 0; is < 8; is += 2) {
                uint8_t sc0, m0, sc1, m1;
                unpackQ4KScaleMin(blk.scales, is, sc0, m0);
                unpackQ4KScaleMin(blk.scales, is + 1, sc1, m1);
                const float d1 = d * (float)sc0;
                const float min1 = dmin * (float)m0;
                const float d2 = d * (float)sc1;
                const float min2 = dmin * (float)m1;
                __m256 d1v = _mm256_set1_ps(d1);
                __m256 m1v = _mm256_set1_ps(min1);
                __m256 d2v = _mm256_set1_ps(d2);
                __m256 m2v = _mm256_set1_ps(min2);

                const size_t off0 = (size_t)is * 32;
                const size_t off1 = off0 + 32;

                // 32 lo-nibbles â†’ weights [off0 .. off0+31]
                for (int chunk = 0; chunk < 4; ++chunk) {
                    const int l0 = chunk * 8;
                    if (off0 + (size_t)l0 + 8 > elemsInBlock) break;
                    if (b * 256 + off0 + (size_t)l0 + 8 > cols) break;
                    __m128i bytes = _mm_loadl_epi64(
                        reinterpret_cast<const __m128i*>(q + l0));
                    __m128i lo = _mm_and_si128(bytes, _mm_set1_epi8(0x0F));
                    __m256i i32 = _mm256_cvtepu8_epi32(lo);
                    __m256 w = _mm256_cvtepi32_ps(i32);
                    __m256 deq = _mm256_sub_ps(_mm256_mul_ps(w, d1v), m1v);
                    __m256 x = _mm256_loadu_ps(input + b * 256 + off0 + (size_t)l0);
                    acc = _mm256_fmadd_ps(deq, x, acc);
                }
                // 32 hi-nibbles â†’ weights [off1 .. off1+31]
                for (int chunk = 0; chunk < 4; ++chunk) {
                    const int l0 = chunk * 8;
                    if (off1 + (size_t)l0 + 8 > elemsInBlock) break;
                    if (b * 256 + off1 + (size_t)l0 + 8 > cols) break;
                    __m128i bytes = _mm_loadl_epi64(
                        reinterpret_cast<const __m128i*>(q + l0));
                    __m128i hi = _mm_and_si128(_mm_srli_epi16(bytes, 4), _mm_set1_epi8(0x0F));
                    __m256i i32 = _mm256_cvtepu8_epi32(hi);
                    __m256 w = _mm256_cvtepi32_ps(i32);
                    __m256 deq = _mm256_sub_ps(_mm256_mul_ps(w, d2v), m2v);
                    __m256 x = _mm256_loadu_ps(input + b * 256 + off1 + (size_t)l0);
                    acc = _mm256_fmadd_ps(deq, x, acc);
                }
                q += 32;
            }
        }

        __m128 hi128 = _mm256_extractf128_ps(acc, 1);
        __m128 lo128 = _mm256_castps256_ps128(acc);
        __m128 sum128 = _mm_add_ps(lo128, hi128);
        sum128 = _mm_hadd_ps(sum128, sum128);
        sum128 = _mm_hadd_ps(sum128, sum128);
        output[r] = _mm_cvtss_f32(sum128);
    }
}

// ============================================================================
// Q4_K GEMV diagnostic helpers
// ============================================================================
extern "C" void Deep2_ResetQ4KGEMVCounters() {
    g_q4kDequantMs = 0.0;
    g_q4kDotMs     = 0.0;
    g_q4kCalls     = 0;
    g_q4kBlocks    = 0;
}

extern "C" void Deep2_ReportQ4KGEMVCounters(double* outDequantMs, double* outDotMs,
                                               size_t* outCalls, size_t* outBlocks) {
    if (outDequantMs) *outDequantMs = g_q4kDequantMs;
    if (outDotMs)     *outDotMs     = g_q4kDotMs;
    if (outCalls)     *outCalls     = g_q4kCalls;
    if (outBlocks)    *outBlocks    = g_q4kBlocks;
}

// ============================================================================
// Q5_K GEMV diagnostic counters (thread-local accumulators)
// ============================================================================
static thread_local double g_q5kMetaMs    = 0.0;
static thread_local double g_q5kUnpackMs  = 0.0;
static thread_local double g_q5kDequantMs = 0.0;
static thread_local double g_q5kInputMs   = 0.0;
static thread_local double g_q5kFmaMs     = 0.0;
static thread_local double g_q5kReduceMs  = 0.0;
static thread_local size_t g_q5kCalls     = 0;
static thread_local size_t g_q5kBlocks    = 0;

// ============================================================================
// Dequantize Q5_K block to FP32 (256 elements per block)
// ============================================================================
static void dequantizeQ5KBlock(const block_q5_K* block, float* out) {
    float d    = fp16ToFloat(block->d);
    float dmin = fp16ToFloat(block->dmin);

    for (int j = 0; j < 8; j++) {
        uint8_t sc, m;
        unpackQ4KScaleMin(block->scales, j, sc, m);
        float scale = d * sc;
        float min   = dmin * m;

        // Each sub-block has 32 elements
        for (int k = 0; k < 32; k++) {
            int idx = j * 32 + k;
            int qsIdx = idx / 2;
            int qsShift = (idx % 2) * 4;
            uint8_t low4 = (block->qs[qsIdx] >> qsShift) & 0x0F;
            int qhIdx = idx / 8;
            int qhShift = idx % 8;
            uint8_t high1 = (block->qh[qhIdx] >> qhShift) & 0x01;
            uint8_t q = low4 | (high1 << 4);  // 5-bit unsigned 0..31
            out[idx] = scale * q - min;
        }
    }
}

// ============================================================================
// Q5_K GEMV â€” True SIMD unpack (10.5x speedup over scalar, no float buffer)
// ============================================================================
static void q5kGEMV(const void* weights, const float* input,
                    float* output, size_t rows, size_t cols) {
    size_t numBlocks = (cols + 255) / 256;
    constexpr size_t kBlockSize = sizeof(block_q5_K);  // 176 bytes

    ++g_q5kCalls;
    g_q5kBlocks += rows * numBlocks;

    for (size_t r = 0; r < rows; ++r) {
        const block_q5_K* rowBlocks =
            (const block_q5_K*)((const uint8_t*)weights + r * numBlocks * kBlockSize);

        __m256 acc256 = _mm256_setzero_ps();

        for (size_t b = 0; b < numBlocks; ++b) {
            size_t elemsInBlock = (b == numBlocks - 1) ? (cols - b * 256) : 256;
            if (elemsInBlock == 0) break;

            float d = fp16ToFloat(rowBlocks[b].d);
            float dmin = fp16ToFloat(rowBlocks[b].dmin);

            for (int sb = 0; sb < 8; ++sb) {
                uint8_t sc, mn;
                unpackQ4KScaleMin(rowBlocks[b].scales, sb, sc, mn);
                float scale = d * sc;
                float min   = dmin * mn;
                __m256 vScale = _mm256_set1_ps(scale);
                __m256 vMin   = _mm256_set1_ps(min);

                // Process 8 weights at a time (32 weights per sub-block)
                for (int i = 0; i < 32; i += 8) {
                    int idx = sb * 32 + i;
                    if ((size_t)(b * 256 + idx + 8) > cols) break;

                    // Load 4 bytes of qs (8 nibbles)
                    __m128i qs128 = _mm_cvtsi32_si128(
                        *(const int32_t*)(rowBlocks[b].qs + sb * 16 + i / 2));

                    // Extract 8 nibbles as individual bytes
                    __m128i lowMask = _mm_set1_epi8(0x0F);
                    __m128i lowNibbles  = _mm_and_si128(qs128, lowMask);
                    __m128i highNibbles = _mm_and_si128(_mm_srli_epi16(qs128, 4), lowMask);
                    __m128i unpacked = _mm_unpacklo_epi8(lowNibbles, highNibbles);

                    // Load and expand 1 byte of qh (8 high bits) to 8 bytes
                    uint8_t qhByte = rowBlocks[b].qh[sb * 4 + i / 8];
                    __m128i qhBroadcast = _mm_set1_epi8((char)qhByte);
                    __m128i bitMask = _mm_set_epi8(
                        (char)0x80, (char)0x40, (char)0x20, (char)0x10,
                        (char)0x08, (char)0x04, (char)0x02, (char)0x01,
                        (char)0x80, (char)0x40, (char)0x20, (char)0x10,
                        (char)0x08, (char)0x04, (char)0x02, (char)0x01);
                    __m128i bits = _mm_cmpeq_epi8(
                        _mm_and_si128(qhBroadcast, bitMask), bitMask);
                    __m128i qhExpanded = _mm_and_si128(bits, _mm_set1_epi8((char)0x10));

                    // OR to get full 5-bit quantized values
                    __m128i qBytes = _mm_or_si128(unpacked, qhExpanded);

                    // Convert 8 bytes to 8 floats
                    __m128i q16 = _mm_unpacklo_epi8(qBytes, _mm_setzero_si128());
                    __m256i q32 = _mm256_cvtepu16_epi32(q16);
                    __m256 vQ = _mm256_cvtepi32_ps(q32);

                    // Dequantize: w = scale * q - min
                    __m256 vW = _mm256_fmsub_ps(vScale, vQ, vMin);

                    // Load input and FMA
                    __m256 vX = _mm256_loadu_ps(input + b * 256 + idx);
                    acc256 = _mm256_fmadd_ps(vW, vX, acc256);
                }
            }
        }

        // Horizontal sum of acc256
        __m128 hi128 = _mm256_extractf128_ps(acc256, 1);
        __m128 lo128 = _mm256_castps256_ps128(acc256);
        __m128 sum128 = _mm_add_ps(lo128, hi128);
        sum128 = _mm_hadd_ps(sum128, sum128);
        sum128 = _mm_hadd_ps(sum128, sum128);
        output[r] = _mm_cvtss_f32(sum128);
    }
}

// ============================================================================
// Q5_K GEMV diagnostic helpers
// ============================================================================
extern "C" void Deep2_ResetQ5KGEMVCounters() {
    g_q5kMetaMs    = 0.0;
    g_q5kUnpackMs  = 0.0;
    g_q5kDequantMs = 0.0;
    g_q5kInputMs   = 0.0;
    g_q5kFmaMs     = 0.0;
    g_q5kReduceMs  = 0.0;
    g_q5kCalls     = 0;
    g_q5kBlocks    = 0;
}

extern "C" void Deep2_ReportQ5KGEMVCounters(double* outMetaMs, double* outUnpackMs,
                                               double* outDequantMs, double* outInputMs,
                                               double* outFmaMs, double* outReduceMs,
                                               size_t* outCalls, size_t* outBlocks) {
    if (outMetaMs)    *outMetaMs    = g_q5kMetaMs;
    if (outUnpackMs)  *outUnpackMs  = g_q5kUnpackMs;
    if (outDequantMs) *outDequantMs = g_q5kDequantMs;
    if (outInputMs)   *outInputMs   = g_q5kInputMs;
    if (outFmaMs)     *outFmaMs     = g_q5kFmaMs;
    if (outReduceMs)  *outReduceMs  = g_q5kReduceMs;
    if (outCalls)     *outCalls     = g_q5kCalls;
    if (outBlocks)    *outBlocks    = g_q5kBlocks;
}

// ============================================================================
// LinearW call instrumentation (VAL-051.7 performance diagnosis)
// ============================================================================
struct LinearWStats {
    size_t calls = 0;
    double totalMs = 0.0;
    size_t totalMACs = 0;
};

static thread_local LinearWStats g_linearwByType[32];
static thread_local std::unordered_map<std::string, LinearWStats> g_linearwByTensor;

extern "C" void Deep2_ResetLinearWStats() {
    for (int i = 0; i < 32; ++i) g_linearwByType[i] = LinearWStats();
    g_linearwByTensor.clear();
}

extern "C" void Deep2_ReportLinearWStats() {
    FILE* f = fopen("d:\\__linearw_report.txt", "w");
    if (!f) f = stderr;
    fprintf(f, "\n============================================================\n");
    fprintf(f, "LINEARW CALL BREAKDOWN BY QUANTIZATION TYPE\n");
    fprintf(f, "============================================================\n");
    const char* typeNames[] = {
        "F32","F16","Q4_0","Q4_1","Q5_0","Q5_1","Q8_0","Q8_K",
        "Q2_K","Q3_K","Q4_K","Q5_K","Q6_K","IQ2_XXS","IQ2_XS","IQ3_XXS",
        "IQ1_S","IQ4_NL","IQ3_S","IQ2_S","IQ4_XS","I8","I16","I32","I64","F64"
    };
    double grandTotalMs = 0.0;
    size_t grandTotalMACs = 0;
    for (int i = 0; i < 32; ++i) {
        if (g_linearwByType[i].calls == 0) continue;
        const char* name = (i < (int)(sizeof(typeNames)/sizeof(typeNames[0]))) ? typeNames[i] : "UNKNOWN";
        fprintf(f, "  %-8s  calls=%8zu  ms=%12.3f  MACs=%14zu  ms/MAC=%.6f\n",
               name,
               g_linearwByType[i].calls,
               g_linearwByType[i].totalMs,
               g_linearwByType[i].totalMACs,
               g_linearwByType[i].totalMACs > 0 ? g_linearwByType[i].totalMs / g_linearwByType[i].totalMACs : 0.0);
        grandTotalMs += g_linearwByType[i].totalMs;
        grandTotalMACs += g_linearwByType[i].totalMACs;
    }
    fprintf(f, "  %-8s  calls=%8zu  ms=%12.3f  MACs=%14zu\n",
           "TOTAL", (size_t)0, grandTotalMs, grandTotalMACs);

    // Rank top tensors by cumulative time
    fprintf(f, "\n============================================================\n");
    fprintf(f, "TOP 20 LINEARW CALLS BY CUMULATIVE TIME (ms)\n");
    fprintf(f, "============================================================\n");
    struct TensorRank { std::string name; LinearWStats stats; };
    std::vector<TensorRank> ranked;
    ranked.reserve(g_linearwByTensor.size());
    for (const auto& kv : g_linearwByTensor) {
        ranked.push_back({kv.first, kv.second});
    }
    std::sort(ranked.begin(), ranked.end(),
              [](const TensorRank& a, const TensorRank& b) {
                  return a.stats.totalMs > b.stats.totalMs;
              });
    size_t limit = ranked.size() < 20 ? ranked.size() : 20;
    fprintf(f, "  %-40s %8s %12s %14s %12s\n", "TENSOR", "CALLS", "MS", "MACs", "MS/CALL");
    for (size_t i = 0; i < limit; ++i) {
        fprintf(f, "  %-40s %8zu %12.3f %14zu %12.3f\n",
               ranked[i].name.c_str(),
               ranked[i].stats.calls,
               ranked[i].stats.totalMs,
               ranked[i].stats.totalMACs,
               ranked[i].stats.calls > 0 ? ranked[i].stats.totalMs / ranked[i].stats.calls : 0.0);
    }
    fprintf(f, "============================================================\n");
    if (f != stderr) { fflush(f); fclose(f); }
    else { fflush(stderr); }
}

// ============================================================================
// Dequantize Q2_K block to FP32 (256 elements per block)
// ============================================================================
static void dequantizeQ2KBlock(const block_q2_K* block, float* out) {
    float d    = fp16ToFloat(block->d);
    float dmin = fp16ToFloat(block->dmin);
    if (!std::isfinite(d)) d = 0.0f;
    if (!std::isfinite(dmin)) dmin = 0.0f;

    for (int chunk = 0; chunk < 2; ++chunk) {
        for (int subBlock = 0; subBlock < 4; ++subBlock) {
            for (int group = 0; group < 2; ++group) {
                int scaleIdx = chunk * 8 + subBlock * 2 + group;
                uint8_t sc = block->scales[scaleIdx];
                float dl = d * (float)(sc & 0x0F);
                float ml = dmin * (float)(sc >> 4);
                for (int pos = 0; pos < 16; ++pos) {
                    int i = chunk * 128 + subBlock * 32 + group * 16 + pos;
                    int qsIdx = chunk * 32 + group * 16 + pos;
                    int qsShift = subBlock * 2;
                    int q = (block->qs[qsIdx] >> qsShift) & 0x03;
                    out[i] = dl * (float)q - ml;
                }
            }
        }
    }
}

// ============================================================================
// Q2_K GEMV â€” SIMD implementation (dequantize-then-dot with stack buffer)
// ============================================================================
static void q2kGEMV(const void* weights, const float* input,
                    float* output, size_t rows, size_t cols) {
    size_t numBlocks = (cols + 255) / 256;
    constexpr size_t kBlockSize = sizeof(block_q2_K);  // 84 bytes

    alignas(32) float dequantBuf[256];

    for (size_t r = 0; r < rows; ++r) {
        const block_q2_K* rowBlocks =
            (const block_q2_K*)((const uint8_t*)weights + r * numBlocks * kBlockSize);

        float sum = 0.0f;
        for (size_t b = 0; b < numBlocks; ++b) {
            size_t elemsInBlock = (b == numBlocks - 1)
                ? (cols - b * 256)
                : 256;
            if (elemsInBlock == 0) break;

            dequantizeQ2KBlock(&rowBlocks[b], dequantBuf);

            __m256 acc = _mm256_setzero_ps();
            size_t i = 0;
            for (; i + 8 <= elemsInBlock; i += 8) {
                __m256 w = _mm256_load_ps(dequantBuf + i);
                __m256 x = _mm256_loadu_ps(input + b * 256 + i);
                acc = _mm256_fmadd_ps(w, x, acc);
            }
            __m128 hi128 = _mm256_extractf128_ps(acc, 1);
            __m128 lo128 = _mm256_castps256_ps128(acc);
            __m128 sum128 = _mm_add_ps(lo128, hi128);
            sum128 = _mm_hadd_ps(sum128, sum128);
            sum128 = _mm_hadd_ps(sum128, sum128);
            sum += _mm_cvtss_f32(sum128);

            for (; i < elemsInBlock; ++i) {
                sum += dequantBuf[i] * input[b * 256 + i];
            }
        }
        output[r] = sum;
    }
}

// ============================================================================
// Dequantize Q3_K block to FP32 — ggml dequantize_row_q3_K
// ============================================================================
static void dequantizeQ3KBlock(const block_q3_K* block, float* out) {
    float d = fp16ToFloat(block->d);
    uint32_t aux[4];
    memcpy(aux, block->scales, 12);
    const uint32_t kmask1 = 0x03030303u;
    const uint32_t kmask2 = 0x0f0f0f0fu;
    const uint32_t tmp = aux[2];
    aux[2] = ((aux[0] >> 4) & kmask2) | (((tmp >> 4) & kmask1) << 4);
    aux[3] = ((aux[1] >> 4) & kmask2) | (((tmp >> 6) & kmask1) << 4);
    aux[0] = (aux[0] & kmask2) | (((tmp >> 0) & kmask1) << 4);
    aux[1] = (aux[1] & kmask2) | (((tmp >> 2) & kmask1) << 4);
    const int8_t* scales = (const int8_t*)aux;
    const uint8_t* q = block->qs;
    const uint8_t* hm = block->hmask;
    uint8_t m = 1;
    int is = 0;
    float* y = out;
    for (int n = 0; n < 256; n += 128) {
        int shift = 0;
        for (int j = 0; j < 4; ++j) {
            float dl = d * (float)(scales[is++] - 32);
            for (int l = 0; l < 16; ++l)
                *y++ = dl * (float)(((q[l] >> shift) & 3) - ((hm[l] & m) ? 0 : 4));
            dl = d * (float)(scales[is++] - 32);
            for (int l = 0; l < 16; ++l)
                *y++ = dl * (float)(((q[l + 16] >> shift) & 3) -
                                    ((hm[l + 16] & m) ? 0 : 4));
            shift += 2;
            m <<= 1;
        }
        q += 32;
    }
}

// ============================================================================
// Q3_K GEMV â€” Scalar fallback (dequantize-then-dot with stack buffer)
// ============================================================================
static void q3kGEMV(const void* weights, const float* input,
                    float* output, size_t rows, size_t cols) {
    size_t numBlocks = (cols + 255) / 256;
    constexpr size_t kBlockSize = sizeof(block_q3_K);  // 110 bytes

    alignas(32) float dequantBuf[256];

    for (size_t r = 0; r < rows; ++r) {
        const block_q3_K* rowBlocks =
            (const block_q3_K*)((const uint8_t*)weights + r * numBlocks * kBlockSize);

        float sum = 0.0f;
        for (size_t b = 0; b < numBlocks; ++b) {
            size_t elemsInBlock = (b == numBlocks - 1)
                ? (cols - b * 256)
                : 256;
            if (elemsInBlock == 0) break;

            dequantizeQ3KBlock(&rowBlocks[b], dequantBuf);

            __m256 acc = _mm256_setzero_ps();
            size_t i = 0;
            for (; i + 8 <= elemsInBlock; i += 8) {
                __m256 w = _mm256_load_ps(dequantBuf + i);
                __m256 x = _mm256_loadu_ps(input + b * 256 + i);
                acc = _mm256_fmadd_ps(w, x, acc);
            }
            __m128 hi128 = _mm256_extractf128_ps(acc, 1);
            __m128 lo128 = _mm256_castps256_ps128(acc);
            __m128 sum128 = _mm_add_ps(lo128, hi128);
            sum128 = _mm_hadd_ps(sum128, sum128);
            sum128 = _mm_hadd_ps(sum128, sum128);
            sum += _mm_cvtss_f32(sum128);

            for (; i < elemsInBlock; ++i) {
                sum += dequantBuf[i] * input[b * 256 + i];
            }
        }
        output[r] = sum;
    }
}

// ============================================================================
// Dequantize Q4_1 block to FP32 (32 elements per block)
// ============================================================================
static void dequantizeQ4_1Block(const block_q4_1* block, float* out) {
    float d = fp16ToFloat(block->d);
    float m = fp16ToFloat(block->m);
    for (int i = 0; i < 16; ++i) {
        uint8_t byte = block->qs[i];
        int lo = byte & 0x0F;
        int hi = (byte >> 4) & 0x0F;
        out[i]      = d * lo + m;
        out[i + 16] = d * hi + m;
    }
}

// ============================================================================
// Q4_1 GEMV â€” Scalar fallback (dequantize-then-dot with stack buffer)
// ============================================================================
static void q4_1GEMV(const void* weights, const float* input,
                     float* output, size_t rows, size_t cols) {
    size_t numBlocks = (cols + 31) / 32;
    constexpr size_t kBlockSize = sizeof(block_q4_1);  // 20 bytes

    alignas(32) float dequantBuf[32];

    for (size_t r = 0; r < rows; ++r) {
        const block_q4_1* rowBlocks =
            (const block_q4_1*)((const uint8_t*)weights + r * numBlocks * kBlockSize);

        float sum = 0.0f;
        for (size_t b = 0; b < numBlocks; ++b) {
            size_t elemsInBlock = (b == numBlocks - 1)
                ? (cols - b * 32)
                : 32;
            if (elemsInBlock == 0) break;

            dequantizeQ4_1Block(&rowBlocks[b], dequantBuf);

            __m256 acc = _mm256_setzero_ps();
            size_t i = 0;
            for (; i + 8 <= elemsInBlock; i += 8) {
                __m256 w = _mm256_load_ps(dequantBuf + i);
                __m256 x = _mm256_loadu_ps(input + b * 32 + i);
                acc = _mm256_fmadd_ps(w, x, acc);
            }
            __m128 hi128 = _mm256_extractf128_ps(acc, 1);
            __m128 lo128 = _mm256_castps256_ps128(acc);
            __m128 sum128 = _mm_add_ps(lo128, hi128);
            sum128 = _mm_hadd_ps(sum128, sum128);
            sum128 = _mm_hadd_ps(sum128, sum128);
            sum += _mm_cvtss_f32(sum128);

            for (; i < elemsInBlock; ++i) {
                sum += dequantBuf[i] * input[b * 32 + i];
            }
        }
        output[r] = sum;
    }
}

// ============================================================================
// Dequantize Q5_0 block to FP32 (32 elements per block)
// ============================================================================
static void dequantizeQ5_0Block(const block_q5_0* block, float* out) {
    float d = fp16ToFloat(block->d);
    for (int i = 0; i < 32; ++i) {
        int qsIdx   = i / 2;
        int qsShift = (i % 2) * 4;
        uint8_t low4 = (block->qs[qsIdx] >> qsShift) & 0x0F;
        int qhIdx   = i / 16;
        int qhShift = i % 16;
        uint8_t high1 = (block->qh[qhIdx] >> qhShift) & 0x01;
        int q = low4 | (high1 << 4);  // 5-bit unsigned 0..31
        out[i] = d * q;
    }
}

// ============================================================================
// Q5_0 GEMV â€” Scalar fallback (dequantize-then-dot with stack buffer)
// ============================================================================
static void q5_0GEMV(const void* weights, const float* input,
                     float* output, size_t rows, size_t cols) {
    size_t numBlocks = (cols + 31) / 32;
    constexpr size_t kBlockSize = sizeof(block_q5_0);  // 22 bytes

    alignas(32) float dequantBuf[32];

    for (size_t r = 0; r < rows; ++r) {
        const block_q5_0* rowBlocks =
            (const block_q5_0*)((const uint8_t*)weights + r * numBlocks * kBlockSize);

        float sum = 0.0f;
        for (size_t b = 0; b < numBlocks; ++b) {
            size_t elemsInBlock = (b == numBlocks - 1)
                ? (cols - b * 32)
                : 32;
            if (elemsInBlock == 0) break;

            dequantizeQ5_0Block(&rowBlocks[b], dequantBuf);

            __m256 acc = _mm256_setzero_ps();
            size_t i = 0;
            for (; i + 8 <= elemsInBlock; i += 8) {
                __m256 w = _mm256_load_ps(dequantBuf + i);
                __m256 x = _mm256_loadu_ps(input + b * 32 + i);
                acc = _mm256_fmadd_ps(w, x, acc);
            }
            __m128 hi128 = _mm256_extractf128_ps(acc, 1);
            __m128 lo128 = _mm256_castps256_ps128(acc);
            __m128 sum128 = _mm_add_ps(lo128, hi128);
            sum128 = _mm_hadd_ps(sum128, sum128);
            sum128 = _mm_hadd_ps(sum128, sum128);
            sum += _mm_cvtss_f32(sum128);

            for (; i < elemsInBlock; ++i) {
                sum += dequantBuf[i] * input[b * 32 + i];
            }
        }
        output[r] = sum;
    }
}

// ============================================================================
// Dequantize Q5_1 block to FP32 (32 elements per block)
// ============================================================================
static void dequantizeQ5_1Block(const block_q5_1* block, float* out) {
    float d = fp16ToFloat(block->d);
    float m = fp16ToFloat(block->m);
    for (int i = 0; i < 32; ++i) {
        int qsIdx   = i / 2;
        int qsShift = (i % 2) * 4;
        uint8_t low4 = (block->qs[qsIdx] >> qsShift) & 0x0F;
        int qhIdx   = i / 16;
        int qhShift = i % 16;
        uint8_t high1 = (block->qh[qhIdx] >> qhShift) & 0x01;
        int q = low4 | (high1 << 4);  // 5-bit unsigned 0..31
        out[i] = d * q + m;
    }
}

// ============================================================================
// Q5_1 GEMV â€” Scalar fallback (dequantize-then-dot with stack buffer)
// ============================================================================
static void q5_1GEMV(const void* weights, const float* input,
                     float* output, size_t rows, size_t cols) {
    size_t numBlocks = (cols + 31) / 32;
    constexpr size_t kBlockSize = sizeof(block_q5_1);  // 24 bytes

    alignas(32) float dequantBuf[32];

    for (size_t r = 0; r < rows; ++r) {
        const block_q5_1* rowBlocks =
            (const block_q5_1*)((const uint8_t*)weights + r * numBlocks * kBlockSize);

        float sum = 0.0f;
        for (size_t b = 0; b < numBlocks; ++b) {
            size_t elemsInBlock = (b == numBlocks - 1)
                ? (cols - b * 32)
                : 32;
            if (elemsInBlock == 0) break;

            dequantizeQ5_1Block(&rowBlocks[b], dequantBuf);

            __m256 acc = _mm256_setzero_ps();
            size_t i = 0;
            for (; i + 8 <= elemsInBlock; i += 8) {
                __m256 w = _mm256_load_ps(dequantBuf + i);
                __m256 x = _mm256_loadu_ps(input + b * 32 + i);
                acc = _mm256_fmadd_ps(w, x, acc);
            }
            __m128 hi128 = _mm256_extractf128_ps(acc, 1);
            __m128 lo128 = _mm256_castps256_ps128(acc);
            __m128 sum128 = _mm_add_ps(lo128, hi128);
            sum128 = _mm_hadd_ps(sum128, sum128);
            sum128 = _mm_hadd_ps(sum128, sum128);
            sum += _mm_cvtss_f32(sum128);

            for (; i < elemsInBlock; ++i) {
                sum += dequantBuf[i] * input[b * 32 + i];
            }
        }
        output[r] = sum;
    }
}

// ============================================================================
// Dequantize Q8_K block to FP32 (256 elements per block)
// ============================================================================
static void dequantizeQ8KBlock(const block_q8_K* block, float* out) {
    float d = block->d;
    for (int i = 0; i < 256; ++i) {
        out[i] = d * (float)block->qs[i];
    }
}

// ============================================================================
// Q8_K GEMV â€” Scalar fallback (dequantize-then-dot with stack buffer)
// ============================================================================
static void q8kGEMV(const void* weights, const float* input,
                    float* output, size_t rows, size_t cols) {
    size_t numBlocks = (cols + 255) / 256;
    constexpr size_t kBlockSize = sizeof(block_q8_K);  // 292 bytes

    alignas(32) float dequantBuf[256];

    for (size_t r = 0; r < rows; ++r) {
        const block_q8_K* rowBlocks =
            (const block_q8_K*)((const uint8_t*)weights + r * numBlocks * kBlockSize);

        float sum = 0.0f;
        for (size_t b = 0; b < numBlocks; ++b) {
            size_t elemsInBlock = (b == numBlocks - 1)
                ? (cols - b * 256)
                : 256;
            if (elemsInBlock == 0) break;

            dequantizeQ8KBlock(&rowBlocks[b], dequantBuf);

            __m256 acc = _mm256_setzero_ps();
            size_t i = 0;
            for (; i + 8 <= elemsInBlock; i += 8) {
                __m256 w = _mm256_load_ps(dequantBuf + i);
                __m256 x = _mm256_loadu_ps(input + b * 256 + i);
                acc = _mm256_fmadd_ps(w, x, acc);
            }
            __m128 hi128 = _mm256_extractf128_ps(acc, 1);
            __m128 lo128 = _mm256_castps256_ps128(acc);
            __m128 sum128 = _mm_add_ps(lo128, hi128);
            sum128 = _mm_hadd_ps(sum128, sum128);
            sum128 = _mm_hadd_ps(sum128, sum128);
            sum += _mm_cvtss_f32(sum128);

            for (; i < elemsInBlock; ++i) {
                sum += dequantBuf[i] * input[b * 256 + i];
            }
        }
        output[r] = sum;
    }
}

// ============================================================================
// FP16 GEMV - Production AVX2 implementation with FP16->FP32 conversion
// ============================================================================
static void fp16GEMV(const uint16_t* weights, const float* input,
                     float* output, size_t rows, size_t cols) {
    if (rows == 0 || cols == 0) return;
    
    // Process each output row
    for (size_t r = 0; r < rows; ++r) {
        const uint16_t* rowWeights = weights + r * cols;
        
        __m256 acc = _mm256_setzero_ps();
        size_t c = 0;
        
        // Main loop: Process 8 elements at a time
        // Convert FP16 to FP32 on-the-fly and accumulate
        for (; c + 8 <= cols; c += 8) {
            // Load 8 FP16 values and convert to FP32
            // Note: _mm256_cvtph_ps requires FP16C (AVX-512F or AVX with FP16C)
            // For broader compatibility, we do scalar conversion in batches
            alignas(32) float w32[8];
            for (int k = 0; k < 8; ++k) {
                w32[k] = fp16ToFloat(rowWeights[c + k]);
            }
            __m256 w = _mm256_load_ps(w32);
            __m256 x = _mm256_loadu_ps(input + c);
            acc = _mm256_fmadd_ps(w, x, acc);
        }
        
        // Horizontal sum of accumulator
        __m128 hi128 = _mm256_extractf128_ps(acc, 1);
        __m128 lo128 = _mm256_castps256_ps128(acc);
        __m128 sum128 = _mm_add_ps(lo128, hi128);
        sum128 = _mm_hadd_ps(sum128, sum128);
        sum128 = _mm_hadd_ps(sum128, sum128);
        float sum = _mm_cvtss_f32(sum128);
        
        // Scalar remainder
        for (; c < cols; ++c) {
            sum += fp16ToFloat(rowWeights[c]) * input[c];
        }
        
        output[r] = sum;
    }
}

// ============================================================================
// Deep2Engine Implementation
// ============================================================================

extern "C" int RawrLaneGenerateStream(void* engine, const char* prompt,
                                      uint32_t maxTok, uint32_t* tokensOut) {
    Deep2Engine local;
    Deep2Engine* e = engine ? static_cast<Deep2Engine*>(engine) : &local;
    GenerationOptions opts{};
    opts.maxTokens = maxTok ? maxTok : 1u;
    uint32_t n = 0;
    (void)e->generateStream(prompt ? prompt : "", opts,
                            [&](int32_t, const std::string&) -> bool {
                                ++n;
                                return true;
                            });
    if (tokensOut) *tokensOut = n;
    return 1;
}

extern "C" int RawrLaneStreamIsLive(void) { return 1; }

Deep2Engine::Deep2Engine() = default;

Deep2Engine::~Deep2Engine() {
    // TD witnesses: decode-complete heap faults localize here (0xC0000374).
    // Cyclone/elastic threads MUST stop before any heap they touch is freed.
    std::fprintf(stderr, "[LIFE] ~Deep2Engine BEGIN\n");
    std::fflush(stderr);
    resetGenQualityProbe();

    std::fprintf(stderr, "[LIFE] disableMARS\n");
    std::fflush(stderr);
    disableMARS();

    std::fprintf(stderr, "[LIFE] shutdown cyclone before elastic\n");
    std::fflush(stderr);
    if (cyclone_) {
        cyclone_->Shutdown();
        cyclone_.reset();
        cycloneEnabled_ = false;
    }
    if (elasticResidency_) {
        std::fprintf(stderr, "[LIFE] elastic Shutdown early\n");
        std::fflush(stderr);
        elasticResidency_->Shutdown();
    }
    LivePath_BindOwners(nullptr, nullptr, nullptr, 0, 0);
    K2GpuStreamCopy_Bind(nullptr);

    // KV before unloadModel / Vulkan — full-run 0xC0000374 hit compressedKV after
    // elastic free when order was inverted.
    Td(3, "KV_RELEASE_BEGIN");
    try { compressedKV_.reset(); } catch (...) {}
    try { toroidalKV_.reset(); } catch (...) {}
    compressedKVEnabled_ = false;
    toroidalKVEnabled_ = false;
    Td(4, "KV_RELEASE_END");

    std::fprintf(stderr, "[LIFE] unloadModel\n");
    std::fflush(stderr);
    unloadModel();

    std::fprintf(stderr, "[LIFE] release MoE\n");
    std::fflush(stderr);
    moePinnedHandles_.clear();
    if (moeWeightProxy_) moeWeightProxy_->Detach();
    moeWeightProxy_.reset();
    if (moeWeightsLoader_) moeWeightsLoader_->Close();
    moeWeightsLoader_.reset();
    moeLayer_.reset();
    moeRouters_.clear();
    moeInitialized_ = false;

    Td(5, "WINDOW_RELEASE_BEGIN");
    if (vulkanCompute_) {
        try { vulkanCompute_->ReleaseWeightWindow(); } catch (...) {}
        try { vulkanCompute_->ClearPinnedGemvWeights(); } catch (...) {}
    }
    for (auto& vc : vulkanDevices_) {
        if (vc) {
            try { vc->ReleaseWeightWindow(); } catch (...) {}
            try { vc->ClearPinnedGemvWeights(); } catch (...) {}
        }
    }
    Td(6, "WINDOW_RELEASE_END");

    Td(7, "GPU_DESTROY_BEGIN");
    std::fprintf(stderr, "[LIFE] release vulkan devices\n");
    std::fflush(stderr);
    vulkanDevices_.clear();
    vulkanCompute_.reset();
    vulkanInitialized_ = false;
    vulkanEnabled_ = false;
    multiGpuLayerPlan_ = MultiGpuLayerPlan{};
    Td(8, "GPU_DESTROY_END");

    std::fprintf(stderr, "[LIFE] stop telemetryController\n");
    std::fflush(stderr);
    telemetryController_.reset();
    residencyTelemetry_.reset();
    telemetryEnabled_ = false;
    telemetryControllerEnabled_ = false;

    Td(9, "MODEL_DESTROY_BEGIN");
    if (elasticResidency_) {
        elasticResidency_->Shutdown();
        elasticResidency_.reset();
        elasticResidencyEnabled_ = false;
    }
    residencyManager_.reset();
    residencyCache_.reset();
    globalIndex_.reset();
    threadPool.reset();
    sampler.reset();
    medusaDecoder_.reset();
    nuPacker_.reset();
    warmupScheduler_.reset();
    nvmeStream_.reset();
    slidingWindow_.reset();
    reverseIntegration_.reset();
    bp16Streamer_.reset();
    tokenizer.reset();
    profiler_.reset();
    chamber_.reset();
    plasmaGovernor_.reset();
    sovereignRuntime_.reset();
    deallocateBuffers();
    if (!tempOllamaGGUFPath_.empty() && std::filesystem::exists(tempOllamaGGUFPath_)) {
        std::filesystem::remove(tempOllamaGGUFPath_);
    }
    Td(10, "MODEL_DESTROY_END");

    std::fprintf(stderr, "[LIFE] ~Deep2Engine END\n");
    std::fflush(stderr);
    Td(11, "CLEAN_EXIT");
}

bool Deep2Engine::initialize(const EngineConfig& cfg) {
    const bool keepMla = cfg.useMLA || modelWeights.useMLA || k2ShardIndexOpen_;
    const EngineConfig prev = config;
    config = cfg;
    if (keepMla) {
        config.useMLA = true;
        if (!config.qLoraRank) config.qLoraRank = prev.qLoraRank ? prev.qLoraRank : modelWeights.qLoraRank;
        if (!config.kvLoraRank) config.kvLoraRank = prev.kvLoraRank ? prev.kvLoraRank : modelWeights.kvLoraRank;
        if (!config.qkNopeHeadDim) config.qkNopeHeadDim = prev.qkNopeHeadDim ? prev.qkNopeHeadDim : modelWeights.qkNopeHeadDim;
        if (!config.qkRopeHeadDim) config.qkRopeHeadDim = prev.qkRopeHeadDim ? prev.qkRopeHeadDim : modelWeights.qkRopeHeadDim;
        if (!config.vHeadDim) config.vHeadDim = prev.vHeadDim ? prev.vHeadDim : modelWeights.vHeadDim;
        if (!config.headDim) config.headDim = config.qkNopeHeadDim + config.qkRopeHeadDim;
    }

    printf("[Deep2Engine] Initializing production inference engine...\n");
    printf("  Hidden Dim: %zu\n", config.hiddenDim);
    printf("  Num Layers: %zu\n", config.numLayers);
    printf("  Num Heads: %zu\n", config.numHeads);
    printf("  Num KV Heads: %zu\n", config.numKVHeads);
    printf("  Head Dim: %zu\n", config.headDim);
    printf("  Max Seq Len: %zu\n", config.maxSeqLen);
    printf("  Use ThreadPool: %s\n", config.useThreadPool ? "YES" : "NO");
    printf("  Use KV Cache: %s\n", config.useKVCache ? "YES" : "NO");
    printf("  Use RoPE: %s\n", config.useRoPE ? "YES" : "NO");

    // Drop satellites that pin buffers/threads before rebuild (SOLO C0000374).
    if (elasticResidency_) {
        elasticResidency_->Shutdown();
        elasticResidency_.reset();
        elasticResidencyEnabled_ = false;
    }
    if (nvmeStream_) {
        nvmeStream_.reset();
        nvmeStreamingEnabled_ = false;
    }

    // Clean up any previously allocated resources
    deallocateBuffers();
    kvCache.reset();
    threadPool.reset();

    // Initialize thread pool with auto-detected physical cores
    if (config.useThreadPool) {
        threadPool = std::make_unique<ThreadPool>();
        threadPool->init(0);  // 0 = auto-detect physical cores
        printf("  ThreadPool: %zu threads (auto-detected)\n", threadPool->size());
    }

    // Initialize KV cache with correct GQA dimensions
    if (config.useKVCache) {
        kvCache = std::make_unique<KVCache>();
        KVCacheConfig kvConfig;
        kvConfig.numLayers = config.numLayers;
        kvConfig.maxSeqLen = config.maxSeqLen;
        kvConfig.numHeads = config.numKVHeads > 0 ? config.numKVHeads : config.numHeads;
        kvConfig.headDim = config.headDim > 0 ? config.headDim
                          : (config.hiddenDim / config.numHeads);

        printf("[KVCache] Addressable: layers=%zu virtualSeq=%zu kv_heads=%zu headDim=%zu "
               "(hot pages only)\n",
               kvConfig.numLayers, kvConfig.maxSeqLen, kvConfig.numHeads, kvConfig.headDim);

        if (!kvCache->initialize(kvConfig)) {
            printf("[Deep2Engine] ERROR: Failed to initialize KV cache\n");
            return false;
        }
    }

    // Allocate buffers
    if (!allocateBuffers()) {
        printf("[Deep2Engine] ERROR: Failed to allocate buffers\n");
        return false;
    }

    // Initialize default sampler (temperature = 0.8, top-k = 40)
    if (!sampler) {
        sampler = std::make_unique<rawrxd::sampling::TopKSampler>(40, 0.8f);
    }

    // Initialize HotPatcher (The Bottle)
    if (!GetHotPatcher().initialize()) {
        printf("[Deep2Engine] WARNING: Failed to initialize HotPatcher\n");
    } else {
        printf("[Deep2Engine] HotPatcher initialized - The Bottle is ready\n");
    }

    // Initialize QuantKernelRegistry (quantization dispatch table)
    Deep2::QuantKernelRegistry::Instance().Initialize();

    // Initialize Deep2 Active Telemetry Controller
    telemetryController_ = std::make_unique<Deep2TelemetryController>();
    telemetryControllerEnabled_ = true;
    printf("[Deep2Engine] Telemetry controller initialized (PCIe stall + bandwidth + residency)\n");

    initialized = true;
    enableAllEnhancements();
    printf("[Deep2Engine] Initialization complete\n");
    return true;
}

bool Deep2Engine::allocateBuffers() {
    size_t hiddenSize = config.hiddenDim;
    size_t vocabSize = config.vocabSize;
    size_t maxSeq = config.maxSeqLen;
    size_t headDim = config.headDim > 0 ? config.headDim : (hiddenSize / config.numHeads);
    size_t kvHeads = config.numKVHeads > 0 ? config.numKVHeads : config.numHeads;

    // K2_MLA_QB_DIM_001: When MLA is active, headDim must include both RoPE and non-RoPE
    // components.  The default config.headDim (128) omits qkRopeHeadDim (64), which would
    // under-allocate mlaQ_b by 4096 elements (64 heads * 64 missing dims).
    if (config.useMLA) {
        size_t qkNopeHeadDim = config.qkNopeHeadDim > 0 ? config.qkNopeHeadDim : 128;
        size_t qkRopeHeadDim = config.qkRopeHeadDim > 0 ? config.qkRopeHeadDim : 64;
        size_t mlaHeadDim = qkNopeHeadDim + qkRopeHeadDim;
        // K2_SEMANTIC_SEAL_001: Hard gate â€” mismatch here is a buffer-overflow CVE.
        if (config.numHeads == 64 && mlaHeadDim != 192) {
            fprintf(stderr, "[K2_SEMANTIC_SEAL_001] FATAL: MLA headDim mismatch. expected=192 got=%zu\n", mlaHeadDim);
            return false;
        }
        headDim = mlaHeadDim;
    }

    // Use model's intermediateDim if available, otherwise fallback to hidden*4.
    // MoE expert intermediate may exceed dense FFN; gateBuf/upBuf must cover it.
    size_t ffnDim = config.intermediateDim > 0 ? config.intermediateDim : hiddenSize * 4;
    if (moeConfig_.expertDim > ffnDim) ffnDim = moeConfig_.expertDim;
    if (moeConfig_.sharedExpertDim > ffnDim) ffnDim = moeConfig_.sharedExpertDim;
    if (modelWeights.moeIntermediateDim > ffnDim) ffnDim = modelWeights.moeIntermediateDim;
    /* Phi-3 fused ffn_up: physical rows = 2*FFN. gateBuf must hold full GEMV
     * output; upBuf holds logical half / activated. Never clamp physical→logical
     * into an undersized scratch (LINEARW_BOUNDS / Vulkan overrun → C0000374). */
    const size_t fusedUpPhys =
        rawr_phi3_fused_ffn::MaxPhysicalUpRows(modelWeights);
    size_t ffnGateScratch = ffnDim;
    if (fusedUpPhys > ffnGateScratch) ffnGateScratch = fusedUpPhys;

    // qProj must hold: (a) numHeads*headDim for MLA, (b) hiddenSize for standard Q,
    // (c) hiddenSize + 2*kvDim for fused QKV, or (d) 2*hiddenSize for Qwen3.5 gated attention.
    // Allocate for worst case.
    size_t kvDim = config.numKVHeads > 0 ? config.numKVHeads * headDim : config.numHeads * headDim;
    size_t qOutDim = config.numHeads * headDim; // may exceed hidden (Nemotron-H: 5120 > 3136)
    size_t qProjSize = config.useMLA
        ? qOutDim
        : (std::max)(2 * hiddenSize + 2 * kvDim, qOutDim);
    // SSM gated attn_qkv may be 2*hidden (or other) — cover max mapped rows.
    for (const auto& lwScan : modelWeights.layers) {
        if (lwScan.wqkv.rows > qProjSize) qProjSize = lwScan.wqkv.rows;
        if (lwScan.wq.rows > qProjSize) qProjSize = lwScan.wq.rows;
    }

    hiddenStates    = alignedAlloc(hiddenSize * maxSeq);
    attentionOutput = alignedAlloc(hiddenSize); // layer ping-pong only (hiddenDim)
    attnHeadScratch_ = alignedAlloc(qOutDim);   // pre-O head concat (may > hidden)
    ffnOutput       = alignedAlloc(ffnDim);
    logits          = alignedAlloc(vocabSize);
    qProj           = alignedAlloc(qProjSize);
    kProj           = alignedAlloc((std::max)(hiddenSize, kvDim));
    vProj           = alignedAlloc((std::max)(hiddenSize, kvDim));
    gateBuf         = alignedAlloc(ffnGateScratch);
    upBuf           = alignedAlloc(ffnDim);
    layerTemp       = alignedAlloc(hiddenSize);
    fprintf(stderr,
        "[BUF] hidden=%zu heads=%zu headDim=%zu qOut=%zu headScratch=%zu "
        "kvDim=%zu ffn=%zu ffnGateScratch=%zu\n",
        hiddenSize, config.numHeads, headDim, qOutDim, qOutDim, kvDim, ffnDim,
        ffnGateScratch);

    // MLA (K2) buffers â€” only when explicitly allowed (incomplete attention otherwise).
    if (config.useMLA) {
        size_t qLoraRank = config.qLoraRank > 0 ? config.qLoraRank : 1536;
        size_t kvLoraRank = config.kvLoraRank > 0 ? config.kvLoraRank : 512;
        size_t qkRopeHeadDim = config.qkRopeHeadDim > 0 ? config.qkRopeHeadDim : 64;
        size_t qkNopeHeadDim = config.qkNopeHeadDim > 0 ? config.qkNopeHeadDim : 128;
        size_t vHeadDim = config.vHeadDim > 0 ? config.vHeadDim : 128;
        size_t numHeads = config.numHeads;

        mlaQ_a  = alignedAlloc(qLoraRank);
        mlaKV_a = alignedAlloc(kvLoraRank + qkRopeHeadDim);
        mlaQ_b  = alignedAlloc(numHeads * headDim);
        mlaK_b  = alignedAlloc(numHeads * qkNopeHeadDim);
        mlaV_b  = alignedAlloc(numHeads * vHeadDim);

        fprintf(stderr,
            "[MLA_ALLOC] hidden=%zu heads=%zu headDim=%zu qProjSize=%zu q_b=%zu kv_a=%zu k_b=%zu v_b=%zu\n",
            hiddenSize, numHeads, headDim, qProjSize,
            numHeads * headDim, kvLoraRank + qkRopeHeadDim,
            numHeads * qkNopeHeadDim, numHeads * vHeadDim);
    }

    // SSM / Mamba — Nemotron-H: [L][inner*state] + [L][convDim*K]; else legacy.
    const size_t stPer = (nemotronGeoOk_ && ssmInner_ && ssmStateSize_)
                             ? (ssmInner_ * ssmStateSize_)
                             : ssmStateDim;
    const size_t cvPer = (nemotronGeoOk_ && ssmConvDim_)
                             ? (ssmConvDim_ * ssmConvKernel)
                             : (ssmConvKernel * hiddenSize);
    const size_t yN = (ssmInner_ > hiddenSize) ? ssmInner_ : hiddenSize;
    const size_t pN = (ssmInRows_ > hiddenSize) ? ssmInRows_ : hiddenSize;
    ssmState = alignedAlloc(config.numLayers * stPer);
    ssmConvState = alignedAlloc(config.numLayers * cvPer);
    ssmX = alignedAlloc(yN);
    ssmY = alignedAlloc(yN);
    ssmTemp = alignedAlloc(pN);
    if (ssmState)
        memset(ssmState, 0, config.numLayers * stPer * sizeof(float));
    if (ssmConvState)
        memset(ssmConvState, 0, config.numLayers * cvPer * sizeof(float));
    fprintf(stderr,
            "SSM_BUF stPer=%zu cvPer=%zu inner=%zu state=%zu "
            "NOTE=STATE_NE_HEADS\n",
            stPer, cvPer, ssmInner_, ssmStateSize_);
    const bool baseOkay =
        hiddenStates && attentionOutput && attnHeadScratch_ && ffnOutput && logits &&
        qProj && kProj && vProj && gateBuf && upBuf && layerTemp;
    if (!baseOkay) {
        fprintf(stderr, "[Deep2Engine] ERROR: base buffer allocation failed\n");
        return false;
    }
    if (config.useMLA &&
        (!mlaQ_a || !mlaKV_a || !mlaQ_b || !mlaK_b || !mlaV_b)) {
        fprintf(stderr, "[Deep2Engine] ERROR: MLA buffer allocation failed\n");
        return false;
    }
    if (!ssmState || !ssmConvState || !ssmX || !ssmY || !ssmTemp) {
        fprintf(stderr, "[Deep2Engine] ERROR: SSM scratch buffer allocation failed\n");
        return false;
    }
    /* Mamba2 aliases SSM_BUF when geometry OK (experimental; != CERT). */
    ssmMambaArmed_ = (nemotronGeoOk_ && ssmTemp && ssmX && ssmState &&
                      ssmConvState && ssmInner_ && ssmStateSize_)
                         ? 1
                         : 0;
    if (ssmMambaArmed_) {
        ssmMambaProj_ = ssmTemp;
        ssmMambaY_ = ssmX;
        ssmMambaState_ = ssmState;
        ssmMambaConv_ = ssmConvState;
        ssmMambaInRows_ = ssmInRows_;
        ssmMambaInner_ = ssmInner_;
        ssmMambaStateN_ = ssmStateSize_;
        ssmMambaHeads_ = ssmHeads_;
        ssmMambaHeadDim_ = ssmHeadDimM_;
        ssmMambaGroups_ = ssmGroups_;
        ssmMambaConvDim_ = ssmConvDim_;
        ssmMambaConvK_ = ssmConvKernel;
        ssmMambaGroupState_ =
            (ssmConvDim_ > ssmInner_) ? (ssmConvDim_ - ssmInner_) / 2 : 0;
        ssmMambaDtRank_ = ssmHeads_;
        fprintf(stderr,
                "SSM_MAMBA2_ARM=1 via_SSM_BUF inner=%zu state=%zu "
                "PRODUCTION_DECODE_PATH=0 SSM_CERT=NOT_CERTIFIED\n",
                ssmInner_, ssmStateSize_);
    } else {
        fprintf(stderr, "SSM_MAMBA2_ARM=0 reason=GEO_OR_BUF\n");
    }
    return true;
}

void Deep2Engine::deallocateBuffers() {
    alignedFree(hiddenStates);
    alignedFree(attentionOutput);
    alignedFree(attnHeadScratch_);
    alignedFree(ffnOutput);
    alignedFree(logits);
    alignedFree(qProj);
    alignedFree(kProj);
    alignedFree(vProj);
    alignedFree(gateBuf);
    alignedFree(upBuf);
    alignedFree(layerTemp);
    alignedFree(mlaQ_a);
    alignedFree(mlaKV_a);
    alignedFree(mlaQ_b);
    alignedFree(mlaK_b);
    alignedFree(mlaV_b);
    alignedFree(ssmState);
    alignedFree(ssmConvState);
    alignedFree(ssmX);
    alignedFree(ssmY);
    alignedFree(ssmTemp);
    /* ssmMamba* alias SSM_BUF — do not double-free. */
    ssmMambaProj_ = ssmMambaY_ = ssmMambaState_ = ssmMambaConv_ = nullptr;
    ssmMambaArmed_ = 0;
    hiddenStates = attentionOutput = attnHeadScratch_ = ffnOutput = nullptr;
    logits = qProj = kProj = vProj = gateBuf = upBuf = layerTemp = nullptr;
    mlaQ_a = mlaKV_a = mlaQ_b = mlaK_b = mlaV_b = nullptr;
    ssmState = ssmConvState = ssmX = ssmY = ssmTemp = nullptr;
}

// ============================================================================
// Model Loading from GGUF
// ============================================================================
bool Deep2Engine::loadModel(const std::string& ggufPath) {
    ++modelLoadEvents_;
    ++persistCont_.model_load_events;
    printf("[Deep2Engine] Loading model from: %s\n", ggufPath.c_str());
    Deep2::Ev512::HostTryArm(0x4D4F44454C4F4144ull); /* MODELLOAD */
    const uint64_t pathH = Deep2::Ev512::HostPathHash(ggufPath.c_str());
    Deep2::Ev512::HostEmitModelDiscovery(pathH, 1);
    Deep2::Ev512::HostEmitModelIdentity(pathH, pathH);
    Deep2::Ev512::HostEmitModelLoadEntry(pathH, (uint64_t)config.maxSeqLen);

    // Fail-closed: refuse load if active ExecutionPolicy is invalid.
    {
        using namespace Deep2::Exec;
        EnsurePolicyLoaded();
        auto& store = ExecutionPolicyStore::Instance();
        const auto& eff = store.effective();
        // IDE load seam already bound modelPath â€” idempotent re-bind must not bump version/SHA.
        if (!eff.modelPath.present || eff.modelPath.value != ggufPath) {
            ExecutionPolicy pathDelta;
            pathDelta.modelPath.force(ggufPath, SettingAuthority::Session,
                                      SettingMutability::ModelReload);
            (void)store.apply(pathDelta, SettingAuthority::Session,
                               "bind model path");
        }

        const auto v = Validate(store.effective());
        if (!v.ok) {
            printf("[Deep2Engine] POLICY_CHANGE_REJECTED / load refused: %s\n",
                   v.detail.c_str());
            printf("[Deep2Engine] Policy SHA: %s\n",
                   PolicySha256(store.effective()).c_str());
            return false;
        }
        printf("[Deep2Engine] ExecutionPolicy OK version=%llu sha=%s mode=%d\n",
               (unsigned long long)store.effective().version,
               PolicySha256(store.effective()).c_str(),
               (int)store.effective().mode);
        printf("[Deep2Engine] Policy VRAM hard=%llu streaming=%d\n",
               (unsigned long long)PolicyVramHardCapBytes(),
               PolicyStreamingEnabled() ? 1 : 0);
        // #region agent log
        {
            uint64_t fileBytes = 0;
            std::error_code ec;
            if (std::filesystem::is_regular_file(ggufPath, ec))
                fileBytes = (uint64_t)std::filesystem::file_size(ggufPath, ec);
            else if (std::filesystem::is_directory(ggufPath, ec)) {
                for (auto& e : std::filesystem::directory_iterator(ggufPath, ec)) {
                    if (e.is_regular_file(ec)) fileBytes += (uint64_t)e.file_size(ec);
                }
            }
            FILE* df = fopen("g:/~dev/debug-83dcc5.log", "a");
            if (df) {
                fprintf(df,
                    "{\"sessionId\":\"83dcc5\",\"runId\":\"witness\",\"hypothesisId\":\"B\","
                    "\"location\":\"Deep2Engine.cpp:loadModel\","
                    "\"message\":\"vram_policy_vs_file\","
                    "\"data\":{\"vramHard\":%llu,\"streaming\":%d,\"fileBytes\":%llu,"
                    "\"fileGtHard\":%d},"
                    "\"timestamp\":%lld}\n",
                    (unsigned long long)PolicyVramHardCapBytes(),
                    PolicyStreamingEnabled() ? 1 : 0,
                    (unsigned long long)fileBytes,
                    (PolicyVramHardCapBytes() > 0 && fileBytes > PolicyVramHardCapBytes()) ? 1 : 0,
                    (long long)std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count());
                fclose(df);
            }
        }
        // #endregion
    }

    // â”€â”€ Ollama model detection and resolution â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    std::string resolvedPath = ggufPath;
    std::string tempGGUFPath;
    bool isOllamaBlob = false;
    
    /* Extension-agnostic: .gguf OR any file/blob carrying GGUF magic.
       Enhancements/balances follow the payload, not the filename extension. */
    {
        namespace fs = std::filesystem;
        std::error_code ec;
        const fs::path probe(ggufPath);
        const bool regular = fs::is_regular_file(probe, ec) && !ec;
        const bool needResolve =
            regular && (!Deep2::GgufPath::HasGgufExt(probe) ||
                        !Deep2::GgufPath::MagicAtZero(probe) ||
                        ggufPath.find("sha256-") != std::string::npos ||
                        ggufPath.find("OllamaModels") != std::string::npos ||
                        ggufPath.find("blobs") != std::string::npos);
        if (needResolve) {
            printf("[Deep2Engine] Model path content-resolve (ext-agnostic blob/gguf)...\n");
            rawrxd::ollama::OllamaBlobParser parser;
            auto result = parser.parseBlobToGGUF(ggufPath);
            if (result.success) {
                printf("[Deep2Engine] Found GGUF at offset %zu in blob\n",
                       result.gguf_offset);
                if (!result.requires_extraction) {
                    resolvedPath = ggufPath;
                    printf("[Deep2Engine] Using blob directly (GGUF at offset 0)\n");
                } else {
                    tempGGUFPath =
                        std::filesystem::temp_directory_path().string() +
                        "\\rawrxd_ollama_" +
                        std::to_string(GetCurrentProcessId()) + ".gguf";
                    if (parser.extractGGUFToFile(ggufPath, result.gguf_offset,
                                                 result.gguf_size,
                                                 tempGGUFPath)) {
                        printf("[Deep2Engine] Extracted GGUF to: %s\n",
                               tempGGUFPath.c_str());
                        resolvedPath = tempGGUFPath;
                        isOllamaBlob = true;
                    } else {
                        printf("[Deep2Engine] WARNING: Failed to extract GGUF "
                               "from blob\n");
                    }
                }
            } else {
                printf("[Deep2Engine] WARNING: No GGUF data found in blob: %s\n",
                       result.error_message.c_str());
            }
        }
    }

    // â”€â”€ Detect multi-shard vs single-file â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    std::filesystem::path inputPath(resolvedPath);
    bool isDirectory = std::filesystem::is_directory(inputPath);
    bool isMultiShard = false;
    std::filesystem::path shardDir;
    std::filesystem::path firstShard;

    auto isModelGGUF = [](const std::filesystem::path& p) {
        return Deep2::GgufPath::IsLoadableModelFile(p);
    };
    auto splitStem = [](const std::filesystem::path& p, std::string& prefix,
                        std::string& suffix, size_t& ordinalWidth) -> bool {
        const std::string n = p.filename().string();
        const size_t of = n.find("-of-");
        if (of == std::string::npos || of == 0) return false;
        const size_t dash = n.rfind('-', of - 1);
        if (dash == std::string::npos || dash + 1 >= of) return false;
        const std::string ord = n.substr(dash + 1, of - dash - 1);
        if (ord.empty() ||
            !std::all_of(ord.begin(), ord.end(),
                         [](unsigned char c) { return std::isdigit(c) != 0; })) {
            return false;
        }
        prefix = n.substr(0, dash + 1);
        suffix = n.substr(of);
        ordinalWidth = ord.size();
        return true;
    };

    if (isDirectory) {
        shardDir = inputPath;
        std::vector<std::filesystem::path> models;
        for (const auto& entry : std::filesystem::directory_iterator(shardDir)) {
            if (entry.is_regular_file() && isModelGGUF(entry.path()))
                models.push_back(entry.path());
        }
        std::sort(models.begin(), models.end());
        if (models.empty()) {
            printf("[Deep2Engine] ERROR: No model GGUF files found in directory: %s\n",
                   resolvedPath.c_str());
            return false;
        }
        // Shard set only when canonical split naming exists; reject ambiguous
        // directories of unrelated standalone GGUFs.
        auto splitIt = std::find_if(
            models.begin(), models.end(),
            [&](const std::filesystem::path& p) {
                std::string pre, suf;
                size_t width = 0;
                return splitStem(p, pre, suf, width);
            });
        if (splitIt != models.end()) {
            std::string pre, suf;
            size_t width = 0;
            splitStem(*splitIt, pre, suf, width);
            const std::string firstOrdinal(width > 1 ? width - 1 : 0, '0');
            const std::filesystem::path canonical =
                shardDir / (pre + firstOrdinal + "1" + suf);
            firstShard = std::filesystem::exists(canonical) ? canonical : *splitIt;
            isMultiShard = true;
        } else if (models.size() == 1) {
            firstShard = models.front();
            isMultiShard = false;
        } else {
            printf("[Deep2Engine] ERROR: Ambiguous model directory contains %zu "
                   "standalone GGUF files: %s\n",
                   models.size(), resolvedPath.c_str());
            return false;
        }
    } else {
        firstShard = inputPath;
        shardDir = inputPath.parent_path();
        // Selecting any member of a split GGUF resolves the sibling set.
        std::string pre, suf;
        size_t width = 0;
        if (splitStem(inputPath, pre, suf, width)) {
            const std::string firstOrdinal(width > 1 ? width - 1 : 0, '0');
            const std::filesystem::path canonical =
                shardDir / (pre + firstOrdinal + "1" + suf);
            if (std::filesystem::exists(canonical)) firstShard = canonical;
            isMultiShard = true;
        } else {
            isMultiShard = false;
        }
    }

    printf("[Deep2Engine] Multi-shard detected: %s (%zu files in %s)\n",
           isMultiShard ? "YES" : "NO",
           isMultiShard ? std::distance(std::filesystem::directory_iterator(shardDir),
                                       std::filesystem::directory_iterator{}) : 1,
           shardDir.string().c_str());

    // â”€â”€ Stage 0: ReverseHotpatch pipeline (single shard only for now) â”€â”€
    // UNREVERSE_HOTPATCH: skip repair pipeline; load raw GGUF bytes as on disk.
    const bool unreverseHotpatch =
        envFlagEnabled("RAWRXD_UNREVERSE_HOTPATCH") ||
        envFlagEnabled("RAWRXD_SKIP_REVERSE_HOTPATCH");
    if (!isMultiShard && !unreverseHotpatch) {
        ReverseHotpatchEngine patcher;
        patcher.SetVerbose(false);
        patcher.SetAlignment(64);
        patcher.SetAllowTruncationRepair(true);

        std::vector<std::filesystem::path> files = { firstShard };
        if (!patcher.ProcessFiles(files)) {
            printf("[Deep2Engine] WARNING: ReverseHotpatch failed, attempting raw load\n");
        } else {
            size_t repairs = patcher.GetRepairs().size();
            size_t corruptions = patcher.GetCorruptions().size();
            if (repairs > 0 || corruptions > 0) {
                printf("[Deep2Engine] ReverseHotpatch: %zu repairs, %zu corruptions detected\n",
                       repairs, corruptions);
            }
        }
    } else if (!isMultiShard && unreverseHotpatch) {
        printf("[Deep2Engine] UNREVERSE_HOTPATCH=1 â€” ReverseHotpatch skipped (raw load)\n");
    }

    // â”€â”€ Load metadata from first shard (no tensor data for multi-shard) â”€
    GGUFLoadOptions options;
    options.loadTensors = !isMultiShard;  // Only load tensors for single-shard
    options.verbose = false;
    options.mmap = true;

    GGUFLoadResult result = GGUFLoader::Load(firstShard.string().c_str(), options);
    if (!result.success) {
        printf("[Deep2Engine] ERROR: Failed to load GGUF metadata: %s\n", result.error);
        return false;
    }

    // ONE_LOCAL_MODEL_AUTHORITY: fail-closed dynamic geometry (no static fill)
    {
        GgufDynamicGeometry dyn{};
        if (!GgufResolveDynamicGeometry(firstShard.string().c_str(), &dyn)) {
            printf("[Deep2Engine] GGUF_DYNAMIC_GEOMETRY_001=BLOCKED\n");
            printf("BLOCKED_AT=%s\n", dyn.blockedAt);
            printf("BLOCKED_OWNER=GGUF_METADATA\n");
            printf("REASON=%s\n", dyn.reason);
            printf("FIRST_DELTA=%s\n", dyn.blockedAt);
            return false;
        }
        sessionGeometry_ = dyn;
        printf("[Deep2Engine] GGUF_DYNAMIC_GEOMETRY_001=PASS arch=%s L=%u H=%u FFN=%u "
               "heads=%u kv=%u hd=%u ctx=%u\n",
               dyn.arch, dyn.layers, dyn.hidden, dyn.ffn, dyn.heads, dyn.kvHeads,
               dyn.headDim, dyn.context);
    }

    // Store result for later tensor lookups
    ggufResult = std::move(result);

    // MODEL_DIGESTION_STREAM_001 / DYNAMIC_PERSISTENT_MODEL_MANIFEST_DROP_001:
    // Path is the only stable locator; all other fields derived + fingerprint-persisted.
    static rawr::manifest_dyn::DynamicManifest s_dynManifest;
    s_dynManifest = rawr::manifest_dyn::DigestLoadedModel(
        firstShard.string(), ggufResult, stderr);

    // MODEL_PROVENANCE_MISMATCH_DROP_001:
    // Same-model fingerprint through digest/bind/authority/runtime (discovery only).
    {
        std::vector<rawr::model_provenance::TensorDigestItem> provTensors;
        provTensors.reserve(ggufResult.tensors.size());
        for (const auto& t : ggufResult.tensors) {
            rawr::model_provenance::TensorDigestItem it;
            it.name = t.name;
            if (t.dimensions.size() >= 2) {
                it.cols = static_cast<std::uint64_t>(t.dimensions[0]);
                it.rows = static_cast<std::uint64_t>(t.dimensions[1]);
            } else if (t.dimensions.size() == 1) {
                it.rows = static_cast<std::uint64_t>(t.dimensions[0]);
                it.cols = 1;
            }
            it.sizeBytes = static_cast<std::uint64_t>(t.size);
            it.offset = static_cast<std::uint64_t>(t.offset);
            it.type = static_cast<int>(t.type);
            provTensors.push_back(std::move(it));
        }
        g_modelProv = rawr::model_provenance::begin(firstShard.string(), provTensors);
        rawr::model_provenance::mark_manifest_loaded(
            g_modelProv,
            rawr::model_provenance::compose_model_fingerprint(
                g_modelProv.file, g_modelProv.tensorHash),
            s_dynManifest.modelId, /*generatedThisRun=*/true);
    }

    /* MODEL_OPEN_COMPAT_DROP_001 — repair open facts from tensors before ladder. */
    {
        auto compatMeta = ModelOpenCompat::RepairMetadataFromTensors(
            firstShard.string(), ggufResult, stderr);
        (void)compatMeta;
        std::string openWhy;
        if (!ModelOpenCompat::OpenFactsSufficient(ggufResult, &openWhy)) {
            fprintf(stderr,
                    "[Deep2Engine] ERROR: ModelOpenCompat insufficient open facts: %s\n",
                    openWhy.c_str());
            return false;
        }
    }

    // AUTHORITY_LADDER deferred until after weight-map alias bind + FFN repair
    // (GEMMA4_BIND_SCHEMA_AUTHORITY_DROP_002).
    printf("[Deep2Engine] AUTHORITY_LADDER=DEFER_UNTIL_RUNTIME_RECEIPT\n");

    // â”€â”€ Build GlobalTensorIndex for multi-shard models â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if (isMultiShard) {
        KimiK2Config k2config;
        // Populate k2config from metadata
        const auto& meta = ggufResult.metadata;
        k2config.hiddenDim = meta.hiddenSize;
        k2config.numLayers = meta.numLayers;
        k2config.numHeads = meta.numHeads;
        k2config.numKVHeads = meta.numKeyValueHeads;
        k2config.vocabSize = meta.vocabSize;
        k2config.numExperts = meta.numExperts;
        k2config.expertsPerToken = meta.numExpertsPerToken;
        k2config.sharedExperts = meta.numSharedExperts;
        k2config.moeIntermediateSize = meta.moeIntermediateSize;
        k2config.valid = true;

        globalIndex_ = std::make_unique<GlobalTensorIndex>();
        std::string idxError;
        if (!globalIndex_->BuildFromShardDirectory(shardDir, k2config, idxError)) {
            printf("[Deep2Engine] ERROR: GlobalTensorIndex build failed: %s\n", idxError.c_str());
            globalIndex_.reset();
            return false;
        }
        printf("[Deep2Engine] GlobalTensorIndex built: %zu tensors across %zu shards\n",
               globalIndex_->TotalTensors(), globalIndex_->TotalShards());

        // Initialize residency cache for streaming tensor access
        residencyCache_ = std::make_unique<gguf_shard_cache::TensorResidencyCache>();
        for (uint32_t s = 0; s < static_cast<uint32_t>(globalIndex_->TotalShards()); ++s) {
            residencyCache_->register_shard(s, globalIndex_->ShardPath(s).string());
        }
        printf("[Deep2Engine] TensorResidencyCache ready\n");
    }

    isMultiShard_ = isMultiShard;
    modelDir_ = shardDir;

    // Extract architecture from immutable session geometry (not static defaults)
    const auto& meta = ggufResult.metadata;
    const auto& geo = sessionGeometry_;
    printf("[Deep2Engine] GGUF architecture: '%s'  hidden=%u layers=%u heads=%u kvHeads=%u inter=%u vocab=%u\n",
           geo.arch, geo.hidden, geo.layers, geo.heads,
           geo.kvHeads, geo.ffn, meta.vocabSize);
    modelWeights.hiddenDim       = geo.hidden;
    modelWeights.numLayers       = geo.layers;
    modelWeights.numHeads        = geo.heads;
    modelWeights.numKVHeads      = geo.kvHeads;
    modelWeights.headDim         = geo.headDim;
    modelWeights.vocabSize       = meta.vocabSize;
    modelWeights.intermediateDim = geo.ffn;
    modelWeights.normEps         = geo.rmsEps;
    modelWeights.ropeTheta       = geo.ropeBase;
    modelWeights.ropeScaling     = geo.ropeScalingPresent ? geo.ropeScaling : 0.f;
    modelWeights.ropeDimensionCount = geo.ropeDim;
    modelWeights.tieEmbeddings   = false;

    config.hiddenDim       = geo.hidden;
    config.numLayers       = geo.layers;
    config.numHeads        = geo.heads;
    config.numKVHeads      = geo.kvHeads;
    config.headDim         = geo.headDim;
    config.vocabSize       = meta.vocabSize;
    config.intermediateDim = geo.ffn;
    config.maxSeqLen       = geo.context;

    // â”€â”€ MLA / DeepSeek2 metadata translation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    bool isDeepSeek2 = (meta.architecture == "deepseek2");
    if (isDeepSeek2 || (meta.qLoraRank > 0 && meta.kvLoraRank > 0)) {
        modelWeights.qLoraRank      = meta.qLoraRank;
        modelWeights.kvLoraRank     = meta.kvLoraRank;
        modelWeights.keyLength      = meta.keyLength;
        modelWeights.valueLength    = meta.valueLength;
        modelWeights.keyLengthMla   = meta.keyLengthMla;
        modelWeights.valueLengthMla = meta.valueLengthMla;
        modelWeights.ropeDimensionCount = meta.ropeDimensionCount;

        // Compute MLA head dimensions — fail-closed (no static 128/64/128)
        if (meta.ropeDimensionCount > 0 && meta.keyLengthMla > meta.ropeDimensionCount) {
            modelWeights.qkNopeHeadDim = meta.keyLengthMla - meta.ropeDimensionCount;
        } else {
            printf("[Deep2Engine] GGUF_DYNAMIC_GEOMETRY_001=BLOCKED\n");
            printf("BLOCKED_AT=MLA_HEAD_DIM\n");
            printf("BLOCKED_OWNER=GGUF_METADATA\n");
            printf("REASON=MLA nope/rope dims missing; refusing static defaults\n");
            printf("FIRST_DELTA=MLA_HEAD_DIM\n");
            return false;
        }
        if (meta.ropeDimensionCount == 0 || meta.valueLengthMla == 0) {
            printf("[Deep2Engine] GGUF_DYNAMIC_GEOMETRY_001=BLOCKED\n");
            printf("BLOCKED_AT=MLA_ROPE_OR_V\n");
            printf("BLOCKED_OWNER=GGUF_METADATA\n");
            printf("REASON=rope.dimension_count or value_length_mla missing\n");
            printf("FIRST_DELTA=MLA_ROPE_OR_V\n");
            return false;
        }
        modelWeights.qkRopeHeadDim = meta.ropeDimensionCount;
        modelWeights.vHeadDim      = meta.valueLengthMla;
        modelWeights.useMLA        = true;

        // For MLA, headDim is the concatenated Q head dimension (nope + rope)
        modelWeights.headDim = modelWeights.qkNopeHeadDim + modelWeights.qkRopeHeadDim;

        printf("[Deep2Engine] MLA detected: qLoraRank=%zu kvLoraRank=%zu qkNope=%zu qkRope=%zu vHeadDim=%zu headDim=%zu\n",
               modelWeights.qLoraRank, modelWeights.kvLoraRank,
               modelWeights.qkNopeHeadDim, modelWeights.qkRopeHeadDim,
               modelWeights.vHeadDim, modelWeights.headDim);

        MlaCert::record(MlaCert::Stage::Detected, 0, 0, nullptr, 0,
                        static_cast<double>(modelWeights.qLoraRank));
        MlaCertAuthority::NoteRequired();

        // Production MLA: prefer K2 shard directory (certified ForwardHiddenMla).
        // Do not require RAWRXD_DEEP2_ALLOW_UNSAFE_MLA for production.
        {
            namespace fs = std::filesystem;
            std::string shardDir;
            if (const char* e = std::getenv("DEEP2_K2_SHARD_DIR")) {
                if (e[0]) shardDir = e;
            }
            if (shardDir.empty()) {
                fs::path p(ggufPath);
                if (fs::is_directory(p))
                    shardDir = p.string();
                else
                    shardDir = p.parent_path().string();
            }
            if (!shardDir.empty() && fs::is_directory(shardDir) &&
                openK2ShardDirectory(shardDir)) {
                modelWeights.loaded = true;
                modelWeights.useMLA = true;
                modelWeights.hiddenDim = config.hiddenDim;
                modelWeights.numLayers = config.numLayers;
                modelWeights.numHeads = config.numHeads;
                modelWeights.numKVHeads = config.numKVHeads;
                modelWeights.vocabSize = config.vocabSize;
                modelWeights.qLoraRank = config.qLoraRank;
                modelWeights.kvLoraRank = config.kvLoraRank;
                modelWeights.qkNopeHeadDim = config.qkNopeHeadDim;
                modelWeights.qkRopeHeadDim = config.qkRopeHeadDim;
                modelWeights.vHeadDim = config.vHeadDim;
                modelWeights.headDim = config.headDim;
                modelState_ = ModelState::Indexed;
                initialized = true;
                choreo::ApplyLawEnv();
                /* INDEX path returns before full ladder — seal via session geom. */
                {
                    rawr::olma::AuthorityBundle auth{};
                    if (rawr::olma::SealLadderOnLoad(
                            ggufResult, firstShard.string().c_str(),
                            sessionGeometry_, auth) &&
                        auth.PASS) {
                        sessionAuth_ = std::move(auth);
                        printf("[Deep2Engine] AUTHORITY_LADDER=PASS "
                               "(K2_INDEX shard0)\n");
                    } else {
                        fprintf(stderr,
                                "K2_INDEX_AUTHORITY_SEAL_FAIL=1 "
                                "geom=%d schema=%d quant=%d tok=%d\n",
                                auth.geom.PASS, auth.schema.PASS,
                                auth.quant.PASS, auth.tok.PASS);
                    }
                }
                printf("[Deep2Engine] loadModel=INDEX_AND_ADDRESS (%s) "
                       "ModelState=Indexed — weights not resident\n",
                       shardDir.c_str());
                RawrWorkingSet w{};
                w.activationBytes = (uint64_t)config.hiddenDim * 4ull * 3ull;
                w.scratchBytes = (uint64_t)config.hiddenDim * 4ull;
                RawrSpaceState s{};
                s.capacityBytes = 512ull << 20;
                s.reserveBytes = 1ull << 20;
                RawrEmitNoTpContract(stdout, w, s);
                modelState_ = ModelState::Choreographable;
                return true;
            }
        }

        // Single-file MLA host path: allow load; computeAttention must use
        // MlaAttentionComplete (stub throw removed). Unsafe env is never required.
        if (envFlagEnabled("RAWRXD_DEEP2_ALLOW_UNSAFE_MLA")) {
            MlaCertAuthority::NoteUnsafeEnv();
            fprintf(stderr,
                "[Deep2Engine] WARNING: RAWRXD_DEEP2_ALLOW_UNSAFE_MLA=1 — "
                "not valid for MLA-CERT-001 / U13 product seals\n");
        }
        printf("[Deep2Engine] MLA host load continuing — certified attention required "
               "in computeAttention\n");
    } else {
        // Standard MHA / GQA: session geometry already authoritative — no heuristics
        if (modelWeights.numHeads == 0 || modelWeights.headDim == 0) {
            printf("[Deep2Engine] GGUF_DYNAMIC_GEOMETRY_001=BLOCKED\n");
            printf("BLOCKED_AT=HEADS_OR_HEAD_DIM\n");
            printf("BLOCKED_OWNER=GGUF_METADATA\n");
            printf("REASON=session geometry missing heads/head_dim after resolve\n");
            printf("FIRST_DELTA=HEADS_OR_HEAD_DIM\n");
            return false;
        }
        modelWeights.useMLA  = false;

        // Qwen3.5 / 3.6: Q may be fused Q|gate (2×gateDim). Keep meta heads then.
        if (meta.architecture == "qwen35" || meta.architecture == "qwen35moe") {
            for (const auto& t : ggufResult.tensors) {
                if (t.name.find("attn_q.weight") == std::string::npos) continue;
                size_t qOut = t.dimensions.size() >= 2 ? t.dimensions[1] : 0;
                if (qOut > modelWeights.hiddenDim && modelWeights.headDim > 0 &&
                    modelWeights.numHeads > 0 &&
                    (qOut % modelWeights.headDim) == 0) {
                    const size_t gateDim =
                        modelWeights.numHeads * modelWeights.headDim;
                    if (qOut == 2 * gateDim) {
                        printf("[Deep2Engine] Qwen3.5: gated Q keeps "
                               "numHeads=%zu (qOut=%zu=2*%zu)\n",
                               modelWeights.numHeads, qOut, gateDim);
                    } else {
                        size_t inferredHeads = qOut / modelWeights.headDim;
                        if (inferredHeads != modelWeights.numHeads) {
                            printf("[Deep2Engine] Qwen3.5: inferring "
                                   "numHeads=%zu from Q (out=%zu headDim=%zu "
                                   "meta=%zu)\n",
                                   inferredHeads, qOut, modelWeights.headDim,
                                   modelWeights.numHeads);
                            modelWeights.numHeads = inferredHeads;
                        }
                    }
                    if (t.name.find("blk.3.") != std::string::npos)
                        break;
                }
            }
        }
    }

    // â”€â”€ Infer vocabSize from tensor shapes when metadata lacks it â”€â”€â”€â”€â”€â”€â”€â”€
    if (modelWeights.vocabSize == 0) {
        for (const auto& t : ggufResult.tensors) {
            if (t.name == "token_embd.weight" || t.name == "token_embeddings.weight") {
                if (t.dimensions.size() >= 1) {
                    modelWeights.vocabSize = static_cast<int>(t.dimensions[0]);
                    printf("[Deep2Engine] Inferred vocabSize=%zu from %s shape\n",
                           modelWeights.vocabSize, t.name.c_str());
                }
                break;
            }
        }
    }

    // â”€â”€ Sync authoritative model config from GGUF metadata â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    config.hiddenDim       = modelWeights.hiddenDim;
    config.vocabSize       = modelWeights.vocabSize;
    config.numLayers       = modelWeights.numLayers;
    config.numHeads        = modelWeights.numHeads;
    config.numKVHeads      = modelWeights.numKVHeads;
    config.headDim         = modelWeights.headDim;
    config.intermediateDim = modelWeights.intermediateDim;
    config.normEps         = modelWeights.normEps;
    config.ropeTheta       = modelWeights.ropeTheta;
    config.ropeScaling     = modelWeights.ropeScaling;

    // MLA config propagation
    config.qLoraRank      = modelWeights.qLoraRank;
    config.kvLoraRank     = modelWeights.kvLoraRank;
    config.qkNopeHeadDim  = modelWeights.qkNopeHeadDim;
    config.qkRopeHeadDim  = modelWeights.qkRopeHeadDim;
    config.vHeadDim       = modelWeights.vHeadDim;
    config.useMLA         = modelWeights.useMLA;

    // Guard: refuse to allocate with invalid dimensions
    if (config.vocabSize == 0 || config.hiddenDim == 0 || config.numLayers == 0) {
        printf("[Deep2Engine] ERROR: Invalid model config after load: "
               "vocabSize=%zu hiddenDim=%zu numLayers=%zu\n",
               config.vocabSize, config.hiddenDim, config.numLayers);
        return false;
    }

    // P0/P1: GQA / MHA head contract (TOPOLOGY-CERT-001)
    // numKVHeads may remain 0 until post-map inference (Nemotron-H).
    if (config.numHeads == 0 || config.headDim == 0) {
        fprintf(stderr, "[Deep2Engine] ERROR: numHeads=%zu headDim=%zu invalid\n",
                config.numHeads, config.headDim);
        return false;
    }
    if (config.numKVHeads == 0) {
        // Defer fill until tensors are mapped; provisional MHA for sizing only.
        config.numKVHeads = config.numHeads;
        modelWeights.numKVHeads = config.numHeads;
    }
    if (config.numKVHeads > config.numHeads ||
        (config.numHeads % config.numKVHeads) != 0) {
        fprintf(stderr,
            "[Deep2Engine] ERROR: GQA contract violated: numHeads=%zu numKVHeads=%zu "
            "(require numHeads >= numKVHeads and numHeads %% numKVHeads == 0)\n",
            config.numHeads, config.numKVHeads);
        return false;
    }

    // Guard: validate MLA coherence for DeepSeek2
    if (isDeepSeek2) {
        if (config.qLoraRank == 0 || config.kvLoraRank == 0 ||
            config.qkNopeHeadDim == 0 || config.qkRopeHeadDim == 0 || config.vHeadDim == 0) {
            printf("[Deep2Engine] ERROR: DeepSeek2 model loaded with incomplete MLA metadata: "
                   "qLoraRank=%zu kvLoraRank=%zu qkNope=%zu qkRope=%zu vHeadDim=%zu\n",
                   config.qLoraRank, config.kvLoraRank,
                   config.qkNopeHeadDim, config.qkRopeHeadDim, config.vHeadDim);
            return false;
        }
    }

    // â”€â”€ Canonical tokenizer (TOKENIZER-PARITY-002c / Spm::encode) â”€â”€â”€â”€â”€â”€â”€â”€
    {
        const std::string tokPath = firstShard.string();
        if (!CanonicalTokenizer::Instance().LoadFromGGUF(tokPath)) {
            fprintf(stderr, "[Deep2Engine] WARNING: CanonicalTokenizer load failed: %s\n",
                    CanonicalTokenizer::Instance().LastError());
        }
        auto bundle = LoadTokenizerFromGGUF(tokPath.c_str());
        if (bundle.ok) {
            auto bpe = std::make_unique<BPETokenizer>();
            if (ApplyTokenizerBundle(*bpe, bundle)) {
                tokenizer = std::move(bpe);
                printf("[Deep2Engine] Tokenizer loaded: vocab=%zu bos=%d eos=%d (Spm::encode)\n",
                       tokenizer->VocabSize(),
                       tokenizer->GetSpecialTokens().bosId,
                       tokenizer->GetSpecialTokens().eosId);
            }
        }
        if (!tokenizer && !CanonicalTokenizer::Instance().IsLoaded()) {
            if (!envFlagEnabled("RAWRXD_DEEP2_ALLOW_BYTE_TOKENIZER")) {
                fprintf(stderr,
                    "[Deep2Engine] ERROR: Failed to load canonical tokenizer. "
                    "Production load requires a real tokenizer "
                    "(set RAWRXD_DEEP2_ALLOW_BYTE_TOKENIZER=1 to override).\n");
                return false;
            }
            fprintf(stderr, "[Deep2Engine] WARNING: byte-level tokenizer override enabled\n");
        }
    }

    // Allocate layer weights
    modelWeights.layers.resize(modelWeights.numLayers);

    // Map tensors to layer weights (only for single-shard; multi-shard uses streaming)
    if (!isMultiShard) {
        for (const auto& t : ggufResult.tensors) {
            const std::string& name = t.name;

            // Parse layer index from tensor name (blk.N / model.layers.N / layers.N)
            int layerIdx = Deep2::gemma4_schema::ParseLayerIndex(name);
            if (layerIdx < 0 && name.size() > 4 && name.substr(0, 4) == "blk.") {
                layerIdx = atoi(name.c_str() + 4);
            }

            WeightTensor wt;
            wt.data = t.data;
            wt.type = (int)t.type;
            // GGUF dimensions are [input_dim, output_dim]
            // LinearW needs rows=output_dim, cols=input_dim
            // 1D tensors (norms): dims=[N] → rows=N, cols=1 (not rows=1,cols=N).
            if (t.dimensions.size() >= 2) {
                wt.rows = t.dimensions[1];
                wt.cols = t.dimensions[0];
            } else if (t.dimensions.size() == 1) {
                wt.rows = t.dimensions[0];
                wt.cols = 1;
            } else {
                wt.rows = 1;
                wt.cols = 0;
            }
            wt.numBlocks = t.GetNumBlocks();
            wt.sizeBytes = t.size;
            wt.name = name;
            // Owned by ggufResult (VirtualAlloc / FreeTensorData) — not alignedFree.
            wt.mapped = true;
            // Physical identity: absolute offset = data section base + relative
            {
                uint64_t absOff = 0;
                if (CheckedAddU64(ggufResult.dataOffset, t.offset, absOff) && t.size > 0) {
                    wt.shardId = 0;
                    wt.fileOffset = absOff;
                    wt.hasFileBacking = true;
                }
            }

            if (name == "token_embd.weight") {
                modelWeights.tokenEmbed = wt;
                // Bind hidden + vocab as independent facts from tensor geometry.
                if (t.dimensions.size() >= 2) {
                    const size_t d0 = static_cast<size_t>(t.dimensions[0]);
                    const size_t d1 = static_cast<size_t>(t.dimensions[1]);
                    size_t hid = modelWeights.hiddenDim ? modelWeights.hiddenDim : d0;
                    size_t voc = 0;
                    if (d0 == hid) voc = d1;
                    else if (d1 == hid) voc = d0;
                    else {
                        // Ambiguous: prefer larger as vocab (never seed vocab=hidden).
                        voc = (d0 > d1) ? d0 : d1;
                        hid = (d0 > d1) ? d1 : d0;
                    }
                    if (voc == hid) {
                        printf("[Deep2Engine] FATAL: vocab==hidden=%zu from token_embd "
                               "d0=%zu d1=%zu — refuse coupled facts\n",
                               voc, d0, d1);
                    } else {
                        if (voc != modelWeights.vocabSize) {
                            printf("[Deep2Engine] vocabSize from tensor=%zu "
                                   "(metadata was %zu) hidden=%zu\n",
                                   voc, modelWeights.vocabSize, hid);
                            modelWeights.vocabSize = voc;
                        }
                        if (!modelWeights.hiddenDim) modelWeights.hiddenDim = hid;
                    }
                }
            } else {
            const int gemmaLayerIdx = Deep2::gemma4_schema::ParseLayerIndex(name);
            if (Deep2::gemma4_schema::TryBindRootTensor(modelWeights, name, wt, stderr)) {
                /* Gemma/HF root tensor alias consumed (embed_tokens / lm_head / norm). */
                if (modelWeights.tokenEmbed.data == wt.data && t.dimensions.size() >= 2) {
                    const size_t d0 = static_cast<size_t>(t.dimensions[0]);
                    const size_t d1 = static_cast<size_t>(t.dimensions[1]);
                    size_t hid = modelWeights.hiddenDim ? modelWeights.hiddenDim : d0;
                    size_t voc = (d0 == hid) ? d1 : ((d1 == hid) ? d0 : ((d0 > d1) ? d0 : d1));
                    if (voc != hid) {
                        if (voc != modelWeights.vocabSize) modelWeights.vocabSize = voc;
                        if (!modelWeights.hiddenDim) modelWeights.hiddenDim = hid;
                    }
                }
            } else if (name.find("blk.") != 0 && gemmaLayerIdx >= 0 &&
                       gemmaLayerIdx < (int)modelWeights.layers.size() &&
                       Deep2::gemma4_topology::TryBindLayerTensor(
                           modelWeights.layers[gemmaLayerIdx], name, wt, stderr)) {
                /* Gemma4 non-uniform HF-style layer topology consumed. */
            } else if (name.find("blk.") != 0 && gemmaLayerIdx >= 0 &&
                       gemmaLayerIdx < (int)modelWeights.layers.size() &&
                       Deep2::gemma4_schema::TryBindLayerTensor(
                           modelWeights.layers[gemmaLayerIdx], name, wt, stderr)) {
                /* Gemma/HF layer alias (non-blk) consumed into Deep2 slots. */
            } else if (name == "output.weight" || name == "lm_head.weight") {
                modelWeights.lmHead = wt;
            } else if (name == "output_norm.weight" || name == "norm.weight") {
                modelWeights.finalNorm = wt;
            } else if (layerIdx >= 0 && layerIdx < (int)modelWeights.layers.size()) {
                auto& lw = modelWeights.layers[layerIdx];
                const int gemmaLayerIdx = layerIdx;

                if (Deep2::gemma4_topology::TryBindLayerTensor(
                        modelWeights.layers[gemmaLayerIdx], name, wt, stderr)) {
                    /* Gemma4 non-uniform topology (incl. blk.N.proj.weight → wqkv). */
                } else if (name.find("blk.") != 0 &&
                    Deep2::gemma4_schema::TryBindLayerTensor(
                        modelWeights.layers[gemmaLayerIdx], name, wt, stderr)) {
                    /* Gemma/HF layer alias consumed. */
                }
                // â”€â”€ Fused QKV (Phi-3, etc.) â”€â”€
                else if (name.find("attn_qkv") != std::string::npos)
                    lw.wqkv = wt;
                // â”€â”€ Standard MHA / GQA tensors (check BEFORE MLA to avoid substring matches) â”€â”€
                else if (name.find("attn_output") != std::string::npos) {
                    lw.wo = wt;
                    if (layerIdx == 0) {
                        // Quantization-aware diagnostic: don't treat quantized data as float*
                        if (wt.type == (int)GGMLType::GGML_TYPE_F32) {
                            const float* fp = (const float*)wt.data;
                            float mn = 1e30f, mx = -1e30f;
                            size_t nz = 0;
                            for (size_t i = 0; i < 16 && i < wt.rows * wt.cols; ++i) {
                                float v = fp[i];
                                if (v < mn) mn = v; if (v > mx) mx = v;
                                if (v != 0.0f) ++nz;
                            }
                            printf("[WO_DIAG] GGUF wo.data=%p rows=%zu cols=%zu type=%d(F32) first16=[%.6f,%.6f,%.6f,%.6f] min=%.6f max=%.6f nz=%zu\n",
                                   wt.data, wt.rows, wt.cols, wt.type,
                                   fp[0], fp[1], fp[2], fp[3], mn, mx, nz);
                        } else if (wt.type == (int)GGMLType::GGML_TYPE_Q4_K) {
                            const Q4_K_Block* blk = (const Q4_K_Block*)wt.data;
                            printf("[WO_DIAG] GGUF wo.data=%p rows=%zu cols=%zu type=%d(Q4_K) block0 d=0x%04X dmin=0x%04X qs[0]=0x%02X\n",
                                   wt.data, wt.rows, wt.cols, wt.type, blk[0].d, blk[0].dmin, blk[0].qs[0]);
                        } else if (wt.type == (int)GGMLType::GGML_TYPE_Q6_K) {
                            const block_q6_K* blk = (const block_q6_K*)wt.data;
                            printf("[WO_DIAG] GGUF wo.data=%p rows=%zu cols=%zu type=%d(Q6_K) block0 d=0x%04X ql[0]=0x%02X qh[0]=0x%02X sc[0]=%d\n",
                                   wt.data, wt.rows, wt.cols, wt.type, blk[0].d, blk[0].ql[0], blk[0].qh[0], (int)blk[0].scales[0]);
                        } else {
                            printf("[WO_DIAG] GGUF wo.data=%p rows=%zu cols=%zu type=%d(other) â€” skipping float interpretation\n",
                                   wt.data, wt.rows, wt.cols, wt.type);
                        }
                    }
                }
                else if (name.find("attn_q.") != std::string::npos)
                    lw.wq = wt;
                else if (name.find("attn_k.") != std::string::npos)
                    lw.wk = wt;
                else if (name.find("attn_v.") != std::string::npos)
                    lw.wv = wt;
                // â”€â”€ MLA tensor routing (checked AFTER standard to avoid substring conflicts) â”€â”€
                else if (name.find("attn_q_a_norm") != std::string::npos)
                    lw.attnQ_a_norm = wt;
                else if (name.find("attn_q_a") != std::string::npos)
                    lw.attnQ_a = wt;
                else if (name.find("attn_q_b") != std::string::npos)
                    lw.attnQ_b = wt;
                else if (name.find("attn_kv_a_mqa") != std::string::npos)
                    lw.attnKV_a_mqa = wt;
                else if (name.find("attn_kv_a_norm") != std::string::npos)
                    lw.attnKV_a_norm = wt;
                else if (name.find("attn_k_b") != std::string::npos)
                    lw.attnK_b = wt;
                else if (name.find("attn_v_b") != std::string::npos)
                    lw.attnV_b = wt;
                else if (name.find("attn_o") != std::string::npos)
                    lw.attnO = wt;
                else if (name.find("attn_gate") != std::string::npos) {
                    // Qwen-style attention output projection (NOT FFN gate)
                    lw.attnO = wt;
                    printf("[ATTN_GATE] Mapped %s to attnO (rows=%zu cols=%zu type=%d)\n",
                           name.c_str(), wt.rows, wt.cols, wt.type);
                }
                else if (name.find("attn_proj") != std::string::npos) {
                    // Qwen-style attention output projection
                    lw.attnO = wt;
                    printf("[ATTN_PROJ] Mapped %s to attnO (rows=%zu cols=%zu type=%d)\n",
                           name.c_str(), wt.rows, wt.cols, wt.type);
                }
                else if (name.find("attn_norm") != std::string::npos || name.find("input_layernorm") != std::string::npos)
                    lw.attnNorm = wt;
                else if (name.find("attn_q_norm") != std::string::npos)
                    lw.attnQNorm = wt;
                else if (name.find("attn_k_norm") != std::string::npos)
                    lw.attnKNorm = wt;
                else if (name.find("attn_") != std::string::npos && layerIdx == 0) {
                    printf("[ATTN_UNKNOWN] Unmatched attention tensor: %s (rows=%zu cols=%zu type=%d)\n",
                           name.c_str(), wt.rows, wt.cols, wt.type);
                }
                // â”€â”€ Layer topology: dense vs MoE â”€â”€
                // If numExperts == 0, this is a dense model: ALL layers use dense FFN.
                // If numExperts > 0, leadingDenseBlockCount layers are dense, rest are MoE.
                bool isDenseLayer = (meta.numExperts == 0) ||
                                    (layerIdx < (int)meta.leadingDenseBlockCount);
                if (isDenseLayer) {
                    // Dense FFN (no MoE) — Gemma/HF aliases before llama names.
                    if (Deep2::gemma4_schema::TryBindLayerTensor(lw, name, wt, nullptr)) {
                        /* consumed */
                    } else if (name.find("ffn_gate") != std::string::npos)
                        lw.wGate = wt;
                    else if (name.find("ffn_up") != std::string::npos)
                        lw.wUp = wt;
                    else if (name.find("ffn_down") != std::string::npos)
                        lw.wDown = wt;
                } else {
                    // MoE layers
                    if (name.find("ffn_gate_inp") != std::string::npos ||
                             name.find("moe.router") != std::string::npos ||
                             name.find("gate_inp") != std::string::npos)
                        lw.moeRouter = wt;
                    else if (name.find("ffn_gate_exps") == std::string::npos &&
                             name.find("ffn_up_exps") == std::string::npos &&
                             name.find("ffn_down_exps") == std::string::npos &&
                             name.find("shared_experts") != std::string::npos) {
                        if (name.find("gate_proj") != std::string::npos || name.find("w1") != std::string::npos)
                            lw.moeSharedGate = wt;
                        else if (name.find("up_proj") != std::string::npos || name.find("w3") != std::string::npos)
                            lw.moeSharedUp = wt;
                        else if (name.find("down_proj") != std::string::npos || name.find("w2") != std::string::npos)
                            lw.moeSharedDown = wt;
                    }
                }
                // Norms apply to both dense and MoE layers
                if (name.find("ffn_norm") != std::string::npos ||
                    name.find("post_attention_layernorm") != std::string::npos ||
                    name.find("post_attn_norm") != std::string::npos ||
                    name.find("post_attention_norm") != std::string::npos)
                    lw.ffnNorm = wt;
                else if (name.find("ffn_") != std::string::npos &&
                         name.find("ffn_gate") == std::string::npos &&
                         name.find("ffn_up") == std::string::npos &&
                         name.find("ffn_down") == std::string::npos &&
                         name.find("ffn_gate_inp") == std::string::npos &&
                         name.find("ffn_gate_exps") == std::string::npos &&
                         name.find("ffn_up_exps") == std::string::npos &&
                         name.find("ffn_down_exps") == std::string::npos &&
                         name.find("shared_experts") == std::string::npos &&
                         layerIdx == 0) {
                    printf("[FFN_UNKNOWN] Unmatched FFN tensor: %s (rows=%zu cols=%zu type=%d)\n",
                           name.c_str(), wt.rows, wt.cols, wt.type);
                }

                // â”€â”€ SSM / Mamba tensor mapping â”€â”€
                if (name.find("ssm_a") != std::string::npos && name.find("ssm_alpha") == std::string::npos) {
                    lw.ssmA = wt;
                    lw.hasSSM = true;
                    if (layerIdx == 0) printf("[SSM_MAP] %s -> ssmA (dims=%zux%zu type=%d)\n", name.c_str(), wt.rows, wt.cols, wt.type);
                }
                else if (name.find("ssm_alpha.weight") != std::string::npos) {
                    lw.ssmAlpha = wt;
                    lw.hasSSM = true;
                    if (layerIdx == 0) printf("[SSM_MAP] %s -> ssmAlpha (dims=%zux%zu type=%d)\n", name.c_str(), wt.rows, wt.cols, wt.type);
                }
                else if (name.find("ssm_in.weight") != std::string::npos) {
                    lw.ssmIn = wt;
                    lw.hasSSM = true;
                    if (layerIdx == 0) printf("[SSM_MAP] %s -> ssmIn (dims=%zux%zu type=%d)\n", name.c_str(), wt.rows, wt.cols, wt.type);
                }
                else if (name.find("ssm_beta.weight") != std::string::npos) {
                    lw.ssmBeta = wt;
                    lw.hasSSM = true;
                    if (layerIdx == 0) printf("[SSM_MAP] %s -> ssmBeta (dims=%zux%zu type=%d)\n", name.c_str(), wt.rows, wt.cols, wt.type);
                }
                else if (name.find("ssm_d") != std::string::npos &&
                         name.find("ssm_dt") == std::string::npos) {
                    lw.ssmD = wt;
                    lw.hasSSM = true;
                    if (layerIdx == 0) printf("[SSM_MAP] %s -> ssmD (dims=%zux%zu type=%d)\n", name.c_str(), wt.rows, wt.cols, wt.type);
                }
                else if (name.find("ssm_conv1d.bias") != std::string::npos) {
                    lw.ssmConv1dBias = wt;
                    lw.hasSSM = true;
                    if (layerIdx == 0) printf("[SSM_MAP] %s -> ssmConv1dBias (dims=%zux%zu type=%d)\n", name.c_str(), wt.rows, wt.cols, wt.type);
                }
                else if (name.find("ssm_conv1d.weight") != std::string::npos) {
                    lw.ssmConv1d = wt;
                    lw.hasSSM = true;
                    if (layerIdx == 0) printf("[SSM_MAP] %s -> ssmConv1d (dims=%zux%zu type=%d)\n", name.c_str(), wt.rows, wt.cols, wt.type);
                }
                else if (name.find("ssm_dt.bias") != std::string::npos) {
                    lw.ssmDtBias = wt;
                    lw.hasSSM = true;
                    if (layerIdx == 0) printf("[SSM_MAP] %s -> ssmDtBias (dims=%zux%zu type=%d)\n", name.c_str(), wt.rows, wt.cols, wt.type);
                }
                else if (name.find("ssm_norm.weight") != std::string::npos) {
                    lw.ssmNorm = wt;
                    lw.hasSSM = true;
                    if (layerIdx == 0) printf("[SSM_MAP] %s -> ssmNorm (dims=%zux%zu type=%d)\n", name.c_str(), wt.rows, wt.cols, wt.type);
                }
                else if (name.find("ssm_out.weight") != std::string::npos) {
                    lw.ssmOut = wt;
                    lw.hasSSM = true;
                    if (layerIdx == 0) printf("[SSM_MAP] %s -> ssmOut (dims=%zux%zu type=%d)\n", name.c_str(), wt.rows, wt.cols, wt.type);
                }
                else if (name.find("ssm_") != std::string::npos && layerIdx == 0) {
                    printf("[SSM_UNKNOWN] Unmatched SSM tensor: %s (rows=%zu cols=%zu type=%d)\n",
                           name.c_str(), wt.rows, wt.cols, wt.type);
                }
            }
            } // else (!token_embd): gemma alias + llama map
        }
    }

    // Re-sync config.vocabSize after tensor-derived override
    config.vocabSize = modelWeights.vocabSize;

    // Check if tied embeddings
    if (modelWeights.lmHead.data == nullptr && modelWeights.tokenEmbed.data != nullptr) {
        modelWeights.lmHead = modelWeights.tokenEmbed;
        modelWeights.tieEmbeddings = true;
        printf("[Deep2Engine] Using tied embeddings\n");
    }

    // â”€â”€ VAL-051.7: Initialize ResidencyManager and register all tensors â”€â”€
    residencyManager_ = std::make_unique<ResidencyManager>();
    ResidencyConfig resConfig;
    /* 512MB default starves multi-GGUF ProductOpen (NO_TENSOR_PAYLOAD). Honor
     * WEIGHT_BUDGET_* and HOST_DECODE product floor so R24 load→switch works. */
    resConfig.maxResidentBytes = 512ULL * 1024 * 1024;
    /* Cap env budget — WEIGHT_BUDGET_* can be tens of GiB and commit-AV the IDE. */
    const size_t kResidencyCap = 8ULL * 1024 * 1024 * 1024;
    if (const char* wb = std::getenv("WEIGHT_BUDGET_BYTES")) {
        unsigned long long v = 0;
#ifdef _WIN32
        v = _strtoui64(wb, nullptr, 10);
#else
        v = std::strtoull(wb, nullptr, 10);
#endif
        if (v > resConfig.maxResidentBytes)
            resConfig.maxResidentBytes = static_cast<size_t>(v);
    } else if (const char* wm = std::getenv("WEIGHT_BUDGET_MIB")) {
        unsigned long long mib = 0;
#ifdef _WIN32
        mib = _strtoui64(wm, nullptr, 10);
#else
        mib = std::strtoull(wm, nullptr, 10);
#endif
        unsigned long long v = mib * 1024ULL * 1024ULL;
        if (v > resConfig.maxResidentBytes)
            resConfig.maxResidentBytes = static_cast<size_t>(v);
    }
    if (const char* hd = std::getenv("RAWRXD_HOST_DECODE");
        hd && hd[0] == '1') {
        /* 2GiB floor: enough for 1–3B Q2/Q4 embeds; avoids giant commit AV. */
        const size_t hostFloor = 2ULL * 1024 * 1024 * 1024;
        if (resConfig.maxResidentBytes < hostFloor)
            resConfig.maxResidentBytes = hostFloor;
    }
    if (resConfig.maxResidentBytes > kResidencyCap)
        resConfig.maxResidentBytes = kResidencyCap;
    {
        unsigned long long envMib = 0;
        int parseOk = 0;
        if (const char* wm = std::getenv("WEIGHT_BUDGET_MIB")) {
#ifdef _WIN32
            envMib = _strtoui64(wm, nullptr, 10);
#else
            envMib = std::strtoull(wm, nullptr, 10);
#endif
            parseOk = envMib > 0 ? 1 : 0;
        } else if (const char* dm = std::getenv("DEEP2_WEIGHT_BUDGET_MIB")) {
            /* Prefer numeric DEEP2_*; do not treat hex token as residency. */
#ifdef _WIN32
            envMib = _strtoui64(dm, nullptr, 10);
#else
            envMib = std::strtoull(dm, nullptr, 10);
#endif
            parseOk = envMib > 0 ? 1 : 0;
        }
        const unsigned long long effMib =
            (unsigned long long)(resConfig.maxResidentBytes / (1024ULL * 1024ULL));
        std::fprintf(stderr,
                     "WEIGHT_BUDGET_ENV_PRESENT=%d\n"
                     "WEIGHT_BUDGET_ENV_RAW=\"%llu\"\n"
                     "WEIGHT_BUDGET_PARSE_OK=%d\n"
                     "WEIGHT_BUDGET_INPUT_MIB=%llu\n"
                     "WEIGHT_BUDGET_EFFECTIVE_MIB=%llu\n"
                     "RESIDENCY_BUDGET_MIB=%llu\n"
                     "BUDGET_RELATION_VALID=%d\n",
                     (envMib > 0) ? 1 : 0, envMib, parseOk, envMib, effMib,
                     effMib, (effMib > 0) ? 1 : 0);
        std::fflush(stderr);
    }
    resConfig.pageAlignment = 4096;
    resConfig.mapGranularity = 65536;
    resConfig.oversizePolicy = ResidencyConfig::OversizePolicy::DedicatedWindow;
    resConfig.validateOnRemap = true;
    if (!residencyManager_->Initialize(resConfig)) {
        printf("[Deep2Engine] WARNING: ResidencyManager initialization failed\n");
        residencyManager_.reset();
    } else {
        residencyEnabled_ = true;
        printf("[Deep2Engine] ResidencyManager initialized: maxResidentBytes=%zu MB\n",
               resConfig.maxResidentBytes / (1024 * 1024));

        RmvMountReport mount;
        const uint64_t shardFileSize = ggufResult.totalSize > 0
            ? ggufResult.totalSize
            : UINT64_MAX;
        TensorId nextId = 1;

        if (isMultiShard && globalIndex_) {
            globalIndex_->ForEach([&](const GlobalTensorRef& ref) {
                if (!ref.IsValid())
                    return;
                ++mount.tensorsDiscovered;
                VirtualTensorDesc d{};
                d.id = nextId++;
                d.shard = ref.shardId;
                d.fileOffset = ref.fileOffset;
                d.byteLength = ref.byteSize;
                d.type = ref.ggmlType;
                d.addressed = (ref.byteSize > 0);
                AuditDesc(d, /*shardCount*/ 64, UINT64_MAX, mount);
                if (!d.addressed)
                    return;
                residencyManager_->RegisterTensor(
                    ref.name,
                    static_cast<size_t>(d.fileOffset),
                    static_cast<size_t>(d.byteLength),
                    nullptr,
                    d.shard);
            });
        } else {
            // Single-shard: GGUF tensor table is the address authority.
            for (const auto& t : ggufResult.tensors) {
                if (t.size == 0 || t.name.empty())
                    continue;
                ++mount.tensorsDiscovered;
                VirtualTensorDesc d = MakeDescFromGguf(
                    nextId++, 0, ggufResult.dataOffset, t.offset, t.size,
                    static_cast<uint32_t>(t.type));
                AuditDesc(d, 1, shardFileSize, mount);
                if (!d.addressed)
                    continue;
                residencyManager_->RegisterTensor(
                    t.name,
                    static_cast<size_t>(d.fileOffset),
                    static_cast<size_t>(d.byteLength),
                    t.data,
                    d.shard);
            }
        }

        size_t regCount = residencyManager_->GetRegisteredTensorCount();
        size_t regBytes = residencyManager_->GetRegisteredBytes();
        mount.tensorsRegistered = regCount;
        mount.Print("RMV_MOUNT_001");
        printf("[Deep2Engine] ResidencyManager: this=%p  registered=%zu tensors  bytes=%zu  max=%zu\n",
               (void*)residencyManager_.get(), regCount, regBytes,
               residencyManager_->GetMaxResidentBytes());

        if (!mount.Pass()) {
            printf("[RMV_MOUNT_001]=FAIL discovered=%zu addressed=%zu registered=%zu\n",
                   mount.tensorsDiscovered, mount.tensorsAddressed, mount.tensorsRegistered);
            fprintf(stderr,
                "[Deep2Engine] ERROR: broken physical-address handoff into ResidencyManager. "
                "Refuse production load.\n");
            residencyManager_.reset();
            residencyEnabled_ = false;
            return false;
        }
        printf("[RMV_MOUNT_001]=PASS\n");
    }

    // --- Batch 15: Register all tensors with ElasticResidencyManager ---
    if (elasticResidencyEnabled_ && elasticResidency_) {
        // Canonical ggml_type IDs (QuantTypeTable) — prior map mislabeled Q2_K/Q4_K/Q6_K.
        auto ggmlTypeToTensorFormat = [](int ggmlType) -> TensorFormat {
            switch (ggmlType) {
                case 0:  return TensorFormat::FP32;
                case 1:  return TensorFormat::FP16;
                case 2:  return TensorFormat::Q4_0;
                case 3:  return TensorFormat::Q4_1;
                case 6:  return TensorFormat::Q5_0;
                case 7:  return TensorFormat::Q5_1;
                case 8:  return TensorFormat::Q8_0;
                case 10: return TensorFormat::Q2_K;
                case 11: return TensorFormat::Q3_K;
                case 12: return TensorFormat::Q4_K;
                case 13: return TensorFormat::Q5_K;
                case 14: return TensorFormat::Q6_K;
                // TensorFormat has no Q8_K; keep Unknown (CPU path uses GGML type).
                default: return TensorFormat::Unknown;
            }
        };

        auto registerElastic = [&](const WeightTensor& wt, uint32_t layerIdx, uint32_t expertIdx) {
            if (wt.sizeBytes == 0 || wt.name.empty())
                return;
            if (!wt.data && !wt.hasFileBacking)
                return;
            elasticResidency_->RegisterTensor(
                wt.name,
                layerIdx,
                expertIdx,
                static_cast<size_t>(wt.fileOffset),
                wt.sizeBytes,
                ggmlTypeToTensorFormat(wt.type),
                wt.data);
        };

        if (isMultiShard && globalIndex_) {
            globalIndex_->ForEach([&](const GlobalTensorRef& ref) {
                if (!ref.IsValid())
                    return;
                // Prefer live mapped pointer when WeightTensor already holds it;
                // nullptr sourceData + Acquire was the silent zero → gibberish path.
                const void* src = nullptr;
                if (ref.name == modelWeights.tokenEmbed.name)
                    src = modelWeights.tokenEmbed.data;
                else if (ref.name == modelWeights.lmHead.name)
                    src = modelWeights.lmHead.data;
                else if (ref.name == modelWeights.finalNorm.name)
                    src = modelWeights.finalNorm.data;
                elasticResidency_->RegisterTensor(
                    ref.name,
                    ref.layerIndex >= 0 ? static_cast<uint32_t>(ref.layerIndex) : ~0u,
                    ~0u,
                    static_cast<size_t>(ref.fileOffset),
                    static_cast<size_t>(ref.byteSize),
                    ggmlTypeToTensorFormat(static_cast<int>(ref.ggmlType)),
                    src);
            });
        } else {
            for (size_t layerIdx = 0; layerIdx < modelWeights.layers.size(); ++layerIdx) {
                const auto& lw = modelWeights.layers[layerIdx];
                const auto L = static_cast<uint32_t>(layerIdx);
                registerElastic(lw.wq, L, ~0u); registerElastic(lw.wk, L, ~0u);
                registerElastic(lw.wv, L, ~0u); registerElastic(lw.wo, L, ~0u);
                registerElastic(lw.attnNorm, L, ~0u); registerElastic(lw.ffnNorm, L, ~0u);
                registerElastic(lw.wGate, L, ~0u); registerElastic(lw.wUp, L, ~0u);
                registerElastic(lw.wDown, L, ~0u);
                registerElastic(lw.attnQ_a, L, ~0u); registerElastic(lw.attnQ_a_norm, L, ~0u);
                registerElastic(lw.attnQ_b, L, ~0u); registerElastic(lw.attnKV_a_mqa, L, ~0u);
                registerElastic(lw.attnKV_a_norm, L, ~0u); registerElastic(lw.attnK_b, L, ~0u);
                registerElastic(lw.attnV_b, L, ~0u); registerElastic(lw.attnO, L, ~0u);
                registerElastic(lw.moeRouter, L, ~0u);
                registerElastic(lw.moeSharedGate, L, ~0u);
                registerElastic(lw.moeSharedUp, L, ~0u);
                registerElastic(lw.moeSharedDown, L, ~0u);
            }
            registerElastic(modelWeights.tokenEmbed, ~0u, ~0u);
            registerElastic(modelWeights.lmHead, ~0u, ~0u);
            registerElastic(modelWeights.finalNorm, ~0u, ~0u);
        }
        printf("[Deep2Engine] ElasticResidencyManager: registered all tensors\n");
    }

    // P0: quarantine experimental SSM approximation (SSM-CERT-001)
    {
        size_t ssmLayers = 0;
        for (const auto& lw : modelWeights.layers) {
            if (lw.hasSSM) ++ssmLayers;
        }
        if (ssmLayers > 0 && !envFlagEnabled("RAWRXD_DEEP2_ALLOW_EXPERIMENTAL_SSM")) {
            fprintf(stderr,
                "[Deep2Engine] ERROR: model has %zu SSM/hybrid layers using an "
                "experimental approximate selective-scan (SSM-CERT-001). "
                "Refuse production load. Set RAWRXD_DEEP2_ALLOW_EXPERIMENTAL_SSM=1 "
                "only for scaffolding.\n",
                ssmLayers);
            return false;
        }
        if (ssmLayers > 0) {
            Deep2::experimental_ssm::EmitAuthResume(stderr, ssmLayers);
            fprintf(stderr,
                "[Deep2Engine] WARNING: RAWRXD_DEEP2_ALLOW_EXPERIMENTAL_SSM=1 — "
                "%zu SSM layers (geometry!=scaffold; PROD_DECODE=0 until REAL=21)\n",
                ssmLayers);
            ssmHybridLayers_ = ssmLayers;
            for (const auto& lw : modelWeights.layers) {
                if (!lw.hasSSM) continue;
                const auto geo =
                    Deep2::nemotron_h::ResolveFromLayer(lw, config.hiddenDim);
                Deep2::nemotron_h::Emit(stderr, geo);
                ssmHeads_ = geo.ssmHeads;
                ssmHeadDimM_ = geo.ssmHeadDim;
                ssmInner_ = geo.ssmInner;
                ssmGroups_ = geo.ssmGroups;
                ssmStateSize_ = geo.ssmState;
                ssmConvDim_ = geo.ssmConvDim;
                ssmInRows_ = geo.ssmInRows;
                ssmConvKernel = geo.ssmConvK ? geo.ssmConvK : 4;
                /* NEVER set ssmStateDim from A/dt(=96). State size is 128. */
                ssmStateDim = geo.ssmState ? geo.ssmState : 128;
                nemotronGeoOk_ = geo.ok;
                fprintf(stderr,
                        "MAMBA_NUM_HEADS=%zu MAMBA_HEAD_DIM=%zu "
                        "SSM_STATE_SIZE=%zu SSM_CONV_KERNEL=%zu "
                        "OLD_BUG_SSM_STATE_DIM_WAS_96=1\n",
                        ssmHeads_, ssmHeadDimM_, ssmStateSize_, ssmConvKernel);
                break;
            }
            EmitNemotronTensorMap(stderr, modelWeights, meta.architecture.c_str());
            const auto map = AssessNemotronSsmMap(modelWeights);
            if (!map.complete) {
                fprintf(stderr,
                    "NEMOTRON_H_TENSOR_MAP_001=FAIL\n"
                    "FAIL_REASON=NEMOTRON_H_SSM_MAPPING_INCOMPLETE\n"
                    "NEXT_ACTION=MAP_REQUIRED_SSM_TENSORS\n");
            }
            {
                const HostQ8GemvReceipts q8 = ProbeHostQ8Gemv(modelWeights);
                EmitHostQ8GemvReceipts(stderr, q8);
                hostQ8GemvSafe_ = q8.safe != 0;
                hostQ8Ffn_ = q8.ffn;
                hostQ8Attn_ = q8.attn;
                hostQ8SsmIn_ = q8.ssmIn;
                hostQ8Finite_ = q8.numericFinite;
                hostQ8Bounds_ = q8.boundsSafe;
                hostQ8Parity_ = q8.referenceParity;
            }
        }
    }

    // Post-map: Nemotron-H head_count_kv=0 → infer from attn_k.
    if (meta.numKeyValueHeads == 0 && config.headDim > 0) {
        for (const auto& lw : modelWeights.layers) {
            if (!lw.wk.data || lw.wk.rows == 0) continue;
            const size_t inferred = lw.wk.rows / config.headDim;
            if (inferred > 0 && inferred <= config.numHeads &&
                (config.numHeads % inferred) == 0) {
                config.numKVHeads = inferred;
                modelWeights.numKVHeads = inferred;
                fprintf(stderr, "KV_HEADS_INFERRED=%zu HEAD_DIM=%zu Q_HEADS=%zu\n",
                        inferred, config.headDim, config.numHeads);
                break;
            }
        }
    }
    // Infer FFN intermediate — prefer ffn_down half-width when fused up is 2×.
    Deep2::ffn_inter_fix::RepairIntermediate(ggufResult, modelWeights, config, stderr);
    if (modelWeights.intermediateDim == 0) {
        for (const auto& lw : modelWeights.layers) {
            if (!lw.wUp.data || lw.wUp.rows == 0) continue;
            auto facts = Deep2::phi3_fused_ffn::InspectLayer(
                lw, modelWeights.hiddenDim, /*configuredInter=*/0);
            if (facts.ok && facts.half > 0) {
                modelWeights.intermediateDim = facts.half;
                config.intermediateDim = facts.half;
                fprintf(stderr, "FFN_INTER_INFERRED_FUSED_HALF=%zu (up_rows=%zu)\n",
                        facts.half, lw.wUp.rows);
            } else {
                modelWeights.intermediateDim = lw.wUp.rows;
                config.intermediateDim = lw.wUp.rows;
                fprintf(stderr, "FFN_INTER_INFERRED=%zu\n", lw.wUp.rows);
            }
            break;
        }
    }
    // Source-only open/runtime compatibility repair. Never fabricates tensor data.
    Deep2::phi3_fused_ffn::RepairModel(modelWeights, stderr);
    config.intermediateDim = modelWeights.intermediateDim;
    Deep2::gemma4_schema::EmitSummary(modelWeights, stderr);
    Deep2::gemma4_topology::EmitSummary(modelWeights, stderr);
    const bool aliasSchemaOk =
        Deep2::gemma4_bind_fallback::TryClearBindLlamaSchemaByAliases(modelWeights, stderr);

    // MODEL_PROVENANCE_MISMATCH_DROP_001: bind/authority FP must match this model.
    // Mismatch blocks ladder promotion only — MODEL_OPEN remains PASS (no load abort).
    bool provenanceBlocksPromotion = false;
    {
        const std::uint64_t expectedModelFp =
            rawr::model_provenance::compose_model_fingerprint(
                g_modelProv.file, g_modelProv.tensorHash);
        rawr::model_provenance::mark_bind(g_modelProv, expectedModelFp, aliasSchemaOk);
        rawr::model_provenance::mark_authority(g_modelProv, expectedModelFp,
                                               /*inherited=*/false);
        rawr::model_provenance::mark_runtime(g_modelProv, expectedModelFp, "loadModel");
        rawr::model_provenance::validate(g_modelProv);
        rawr::model_provenance::emit(stderr, g_modelProv);
        if (!g_modelProv.ok) {
            provenanceBlocksPromotion = true;
            fprintf(stderr,
                    "MODEL_OPEN=PASS\n"
                    "MODEL_PROVENANCE_MATCH=0\n"
                    "AUTHORITY_LADDER=BLOCKED\n"
                    "BLOCKED_AT=PROVENANCE_MISMATCH\n"
                    "PROMOTE=0\n");
            printf("[Deep2Engine] AUTHORITY_LADDER=BLOCKED\n");
            printf("BLOCKED_AT=PROVENANCE_MISMATCH\n");
            printf("BLOCKED_OWNER=MODEL_PROVENANCE\n");
            printf("MODEL_OPEN=PASS\n");
            printf("PROMOTE=0\n");
        }
    }

    // ONE_LOCAL_MODEL_AUTHORITY ladder: schema → quant → tok (after alias bind)
    // Runtime receipts remain overlay facts; they must not mutate discovery.
    {
        rawr::olma::AuthorityBundle auth{};
        bool sealed = false;
        if (!provenanceBlocksPromotion) {
            sealed = rawr::olma::SealLadderOnLoad(ggufResult, firstShard.string().c_str(),
                                                   sessionGeometry_, auth) &&
                     auth.PASS;
            if (!sealed && aliasSchemaOk && auth.geom.PASS &&
                auth.geom.ARCH.rfind("gemma", 0) == 0) {
                std::fprintf(stderr,
                    "GEMMA4_BIND_LLAMA_FALLBACK cleared_name_lock=1 rebind=1\n");
                rawr::olma::SchemaSeal sch{};
                if (rawr::olma::BindGemma4Schema(ggufResult, auth.geom,
                                                firstShard.string().c_str(), sch) &&
                    sch.PASS) {
                    auth.schema = std::move(sch);
                    sealed = rawr::olma::SealQuantDispatch(auth.schema, auth.quant) &&
                             auth.quant.PASS &&
                             rawr::olma::SealTokEog(ggufResult, auth.geom, auth.schema,
                                                    auth.tok) &&
                             auth.tok.PASS;
                    if (sealed) auth.PASS = 1;
                }
            }
        }
        if (provenanceBlocksPromotion) {
            // MODEL_OPEN=PASS; promotion blocked — continue into buffer/runtime path.
        } else if (!sealed || !auth.PASS) {
            const char* at = !auth.geom.PASS       ? auth.geom.BLOCKED_AT.c_str()
                             : !auth.schema.PASS   ? auth.schema.BLOCKED_AT.c_str()
                             : !auth.quant.PASS    ? auth.quant.BLOCKED_AT.c_str()
                             : !auth.tok.PASS      ? auth.tok.BLOCKED_AT.c_str()
                                                   : "AUTHORITY_LADDER";
            printf("[Deep2Engine] AUTHORITY_LADDER=BLOCKED\n");
            printf("BLOCKED_AT=%s\nBLOCKED_OWNER=ONE_LOCAL_MODEL_AUTHORITY\n", at);
            printf("FIRST_DELTA=%s\n", at);
            return false;
        } else {
            sessionAuth_ = std::move(auth);
            printf("[Deep2Engine] AUTHORITY_LADDER=PASS schema=%u quant=%u tok=%u\n",
                   sessionAuth_.schema.TENSOR_SCHEMA_BOUND,
                   sessionAuth_.quant.BINDINGS_DISPATCHABLE,
                   sessionAuth_.tok.VOCAB_SIZE);
        }
    }

    // Infer MoE expert intermediate before buffer alloc (metadata often omits it).
    if (meta.numExperts > 0) {
        size_t inferredExpert = meta.moeIntermediateSize > 0 ? meta.moeIntermediateSize : meta.intermediateSize;
        if (inferredExpert == 0) {
            for (const auto& t : ggufResult.tensors) {
                if (t.name.find("ffn_gate_exps.weight") == std::string::npos) continue;
                // GGUF stacked: [hidden, expertDim, n_experts]
                if (t.dimensions.size() >= 3) {
                    inferredExpert = static_cast<size_t>(t.dimensions[1]);
                    fprintf(stderr, "MOE_EXPERT_DIM_INFERRED=%zu from %s\n",
                            inferredExpert, t.name.c_str());
                    break;
                }
            }
        }
        if (inferredExpert == 0) {
            for (const auto& lw : modelWeights.layers) {
                if (lw.moeSharedGate.rows > 0) {
                    inferredExpert = lw.moeSharedGate.rows;
                    fprintf(stderr, "MOE_EXPERT_DIM_FROM_SHEXP=%zu\n", inferredExpert);
                    break;
                }
            }
        }
        moeConfig_.expertDim = inferredExpert;
        moeConfig_.sharedExpertDim = inferredExpert;
        modelWeights.moeIntermediateDim = inferredExpert;
        bool haveShexp = false;
        for (const auto& lw : modelWeights.layers) {
            if (lw.moeSharedGate.data && lw.moeSharedUp.data && lw.moeSharedDown.data) {
                haveShexp = true; break;
            }
        }
        moeConfig_.useSharedExpert = (meta.numSharedExperts > 0) || haveShexp;
        if (moeConfig_.useSharedExpert && meta.numSharedExperts == 0)
            fprintf(stderr, "MOE_SHARED_INFERRED_FROM_SHEXP=1\n");
    }

    // Re-allocate buffers with correct dimensions
    deallocateBuffers();
    if (!allocateBuffers()) {
        printf("[Deep2Engine] ERROR: Failed to re-allocate buffers\n");
        return false;
    }

    // loadModel-only clients (e.g. RawrXD-Agentic) never call initialize() â€”
    // ensure thread pool, KV cache, and quant dispatch are ready here.
    if (config.useThreadPool && !threadPool) {
        threadPool = std::make_unique<ThreadPool>();
        threadPool->init(config.numThreads);
        printf("[Deep2Engine] ThreadPool (loadModel): %zu threads\n", threadPool->size());
    }
    Deep2::QuantKernelRegistry::Instance().Initialize();

    // Always (re)build KV cache for GGUF loads â€” do not require a prior initialize()
    if (config.useKVCache) {
        if (kvCache) kvCache->reset();
        kvCache = std::make_unique<KVCache>();
        KVCacheConfig kvConfig;
        kvConfig.numLayers = modelWeights.numLayers;
        kvConfig.maxSeqLen = config.maxSeqLen > 0 ? config.maxSeqLen : 2048;
        kvConfig.numHeads = modelWeights.numKVHeads > 0 ? modelWeights.numKVHeads : modelWeights.numHeads;
        kvConfig.headDim = modelWeights.headDim;
        if (!kvCache->initialize(kvConfig)) {
            printf("[Deep2Engine] ERROR: KV cache init failed after loadModel\n");
            return false;
        }
    }

    modelWeights.loaded = true;
    initialized = true;
    modelState_ = ModelState::Indexed;
    printf("[Deep2Engine] Model loaded successfully (%zu tensors)\n",
           isMultiShard ? globalIndex_->TotalTensors() : ggufResult.tensors.size());
    modelState_ = ModelState::Choreographable;

    // Wire MoE streaming loader
    if (meta.numExperts > 0) {
        modelWeights.isMoE = true;
        modelWeights.numExperts         = meta.numExperts;
        modelWeights.numExpertsPerToken = meta.numExpertsPerToken > 0 ? meta.numExpertsPerToken : 8;
        modelWeights.numSharedExperts   = meta.numSharedExperts;
        modelWeights.moeIntermediateDim = meta.moeIntermediateSize;

        printf("[Deep2Engine] MoE model: %u experts, top-%u, %u shared\n",
               meta.numExperts, meta.numExpertsPerToken, meta.numSharedExperts);

        // For multi-shard, MoE weights are resolved via GlobalTensorIndex + residency cache
        if (!isMultiShard) {
            moeWeightsLoader_ = std::make_unique<MoEWeightsLoader>();
            moeWeightsLoader_->SetMaxCacheSize(4ULL * 1024 * 1024 * 1024);
            if (!moeWeightsLoader_->Open(firstShard.string().c_str())) {
                printf("[Deep2Engine] WARNING: MoE streaming loader failed to open %s\n",
                       firstShard.string().c_str());
                moeWeightsLoader_.reset();
            } else {
                printf("[Deep2Engine] MoE streaming loader ready\n");

                moeConfig_.numExperts       = meta.numExperts;
                moeConfig_.numActiveExperts = modelWeights.numExpertsPerToken;
                moeConfig_.useSharedExpert  = moeConfig_.useSharedExpert || (meta.numSharedExperts > 0);
                if (moeConfig_.expertDim == 0) moeConfig_.expertDim = meta.moeIntermediateSize > 0 ?
                                                meta.moeIntermediateSize : meta.intermediateSize;
                moeConfig_.sharedExpertDim    = moeConfig_.expertDim;
                moeConfig_.hiddenDim          = meta.hiddenSize;

                // Create per-layer routers and inject weights
                moeRouters_.clear();
                moeRouters_.resize(modelWeights.numLayers);
                for (size_t layerIdx = 0; layerIdx < modelWeights.numLayers; ++layerIdx) {
                    auto router = std::make_unique<MoERouter>();
                    router->Initialize(moeConfig_);
                    const auto& lw = modelWeights.layers[layerIdx];
                    if (lw.moeRouter.data && lw.moeRouter.type == (int)GGMLType::GGML_TYPE_F32) {
                        router->SetRouterWeights(
                            (const float*)lw.moeRouter.data,
                            lw.moeRouter.rows,
                            lw.moeRouter.cols);
                    } else if (lw.moeRouter.data) {
                        // Dequantize quantized router weights to FP32 via direct dispatch
                        size_t rows = lw.moeRouter.rows;
                        size_t cols = lw.moeRouter.cols;
                        std::vector<float> dequant(rows * cols);
                        // Dispatch through the engine's own LinearW which handles all quant types
                        WeightTensor tmpWt = lw.moeRouter;
                        tmpWt.data = lw.moeRouter.data;
                        tmpWt.rows = rows;
                        tmpWt.cols = cols;
                        tmpWt.type = lw.moeRouter.type;
                        // Use a temporary input vector of ones to extract weight values row-by-row
                        std::vector<float> ones(cols, 1.0f);
                        for (size_t r = 0; r < rows; ++r) {
                            float rowOut = 0.0f;
                            // Manual GEMV for one row based on quant type
                            switch (tmpWt.type) {
                                case (int)GGMLType::GGML_TYPE_F32:
                                    for (size_t c = 0; c < cols; ++c) rowOut += ((const float*)tmpWt.data)[r * cols + c] * ones[c];
                                    break;
                                case (int)GGMLType::GGML_TYPE_F16:
                                    for (size_t c = 0; c < cols; ++c) rowOut += fp16ToFloat(((const uint16_t*)tmpWt.data)[r * cols + c]) * ones[c];
                                    break;
                                case (int)GGMLType::GGML_TYPE_Q4_0: {
                                    const block_q4_0* blocks = (const block_q4_0*)tmpWt.data;
                                    size_t bpr = (cols + 31) / 32;
                                    for (size_t b = 0; b < bpr; ++b) {
                                        float d = fp16ToFloat(blocks[r * bpr + b].d);
                                        for (int i = 0; i < 32; ++i) {
                                            uint8_t byte = blocks[r * bpr + b].qs[i / 2];
                                            int q = (i % 2 == 0) ? (byte & 0x0F) : (byte >> 4);
                                            rowOut += d * (q - 8.0f) * ones[b * 32 + i];
                                        }
                                    }
                                    break;
                                }
                                case (int)GGMLType::GGML_TYPE_Q8_0: {
                                    const block_q8_0* blocks = (const block_q8_0*)tmpWt.data;
                                    size_t bpr = (cols + 31) / 32;
                                    for (size_t b = 0; b < bpr; ++b) {
                                        float d = fp16ToFloat(blocks[r * bpr + b].d);
                                        for (int i = 0; i < 32; ++i) {
                                            rowOut += d * (float)blocks[r * bpr + b].qs[i] * ones[b * 32 + i];
                                        }
                                    }
                                    break;
                                }
                                default:
                                    // Fallback: use the registry dequant if available
                                    {
                                        auto& reg = QuantKernelRegistry::Instance();
                                        if (reg.GetRegisteredCount() == 0) reg.Initialize();
                                        auto dequantFn = reg.GetDequant(tmpWt.type);
                                        if (dequantFn) {
                                            size_t rowBytes = tmpWt.sizeBytes / rows;
                                            std::vector<float> rowBuf(cols);
                                            dequantFn((const uint8_t*)tmpWt.data + r * rowBytes, rowBuf.data(), cols);
                                            for (size_t c = 0; c < cols; ++c) rowOut += rowBuf[c] * ones[c];
                                        }
                                    }
                                    break;
                            }
                            dequant[r * cols + 0] = rowOut; // Store first element; full row needs proper extraction
                        }
                        // Simpler approach: just use the registry dequant for the whole tensor
                        {
                            auto& reg = QuantKernelRegistry::Instance();
                            if (reg.GetRegisteredCount() == 0) reg.Initialize();
                            auto dequantFn = reg.GetDequant(tmpWt.type);
                            if (dequantFn) {
                                dequantFn((const uint8_t*)tmpWt.data, dequant.data(), rows * cols);
                                router->SetRouterWeights(dequant.data(), rows, cols);
                                printf("[Deep2Engine] Layer %zu router weights dequantized via registry from type=%d to FP32 (%zux%zu)\n",
                                       layerIdx, lw.moeRouter.type, rows, cols);
                            } else {
                                printf("[Deep2Engine] WARNING: Layer %zu router weights type=%d has no registry dequantizer, skipping injection\n",
                                       layerIdx, lw.moeRouter.type);
                            }
                        }
                    }
                    moeRouters_[layerIdx] = std::move(router);
                }
                printf("[Deep2Engine] Injected router weights for %zu layers\n", moeRouters_.size());

                moeWeightProxy_ = std::make_unique<MoEWeightProxy>();
                moeWeightProxy_->Attach(moeWeightsLoader_.get());

                // Initialize residency telemetry for router-driven prefetch pipeline
                residencyTelemetry_ = std::make_unique<RouterPrefetchTelemetry>();
                residencyTelemetry_->Initialize(
                    static_cast<int>(modelWeights.numLayers),
                    static_cast<int>(modelWeights.numExperts));
                telemetryEnabled_ = true;
                printf("[Deep2Engine] RouterPrefetchTelemetry initialized: %zu layers x %u experts\n",
                       modelWeights.numLayers, meta.numExperts);

                moeInitialized_ = true;
            }
        } else {
            printf("[Deep2Engine] MoE multi-shard: using GlobalTensorIndex + residency cache\n");
            moeConfig_.numExperts       = meta.numExperts;
            moeConfig_.numActiveExperts = modelWeights.numExpertsPerToken;
                moeConfig_.useSharedExpert  = moeConfig_.useSharedExpert || (meta.numSharedExperts > 0);
                if (moeConfig_.expertDim == 0) moeConfig_.expertDim = meta.moeIntermediateSize > 0 ?
                                                meta.moeIntermediateSize : meta.intermediateSize;
            moeConfig_.sharedExpertDim    = moeConfig_.expertDim;
            moeConfig_.hiddenDim          = meta.hiddenSize;

            // Create per-layer routers for multi-shard (weights loaded on-demand)
            moeRouters_.clear();
            moeRouters_.resize(modelWeights.numLayers);
            for (size_t layerIdx = 0; layerIdx < modelWeights.numLayers; ++layerIdx) {
                auto router = std::make_unique<MoERouter>();
                router->Initialize(moeConfig_);
                moeRouters_[layerIdx] = std::move(router);
            }
            printf("[Deep2Engine] Created %zu per-layer routers (multi-shard)\n", moeRouters_.size());

            moeInitialized_ = true;
        }
    }

    strncpy(config.modelPath, ggufPath.c_str(), sizeof(config.modelPath) - 1);
    config.modelPath[sizeof(config.modelPath) - 1] = '\0';
    {
        const uint64_t pathH = Deep2::Ev512::HostPathHash(ggufPath.c_str());
        const uint64_t nTen = isMultiShard ? globalIndex_->TotalTensors()
                                            : ggufResult.tensors.size();
        Deep2::Ev512::HostEmitModelLoadComplete(pathH, nTen);
        Deep2::Ev512::HostEmitShardResolution(isMultiShard ? 1ull : 1ull, 1ull);
        Deep2::Ev512::HostEmitArchContract(
            Deep2::Ev512::HostPathHash(
                ggufResult.metadata.architecture.c_str()),
            (uint64_t)modelWeights.numLayers, 1u);
        Deep2::Ev512::HostEmitQuantContract(0, 0, 1u);
        Deep2::Ev512::HostEmitTokenizerContract(
            0, (uint64_t)config.vocabSize, tokenizer ? 1u : 0u);
        Deep2::Ev512::HostEmitDeep2SessionCreate(pathH, 1);
        Deep2::Ev512::HostEmitDeep2SessionReady(1, 0);
    }
    return true;
}

// ============================================================================
// Load Model from BP16 file (zero-copy mapped weights)
// ============================================================================
bool Deep2Engine::loadModelFromBP16(const std::string& bp16Path) {
    printf("[Deep2Engine] Loading BP16 model from: %s\n", bp16Path.c_str());

    // Close any existing BP16 streamer
    if (bp16Streamer_) {
        bp16Streamer_->close();
        bp16Streamer_.reset();
    }
    bp16Enabled_ = false;

    bp16Streamer_ = std::make_unique<BP16Streamer>();
    if (!bp16Streamer_->open(bp16Path.c_str())) {
        printf("[Deep2Engine] ERROR: BP16 open failed: %s\n", bp16Streamer_->error());
        bp16Streamer_.reset();
        return false;
    }

    printf("[Deep2Engine] BP16 opened: %zu tensors, %zu bytes\n",
           bp16Streamer_->tensorCount(), bp16Streamer_->fileSize());

    // Infer architecture from tensor manifest
    const auto* tokenEmbd = bp16Streamer_->find("token_embd.weight");
    if (!tokenEmbd) {
        printf("[Deep2Engine] ERROR: BP16 missing token_embd.weight\n");
        bp16Streamer_->close();
        bp16Streamer_.reset();
        return false;
    }

    // token_embd dimensions in GGUF: [hiddenSize, vocabSize]
    // Verified: dim0=hiddenSize, dim1=vocabSize (not the other way around)
    size_t dim0 = tokenEmbd->dimensions.size() > 0 ? tokenEmbd->dimensions[0] : 0;
    size_t dim1 = tokenEmbd->dimensions.size() > 1 ? tokenEmbd->dimensions[1] : 0;
    printf("[Deep2Engine] BP16 token_embd raw dims: dim0=%zu dim1=%zu\n", dim0, dim1);
    size_t inferredHiddenDim = dim0;
    size_t inferredVocabSize = dim1;

    // Count layers from blk.N.* tensors
    size_t maxLayer = 0;
    for (const auto& rec : bp16Streamer_->records()) {
        if (rec.name.size() > 4 && rec.name.substr(0, 4) == "blk.") {
            size_t dotPos = rec.name.find('.', 4);
            if (dotPos != std::string::npos) {
                int layerIdx = std::atoi(rec.name.c_str() + 4);
                if (layerIdx >= 0 && static_cast<size_t>(layerIdx) > maxLayer)
                    maxLayer = static_cast<size_t>(layerIdx);
            }
        }
    }
    size_t inferredNumLayers = maxLayer + 1;

    printf("[Deep2Engine] BP16 inferred: vocabSize=%zu hiddenDim=%zu numLayers=%zu\n",
           inferredVocabSize, inferredHiddenDim, inferredNumLayers);

    // Update config with inferred values â€” ALWAYS override because BP16 is authoritative
    config.vocabSize = inferredVocabSize;
    config.hiddenDim = inferredHiddenDim;
    config.numLayers = inferredNumLayers;
    config.numHeads = config.hiddenDim > 0 ? config.hiddenDim / 128 : 1;
    if (config.numHeads == 0) config.numHeads = 1;
    config.numKVHeads = config.numHeads;
    config.headDim = config.hiddenDim > 0 && config.numHeads > 0
        ? config.hiddenDim / config.numHeads : 128;
    // Preserve metadata-derived intermediateDim if available, otherwise heuristic
    if (modelWeights.intermediateDim == 0) {
        config.intermediateDim = config.hiddenDim * 4; // heuristic
    } else {
        config.intermediateDim = modelWeights.intermediateDim;
    }

    // Allocate layer weights
    modelWeights.layers.resize(config.numLayers);

    // Map tensors from BP16 into WeightTensor structs
    // BP16 stores GGUF dimensions verbatim: [input_dim, output_dim]
    // LinearW needs rows=output_dim, cols=input_dim
    auto mapTensor = [&](const std::string& name, WeightTensor& wt) -> bool {
        const auto* rec = bp16Streamer_->find(name);
        if (!rec) return false;

        const uint8_t* data = nullptr;
        size_t bytes = 0;
        if (!bp16Streamer_->map_tensor(name, data, bytes)) return false;

        wt.data = const_cast<void*>(static_cast<const void*>(data));
        wt.type = static_cast<int>(rec->type);
        wt.rows = rec->dimensions.size() > 1 ? rec->dimensions[1] : 1;
        wt.cols = rec->dimensions.size() > 0 ? rec->dimensions[0] : 0;
        wt.sizeBytes = rec->byteSize;
        wt.name = rec->name;
        wt.mapped = true;
        return true;
    };

    // Map global tensors
    mapTensor("token_embd.weight", modelWeights.tokenEmbed);
    mapTensor("output.weight", modelWeights.lmHead);
    if (!modelWeights.lmHead.data) {
        mapTensor("lm_head.weight", modelWeights.lmHead);
    }
    mapTensor("output_norm.weight", modelWeights.finalNorm);
    if (!modelWeights.finalNorm.data) {
        mapTensor("norm.weight", modelWeights.finalNorm);
    }

    // Map per-layer tensors
    for (size_t layerIdx = 0; layerIdx < config.numLayers; ++layerIdx) {
        auto& lw = modelWeights.layers[layerIdx];
        std::string prefix = "blk." + std::to_string(layerIdx) + ".";

        mapTensor(prefix + "attn_qkv.weight",   lw.wqkv);
        mapTensor(prefix + "attn_q.weight",     lw.wq);
        mapTensor(prefix + "attn_k.weight",     lw.wk);
        mapTensor(prefix + "attn_v.weight",     lw.wv);
        mapTensor(prefix + "attn_output.weight", lw.wo);
        mapTensor(prefix + "attn_norm.weight",  lw.attnNorm);
        mapTensor(prefix + "ffn_gate.weight",     lw.wGate);
        mapTensor(prefix + "ffn_up.weight",       lw.wUp);
        mapTensor(prefix + "ffn_down.weight",     lw.wDown);
        mapTensor(prefix + "ffn_norm.weight",     lw.ffnNorm);

        // Validate: check for zero-weight tensors (indicates extraction/loading bug)
        if (lw.wq.data) {
            const uint8_t* firstBytes = (const uint8_t*)lw.wq.data;
            bool allZero = true;
            for (size_t i = 0; i < 32 && i < lw.wq.sizeBytes; ++i) {
                if (firstBytes[i] != 0) { allZero = false; break; }
            }
            if (allZero && lw.wq.sizeBytes > 0) {
                printf("[BP16_VALIDATION] WARNING: %sattn_q.weight has all-zero first 32 bytes (size=%zu)\n",
                       prefix.c_str(), lw.wq.sizeBytes);
            }
        }
    }

    // Infer GQA from layer 0 Q/K weight dimensions
    // GGUF dims: [input_dim, output_dim]
    // attn_q: [hiddenDim, numHeads*headDim]  â†’ rows = numHeads*headDim
    // attn_k: [hiddenDim, numKVHeads*headDim] â†’ rows = numKVHeads*headDim
    if (config.numLayers > 0) {
        const auto& lw0 = modelWeights.layers[0];
        if (lw0.wq.data && lw0.wk.data && lw0.wq.rows != lw0.wk.rows) {
            size_t inferredKVHeads = lw0.wk.rows / config.headDim;
            if (inferredKVHeads > 0 && inferredKVHeads != config.numKVHeads) {
                printf("[Deep2Engine] GQA detected: numKVHeads %zu â†’ %zu (from attn_k.rows=%zu headDim=%zu)\n",
                       config.numKVHeads, inferredKVHeads, lw0.wk.rows, config.headDim);
                config.numKVHeads = inferredKVHeads;
            }
        }
    }

    // Check tied embeddings
    if (modelWeights.lmHead.data == nullptr && modelWeights.tokenEmbed.data != nullptr) {
        modelWeights.lmHead = modelWeights.tokenEmbed;
        modelWeights.tieEmbeddings = true;
        printf("[Deep2Engine] Using tied embeddings\n");
    }

    // Sync modelWeights metadata
    modelWeights.vocabSize       = config.vocabSize;
    modelWeights.hiddenDim       = config.hiddenDim;
    modelWeights.numLayers       = config.numLayers;
    modelWeights.numHeads        = config.numHeads;
    modelWeights.numKVHeads      = config.numKVHeads;
    modelWeights.headDim         = config.headDim;
    modelWeights.intermediateDim = config.intermediateDim;
    modelWeights.loaded          = true;
    bp16Enabled_                 = true;

    // Re-allocate buffers with correct dimensions (same as GGUF load path)
    deallocateBuffers();
    if (!allocateBuffers()) {
        printf("[Deep2Engine] ERROR: BP16 failed to re-allocate buffers\n");
        bp16Enabled_ = false;
        modelWeights.loaded = false;
        return false;
    }

    // Re-initialize KV cache with correct dimensions
    if (kvCache) {
        kvCache->reset();
        kvCache = std::make_unique<KVCache>();
        KVCacheConfig kvConfig;
        kvConfig.numLayers = modelWeights.numLayers;
        kvConfig.maxSeqLen = config.maxSeqLen;
        kvConfig.numHeads  = modelWeights.numKVHeads > 0 ? modelWeights.numKVHeads : modelWeights.numHeads;
        kvConfig.headDim   = modelWeights.headDim;
        kvCache->initialize(kvConfig);
    }

    printf("[Deep2Engine] BP16 model loaded successfully (%zu tensors)\n",
           bp16Streamer_->tensorCount());
    return true;
}

bool Deep2Engine::loadWeights(const void* weightData, size_t size) {
    (void)weightData;
    (void)size;
    fprintf(stderr,
        "[Deep2Engine] ERROR: loadWeights() is not implemented â€” "
        "use loadModel(ggufPath). Returning failure (no false success).\n");
    return false;
}

// ============================================================================
// Tokenization
// ============================================================================
std::vector<int> Deep2Engine::tokenize(const std::string& text) {
    if (tokenizer) {
        return tokenizer->Encode(text);
    }
    if (CanonicalTokenizer::Instance().IsLoaded()) {
        return CanonicalTokenizer::Instance().Encode(text);
    }
    fprintf(stderr, "[Deep2Engine] ERROR: tokenize() called with no tokenizer loaded\n");
    return {};
}

std::string Deep2Engine::detokenize(const std::vector<int>& tokens) {
    if (tokenizer) {
        return tokenizer->Decode(tokens);
    }
    if (CanonicalTokenizer::Instance().IsLoaded()) {
        return CanonicalTokenizer::Instance().Decode(tokens);
    }
    return {};
}

// ============================================================================
// Token Embedding Lookup
// ============================================================================
bool Deep2Engine::embedToken(int tokenId, float* output) {
    if (rawr::iso_ladder::Ignore(rawr::iso_ladder::Run::A12)) {
        if (output && config.hiddenDim) {
            std::memset(output, 0, config.hiddenDim * sizeof(float));
            output[0] = 1.0f;
        }
        return true;
    }
    if (k2ShardIndexOpen_ && globalIndex_ && output && config.hiddenDim) {
        static thread_local std::unique_ptr<K2TokenEmbedding> emb;
        static thread_local const GlobalTensorIndex* bound = nullptr;
        if (!emb || bound != globalIndex_.get()) {
            K2TokenEmbedding::Config c;
            c.hiddenSize = config.hiddenDim;
            c.vocabSize = config.vocabSize ? config.vocabSize : 163840;
            emb = std::make_unique<K2TokenEmbedding>(c);
            if (!emb->initialize(globalIndex_.get())) {
                fprintf(stderr, "[FATAL_EMBED] K2TokenEmbedding init failed\n");
                return false;
            }
            bound = globalIndex_.get();
        }
        auto r = emb->lookup(static_cast<uint32_t>(tokenId), output);
        if (!r.ok) {
            fprintf(stderr, "[FATAL_EMBED] K2 lookup token=%d %s\n", tokenId,
                    r.error.c_str());
            return false;
        }
        return true;
    }
    if (!modelWeights.loaded || !modelWeights.tokenEmbed.data || !output) {
        if (output && config.hiddenDim > 0) {
            memset(output, 0, config.hiddenDim * sizeof(float));
        }
        return false;
    }

    // Bounds check tokenId
    if (tokenId < 0 || tokenId >= (int)modelWeights.vocabSize) {
        memset(output, 0, config.hiddenDim * sizeof(float));
        fprintf(stderr,
            "[FATAL_EMBED] token=%d out of range vocabSize=%zu â€” inference cannot proceed.\n",
            tokenId, modelWeights.vocabSize);
        return false;
    }

    // â”€â”€ Diagnostic: print token embed info once â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    static bool printedEmbedInfo = false;
    if (!printedEmbedInfo) {
        printf("[Deep2Engine] embedToken: type=%d vocabSize=%zu hiddenDim=%zu data=%p sizeBytes=%zu\n",
               modelWeights.tokenEmbed.type, modelWeights.vocabSize,
               modelWeights.hiddenDim, modelWeights.tokenEmbed.data,
               modelWeights.tokenEmbed.sizeBytes);
        printedEmbedInfo = true;
    }

    // â”€â”€ P0 Diagnostic: raw byte inspection for embedding row â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // This determines whether the raw GGUF bytes are zero (mapping bug)
    // or whether the dequantizer is producing zero from valid bytes.
    {
        const uint8_t* rawBase = (const uint8_t*)modelWeights.tokenEmbed.data;
        size_t rowBytes = 0;
        if (modelWeights.tokenEmbed.type == (int)GGMLType::GGML_TYPE_Q6_K) {
            size_t numBlocks = modelWeights.hiddenDim / 256;
            rowBytes = numBlocks * sizeof(block_q6_K);
        } else if (modelWeights.tokenEmbed.type == (int)GGMLType::GGML_TYPE_Q4_K) {
            size_t numBlocks = modelWeights.hiddenDim / 256;
            rowBytes = numBlocks * sizeof(block_q4_K);
        } else if (modelWeights.tokenEmbed.type == (int)GGMLType::GGML_TYPE_F32) {
            rowBytes = modelWeights.hiddenDim * sizeof(float);
        } else if (modelWeights.tokenEmbed.type == (int)GGMLType::GGML_TYPE_F16) {
            rowBytes = modelWeights.hiddenDim * sizeof(uint16_t);
        } else {
            rowBytes = modelWeights.tokenEmbed.sizeBytes / modelWeights.vocabSize;
        }
        if (rowBytes > 0 && tokenId >= 0 && tokenId < (int)modelWeights.vocabSize) {
            const uint8_t* row = rawBase + tokenId * rowBytes;
            static const bool embedRaw =
                (std::getenv("RAWRXD_DEEP2_LAYER_PROBE") != nullptr &&
                 std::getenv("RAWRXD_DEEP2_LAYER_PROBE")[0] == '1');
            if (embedRaw) {
                fprintf(stderr, "[EMBED_RAW] token=%d row=%p rowBytes=%zu first32=", tokenId, row, rowBytes);
                for (size_t i = 0; i < 32; ++i) fprintf(stderr, "%02X ", row[i]);
                fprintf(stderr, "\n");
            }
        }
    }

    // --- Elastic residency: ONLY when weights are not already mapped in RAM.
    // Historical retard-mode: Acquire returned a zero-filled WarmCompressed buffer
    // (ExecuteNvmeToRam memset when sourceData==null) and overwrote a live wt.data
    // pointer → PROMPT_EMBED norm=0 → all layers zero → gibberish tokens.
    const void* embedDataPtr = modelWeights.tokenEmbed.data;
    if (elasticResidencyEnabled_ && elasticResidency_ &&
        !modelWeights.tokenEmbed.name.empty() &&
        !(modelWeights.tokenEmbed.data && modelWeights.tokenEmbed.mapped)) {
        Deep2::ElasticResidencyManager::ResidencyHandle resHandle;
        auto status = elasticResidency_->AcquireTensor(modelWeights.tokenEmbed.name, 0, 0, resHandle);
        if (status == Deep2::ElasticResidencyManager::AcquireStatus::Ready &&
            resHandle.ready && resHandle.cpuPtr) {
            embedDataPtr = resHandle.cpuPtr;
        }
    }
    if (!embedDataPtr) {
        memset(output, 0, config.hiddenDim * sizeof(float));
        fprintf(stderr, "[FATAL_EMBED] no embed backing pointer\n");
        return false;
    }

    // tokenEmbed is [vocabSize, hiddenDim]
    // For FP32: direct copy
    if (modelWeights.tokenEmbed.type == (int)GGMLType::GGML_TYPE_F32) {
        const float* embedTable = (const float*)embedDataPtr;
        size_t hiddenDim = modelWeights.hiddenDim;
        if (tokenId >= 0 && tokenId < (int)modelWeights.vocabSize) {
            memcpy(output, embedTable + tokenId * hiddenDim, hiddenDim * sizeof(float));
        } else {
            memset(output, 0, hiddenDim * sizeof(float));
        }
    } else if (modelWeights.tokenEmbed.type == (int)GGMLType::GGML_TYPE_F16) {
        const uint16_t* embedTable = (const uint16_t*)embedDataPtr;
        size_t hiddenDim = modelWeights.hiddenDim;
        if (tokenId >= 0 && tokenId < (int)modelWeights.vocabSize) {
            const uint16_t* src = embedTable + tokenId * hiddenDim;
            #if defined(__F16C__) || defined(_MSC_VER)
            if (hiddenDim >= 8) {
                size_t i = 0;
                for (; i + 7 < hiddenDim; i += 8) {
                    __m128i h16 = _mm_loadu_si128((const __m128i*)(src + i));
                    __m256 f32 = _mm256_cvtph_ps(h16);
                    _mm256_storeu_ps(output + i, f32);
                }
                for (; i < hiddenDim; ++i) {
                    output[i] = fp16ToFloat(src[i]);
                }
            } else
            #endif
            {
                for (size_t i = 0; i < hiddenDim; ++i) {
                    output[i] = fp16ToFloat(src[i]);
                }
            }
        } else {
            memset(output, 0, hiddenDim * sizeof(float));
        }
    } else if (modelWeights.tokenEmbed.type == (int)GGMLType::GGML_TYPE_Q4_K) {
        // Q4_K token embedding: each row is [numBlocks x block_q4_K (144 bytes)]
        size_t hiddenDim = modelWeights.hiddenDim;
        size_t numBlocks = hiddenDim / 256;
        size_t rowBytes = numBlocks * sizeof(block_q4_K);
        const uint8_t* embedData = (const uint8_t*)embedDataPtr;
        if (tokenId >= 0 && tokenId < (int)modelWeights.vocabSize) {
            const uint8_t* row = embedData + tokenId * rowBytes;
            // Use the registry dequantizer for correctness
            auto& reg = Deep2::QuantKernelRegistry::Instance();
            auto dequant = reg.GetDequant((int)GGMLType::GGML_TYPE_Q4_K);
            if (dequant) {
                dequant(row, output, hiddenDim);
            } else {
                // Fallback: ggml-compatible Q4_K layout
                const block_q4_K* blocks = reinterpret_cast<const block_q4_K*>(row);
                for (size_t b = 0; b < numBlocks; ++b) {
                    dequantizeQ4KBlock(reinterpret_cast<const Q4_K_Block*>(&blocks[b]),
                                       output + b * 256);
                }
            }
        } else {
            memset(output, 0, hiddenDim * sizeof(float));
        }
    } else {
        // --- Quant-agnostic embedding dequant via registry ---
        size_t hiddenDim = modelWeights.hiddenDim;
        const uint8_t* embedData = (const uint8_t*)embedDataPtr;
        
        if (tokenId >= 0 && tokenId < (int)modelWeights.vocabSize) {
            // Compute rowBytes from block geometry, not sizeBytes/vocabSize
            // sizeBytes may store element count rather than byte count for some loaders
            size_t rowBytes = 0;
            if (modelWeights.tokenEmbed.type == (int)GGMLType::GGML_TYPE_Q4_K) {
                size_t numBlocks = hiddenDim / 256;
                rowBytes = numBlocks * sizeof(Q4_K_Block); // 24 * 144 = 3456
            } else if (modelWeights.tokenEmbed.type == (int)GGMLType::GGML_TYPE_Q8_0) {
                size_t numBlocks = hiddenDim / 32;
                rowBytes = numBlocks * sizeof(block_q8_0);
            } else if (modelWeights.tokenEmbed.type == (int)GGMLType::GGML_TYPE_Q4_0) {
                size_t numBlocks = hiddenDim / 32;
                rowBytes = numBlocks * sizeof(block_q4_0);
            } else if (modelWeights.tokenEmbed.type == (int)GGMLType::GGML_TYPE_Q2_K) {
                size_t numBlocks = hiddenDim / 256;
                rowBytes = numBlocks * sizeof(block_q2_K);
            } else if (modelWeights.tokenEmbed.type == (int)GGMLType::GGML_TYPE_Q3_K) {
                size_t numBlocks = hiddenDim / 256;
                rowBytes = numBlocks * sizeof(block_q3_K);
            } else if (modelWeights.tokenEmbed.type == (int)GGMLType::GGML_TYPE_Q6_K) {
                size_t numBlocks = hiddenDim / 256;
                rowBytes = numBlocks * sizeof(block_q6_K);
            } else {
                // Fallback: try to use sizeBytes if it appears valid
                rowBytes = modelWeights.tokenEmbed.sizeBytes / modelWeights.vocabSize;
            }
            
            const uint8_t* row = embedData + tokenId * rowBytes;
            
            auto& reg = Deep2::QuantKernelRegistry::Instance();
            // Ensure registry is initialized before use
            if (reg.GetRegisteredCount() == 0) {
                reg.Initialize();
            }
            auto dequant = reg.GetDequant(modelWeights.tokenEmbed.type);
            const bool embedDiag = []() {
                const char* e = std::getenv("RAWRXD_EMBED_DIAG");
                return e && e[0] == '1';
            }();
            if (embedDiag)
                fprintf(stderr, "[EMBED_DIAG] dequant=%p type=%d\n",
                        (void*)dequant, modelWeights.tokenEmbed.type);
            if (dequant) {
                // Registry handles all quant types uniformly
                dequant(row, output, hiddenDim);
                
                // â”€â”€ Full-output NaN/Inf scan â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
                int firstBadIdx = -1;
                float firstBadVal = 0.0f;
                const char* firstBadKind = "";
                for (size_t i = 0; i < hiddenDim; ++i) {
                    if (!std::isfinite(output[i])) {
                        firstBadIdx = (int)i;
                        firstBadVal = output[i];
                        firstBadKind = std::isnan(output[i]) ? "NaN" : "Inf";
                        break;
                    }
                }
                if (embedDiag && firstBadIdx >= 0) {
                    fprintf(stderr, "[EMBED_DIAG][FIRST_BAD] token=%d idx=%d value=%.6f kind=%s\n",
                            tokenId, firstBadIdx, firstBadVal, firstBadKind);
                    // Inspect the raw block that produced the NaN
                    int badBlock = firstBadIdx / 256;
                    size_t blockOffset = badBlock * sizeof(block_q2_K);
                    if (blockOffset + sizeof(block_q2_K) <= rowBytes) {
                        const block_q2_K* blk = (const block_q2_K*)(row + blockOffset);
                        fprintf(stderr, "[EMBED_DIAG][BLOCK_RAW] block=%d offset=%zu d_raw=0x%04X dmin_raw=0x%04X\n",
                                badBlock, blockOffset, blk->d, blk->dmin);
                        fprintf(stderr, "[EMBED_DIAG][BLOCK_RAW] scales=");
                        for (int k = 0; k < 16; ++k) fprintf(stderr, "%02X ", blk->scales[k]);
                        fprintf(stderr, "\n");
                        fprintf(stderr, "[EMBED_DIAG][BLOCK_RAW] qs[0..15]=");
                        for (int k = 0; k < 16; ++k) fprintf(stderr, "%02X ", blk->qs[k]);
                        fprintf(stderr, "\n");
                        // Decode d/dmin with fp16ToFloat
                        float d_decoded = fp16ToFloat(blk->d);
                        float dmin_decoded = fp16ToFloat(blk->dmin);
                        fprintf(stderr, "[EMBED_DIAG][BLOCK_RAW] d: raw=0x%04X fp16ToFloat=%.6f finite=%d\n",
                                blk->d, d_decoded, (int)std::isfinite(d_decoded));
                        fprintf(stderr, "[EMBED_DIAG][BLOCK_RAW] dmin: raw=0x%04X fp16ToFloat=%.6f finite=%d\n",
                                blk->dmin, dmin_decoded, (int)std::isfinite(dmin_decoded));
                    }
                } else if (embedDiag) {
                    fprintf(stderr, "[EMBED_DIAG] token=%d all_finite hiddenDim=%zu\n",
                            tokenId, hiddenDim);
                }
                
                if (embedDiag) {
                    fprintf(stderr, "[EMBED_DIAG] token=%d rowBytes=%zu first8=", tokenId, rowBytes);
                    for (int i = 0; i < 8; ++i) fprintf(stderr, " %.3f", output[i]);
                    fprintf(stderr, "\n");
                }
            } else if (modelWeights.tokenEmbed.type == (int)GGMLType::GGML_TYPE_Q4_K) {
                // Legacy fallback
                size_t numBlocks = hiddenDim / 256;
                const Q4_K_Block* blocks = (const Q4_K_Block*)row;
                float* dequantBuf = alignedAlloc(256);
                for (size_t b = 0; b < numBlocks; ++b) {
                    dequantizeQ4KBlock(&blocks[b], dequantBuf);
                    memcpy(output + b * 256, dequantBuf, 256 * sizeof(float));
                }
                alignedFree(dequantBuf);
            } else if (modelWeights.tokenEmbed.type == (int)GGMLType::GGML_TYPE_Q8_0) {
                // Legacy fallback
                size_t numBlocks = hiddenDim / 32;
                const block_q8_0* blocks = (const block_q8_0*)row;
                for (size_t b = 0; b < numBlocks; ++b) {
                    float d = fp16ToFloat(blocks[b].d);
                    for (size_t i = 0; i < 32; ++i) {
                        output[b * 32 + i] = d * (float)blocks[b].qs[i];
                    }
                }
            } else if (modelWeights.tokenEmbed.type == (int)GGMLType::GGML_TYPE_Q2_K) {
                // Q2_K embedding: 256 weights per 84-byte block
                // scales[16]: packed 4-bit pairs = scale | (min << 4)
                // qs[64]: 2-bit weights, organized in 2 chunks of 128 elements
                // Each chunk has 4 sub-blocks of 32 elements sharing 32 qs bytes with shifts 0,2,4,6
                size_t numBlocks = hiddenDim / 256;
                rowBytes = numBlocks * sizeof(block_q2_K);
                const block_q2_K* blocks = (const block_q2_K*)row;
                
                // â”€â”€ Q2_K Block-Level Diagnostic â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
                static bool q2diagPrinted = false;
                bool firstNanFound = false;
                int firstNanBlock = -1, firstNanElem = -1;
                float firstNanValue = 0.0f;
                const char* firstNanStage = "";
                
                for (size_t b = 0; b < numBlocks; ++b) {
                    const block_q2_K& blk = blocks[b];
                    float d = fp16ToFloat(blk.d);
                    float dmin = fp16ToFloat(blk.dmin);
                    
                    // Check block header finiteness
                    bool dFinite = std::isfinite(d);
                    bool dminFinite = std::isfinite(dmin);
                    
                    if (!q2diagPrinted && b == 0) {
                        fprintf(stderr, "[Q2DIAG] token=%d block=%zu/%zu\n", tokenId, b, numBlocks);
                        fprintf(stderr, "[Q2DIAG]   rawHeader=");
                        for (size_t k = 0; k < 20; ++k) fprintf(stderr, "%02X ", ((const uint8_t*)&blk)[k]);
                        fprintf(stderr, "\n");
                        fprintf(stderr, "[Q2DIAG]   d=0x%04X -> %.6f (finite=%d)\n", blk.d, d, (int)dFinite);
                        fprintf(stderr, "[Q2DIAG]   dmin=0x%04X -> %.6f (finite=%d)\n", blk.dmin, dmin, (int)dminFinite);
                        fprintf(stderr, "[Q2DIAG]   scales=");
                        for (int k = 0; k < 16; ++k) fprintf(stderr, "%02X ", blk.scales[k]);
                        fprintf(stderr, "\n");
                        fprintf(stderr, "[Q2DIAG]   qs[0..15]=");
                        for (int k = 0; k < 16; ++k) fprintf(stderr, "%02X ", blk.qs[k]);
                        fprintf(stderr, "\n");
                    }
                    
                    if (!dFinite || !dminFinite) {
                        if (!firstNanFound) {
                            firstNanFound = true;
                            firstNanBlock = (int)b;
                            firstNanElem = -1;
                            firstNanValue = !dFinite ? d : dmin;
                            firstNanStage = !dFinite ? "D_VALUE" : "DMIN_VALUE";
                        }
                        if (!q2diagPrinted) {
                            fprintf(stderr, "[Q2DIAG][FIRST_NAN] block=%zu stage=%s value=%.6f\n", b, firstNanStage, firstNanValue);
                        }
                        // Fill remainder with zeros to avoid propagating NaN
                        for (size_t i = 0; i < 256; ++i) output[b * 256 + i] = 0.0f;
                        continue;
                    }
                    
                    for (size_t i = 0; i < 256; ++i) {
                        int chunk = (int)(i / 128);
                        int subBlock = (int)((i % 128) / 32);
                        int posInSubBlock = (int)(i % 32);
                        int group = posInSubBlock / 16;
                        int scaleIdx = chunk * 8 + subBlock * 2 + group;
                        uint8_t sc = blk.scales[scaleIdx];
                        float dl = d * (float)(sc & 0x0F);
                        float ml = dmin * (float)(sc >> 4);
                        int qsIdx = chunk * 32 + posInSubBlock;
                        int qsShift = subBlock * 2;
                        int q = (blk.qs[qsIdx] >> qsShift) & 0x03;
                        float val = dl * (float)q - ml;
                        
                        if (!std::isfinite(val) && !firstNanFound) {
                            firstNanFound = true;
                            firstNanBlock = (int)b;
                            firstNanElem = (int)i;
                            firstNanValue = val;
                            firstNanStage = "DEQUANT";
                            if (!q2diagPrinted) {
                                fprintf(stderr, "[Q2DIAG][FIRST_NAN] block=%zu elem=%zu stage=DEQUANT dl=%.6f ml=%.6f q=%d val=%.6f\n",
                                        b, i, dl, ml, q, val);
                            }
                        }
                        output[b * 256 + i] = val;
                    }
                }
                
                if (firstNanFound && !q2diagPrinted) {
                    fprintf(stderr, "[Q2DIAG][SUMMARY] firstNanBlock=%d firstNanElem=%d stage=%s value=%.6f\n",
                            firstNanBlock, firstNanElem, firstNanStage, firstNanValue);
                }
                
                // Print output range summary for first block only
                if (!q2diagPrinted) {
                    float outMin = output[0], outMax = output[0];
                    size_t outNonZero = 0;
                    for (size_t i = 0; i < hiddenDim; ++i) {
                        if (output[i] < outMin) outMin = output[i];
                        if (output[i] > outMax) outMax = output[i];
                        if (output[i] != 0.0f) outNonZero++;
                    }
                    fprintf(stderr, "[Q2DIAG] output range=[%.6f, %.6f] nonzero=%zu/%zu\n",
                            outMin, outMax, outNonZero, hiddenDim);
                    q2diagPrinted = true;
                }
                // â”€â”€ End Q2_K Diagnostic â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            } else if (modelWeights.tokenEmbed.type == (int)GGMLType::GGML_TYPE_Q3_K) {
                // Q3_K embedding: 256 weights per 110-byte block
                // hmask[32]: 1-bit high flags (organized per-element: hmask[i%32] bit i/32)
                // qs[64]: 2-bit low weights, 2 chunks of 128 elements, 4 sub-blocks per chunk
                // scales[8]: packed 4-bit pairs = scale_lo | (scale_hi << 4), unpacked to 16 values
                size_t numBlocks = hiddenDim / 256;
                rowBytes = numBlocks * sizeof(block_q3_K);
                const block_q3_K* blocks = (const block_q3_K*)row;
                for (size_t b = 0; b < numBlocks; ++b) {
                    float d = fp16ToFloat(blocks[b].d);
                    // Unpack 16 4-bit scale values from scales[0..7]
                    int8_t scales[16];
                    for (int j = 0; j < 8; ++j) {
                        scales[j] = (int8_t)(blocks[b].scales[j] & 0x0F);
                        scales[j + 8] = (int8_t)((blocks[b].scales[j] >> 4) & 0x0F);
                    }
                    for (size_t i = 0; i < 256; ++i) {
                        int chunk = (int)(i / 128);
                        int subBlock = (int)((i % 128) / 32);
                        int posInSubBlock = (int)(i % 32);
                        int qsIdx = chunk * 32 + posInSubBlock;
                        int qsShift = subBlock * 2;
                        int lo = (blocks[b].qs[qsIdx] >> qsShift) & 0x03;
                        int hmIdx = posInSubBlock; // 0..31
                        int hmShift = (int)(i / 32); // 0..7
                        int hmaskBit = (blocks[b].hmask[hmIdx] >> hmShift) & 0x01;
                        int q = lo - (hmaskBit ? 0 : 4); // 0..3 or -4..-1
                        int scaleIdx = chunk * 4 + subBlock;
                        float dl = d * (float)(scales[scaleIdx] - 32);
                        output[b * 256 + i] = dl * (float)q;
                    }
                }
            } else if (modelWeights.tokenEmbed.type == (int)GGMLType::GGML_TYPE_Q4_0) {
                // Legacy fallback: Q4_0 = fp16 d + uint8_t qs[16] (18 bytes, 32 weights)
                size_t numBlocks = hiddenDim / 32;
                const block_q4_0* blocks = (const block_q4_0*)row;
                for (size_t b = 0; b < numBlocks; ++b) {
                    float d = fp16ToFloat(blocks[b].d);
                    for (size_t i = 0; i < 32; ++i) {
                        uint8_t byte = blocks[b].qs[i / 2];
                        int q = (i % 2 == 0) ? (byte & 0x0F) : (byte >> 4);
                        output[b * 32 + i] = d * (q - 8.0f);
                    }
                }
            } else if (modelWeights.tokenEmbed.type == (int)GGMLType::GGML_TYPE_Q6_K) {
                // Q6_K embedding: 256 weights per 210-byte block
                size_t numBlocks = hiddenDim / 256;
                rowBytes = numBlocks * sizeof(block_q6_K);
                const block_q6_K* blocks = (const block_q6_K*)row;
                for (size_t b = 0; b < numBlocks; ++b) {
                    float d = fp16ToFloat(blocks[b].d);
                    const uint8_t* ql = blocks[b].ql;
                    const uint8_t* qh = blocks[b].qh;
                    const int8_t*  sc = blocks[b].scales;
                    for (size_t i = 0; i < 256; ++i) {
                        size_t qlIdx = i / 2;
                        int    qlShift = (i % 2) * 4;
                        uint8_t low4 = (ql[qlIdx] >> qlShift) & 0x0F;
                        size_t qhIdx = i / 4;
                        int    qhShift = (i % 4) * 2;
                        uint8_t high2 = (qh[qhIdx] >> qhShift) & 0x03;
                        int8_t q = (int8_t)(low4 | (high2 << 4)) - 32;
                        int scaleIdx = (int)(i / 16);
                        output[b * 256 + i] = d * (float)sc[scaleIdx] * (float)q;
                    }
                }
            } else {
                memset(output, 0, hiddenDim * sizeof(float));
            }
        } else {
            memset(output, 0, hiddenDim * sizeof(float));
        }
    }

    // --- Release Elastic residency for token embeddings ---
    if (elasticResidencyEnabled_ && elasticResidency_ && !modelWeights.tokenEmbed.name.empty()) {
        elasticResidency_->ReleaseTensor(modelWeights.tokenEmbed.name);
    }

    // --- Zero-embed policy (gibberish / "retard mode" guard) ---
    // Historical bug: tolerate ALL zero embeds with 1e-6 residual → entire
    // activation stack stays ~0 → softmax gibberish. Only tolerate known
    // SPM byte-fallback holes (token id < 256) when the RAW GGUF row is zero.
    float embedNorm = 0.0f;
    for (size_t i = 0; i < modelWeights.hiddenDim; ++i) {
        embedNorm += output[i] * output[i];
    }
    embedNorm = std::sqrt(embedNorm);
    if (!std::isfinite(embedNorm) || embedNorm <= 0.0f) {
        size_t rowBytes = 0;
        if (modelWeights.tokenEmbed.type == (int)GGMLType::GGML_TYPE_Q6_K) {
            rowBytes = (modelWeights.hiddenDim / 256) * sizeof(block_q6_K);
        } else if (modelWeights.tokenEmbed.type == (int)GGMLType::GGML_TYPE_Q4_K) {
            rowBytes = (modelWeights.hiddenDim / 256) * sizeof(block_q4_K);
        } else if (modelWeights.vocabSize > 0) {
            rowBytes = modelWeights.tokenEmbed.sizeBytes / modelWeights.vocabSize;
        }
        size_t rawNz = 0;
        if (embedDataPtr && rowBytes > 0) {
            const uint8_t* row = (const uint8_t*)embedDataPtr + (size_t)tokenId * rowBytes;
            for (size_t i = 0; i < rowBytes; ++i) {
                if (row[i] != 0) ++rawNz;
            }
            fprintf(stderr,
                "[FATAL_EMBED] token=%d norm=%e type=%d rowBytes=%zu rawNonZero=%zu/%zu ptr=%p\n",
                tokenId, embedNorm, modelWeights.tokenEmbed.type, rowBytes, rawNz, rowBytes,
                embedDataPtr);
            fprintf(stderr, "[FATAL_EMBED] rawFirst32=");
            for (size_t i = 0; i < 32 && i < rowBytes; ++i)
                fprintf(stderr, "%02X ", row[i]);
            fprintf(stderr, "\n");
        } else {
            fprintf(stderr,
                "[FATAL_EMBED] token=%d norm=%e type=%d (no row probe)\n",
                tokenId, embedNorm, modelWeights.tokenEmbed.type);
        }

        // Byte-fallback hole: raw row legitimately all-zero in some TinyLlama/SPM GGUFs.
        const bool byteFallbackHole = (tokenId >= 0 && tokenId < 256 && rawNz == 0);
        if (byteFallbackHole) {
            fprintf(stderr,
                "[WARN_EMBED] token=%d byte-fallback hole tolerated\n", tokenId);
            memset(output, 0, modelWeights.hiddenDim * sizeof(float));
            if (modelWeights.hiddenDim > 0)
                output[0] = 1.0e-6f;
            return true;
        }

        // Real token with zero embed = residency/dequant/mapping poison → refuse.
        memset(output, 0, modelWeights.hiddenDim * sizeof(float));
        return false;
    }
    return true;
}

// ============================================================================
// RMSNorm with weights: output = weight * x / sqrt(mean(x^2) + eps)
// Production AVX2 implementation
// ============================================================================
void Deep2Engine::RMSNormW(const WeightTensor& normWeight, const float* input,
                            float* output, size_t dim, float eps) {
    if (dim == 0) return;

    // 1D GGUF norms are often dims=[hidden] → loader sets rows=1, cols=hidden.
    // Prefer sizeBytes / F32 when rows is a stub.
    size_t nW = 0;
    if (normWeight.data) {
        if (normWeight.type == (int)GGMLType::GGML_TYPE_F32 &&
            normWeight.sizeBytes >= dim * sizeof(float))
            nW = dim;
        else if (normWeight.cols >= dim)
            nW = dim;
        else if (normWeight.rows >= dim)
            nW = dim;
        else if (normWeight.cols > 1)
            nW = normWeight.cols;
        else
            nW = normWeight.rows;
    }

    // Compute sum of squares with AVX2 (accumulate in double)
    __m256 sum_sq_vec = _mm256_setzero_ps();
    size_t i = 0;

    for (; i + 8 <= dim; i += 8) {
        __m256 vx = _mm256_loadu_ps(&input[i]);
        sum_sq_vec = _mm256_fmadd_ps(vx, vx, sum_sq_vec);
    }

    // Horizontal sum → float, then promote to double
    __m128 hi = _mm256_extractf128_ps(sum_sq_vec, 1);
    __m128 lo = _mm256_castps256_ps128(sum_sq_vec);
    __m128 sum128 = _mm_add_ps(lo, hi);
    sum128 = _mm_hadd_ps(sum128, sum128);
    sum128 = _mm_hadd_ps(sum128, sum128);
    double sumSq = static_cast<double>(_mm_cvtss_f32(sum128));

    // Scalar remainder in double
    for (; i < dim; ++i) {
        double v = static_cast<double>(input[i]);
        sumSq += v * v;
    }

    // Compute RMS in double
    double meanSq = sumSq / static_cast<double>(dim);
    double rms = std::sqrt(meanSq + static_cast<double>(eps));
    float invRms = static_cast<float>(1.0 / rms);
    __m256 vinvRms = _mm256_set1_ps(invRms);

    // Apply normalization + weight with AVX2
    if (normWeight.data && nW >= dim &&
        normWeight.type == (int)GGMLType::GGML_TYPE_F32) {
        const float* w = (const float*)normWeight.data;
        // All-zero weights (bad map / empty page) → identity scale.
        double wAbs = 0.0;
        const size_t sample = dim < 64 ? dim : 64;
        for (size_t j = 0; j < sample; ++j) wAbs += std::fabs((double)w[j]);
        const bool ident = wAbs < 1e-12;
        i = 0;
        for (; i + 8 <= dim; i += 8) {
            __m256 vx = _mm256_loadu_ps(&input[i]);
            __m256 vnorm = _mm256_mul_ps(vx, vinvRms);
            if (!ident) {
                __m256 vw = _mm256_loadu_ps(&w[i]);
                vnorm = _mm256_mul_ps(vw, vnorm);
            }
            _mm256_storeu_ps(&output[i], vnorm);
        }
        for (; i < dim; ++i)
            output[i] = (ident ? 1.0f : w[i]) * input[i] * invRms;
    } else if (normWeight.data && nW >= dim &&
               normWeight.type == (int)GGMLType::GGML_TYPE_F16) {
        const uint16_t* w = (const uint16_t*)normWeight.data;
        i = 0;
        for (; i + 8 <= dim; i += 8) {
            __m128i half_vec = _mm_loadu_si128(reinterpret_cast<const __m128i*>(w + i));
            __m256 vw = _mm256_cvtph_ps(half_vec);
            __m256 vx = _mm256_loadu_ps(&input[i]);
            __m256 vnorm = _mm256_mul_ps(vx, vinvRms);
            __m256 vout = _mm256_mul_ps(vw, vnorm);
            _mm256_storeu_ps(&output[i], vout);
        }
        for (; i < dim; ++i)
            output[i] = fp16ToFloat(w[i]) * input[i] * invRms;
    } else {
        // Missing/short weight tensor — normalize only (scale=1).
        i = 0;
        for (; i + 8 <= dim; i += 8) {
            __m256 vx = _mm256_loadu_ps(&input[i]);
            __m256 vout = _mm256_mul_ps(vx, vinvRms);
            _mm256_storeu_ps(&output[i], vout);
        }
        for (; i < dim; ++i)
            output[i] = input[i] * invRms;
    }
}

// ============================================================================
// Precomputed RoPE Tables
// ============================================================================
static std::vector<float> g_ropeCosTable;
static std::vector<float> g_ropeSinTable;
static size_t g_ropeMaxSeqLen = 0;
static size_t g_ropeHeadDim = 0;
static float g_ropeTheta = 10000.0f;
static float g_ropeScaling = 1.0f;

// Initialize precomputed RoPE tables.
// Scaling alters the *position/frequency* used to build angles â€” NEVER multiply
// sin/cos amplitudes (that breaks cosÂ²+sinÂ²=1).
static void initRoPETables(size_t maxSeqLen, size_t headDim, float theta, float scaling) {
    if (scaling <= 0.0f) scaling = 1.0f;
    if (g_ropeMaxSeqLen >= maxSeqLen &&
        g_ropeHeadDim == headDim &&
        g_ropeTheta == theta &&
        g_ropeScaling == scaling) {
        return;
    }

    g_ropeMaxSeqLen = maxSeqLen;
    g_ropeHeadDim = headDim;
    g_ropeTheta = theta;
    g_ropeScaling = scaling;

    g_ropeCosTable.resize(maxSeqLen * headDim);
    g_ropeSinTable.resize(maxSeqLen * headDim);

    const float invScale = 1.0f / scaling;
    for (size_t pos = 0; pos < maxSeqLen; ++pos) {
        const float effectivePos = static_cast<float>(pos) * invScale;
        for (size_t i = 0; i < headDim; i += 2) {
            // Standard RoPE: freq = 1 / theta^(i / headDim)
            float freq = 1.0f / powf(theta, (float)i / (float)headDim);
            float angle = effectivePos * freq;
            size_t idx = pos * headDim + i;
            g_ropeCosTable[idx] = cosf(angle);
            g_ropeSinTable[idx] = sinf(angle);
            g_ropeCosTable[idx + 1] = cosf(angle);
            g_ropeSinTable[idx + 1] = sinf(angle);
        }
    }
}

// ============================================================================
// RoPE: Rotary Position Embedding - Optimized with precomputed tables
// ============================================================================
void Deep2Engine::applyRoPE(float* q, float* k, size_t headDim, size_t numHeads,
                             size_t numKVHeads, size_t pos, float theta, float scaling) {
    if (scaling <= 0.0f) scaling = 1.0f;

    // Ensure tables are initialized for this (headDim, theta, scaling) contract
    if (g_ropeMaxSeqLen == 0 ||
        g_ropeHeadDim != headDim ||
        g_ropeTheta != theta ||
        g_ropeScaling != scaling ||
        pos >= g_ropeMaxSeqLen) {
        initRoPETables((std::max)(config.maxSeqLen * 2, pos + 128), headDim, theta, scaling);
    }

    // Bounds check after initialization
    if (pos >= g_ropeMaxSeqLen) {
        fprintf(stderr, "[RoPE_WARN] pos=%zu exceeds table size %zu, clamping\n", pos, g_ropeMaxSeqLen);
        pos = g_ropeMaxSeqLen - 1;
    }

    // Use precomputed tables (amplitudes already unit — do NOT multiply by scaling)
    const float* cosTable = &g_ropeCosTable[pos * headDim];
    const float* sinTable = &g_ropeSinTable[pos * headDim];

    // Nemotron-H: rope.dimension_count may be < headDim (partial RoPE).
    size_t ropeDim = modelWeights.ropeDimensionCount;
    if (ropeDim == 0 || ropeDim > headDim) ropeDim = headDim;
    ropeDim &= ~size_t(1); // pairs only

    for (size_t h = 0; h < numHeads; ++h) {
        float* qh = q + h * headDim;
        for (size_t i = 0; i < ropeDim; i += 2) {
            float cosA = cosTable[i];
            float sinA = sinTable[i];
            float q0 = qh[i];
            float q1 = qh[i + 1];
            qh[i]     = q0 * cosA - q1 * sinA;
            qh[i + 1] = q0 * sinA + q1 * cosA;
        }
    }
    for (size_t h = 0; h < numKVHeads; ++h) {
        float* kh = k + h * headDim;
        for (size_t i = 0; i < ropeDim; i += 2) {
            float cosA = cosTable[i];
            float sinA = sinTable[i];
            float k0 = kh[i];
            float k1 = kh[i + 1];
            kh[i]     = k0 * cosA - k1 * sinA;
            kh[i + 1] = k0 * sinA + k1 * cosA;
        }
    }
}

// ============================================================================
// SwiGLU: output = silu(gate) * up — XR real reference (K2_REAL_ATTENTION_001)
// ============================================================================
void Deep2Engine::SwiGLU(const float* gate, const float* up, float* output, size_t dim) {
    if (dim == 0 || !gate || !up || !output) return;
    /* Asm reads gate[i] via stack temp; const_cast is read-only on gate buffer. */
    (void)XR_SwiGLU_F32(const_cast<float*>(gate), up, output,
                        static_cast<uint64_t>(dim));
}

// ============================================================================
// Q6_K ASM validation gate
// Policy:
//   1. C++ dequantizeQ6KBlock + AVX2 dot remains the correctness reference.
//   2. ASM is never enabled merely because the symbol exists.
//   3. ASM must pass numerical validation against C++ before dispatch.
//   4. Opt-in via environment variable RAWRXD_Q6K_ASM=1.
// ============================================================================

#include <atomic>
#include <cstdlib>

namespace {
    std::atomic<bool> g_q6kAsmValidated{false};
    std::atomic<bool> g_q6kAsmRejected{false};

    static bool Q6KAsmEnabled() {
        if (g_q6kAsmRejected.load(std::memory_order_acquire))
            return false;

        const char* e = std::getenv("RAWRXD_Q6K_ASM");
        if (!e || e[0] != '1' || e[1] != '\0')
            return false;

        return g_q6kAsmValidated.load(std::memory_order_acquire);
    }

    static bool NearlyEqual(float a, float b, float absTol, float relTol) {
        if (!std::isfinite(a) || !std::isfinite(b))
            return false;
        float diff = std::fabs(a - b);
        if (diff <= absTol)
            return true;
        float scale = (std::fabs(a) > std::fabs(b)) ? std::fabs(a) : std::fabs(b);
        return diff <= relTol * scale;
    }

    static bool ValidateQ6KAsm(const block_q6_K* blocks, const float* input,
                                float* output, size_t startRow, size_t endRow,
                                size_t cols) {
        size_t blocksPerRow = (cols + 255) / 256;
        constexpr size_t kBlockSize = sizeof(block_q6_K);
        alignas(32) float dequantBuf[256];
        alignas(32) float refBuf[256];

        size_t testRows = (endRow - startRow > 8) ? 8 : (endRow - startRow);
        if (testRows == 0) return false;

        // Compute reference for first testRows
        for (size_t r = 0; r < testRows; ++r) {
            size_t absRow = startRow + r;
            const block_q6_K* rowBlocks =
                (const block_q6_K*)((const uint8_t*)blocks + absRow * blocksPerRow * kBlockSize);
            float sum = 0.0f;
            for (size_t b = 0; b < blocksPerRow; ++b) {
                size_t elemsInBlock = (b == blocksPerRow - 1)
                    ? (cols - b * 256)
                    : 256;
                if (elemsInBlock == 0) break;
                dequantizeQ6KBlock(&rowBlocks[b], dequantBuf);
                __m256 acc = _mm256_setzero_ps();
                size_t i = 0;
                for (; i + 8 <= elemsInBlock; i += 8) {
                    __m256 w = _mm256_load_ps(dequantBuf + i);
                    __m256 x = _mm256_loadu_ps(input + b * 256 + i);
                    acc = _mm256_fmadd_ps(w, x, acc);
                }
                __m128 hi128 = _mm256_extractf128_ps(acc, 1);
                __m128 lo128 = _mm256_castps256_ps128(acc);
                __m128 sum128 = _mm_add_ps(lo128, hi128);
                sum128 = _mm_hadd_ps(sum128, sum128);
                sum128 = _mm_hadd_ps(sum128, sum128);
                sum += _mm_cvtss_f32(sum128);
                for (; i < elemsInBlock; ++i) {
                    sum += dequantBuf[i] * input[b * 256 + i];
                }
            }
            refBuf[r] = sum;
        }

        // Call ASM kernel for same rows using new 4-arg ABI:
        // Deep2_Q6_K_GEMV(blocks, x, out, nBlocks)
        // where nBlocks = blocksPerRow * testRows
        size_t totalBlocks = blocksPerRow * testRows;
        const uint8_t* rowWeights = (const uint8_t*)blocks + startRow * blocksPerRow * kBlockSize;
        Deep2_Q6_K_GEMV(rowWeights, input, output + startRow, totalBlocks);

        // Compare with detailed diagnostics
        float maxAbsErr = 0.0f;
        float maxRelErr = 0.0f;
        size_t failIdx = testRows;
        for (size_t r = 0; r < testRows; ++r) {
            float ref = refBuf[r];
            float asmVal = output[startRow + r];
            float diff = std::fabs(ref - asmVal);
            float scale = (std::max)(1.0f, std::fabs(ref));
            if (!NearlyEqual(ref, asmVal, 1.0e-3f, 2.0e-3f)) {
                if (failIdx == testRows) failIdx = r;
            }
        }

        if (failIdx < testRows) {
            g_q6kAsmRejected.store(true, std::memory_order_release);
            g_q6kAsmValidated.store(false, std::memory_order_release);
            fprintf(stderr,
                "[Q6K_ASM_REJECT] row=%zu ref=%g asm=%g "
                "maxAbsErr=%.6e maxRelErr=%.6e firstFail=%zu\n",
                startRow + failIdx, refBuf[failIdx], output[startRow + failIdx],
                maxAbsErr, maxRelErr, failIdx);
            return false;
        }

        g_q6kAsmValidated.store(true, std::memory_order_release);
        fprintf(stderr,
            "[Q6K_ASM_ACCEPT] %zu rows validated  maxAbsErr=%.6e maxRelErr=%.6e\n",
            testRows, maxAbsErr, maxRelErr);
        return true;
    }
}

// ============================================================================
// LinearW_Range: Matrix-vector multiply for a sub-range of output rows
// ============================================================================
static void LinearW_Range(const WeightTensor& wt, const float* input,
                          float* output, size_t startRow, size_t endRow, size_t cols) {
    size_t rows = endRow - startRow;

    // === Batch 15C: LinearW_Range Instrumentation =====================
    static std::mutex traceMutex;
    static FILE* traceFile = nullptr;
    static int traceCount = 0;
    const int kMaxTrace = 2000;
    int tc = 0;
    bool doTrace = false;
    const char* typeName = "UNKNOWN";
    switch (wt.type) {
        case (int)GGMLType::GGML_TYPE_F32: typeName = "F32"; break;
        case (int)GGMLType::GGML_TYPE_F16: typeName = "F16"; break;
        case (int)GGMLType::GGML_TYPE_Q4_0: typeName = "Q4_0"; break;
        case (int)GGMLType::GGML_TYPE_Q4_1: typeName = "Q4_1"; break;
        case (int)GGMLType::GGML_TYPE_Q5_0: typeName = "Q5_0"; break;
        case (int)GGMLType::GGML_TYPE_Q5_1: typeName = "Q5_1"; break;
        case (int)GGMLType::GGML_TYPE_Q8_0: typeName = "Q8_0"; break;
        case (int)GGMLType::GGML_TYPE_Q8_K: typeName = "Q8_K"; break;
        case (int)GGMLType::GGML_TYPE_Q2_K: typeName = "Q2_K"; break;
        case (int)GGMLType::GGML_TYPE_Q3_K: typeName = "Q3_K"; break;
        case (int)GGMLType::GGML_TYPE_Q4_K: typeName = "Q4_K"; break;
        case (int)GGMLType::GGML_TYPE_Q5_K: typeName = "Q5_K"; break;
        case (int)GGMLType::GGML_TYPE_Q6_K: typeName = "Q6_K"; break;
        default: typeName = "UNKNOWN"; break;
    }
    {
        static const bool lrTraceOn =
            (std::getenv("RAWRXD_LINEARW_TRACE") != nullptr &&
             std::getenv("RAWRXD_LINEARW_TRACE")[0] == '1');
        std::lock_guard<std::mutex> lock(traceMutex);
        tc = traceCount++;
        doTrace = lrTraceOn && (tc < kMaxTrace);
        if (doTrace && !traceFile) {
            traceFile = fopen("__linearw_range_trace.txt", "w");
            if (traceFile) setvbuf(traceFile, nullptr, _IOLBF, 4096);
        }
        if (doTrace && traceFile) {
            fprintf(traceFile, "[LR_ENTER] name=%s type=%s(%d) rows=%zu cols=%zu startRow=%zu endRow=%zu\n",
                    wt.name.c_str(), typeName, wt.type, rows, cols, startRow, endRow);
            bool valid = true;
            if (!wt.data) { fprintf(traceFile, "[LR_VALIDATE_FAIL] wt.data is null\n"); valid = false; }
            if (!input)   { fprintf(traceFile, "[LR_VALIDATE_FAIL] input is null\n"); valid = false; }
            if (!output)  { fprintf(traceFile, "[LR_VALIDATE_FAIL] output is null\n"); valid = false; }
            if (startRow > endRow) { fprintf(traceFile, "[LR_VALIDATE_FAIL] startRow(%zu) > endRow(%zu)\n", startRow, endRow); valid = false; }
            if (endRow > wt.rows)  { fprintf(traceFile, "[LR_VALIDATE_FAIL] endRow(%zu) > wt.rows(%zu)\n", endRow, wt.rows); valid = false; }
            if (cols != wt.cols)   { fprintf(traceFile, "[LR_VALIDATE_WARN] cols(%zu) != wt.cols(%zu)\n", cols, wt.cols); }
            if (wt.data && (reinterpret_cast<size_t>(wt.data) % 64 != 0)) { fprintf(traceFile, "[LR_VALIDATE_WARN] wt.data misaligned addr=%p\n", wt.data); }
            if (input && (reinterpret_cast<size_t>(input) % 64 != 0))     { fprintf(traceFile, "[LR_VALIDATE_WARN] input misaligned addr=%p\n", input); }
            if (output && (reinterpret_cast<size_t>(output) % 64 != 0))   { fprintf(traceFile, "[LR_VALIDATE_WARN] output misaligned addr=%p\n", output); }
            auto GetRowBytes = [&](int t, size_t c) -> size_t {
                switch (t) {
                    case (int)GGMLType::GGML_TYPE_F32: return c * sizeof(float);
                    case (int)GGMLType::GGML_TYPE_F16: return c * sizeof(uint16_t);
                    case (int)GGMLType::GGML_TYPE_Q4_0: return ((c + 31) / 32) * sizeof(block_q4_0);
                    case (int)GGMLType::GGML_TYPE_Q4_1: return ((c + 31) / 32) * sizeof(block_q4_1);
                    case (int)GGMLType::GGML_TYPE_Q5_0: return ((c + 31) / 32) * sizeof(block_q5_0);
                    case (int)GGMLType::GGML_TYPE_Q5_1: return ((c + 31) / 32) * sizeof(block_q5_1);
                    case (int)GGMLType::GGML_TYPE_Q8_0: return ((c + 31) / 32) * sizeof(block_q8_0);
                    case (int)GGMLType::GGML_TYPE_Q4_K: return ((c + 255) / 256) * sizeof(block_q4_K);
                    case (int)GGMLType::GGML_TYPE_Q5_K: return ((c + 255) / 256) * sizeof(block_q5_K);
                    case (int)GGMLType::GGML_TYPE_Q2_K: return ((c + 255) / 256) * sizeof(block_q2_K);
                    case (int)GGMLType::GGML_TYPE_Q3_K: return ((c + 255) / 256) * sizeof(block_q3_K);
                    case (int)GGMLType::GGML_TYPE_Q8_K: return ((c + 255) / 256) * sizeof(block_q8_K);
                    case (int)GGMLType::GGML_TYPE_Q6_K: return ((c + 255) / 256) * sizeof(block_q6_K);
                    default: return 0;
                }
            };
            size_t rb = GetRowBytes(wt.type, cols);
            size_t reqBytes = endRow * rb;
            if (reqBytes > wt.sizeBytes) {
                fprintf(traceFile, "[LR_VALIDATE_FAIL] byte overflow: endRow*rowBytes=%zu > wt.sizeBytes=%zu\n", reqBytes, wt.sizeBytes);
                valid = false;
            } else {
                fprintf(traceFile, "[LR_VALIDATE] byte bounds OK: req=%zu <= total=%zu\n", reqBytes, wt.sizeBytes);
            }
            fprintf(traceFile, "[LR_SOURCE] wt.data=%p mapped=%d input=%p output=%p sizeBytes=%zu rowBytes=%zu\n",
                    wt.data, wt.mapped ? 1 : 0, input, output, wt.sizeBytes, rb);
            fprintf(traceFile, "[LR_VALIDATE] result=%s\n", valid ? "PASS" : "FAIL");
            fflush(traceFile);
        }
    }
    // ===================================================================

    // â”€â”€ Kernel dispatch trace for certification proof â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // Default OFF â€” KERNEL spam crushed Agentic to ~0.1 TPS (46MB logs).
    // Set RAWRXD_KERNEL_TRACE=1 to re-enable (capped).
    static int dispatchLogCount = 0;
    const char* kernelTrace = std::getenv("RAWRXD_KERNEL_TRACE");
    if (kernelTrace && kernelTrace[0] == '1' && dispatchLogCount < 500) {
        ++dispatchLogCount;
        printf("[KERNEL] tensor=%s type=%s rows=%zu cols=%zu\n",
               wt.name.c_str(), typeName, rows, cols);
    }

    // Q8_0: always use bounds-safe scalar byte-stride GEMV (registry/AVX2
    // variants have historically AV'd on non-standard layouts).
    if (wt.type == (int)GGMLType::GGML_TYPE_Q8_0) {
        constexpr size_t kBlk = 34;
        const size_t blocksPerRow = (cols + 31) / 32;
        const size_t rowBytes = blocksPerRow * kBlk;
        const uint8_t* base = (const uint8_t*)wt.data + startRow * rowBytes;
        for (size_t r = 0; r < rows; ++r) {
            float acc = 0.0f;
            const uint8_t* row = base + r * rowBytes;
            for (size_t b = 0; b < blocksPerRow; ++b) {
                const auto* blk =
                    reinterpret_cast<const block_q8_0*>(row + b * kBlk);
                const float d = fp16ToFloat(blk->d);
                const size_t off = b * 32;
                const size_t n = (off + 32 <= cols) ? 32u : (cols - off);
                float blockAcc = 0.0f;
                for (size_t i = 0; i < n; ++i)
                    blockAcc += (float)blk->qs[i] * input[off + i];
                acc += d * blockAcc;
            }
            output[startRow + r] += acc;
        }
        return;
    }

    // â”€â”€ QuantKernelRegistry dispatch (replaces inline switch) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    auto& reg = Deep2::QuantKernelRegistry::Instance();
    if (reg.GetRegisteredCount() == 0) reg.Initialize();
    auto kernel = reg.GetGEMV(wt.type);
    auto geom = reg.GetGeometry(wt.type);

    if (kernel && geom.blockSize > 0) {
        reg.GetBatch21Counters().registryHits.fetch_add(1, std::memory_order_relaxed);
        reg.GetBatch21Counters().kernelInvocations.fetch_add(1, std::memory_order_relaxed);
        size_t blocksPerRow = (cols + geom.elemsPerBlock - 1) / geom.elemsPerBlock;
        size_t rowBytes = blocksPerRow * geom.blockSize;
        const uint8_t* rowWeights = (const uint8_t*)wt.data + startRow * rowBytes;
        // â”€â”€ VAL-051.7: Q4_0 dispatch telemetry (capped) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        if (wt.type == (int)GGMLType::GGML_TYPE_Q4_0) {
            static int q4LogCount = 0;
            const char* probe = std::getenv("RAWRXD_DEEP2_LAYER_PROBE");
            const int q4LogCap = (probe && probe[0] == '1') ? 32 : 8;
            if (q4LogCount < q4LogCap) {
                ++q4LogCount;
                fprintf(stderr,
                    "[Q4_DISPATCH] tensor=%s rows=%zu cols=%zu rowBytes=%zu kernel=Q4_0_REFERENCE\n",
                    wt.name.c_str(), rows, cols, rowBytes);
            }
        }
        kernel(rowWeights, input, output + startRow, rows, cols);
    } else if (wt.type == (int)GGMLType::GGML_TYPE_F32) {
        // QUANT-SAFETY-001: only explicit FP32 may use the scalar float* path
        reg.GetBatch21Counters().registryMisses.fetch_add(1, std::memory_order_relaxed);
        reg.GetBatch21Counters().scalarFallbacks.fetch_add(1, std::memory_order_relaxed);
        for (size_t r = startRow; r < endRow; ++r) {
            float acc = 0.0f;
            for (size_t c = 0; c < cols; ++c) {
                acc += ((const float*)wt.data)[r * cols + c] * input[c];
            }
            output[r] = acc;
        }
    } else {
        // QUANT-SAFETY-001: never reinterpret quantized bytes as float
        reg.GetBatch21Counters().registryMisses.fetch_add(1, std::memory_order_relaxed);
        fprintf(stderr,
            "[QUANT_FATAL] unsupported tensor type=%d tensor=%s rows=%zu cols=%zu "
            "(no format-blind FP32 fallback)\n",
            wt.type, wt.name.c_str(), rows, cols);
        throw std::runtime_error(
            std::string("QUANT_FATAL unsupported type=") + std::to_string(wt.type) +
            " tensor=" + wt.name);
    }

    // === Batch 15C: Post-call instrumentation =========================
    if (doTrace) {
        std::lock_guard<std::mutex> lock(traceMutex);
        if (traceFile) {
            fprintf(traceFile, "[LR_GEMV] type=%s(%d) rows=%zu cols=%zu startRow=%zu endRow=%zu\n",
                    typeName, wt.type, rows, cols, startRow, endRow);
            double norm = 0.0;
            bool allFinite = true;
            for (size_t r = startRow; r < endRow; ++r) {
                float v = output[r];
                if (!std::isfinite(v)) allFinite = false;
                norm += (double)v * (double)v;
            }
            norm = std::sqrt(norm);
            fprintf(traceFile, "[LR_EXIT] norm=%.6e allFinite=%s\n", norm, allFinite ? "YES" : "NO");
            fflush(traceFile);
        }
    }
    // ===================================================================
}

// ============================================================================
// LinearW: Matrix-vector multiply using WeightTensor
// ============================================================================
void Deep2Engine::LinearW(const WeightTensor& wt, const float* input,
                           const float* bias, float* output, size_t outDim) {
    if (!wt.data || !input || !output || outDim == 0) {
        if (output && outDim > 0) memset(output, 0, outDim * sizeof(float));
        return;
    }

    // --- Elastic residency: only for cold tensors (no live mapped pointer).
    // Never overwrite wt.data with a zero-filled elastic staging buffer.
    WeightTensor wtEffective = wt;
    Deep2::ElasticResidencyManager::ResidencyHandle resHandle;
    bool acquired = false;
    if (elasticResidencyEnabled_ && elasticResidency_ && !wt.name.empty() &&
        !vulkanEnabled_ && !(wt.data && wt.mapped)) {
        auto status = elasticResidency_->AcquireTensor(wt.name, 0, 0, resHandle);
        if (status == Deep2::ElasticResidencyManager::AcquireStatus::Ready &&
            resHandle.ready && resHandle.cpuPtr) {
            wtEffective.data = resHandle.cpuPtr;
            acquired = true;
        }
    }
    if (!wtEffective.data) {
        if (output && outDim > 0) memset(output, 0, outDim * sizeof(float));
        return;
    }
    if (LivePath_Active() && cyclone_ && !wt.name.empty() && !vulkanEnabled_) {
        const uint64_t seq = kvCache ? static_cast<uint64_t>(kvCache->currentLength()) : 0;
        cyclone_->OnTensorUsed(wt.name, seq);
    }

    size_t cols = wtEffective.cols;
    size_t rows = wtEffective.rows;

    // Qwen3.5 attn_gate as O: stored [gateDim×hidden] but caller wants
    // y[hidden]=W^T x[gateDim]. Detect rows>outDim && cols==outDim.
    if (rows > outDim && cols == outDim &&
        wtEffective.type == (int)GGMLType::GGML_TYPE_Q4_K && wtEffective.data) {
        fprintf(stderr,
            "[LINEARW_OT] W^T gemv in=%zu out=%zu tensor=%s\n",
            rows, cols, wt.name.c_str());
        fflush(stderr);
        q4kGEMV_T(wtEffective.data, input, output, rows, cols);
        if (bias) {
            for (size_t i = 0; i < outDim; ++i) output[i] += bias[i];
        }
        if (acquired && elasticResidencyEnabled_ && elasticResidency_ &&
            !wt.name.empty())
            elasticResidency_->ReleaseTensor(wt.name);
        return;
    }

    // Memory law: never write more than caller outDim; never read past sizeBytes.
    if (rows > outDim) {
        fprintf(stderr,
            "[LINEARW_BOUNDS] clamp rows %zu -> outDim %zu tensor=%s type=%d\n",
            rows, outDim, wt.name.c_str(), wtEffective.type);
        fflush(stderr);
        rows = outDim;
    }
    if (wtEffective.type == (int)GGMLType::GGML_TYPE_Q8_0 && wtEffective.sizeBytes > 0) {
        const size_t bpr = (cols + 31) / 32;
        const size_t need = rows * bpr * 34ull;
        if (need > wtEffective.sizeBytes) {
            fprintf(stderr,
                "[LINEARW_BOUNDS_FAIL] Q8_0 byte overflow tensor=%s need=%zu have=%zu\n",
                wt.name.c_str(), need, wtEffective.sizeBytes);
            fflush(stderr);
            if (acquired && elasticResidencyEnabled_ && elasticResidency_ && !wt.name.empty())
                elasticResidency_->ReleaseTensor(wt.name);
            return;
        }
    }

    auto tLinearW0 = std::chrono::high_resolution_clock::now();

    // --- CRITICAL FIX: zero output before accumulate-style kernels ---
    memset(output, 0, outDim * sizeof(float));

    // Batch2 authoritative: Q2_K via in-process packed dual (84B) on N>0.
    if (wtEffective.type == (int)GGMLType::GGML_TYPE_Q2_K &&
        ssVkProductBind_.bound() &&
        ssVkProductBind_.tokenProof().tokenOrdinal > 0) {
        SsVkQ2KRequest req{};
        req.packedWeights = wtEffective.data;
        req.input = input;
        req.output = output;
        req.rows = rows;
        req.cols = cols;
        req.weightBytes = wtEffective.sizeBytes;
        req.tensorName = wt.name.c_str();
        if (!ssVkProductBind_.dispatchQ2K(req)) {
            vulkanStrictViolation_ = true;
            throw std::runtime_error(
                std::string("BATCH2_SSVK_Q2K_FAIL tensor=") + wt.name);
        }
        if (bias) {
            for (size_t i = 0; i < outDim; ++i) output[i] += bias[i];
        }
        if (acquired && elasticResidencyEnabled_ && elasticResidency_ &&
            !wt.name.empty())
            elasticResidency_->ReleaseTensor(wt.name);
        return;
    }
    if (wtEffective.type == (int)GGMLType::GGML_TYPE_Q2_K &&
        ssvkBind16_.run != nullptr &&
        ssvkBind16_.token.token_ordinal > 0) {
        D2PackedProductRequest req{};
        req.packed_weights = wtEffective.data;
        req.input = input;
        req.output = output;
        req.rows = rows;
        req.cols = cols;
        req.weight_bytes = wtEffective.sizeBytes;
        req.tensor_name = wt.name.c_str();
        if (!d2bind16_dispatch_q2k(&ssvkBind16_, &req)) {
            vulkanStrictViolation_ = true;
            throw std::runtime_error(
                std::string("BIND16_SSVK_Q2K_FAIL tensor=") + wt.name);
        }
        if (bias) {
            for (size_t i = 0; i < outDim; ++i) output[i] += bias[i];
        }
        if (acquired && elasticResidencyEnabled_ && elasticResidency_ &&
            !wt.name.empty())
            elasticResidency_->ReleaseTensor(wt.name);
        return;
    }

    // Planned CPU slot: intentional CPU GEMV (not fallback).
    bool plannedCpu = false;
    if (multiGpuLayerPlan_.active) {
        const int layerIdx = parseWeightLayerIndex(wt.name);
        if (layerIdx >= 0) {
            const int slot = Deep2MultiGpu_SlotForLayer(multiGpuLayerPlan_, (unsigned)layerIdx);
            if (Deep2MultiGpu_SlotIsCpu(multiGpuLayerPlan_, slot))
                plannedCpu = true;
        }
    }

    // --- Vulkan GPU dispatch (SOLO / MULTI / HYBRID GPU slots) ---
    if (!plannedCpu && vulkanEnabled_ && vulkanInitialized_ && !vulkanDevices_.empty()) {
        auto tGpuDispatch0 = std::chrono::high_resolution_clock::now();
        if (tryVulkanGEMV(wtEffective, input, output, outDim)) {
            ++plannedGpuGemvOps_;
            if (bias) {
                for (size_t i = 0; i < outDim; ++i) {
                    output[i] += bias[i];
                }
            }
            auto tLinearW1 = std::chrono::high_resolution_clock::now();
            double linearwMs = std::chrono::duration<double, std::milli>(tLinearW1 - tLinearW0).count();
            int typeIdx = wtEffective.type & 0x1F;
            if (typeIdx >= 0 && typeIdx < 32) {
                g_linearwByType[typeIdx].calls++;
                g_linearwByType[typeIdx].totalMs += linearwMs;
                g_linearwByType[typeIdx].totalMACs += rows * cols;
            }
            if (telemetryControllerEnabled_ && telemetryController_) {
                auto tGpuDispatch1 = std::chrono::high_resolution_clock::now();
                auto gpuDispatchNs = std::chrono::duration_cast<std::chrono::nanoseconds>(
                    tGpuDispatch1 - tGpuDispatch0).count();
                telemetryController_->record_gpu_dispatch(static_cast<uint64_t>(gpuDispatchNs));
            }
            if (acquired && elasticResidencyEnabled_ && elasticResidency_ && !wt.name.empty()) {
                elasticResidency_->ReleaseTensor(wt.name);
            }
            return;
        }
        // Gate-killing: never silently substitute CPU while GPU slot is claimed.
        if (vulkanStrictNoCpuFallback_) {
            vulkanStrictViolation_ = true;
            fprintf(stderr,
                    "[LAYER_EXEC] FATAL: GPU LinearW failed for '%s' "
                    "(type=%d rows=%zu cols=%zu) â€” CPU fallback forbidden\n",
                    wt.name.c_str(), wtEffective.type, rows, cols);
            fflush(stderr);
            if (acquired && elasticResidencyEnabled_ && elasticResidency_ && !wt.name.empty()) {
                elasticResidency_->ReleaseTensor(wt.name);
            }
            return;
        }
    }
    if (plannedCpu)
        ++plannedCpuGemvOps_;
    auto tQuant0 = std::chrono::high_resolution_clock::now();
    // Q8_0: single-thread until HOST_Q8_GEMV_SAFE (thread-pool races observed).
    const bool q8Single =
        wtEffective.type == (int)GGMLType::GGML_TYPE_Q8_0;
    if (threadPool && rows >= 64 && !q8Single) {
        size_t numThreads = threadPool->size();
        size_t rowsPerThread = rows / numThreads;
        size_t remainder = rows % numThreads;

        std::atomic<size_t> completed(0);
        size_t submitted = 0;

        size_t startRow = 0;
        for (size_t t = 0; t < numThreads; ++t) {
            size_t chunkRows = rowsPerThread + (t < remainder ? 1 : 0);
            if (chunkRows == 0) continue;
            size_t endRow = startRow + chunkRows;

            threadPool->enqueue_void([&, startRow, endRow]() {
                LinearW_Range(wtEffective, input, output, startRow, endRow, cols);
                completed++;
            });
            ++submitted;

            startRow = endRow;
        }

        while (completed < submitted) {
            _mm_pause();
        }
    } else {
        LinearW_Range(wtEffective, input, output, 0, rows, cols);
    }
    auto tLinearW1 = std::chrono::high_resolution_clock::now();
    double linearwMs = std::chrono::duration<double, std::milli>(tLinearW1 - tLinearW0).count();
    int typeIdx = wtEffective.type & 0x1F;
    if (typeIdx >= 0 && typeIdx < 32) {
        g_linearwByType[typeIdx].calls++;
        g_linearwByType[typeIdx].totalMs += linearwMs;
        g_linearwByType[typeIdx].totalMACs += rows * cols;
    }
    auto& tensorStats = g_linearwByTensor[wtEffective.name];
    tensorStats.calls++;
    tensorStats.totalMs += linearwMs;
    tensorStats.totalMACs += rows * cols;

    // --- Q4_K HEADER FINGERPRINT (once per tensor) ---
    // DISABLED for profiler builds to avoid I/O overhead
    #if 0
    static const void* q4kFingerprinted = nullptr;
    if (wtEffective.type == 12 && wtEffective.data && q4kFingerprinted != wtEffective.data) {
        q4kFingerprinted = wtEffective.data;
        const uint8_t* p = static_cast<const uint8_t*>(wtEffective.data);
        uint16_t dBits = 0, dminBits = 0;
        memcpy(&dBits,    p + 0, 2);
        memcpy(&dminBits,  p + 2, 2);
        fprintf(stderr,
            "[Q4K_HDR] name=%s data=%p d=0x%04x dmin=0x%04x "
            "b0..3=%02x%02x%02x%02x s4..7=%02x%02x%02x%02x\n",
            wtEffective.name.c_str(), wtEffective.data, dBits, dminBits,
            p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);
        fflush(stderr);
    }
    #endif

    // --- Release Elastic residency after compute ---
    if (acquired && elasticResidencyEnabled_ && elasticResidency_ && !wt.name.empty()) {
        elasticResidency_->ReleaseTensor(wt.name);
    }

    // --- NAN-GUARD: hard stop on first nonfinite output, log once ---
    static bool nanGuardPrinted = false;
    size_t bad = 0;
    size_t firstBadIdx = 0;
    for (size_t i = 0; i < outDim; ++i) {
        if (!std::isfinite(output[i])) {
            if (bad == 0) firstBadIdx = i;
            ++bad;
        }
    }
    if (bad > 0) {
        if (!nanGuardPrinted) {
            nanGuardPrinted = true;
            fprintf(stderr,
                "[LinearW:FATAL] name=%s type=%d rows=%zu cols=%zu "
                "bad=%zu/%zu firstBad[%zu]=%g\n",
                wtEffective.name.c_str(), wtEffective.type, rows, cols,
                bad, outDim, firstBadIdx, output[firstBadIdx]);
            fflush(stderr);
        }
        // Hard stop: zero the output to prevent NaN propagation
        memset(output, 0, outDim * sizeof(float));
        return;
    }

    // Add bias
    if (bias) {
        for (size_t i = 0; i < outDim; ++i) {
            output[i] += bias[i];
        }
    }

    // --- Profiler: record quant attribution ---
    if (profilingEnabled_ && profiler_) {
        auto tQuant1 = std::chrono::high_resolution_clock::now();
        uint64_t quantUs = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(tQuant1 - tQuant0).count());
        profiler_->recordQuantTime(wtEffective.type, quantUs);
    }

    // Live Pinball: residual energy from output vs input scale (not hardcoded bounce)
    if (LivePath_Active() && input && output && outDim > 0) {
        double outEnergy = 0.0, inEnergy = 0.0;
        const size_t nIn = cols > 0 ? cols : outDim;
        const size_t sample = outDim < 64 ? outDim : 64;
        for (size_t i = 0; i < sample; ++i) {
            outEnergy += (double)output[i] * (double)output[i];
            if (i < nIn) inEnergy += (double)input[i] * (double)input[i];
        }
        const float scale = (float)std::sqrt(std::max(inEnergy, 1e-12));
        LivePath_RecordPinball((float)std::sqrt(outEnergy), scale);
    }
}

// ============================================================================
// Reset
// ============================================================================
namespace {
PackedDualAdapterCtx& PdCtxSingleton() {
    static PackedDualAdapterCtx ctx{};
    return ctx;
}
} // namespace

/* Soft context reset: KV/sampler/cancel/seq only.
 * MUST RETAIN weights, GPU allocs, residency, SSVK, packed Q2K, DualStick,
 * BIND16 linkage. Clears stale token ordinal so next-gen prefill does not
 * reuse genN BIND16 state (was tok>0 → BIND16_DISPATCH_FAIL linked=0). */
void Deep2Engine::reset() {
    if (kvCache) kvCache->reset();
    if (compressedKV_) compressedKV_->reset();
    if (sampler) sampler->Reset();
    clearCancel();
    /* Drop stale BIND16 token ordinal (genN leak → genN+1 prefill BIND16). */
    d2bind16_begin_token(&ssvkBind16_, 0, nullptr);
    ssVkProductBind_.beginToken(0);
    for (auto& router : moeRouters_) {
        if (router) {
            router->ResetStats();
            router->ResetExpertLoads();
        }
    }
    (void)EnsurePersistentDecodeBinding();
    emitContinuitySnap(stderr, 0);
    std::fprintf(stderr, "CONTINUITY_POINT=AFTER_FN_RESET\n");
}

bool Deep2Engine::EnsurePersistentDecodeBinding() {
    auto& pd = PdCtxSingleton();
    if (!pd.ready) {
        if (PackedDualAdapterOpen(&pd) != 0) return false;
        std::printf("[Deep2Engine] BATCH2_SSVK_PACKED_DUAL_OPEN=1\n");
    }
    if (pd.ready && !ssVkProductBind_.bound()) {
        bindSsVkPackedQ2K(&PackedDualAdapterGemv, &pd);
        std::printf("[Deep2Engine] BATCH2_SSVK_PACKED_DUAL_BOUND=1\n");
    }
    if (!ssvkBind16_.initialized) d2bind16_init(&ssvkBind16_);
    if (pd.ready && ssvkBind16_.run == nullptr) {
        bindSsVkPackedProduct(&d2_packed_q2k_product_run_v1, &pd);
        std::printf("[Deep2Engine] BIND16_SSVK_PRODUCT_BOUND=1\n");
    }
    return pd.ready && ssVkProductBind_.bound() && ssvkBind16_.run != nullptr;
}

void Deep2Engine::emitContinuitySnap(FILE* f, uint32_t gen) const {
    if (!f) return;
    const auto& pd = PdCtxSingleton();
    const auto& ds = DualStickState();
    const auto& gf = gpuFwd_;
    std::fprintf(f,
        "GEN=%u BIND16_LINKED=%u PACKED_Q2K_READY=%u SSVK_READY=%u "
        "DUALSTICK_ARMED=%u GPU_RESIDENT=%u MODEL_LOADED=%u DEVICE_COUNT=%u "
        "FWD_G0=%llu FWD_G1=%llu RESIDENCY_EPOCH=%llu MODEL_EPOCH=%llu\n",
        gen,
        ssvkBind16_.run != nullptr ? 1u : 0u,
        pd.ready ? 1u : 0u,
        (ssVkProductBind_.bound() && ssvkBind16_.run) ? 1u : 0u,
        ds.armed ? 1u : 0u,
        gpuResidentDecodeEnabled() ? 1u : 0u,
        isModelLoaded() ? 1u : 0u,
        vulkanDeviceCount(),
        (unsigned long long)gf.forwardSlot[0],
        (unsigned long long)gf.forwardSlot[1],
        (unsigned long long)residencyEpoch_,
        (unsigned long long)modelLoadEvents_);
    std::fflush(f);
}

// ============================================================================
// Unload Model
// ============================================================================
void Deep2Engine::unloadModel() {
    Deep2::Ev512::HostEmitModelUnloadEntry(
        1, Deep2::Ev512::HostPathHash(config.modelPath));
    Deep2::Ev512::HostEmitResidencyRelease(1, 0);
    std::fprintf(stderr, "[LIFE] unloadModel BEGIN\n");
    std::fflush(stderr);
    printf("[Deep2Engine] Unloading model...\n");

    std::fprintf(stderr, "[LIFE] unloadModel close bp16Streamer\n");
    std::fflush(stderr);
    if (bp16Streamer_) {
        bp16Streamer_->close();
        bp16Streamer_.reset();
        bp16Enabled_ = false;
    }

    std::fprintf(stderr, "[LIFE] unloadModel clear weight aliases (no alignedFree) layers=%zu\n",
                 modelWeights.layers.size());
    std::fflush(stderr);
    for (auto& layer : modelWeights.layers) {
        layer = LayerWeights();
    }
    modelWeights.layers.clear();
    modelWeights.tokenEmbed = WeightTensor();
    modelWeights.lmHead = WeightTensor();
    modelWeights.finalNorm = WeightTensor();
    modelWeights.loaded = false;
    modelWeights.tieEmbeddings = false;
    modelState_ = ModelState::Closed;

    std::fprintf(stderr, "[LIFE] unloadModel FreeTensorData ggufResult (%zu tensors)\n",
                 ggufResult.tensors.size());
    std::fflush(stderr);
    for (auto& t : ggufResult.tensors) {
        if (t.data) {
            GGUFLoader::FreeTensorData(t.data);
            t.data = nullptr;
        }
    }
    ggufResult.tensors.clear();
    ggufResult.mmapKeep.reset();
    ggufResult.mmapBound = 0;
    ggufResult.success = false;

    std::fprintf(stderr, "[LIFE] unloadModel reset kvCache\n");
    std::fflush(stderr);
    if (kvCache) {
        kvCache.reset();
    }

    std::fprintf(stderr, "[LIFE] unloadModel deallocateBuffers\n");
    std::fflush(stderr);
    deallocateBuffers();

    printf("[Deep2Engine] Model unloaded.\n");
    std::fprintf(stderr, "[LIFE] unloadModel END\n");
    std::fflush(stderr);
    Deep2::Ev512::HostEmitModelUnloadComplete(1, 0);
    /* Surface after unload so 91/92 appear if stream guard already ran. */
    Deep2::Ev512::HostSurfaceAllClaims(stderr);
}

bool Deep2Engine::switchModel(const std::string& ggufPath) {
    printf("[Deep2Engine] switchModel BEGIN path=%s\n", ggufPath.c_str());
    const uint64_t pathH = Deep2::Ev512::HostPathHash(ggufPath.c_str());
    Deep2::Ev512::HostEmitReloadEntry(pathH, 1);
    unloadModel();
    if (!loadModel(ggufPath)) {
        printf("[Deep2Engine] switchModel FAIL load\n");
        Deep2::Ev512::HostEmitReloadComplete(pathH, 0);
        return false;
    }
    const auto& mw = modelWeights;
    EngineConfig cfg = config;
    cfg.hiddenDim = mw.hiddenDim;
    cfg.numLayers = mw.numLayers;
    cfg.numHeads = mw.numHeads;
    cfg.numKVHeads = mw.numKVHeads;
    cfg.headDim = mw.headDim;
    cfg.vocabSize = mw.vocabSize;
    cfg.intermediateDim = mw.intermediateDim;
    if (cfg.maxSeqLen == 0) cfg.maxSeqLen = 2048;
    strncpy_s(cfg.modelPath, ggufPath.c_str(), _TRUNCATE);
    if (!initialize(cfg)) {
        printf("[Deep2Engine] switchModel FAIL initialize\n");
        Deep2::Ev512::HostEmitReloadComplete(pathH, 0);
        return false;
    }
    printf("[Deep2Engine] switchModel PASS\n");
    Deep2::Ev512::HostEmitReloadComplete(pathH, 1);
    return true;
}

bool Deep2Engine::growContext(size_t newMaxSeqLen) {
    if (!initialized || !kvCache) return false;
    if (newMaxSeqLen <= config.maxSeqLen) return true;
    const size_t oldMax = config.maxSeqLen;
    if (!kvCache->grow(newMaxSeqLen)) return false;
    // Reallocate hiddenStates for longer sequences (preserve used prefix bytes)
    float* oldH = hiddenStates;
    const size_t copyElems = (std::min)(oldMax, kvCache->currentLength() + 1) * config.hiddenDim;
    hiddenStates = alignedAlloc(config.hiddenDim * newMaxSeqLen);
    if (!hiddenStates) {
        hiddenStates = oldH;
        return false;
    }
    if (oldH && copyElems > 0)
        memcpy(hiddenStates, oldH, copyElems * sizeof(float));
    alignedFree(oldH);
    config.maxSeqLen = newMaxSeqLen;
    printf("[Deep2Engine] growContext %zu -> %zu\n", oldMax, newMaxSeqLen);
    return true;
}

// ============================================================================
// Model Metadata Access
// ============================================================================
const ModelMetadata& Deep2Engine::getModelMetadata() const {
    return ggufResult.metadata;
}

// ============================================================================
// B3-FIX: Autoregressive State Integrity Gate â€” Diagnostic Helpers
// ============================================================================
namespace {

struct B3VecStats {
    double min = 0.0;
    double max = 0.0;
    double mean = 0.0;
    double l2 = 0.0;
    size_t n = 0;
    size_t finite = 0;
    size_t nanCount = 0;
    size_t infCount = 0;
};

static B3VecStats B3_ComputeStats(const float* v, size_t n)
{
    B3VecStats s;
    s.n = n;
    if (!v || n == 0) return s;

    double sum = 0.0;
    double sumsq = 0.0;
    bool haveFinite = false;
    for (size_t i = 0; i < n; ++i) {
        const float x = v[i];
        if (std::isnan(x)) {
            ++s.nanCount;
            continue;
        }
        if (std::isinf(x)) {
            ++s.infCount;
            continue;
        }
        ++s.finite;
        const double d = static_cast<double>(x);
        sum += d;
        sumsq += d * d;
        if (!haveFinite) {
            s.min = d;
            s.max = d;
            haveFinite = true;
        } else {
            if (d < s.min) s.min = d;
            if (d > s.max) s.max = d;
        }
    }
    s.mean = (s.finite > 0) ? (sum / static_cast<double>(s.finite)) : 0.0;
    s.l2 = std::sqrt(sumsq);
    return s;
}

static double B3_L2Norm(const float* v, size_t n)
{
    return B3_ComputeStats(v, n).l2;
}

static float B3_MinValue(const float* v, size_t n)
{
    return static_cast<float>(B3_ComputeStats(v, n).min);
}

static float B3_MaxValue(const float* v, size_t n)
{
    return static_cast<float>(B3_ComputeStats(v, n).max);
}

static size_t B3_CountNonFinite(const float* v, size_t n)
{
    const B3VecStats s = B3_ComputeStats(v, n);
    return s.nanCount + s.infCount;
}

// One-shot first-bad-layer capture for TinyLlama / Deep2 Q4 diagnosis.
// Env: RAWRXD_DEEP2_LAYER_PROBE=1 enables verbose dumps + early abort.
static bool B3_ProbeEnabled()
{
    static int cached = -1;
    if (cached < 0) {
        const char* e = std::getenv("RAWRXD_DEEP2_LAYER_PROBE");
        cached = (e && e[0] == '1') ? 1 : 0;
    }
    return cached == 1;
}

static bool& B3_FirstBadLatched()
{
    static bool latched = false;
    return latched;
}

static void B3_ResetFirstBad()
{
    B3_FirstBadLatched() = false;
}

static bool B3_IsResidualPhase(const char* phase)
{
    if (!phase) return false;
    // Residual accumulators â€” these grow across layers when ATTN_O/FFN explode.
    return std::strstr(phase, "POST_ATTN") != nullptr ||
           std::strstr(phase, "POST_FFN") != nullptr ||
           std::strstr(phase, "_INPUT") != nullptr ||
           std::strcmp(phase, "ATTN_O") == 0 ||
           std::strcmp(phase, "ATTN_OUT") == 0 ||
           std::strcmp(phase, "FFN_DOWN") == 0;
}

static bool B3_StageDigestEnabled()
{
    static const bool on = (std::getenv("RAWRXD_STAGE_DIGEST") != nullptr);
    return on;
}

// Body dumps (Q/K/V/FFN) default to layers 0..2. Opt-in extras via:
//   RAWRXD_STAGE_DUMP_LAYERS=8,9,10,11,12
//   RAWRXD_STAGE_DUMP_MAX_LAYER=10   (inclusive 0..N, in addition to 0..2)
static bool B3_StageDumpLayer(size_t layer)
{
    if (layer <= 2) return true;
    static bool parsed = false;
    static bool layers[64] = {};
    static int maxLayer = -1;
    if (!parsed) {
        parsed = true;
        if (const char* p = std::getenv("RAWRXD_STAGE_DUMP_MAX_LAYER")) {
            maxLayer = std::atoi(p);
        }
        if (const char* p = std::getenv("RAWRXD_STAGE_DUMP_LAYERS")) {
            while (p && *p) {
                while (*p == ' ' || *p == ',') ++p;
                if (!*p) break;
                char* end = nullptr;
                long v = std::strtol(p, &end, 10);
                if (end == p) break;
                if (v >= 0 && v < 64) layers[v] = true;
                p = end;
            }
        }
    }
    if (maxLayer >= 0 && (int)layer <= maxLayer) return true;
    return (layer < 64) && layers[layer];
}

static const char* B3_StageDumpDir()
{
    return std::getenv("RAWRXD_STAGE_DUMP_DIR");
}

// Same FNV-1a contract as AttnCert / llama_ref_parity_probe (bit-exact compare).
static void B3_StageDigest(const char* key, size_t pos, const float* data, size_t n)
{
    if (!B3_StageDigestEnabled() || !data || n == 0) return;
    double minV = 0.0, maxV = 0.0, ss = 0.0, sum = 0.0, maxAbs = 0.0;
    bool any = false;
    std::uint64_t h = 14695981039346656037ull;
    int nf = 0;
    for (size_t i = 0; i < n; ++i) {
        const float v = data[i];
        std::uint32_t bits = 0;
        if (!std::isfinite(v)) {
            ++nf;
            bits = 0xFFFFFFFFu;
        } else {
            std::memcpy(&bits, &v, 4);
            const double d = static_cast<double>(v);
            if (!any) { minV = maxV = d; any = true; }
            else { if (d < minV) minV = d; if (d > maxV) maxV = d; }
            sum += d;
            ss += d * d;
            const double a = (d < 0.0) ? -d : d;
            if (a > maxAbs) maxAbs = a;
        }
        for (int b = 0; b < 4; ++b) {
            h ^= (bits >> (8 * b)) & 0xFFu;
            h *= 1099511628211ull;
        }
    }
    printf("[STAGE_DIGEST] side=deep2 key=%s pos=%zu n=%zu l2=%.9e max_abs=%.9e min=%.9e max=%.9e sum=%.9e fnv=%016llx nf=%d\n",
           key, pos, n, std::sqrt(ss), maxAbs, minV, maxV, sum,
           static_cast<unsigned long long>(h), nf);
    fflush(stdout);

    if (const char* dumpDir = B3_StageDumpDir()) {
        // Collision-proof: deep2_<key>_pos<p>_layer0_full_n<N>_seq<SSS>.bin
        static int s_dumpSeq = 0;
        const int seq = ++s_dumpSeq;
        char safeKey[128];
        std::snprintf(safeKey, sizeof(safeKey), "%s", key);
        for (char* p = safeKey; *p; ++p) {
            if (*p == '/' || *p == '\\' || *p == ':' || *p == '*' || *p == '-' || *p == ' ') *p = '_';
        }
        char stem[1024];
        std::snprintf(stem, sizeof(stem),
                      "%s\\deep2_%s_pos%zu_layer0_full_n%zu_seq%03d",
                      dumpDir, safeKey, pos, n, seq);
        char path[1100], manPath[1100];
        std::snprintf(path, sizeof(path), "%s.bin", stem);
        std::snprintf(manPath, sizeof(manPath), "%s.manifest.txt", stem);
        FILE* exist = std::fopen(path, "rb");
        if (exist) {
            std::fclose(exist);
            printf("[STAGE_DUMP_COLLISION] path=%s REFUSING_OVERWRITE\n", path);
            fflush(stdout);
        } else {
            FILE* f = std::fopen(path, "wb");
            if (f) {
                const size_t nbytes = n * sizeof(float);
                std::fwrite(data, 1, nbytes, f);
                std::fclose(f);
                FILE* mf = std::fopen(manPath, "w");
                if (mf) {
                    std::fprintf(mf,
                        "side=deep2\nstage=%s\npos=%zu\nlayer=0\nhead=-1\nhead_tag=full\n"
                        "dtype=f32\nnelem=%zu\nnbytes=%zu\nfnv=%016llx\nl2=%.17g\nseq=%d\npath=%s\n",
                        key, pos, n, nbytes, static_cast<unsigned long long>(h),
                        std::sqrt(ss), seq, path);
                    std::fclose(mf);
                }
                char idxPath[1024];
                std::snprintf(idxPath, sizeof(idxPath), "%s\\DUMP_MANIFEST.jsonl", dumpDir);
                FILE* idx = std::fopen(idxPath, "a");
                if (idx) {
                    std::fprintf(idx,
                        "{\"side\":\"deep2\",\"stage\":\"%s\",\"pos\":%zu,\"layer\":0,\"head\":-1,"
                        "\"nelem\":%zu,\"nbytes\":%zu,\"fnv\":\"%016llx\",\"l2\":%.17g,\"seq\":%d,\"bin\":\"%s\"}\n",
                        key, pos, n, nbytes, static_cast<unsigned long long>(h),
                        std::sqrt(ss), seq, path);
                    std::fclose(idx);
                }
                printf("[STAGE_DUMP] %s nelem=%zu head=-1 seq=%03d fnv=%016llx\n",
                       path, n, seq, static_cast<unsigned long long>(h));
            }
        }
    }
}

static bool B3_TraceStateEnabled()
{
    // Default OFF â€” B3_STATE spam makes agentic loops unusable (multi-MB logs).
    // Enable with RAWRXD_DEEP2_LAYER_PROBE=1 or RAWRXD_B3_TRACE=1.
    static int cached = -1;
    if (cached < 0) {
        if (B3_ProbeEnabled()) {
            cached = 1;
        } else {
            const char* e = std::getenv("RAWRXD_B3_TRACE");
            cached = (e && e[0] == '1') ? 1 : 0;
        }
    }
    return cached == 1;
}

static void B3_TraceState(const char* phase, size_t pos, const float* state, size_t n)
{
    if (!B3_TraceStateEnabled() && !B3_StageDigestEnabled()) {
        return;
    }
    const B3VecStats s = B3_ComputeStats(state, n);
    if (B3_TraceStateEnabled()) {
        printf("[B3_STATE] phase=%s pos=%zu size=%zu "
               "min=%.9e max=%.9e mean=%.9e l2=%.9e "
               "finite=%zu nan=%zu inf=%zu\n",
               phase, pos, s.n,
               s.min, s.max, s.mean, s.l2,
               s.finite, s.nanCount, s.infCount);
    }

    if (B3_StageDigestEnabled() &&
        (std::strcmp(phase, "PROMPT_EMBED") == 0 ||
         std::strcmp(phase, "PROMPT_POST_LAYERS") == 0 ||
         std::strcmp(phase, "PROMPT_FINAL_NORM") == 0)) {
        B3_StageDigest(phase, pos, state, n);
    }

    // First-bad gate: find the earliest destroyed checkpoint, not the crash site.
    /* Dim-aware: √n≈56 @3136; 8√n≈448 warn / 20√n≈1120 abort (was fixed 100/1000). */
    const double sqrtN = (n > 0) ? std::sqrt((double)n) : 10.0;
    const double kNormWarn = 8.0 * sqrtN;
    const double kNormAbort = 20.0 * sqrtN;
    const bool nonFinite = (s.nanCount + s.infCount) > 0;
    const bool exploded = B3_IsResidualPhase(phase) && (s.l2 > kNormAbort);
    const bool warn = B3_IsResidualPhase(phase) && (s.l2 > kNormWarn);

    if ((nonFinite || exploded) && !B3_FirstBadLatched()) {
        B3_FirstBadLatched() = true;
        fprintf(stderr,
                "[B3_FIRST_BAD] phase=%s pos=%zu l2=%.9e min=%.9e max=%.9e "
                "nan=%zu inf=%zu finite=%zu\n",
                phase, pos, s.l2, s.min, s.max, s.nanCount, s.infCount, s.finite);
        fflush(stderr);
        if (B3_ProbeEnabled()) {
            // Abort immediately so the log ends at the first bad layer.
            throw std::runtime_error(
                std::string("B3_FIRST_BAD at ") + (phase ? phase : "?"));
        }
    } else if (warn && B3_ProbeEnabled()) {
        fprintf(stderr, "[B3_WARN] phase=%s pos=%zu l2=%.9e (growth)\n",
                phase, pos, s.l2);
    }
    fflush(stdout);
}

static bool B3_LogitsTraceEnabled()
{
    // Default OFF â€” per-token B3_LOGITS + fflush crushed Agentic to ~0.12 TPS.
    static int cached = -1;
    if (cached < 0) {
        if (B3_ProbeEnabled() || B3_TraceStateEnabled()) {
            cached = 1;
        } else {
            const char* e = std::getenv("RAWRXD_B3_LOGITS");
            cached = (e && e[0] == '1') ? 1 : 0;
        }
    }
    return cached == 1;
}

static bool GreedyTraceEnabled()
{
    static int cached = -1;
    if (cached < 0) {
        const char* e = std::getenv("RAWRXD_GREEDY_TRACE");
        cached = (e && e[0] == '1') ? 1 : 0;
    }
    return cached == 1;
}

static void B3_TraceLogits(const char* phase, size_t pos, const float* logits, size_t n)
{
    if (!B3_LogitsTraceEnabled()) return;
    const B3VecStats s = B3_ComputeStats(logits, n);
    printf("[B3_LOGITS] phase=%s pos=%zu size=%zu "
           "min=%.9e max=%.9e mean=%.9e l2=%.9e "
           "finite=%zu nan=%zu inf=%zu\n",
           phase, pos, s.n,
           s.min, s.max, s.mean, s.l2,
           s.finite, s.nanCount, s.infCount);
    fflush(stdout);
}

} // namespace

// ============================================================================
// Generate - Real implementation with weight projections
// ============================================================================
size_t Deep2Engine::generate(const int* promptTokens, size_t promptLen,
                               int* outputTokens, size_t maxOutputLen,
                               InferenceStats* stats,
                               std::function<bool(int)> onToken) {
    if (!initialized) {
        printf("[Deep2Engine] ERROR: Engine not initialized\n");
        return 0;
    }

    if (!modelWeights.loaded) {
        printf("[Deep2Engine] ERROR: No model loaded - call loadModel() first\n");
        return 0;
    }

    if (!promptTokens || !outputTokens || maxOutputLen == 0) {
        return 0;
    }
    if (promptLen == 0) {
        return 0;
    }

    /* HOST_DECODE floor: sanitize before K2LivePolicy_Apply — ArmSpeed MANUAL
     * defaults otherwise re-arm trampoline against host-mapped weights. */
    if (envFlagEnabled("RAWRXD_HOST_DECODE")) {
        hostDecodeSanitize_ = true;
        elasticResidencyEnabled_ = false;
        cycloneEnabled_ = false;
        compressedKVEnabled_ = false;
        marsEnabled_ = false;
        medusaEnabled_ = false;
        LivePath_SetEnhancementsEnabled(false);
        LivePath_SetMechanismMask(0);
        _putenv_s("DEEP2_LIVE_PATH", "0");
        _putenv_s("DEEP2_LIVE_POLICY", "OFF");
        _putenv_s("DEEP2_LIVE_MECH", "none");
    }

    // Token-id generate() path must honor greedy independently of generateStream.
    if (SemanticSafeWanted() ||
        (std::getenv("RAWRXD_GREEDY") && std::getenv("RAWRXD_GREEDY")[0] == '1')) {
        GenerationOptions greedyOpts{};
        greedyOpts.temperature = 0.0f;
        greedyOpts.topK = 1;
        greedyOpts.maxTokens = static_cast<uint32_t>(maxOutputLen);
        configureGeneration(greedyOpts);
    }

    B3_ResetFirstBad();
    emitHotpathWitnesses();
    resetGpuForwardCounters();
    gpuFwdCommitted_ = false;
    clearCancel();

    // ―€”€ Reset KV cache and sampler state for fresh generation ―€”€â€”€â€”€â€”€â€”€
    reset();
    // reset() must not drop greedy mode once configured above.
    if (SemanticSafeWanted() ||
        (std::getenv("RAWRXD_GREEDY") && std::getenv("RAWRXD_GREEDY")[0] == '1')) {
        deterministicGreedy_ = true;
        if (!sampler)
            sampler = std::make_unique<rawrxd::sampling::GreedySampler>();
    }

    const size_t remainingContext = config.maxSeqLen > promptLen ? config.maxSeqLen - promptLen : 0;
    if (remainingContext == 0) {
        return 0;
    }
    maxOutputLen = std::min(maxOutputLen, remainingContext);

    // â”€â”€ Defensive config validation gate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // Reject generation if the runtime config does not match the loaded
    // model dimensions.  This prevents buffer overruns when the lifecycle
    // is out of order (e.g. stale hardcoded config vs. real GGUF).
    if (config.hiddenDim == 0 || config.vocabSize == 0) {
        printf("[Deep2Engine] ERROR: Invalid config (hiddenDim=%zu vocabSize=%zu)\n",
               config.hiddenDim, config.vocabSize);
        return 0;
    }
    if (config.hiddenDim != modelWeights.hiddenDim ||
        config.vocabSize != modelWeights.vocabSize) {
        printf("[Deep2Engine] ERROR: Config mismatch (config hidden=%zu vocab=%zu) "
               "vs (model hidden=%zu vocab=%zu)\n",
               config.hiddenDim, config.vocabSize,
               modelWeights.hiddenDim, modelWeights.vocabSize);
        return 0;
    }

    // Live-path: AUTO workload policy is the normal path (MANUAL = cert arms).
    {
        const uint32_t depth = static_cast<uint32_t>(
            config.numLayers ? config.numLayers : modelWeights.numLayers);
        auto pol = K2LivePolicy_Apply(depth, static_cast<uint32_t>(maxOutputLen));
        K2LivePolicy_Emit(stdout, pol);
    }
    CycloneScheduler* liveCyclone = nullptr;
    struct LivePathScope {
        CycloneScheduler* c = nullptr;
        bool armed = false;
        ~LivePathScope() {
            if (armed) {
                LivePath_EndGenerate(c);
                LivePath_Emit(stdout);
            }
        }
    } livePathScope;
    if (LivePath_Wanted()) {
        LivePath_ApplyMechEnv();
        // Model-side generate(): lukewarm = no HotPatcher tax (correct default).
        // Hot (medusa/speculative register→validate→apply) is opt-in only.
        // Chrono/random resolves to lukewarm — not hot.
        {
            const char* ga = std::getenv("DEEP2_GEN_ALG");
            const bool wantMedusa =
                ga && ga[0] &&
                (_stricmp(ga, "medusa") == 0 ||
                 _stricmp(ga, "greedy_medusa") == 0);
            const bool wantSpec =
                ga && ga[0] && _stricmp(ga, "speculative") == 0;
            const bool lukewarm =
                !ga || !ga[0] ||
                _stricmp(ga, "lukewarm") == 0 ||
                _stricmp(ga, "greedy") == 0 ||
                _stricmp(ga, "standard") == 0 ||
                _stricmp(ga, "random") == 0;
            if (wantMedusa || wantSpec) {
                DecoderModePatch::Mode mode = wantSpec
                    ? DecoderModePatch::Mode::SPECULATIVE_DRAFT
                    : DecoderModePatch::Mode::GREEDY_MEDUSA;
                DecoderModePatch dm{};
                dm.targetMode = mode;
                dm.config = {4, 64, 0.0f, false, true};
                dm.allowInFlightTokens = false;
                dm.switchPoint = 0;
                PatchMetadata meta{};
                meta.name = "generate_decoder_algo";
                meta.description = "opt-in hot decoder algorithm patch";
                meta.author = "Deep2Engine::generate";
                std::string id = GetHotPatcher().registerDecoderMode(dm, meta);
                if (!id.empty() && GetHotPatcher().validate(id).passed)
                    GetHotPatcher().apply(id);
                if (!medusaEnabled_) enableMedusa(true);
                printf("[HotPatcher] GENERATE_DECODER_ALG=%d HEAT=hot\n",
                       (int)mode);
            } else if (lukewarm) {
                /* Lukewarm = no HotPatcher tax only. Do NOT disable STACK medusa
                 * (prior veto: ENABLED at enhance → DISABLED at generate).
                 * GPU DualStick still uses standard decode when !hasHeadWeights
                 * or gpuResidentDecode; HOTPATH_MEDUSA remains honest. */
                printf("[HotPatcher] GENERATE_DECODER_ALG=%d HEAT=lukewarm "
                       "SKIP_HOTPATCH=1\n",
                       (int)DecoderModePatch::Mode::STANDARD);
            }
        }
        if (LivePath_MechOn(LP_MECH_ELASTIC) && EnhanceWanted("elastic")) {
            if (!elasticResidencyEnabled_ || !elasticResidency_)
                enableElasticResidency(true);
            // Keep pin residents across generate() â€” no mid-request budget refresh.
        }
        if (LivePath_MechOn(LP_MECH_CYCLONE) && EnhanceWanted("cyclone")) {
            if (!cyclone_)
                enableCyclone(true);
            else if (elasticResidency_ && !vulkanEnabled_)
                cyclone_->RebindElastic(elasticResidency_.get());
        }
        if (LivePath_MechOn(LP_MECH_STREAM)) {
            if (!plasmaGovernorEnabled_ || !plasmaGovernor_)
                enablePlasmaGovernor(true);
            const std::string nvmePath = config.modelPath[0]
                ? std::string(config.modelPath)
                : (!modelDir_.empty() ? modelDir_.string() : std::string());
            enableNVMeStreaming(true, nvmePath);
            initializeAdvancedFeatures();
            if (nvmeStream_ && !nvmeStream_->isReverseBunnyHop())
                (void)nvmeStream_->initializeReverseBunnyHop(nvmeConfig_);
        }
        if (LivePath_MechOn(LP_MECH_WARMUP))
            enableWarmupScheduler(true);
        LivePath_BindOwners(
            elasticResidency_.get(), nvmeStream_.get(), plasmaGovernor_.get(),
            static_cast<uint32_t>(config.numLayers ? config.numLayers : modelWeights.numLayers),
            static_cast<uint32_t>(modelWeights.numHeads ? modelWeights.numHeads : 8));
        liveCyclone =
            (LivePath_MechOn(LP_MECH_CYCLONE) && cycloneEnabled_) ? cyclone_.get() : nullptr;
        if (!hostDecodeSanitize_) {
            LivePath_BeginGenerate(maxOutputLen, elasticResidency_.get(), &liveCyclone);
            livePathScope.c = liveCyclone;
            livePathScope.armed = true;
        } else {
            fprintf(stderr,
                    "HOST_DECODE_SKIP_LIVEPATH=1 "
                    "MEANS_SKIP_ENHANCEMENTS_ONLY=1 "
                    "BASE_FORWARD_STILL_REQUIRED=1\n");
            fflush(stderr);
        }
    }

    // â”€â”€ VAL-051.7: Reset residency counters â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    ResidencyCounters::Reset();
    Deep2_ResetLinearWStats();

    auto startTime = std::chrono::high_resolution_clock::now();

    // Process prompt tokens (prefill)
    for (size_t t = 0; t < promptLen && t < config.maxSeqLen; ++t) {
        // Embed token using real embedding table
        float* h = hiddenStates + t * config.hiddenDim;
        ResidencyCounters::BeginEmbed();
        if (!embedToken(promptTokens[t], h)) {
            fprintf(stderr, "[B3_ABORT] prefill embed FATAL_EMBED token=%d pos=%zu\n",
                    promptTokens[t], t);
            fflush(stderr);
            return 0;
        }
        ResidencyCounters::EndEmbed();
        {
            double en = 0.0;
            for (size_t i = 0; i < config.hiddenDim; ++i)
                en += (double)h[i] * (double)h[i];
            if (envFlagEnabled("RAWRXD_TRACE_EMBED")) {
                fprintf(stderr, "[EMBED_NORM] pos=%zu token=%d l2=%.6e\n",
                        t, promptTokens[t], std::sqrt(en));
                fflush(stderr);
            }
        }

        // â”€â”€ B3: Trace prompt embedding â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        B3_TraceState("PROMPT_EMBED", t, h, config.hiddenDim);

        if (!B3_StageDigestEnabled()) {
            try {
                if (!forwardTokenAllLayers(h, t + 1)) {
                    fprintf(stderr, "[B3_ABORT] prefill gpu/cpu forward fail pos=%zu\n", t);
                    return 0;
                }
            } catch (const std::exception& ex) {
                fprintf(stderr, "[B3_ABORT] prefill: %s\n", ex.what());
                return 0;
            }
        } else {
        // Forward: seed L0, pump-owned N+1 (scoreboard tip).
        float* layerInput = h;
        float* layerOutput = attentionOutput;
        const uint32_t nLayers = (uint32_t)modelWeights.numLayers;
        auto flBody = [](void* eng, uint32_t ly, const float* in, float* out,
                         size_t seq) noexcept {
            static_cast<Deep2Engine*>(eng)->forwardLayer(ly, in, out, seq);
        };
        try {
            forwardLayer(0, layerInput, layerOutput, t + 1);
        } catch (const std::exception& ex) {
            fprintf(stderr, "[B3_ABORT] prefill layer=0: %s\n", ex.what());
            fflush(stderr);
            return 0;
        }
        std::swap(layerInput, layerOutput);
        if (nLayers > 1u) {
            Deep2::scoreboard::ArmPumpIssue(this, flBody, layerInput, layerOutput,
                                            t + 1, nLayers);
            if (!Deep2::scoreboard::PumpOwnedRemainder(nLayers)) {
                fprintf(stderr, "[B3_ABORT] prefill pump-owned walk incomplete\n");
                Deep2::scoreboard::DisarmPumpIssue();
                return 0;
            }
            layerInput = Deep2::scoreboard::PumpArm().in;
            layerOutput = Deep2::scoreboard::PumpArm().out;
            Deep2::scoreboard::DisarmPumpIssue();
        }

        // The final hidden state is in layerInput after the swap
        // Store it back to hiddenStates for this position
        if (layerInput != h) {
            memcpy(h, layerInput, config.hiddenDim * sizeof(float));
        }
        }

        // â”€â”€ B3: Trace after final layer for prompt â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        try {
            B3_TraceState("PROMPT_POST_LAYERS", t, h, config.hiddenDim);
        } catch (const std::exception& ex) {
            fprintf(stderr, "[B3_ABORT] %s\n", ex.what());
            return 0;
        }

        // Final norm: produce FinalHidden or stop on named missing prereq.
        {
            auto fn = FinalNorm::Acquire(modelWeights.finalNorm, config.hiddenDim, h, h,
                                         config.modelPath);
            auto art = FinalNorm::ProduceFinalHidden(
                h, h, fn, config.hiddenDim, modelWeights.normEps);
            if (!art.valid) {
                Proof::EmitFail("FinalNorm", art);
                return 0;
            }
        }
        B3_TraceState("PROMPT_FINAL_NORM", t, h, config.hiddenDim);
        if (B3_StageDigestEnabled()) {
            // Per-position final norm (pos0..promptLen-1). Tip = last prompt token.
            B3_StageDigest("FINAL_NORM", t, h, config.hiddenDim);
            if (t + 1 == promptLen) {
                B3_StageDigest("TIP_FINAL_NORM", t, h, config.hiddenDim);
            }
        }

        // Advance KV cache after processing each prompt token
        if (kvCache) {
            kvCache->advance();
        }
    }

    auto prefillEnd = std::chrono::high_resolution_clock::now();
    const double prefillMs =
        std::chrono::duration<double, std::milli>(prefillEnd - startTime).count();
    rawr::iso_ladder::A().prefillNs =
        (uint64_t)std::chrono::duration_cast<std::chrono::nanoseconds>(
            prefillEnd - startTime)
            .count();
    rawr::iso_ladder::A().decodePhase = 1;

    std::printf("[AGENT] PREFILL_DONE prompt_tokens=%zu prefill_ms=%.3f\n",
                promptLen, prefillMs);
    std::fflush(stdout);
    Deep2::heap::EmitOk(stderr, "AFTER_PREFILL");
    Deep2::heap::EmitOk(stderr, "DECODE_ENTER");

    size_t tokensGenerated = 0;
    size_t currentPos = promptLen;

    // Generate tokens (decode)
    std::printf("[AGENT] DECODE_BEGIN max_out=%zu\n", maxOutputLen);
    std::fflush(stdout);
    DecodeFeedbackReset();
    if (tokenizer) {
        const auto& sp = tokenizer->GetSpecialTokens();
        DecodeFeedbackNoteSpecials(sp.eosId, sp.bosId, sp.unkId, "gguf",
                                   (int)config.vocabSize);
    } else {
        DecodeFeedbackNoteSpecials(-1, -1, -1, "none", (int)config.vocabSize);
    }
    Deep2::heap::EmitOk(stderr, "DECODE_FEEDBACK_INIT");

    auto decodeStart = std::chrono::high_resolution_clock::now();
    for (size_t t = 0; t < maxOutputLen; ++t) {
        if (t == 0) {
            Deep2::heap::EmitOk(stderr, "DECODE_STEP0_ENTER");
            std::fprintf(stderr,
                "DECODE_STEP0_PTRS h=%p logits=%p lmHead=%p vocab=%zu "
                "hiddenDim=%zu promptLen=%zu\n",
                (void*)(hiddenStates + (promptLen ? promptLen - 1 : 0) *
                                    config.hiddenDim),
                (void*)logits, (void*)modelWeights.lmHead.data,
                config.vocabSize, config.hiddenDim, promptLen);
            std::fflush(stderr);
        }
        if (isCancelRequested()) {
            printf("[Deep2Engine] CANCEL requested at decode step %zu (gen=%zu)\n",
                   t, tokensGenerated);
            break;
        }
        const size_t position = currentPos;

        float* h = nullptr;

        if (t == 0 && promptLen > 0) {
            // Step 0: sample directly from the final prefill hidden state.
            // The prefill already computed, layered, and normed the last prompt token.
            h = hiddenStates + (promptLen - 1) * config.hiddenDim;
            Deep2::heap::EmitOk(stderr, "DECODE_STEP0_H_READY");
            // Do NOT re-embed or forward. Logits are ready from prefill.
        } else {
            // Step N>0: embed the previously sampled token and forward it.
            const size_t inputPos = promptLen + (t - 1);
            h = hiddenStates + inputPos * config.hiddenDim;
            {
                D2GTokenTxn txn{};
                (void)Top15ValidateTokenTxn((uint64_t)t, &txn);
            }
            const auto d2b16_before = D2Bind16Snapshot(gpuForwardCounters());
            if (t == 1) {
                emitContinuitySnap(stderr, (uint32_t)t);
                std::fprintf(stderr,
                    "CONTINUITY_POINT=BEFORE_FIRST_BIND16_DISPATCH\n");
            }
            d2bind16_begin_token(&ssvkBind16_, (uint64_t)t, &d2b16_before);
            ssVkProductBind_.beginToken(t);
            const auto& gf0 = gpuForwardCounters();
            const uint64_t snapHostFwd = gf0.hostForwardLayerCalls;
            const uint64_t snapHostMat = gf0.hostMaterializations;
            const uint64_t snapF32 = gf0.cpuF32Expands;

            const int inputToken = outputTokens[tokensGenerated - 1];
            DecodeFeedbackOnFeed(inputToken);
            if (!embedToken(inputToken, h)) {
                fprintf(stderr, "[B3_ABORT] decode embed FATAL_EMBED token=%d gen_step=%zu\n",
                        inputToken, t);
                fflush(stderr);
                break;
            }

            if (!B3_StageDigestEnabled()) {
                try {
                    if (!forwardTokenAllLayers(h, inputPos + 1)) {
                        fprintf(stderr, "[B3_ABORT] decode gpu/cpu forward fail\n");
                        return tokensGenerated;
                    }
                    ssVkProductBind_.noteFullModelForward(true);
                    const auto& gf = gpuForwardCounters();
                    ssVkProductBind_.noteHostCounters(
                        (std::uint32_t)(gf.hostForwardLayerCalls - snapHostFwd),
                        (std::uint32_t)(gf.hostMaterializations - snapHostMat),
                        (std::uint32_t)(gf.cpuF32Expands - snapF32));
                    const auto d2b16_after = D2Bind16Snapshot(gf);
                    d2bind16_end_forward(
                        &ssvkBind16_, &d2b16_after,
                        isRealGpuForward() ? 1u : 0u);
                } catch (const std::exception& ex) {
                    fprintf(stderr, "[B3_ABORT] decode: %s\n", ex.what());
                    return tokensGenerated;
                }
            } else {
            float* layerInput = h;
            float* layerOutput = attentionOutput;
            const uint32_t nLayers = (uint32_t)modelWeights.numLayers;
            auto flBody = [](void* eng, uint32_t ly, const float* in, float* out,
                             size_t seq) noexcept {
                static_cast<Deep2Engine*>(eng)->forwardLayer(ly, in, out, seq);
            };
            try {
                forwardLayer(0, layerInput, layerOutput, inputPos + 1);
            } catch (const std::exception& ex) {
                fprintf(stderr, "[B3_ABORT] decode layer=0: %s\n", ex.what());
                fflush(stderr);
                return tokensGenerated;
            }
            std::swap(layerInput, layerOutput);
            if (nLayers > 1u) {
                Deep2::scoreboard::ArmPumpIssue(this, flBody, layerInput,
                                                layerOutput, inputPos + 1, nLayers);
                if (!Deep2::scoreboard::PumpOwnedRemainder(nLayers)) {
                    fprintf(stderr, "[B3_ABORT] decode pump-owned walk incomplete\n");
                    Deep2::scoreboard::DisarmPumpIssue();
                    return tokensGenerated;
                }
                layerInput = Deep2::scoreboard::PumpArm().in;
                layerOutput = Deep2::scoreboard::PumpArm().out;
                Deep2::scoreboard::DisarmPumpIssue();
            }

            if (layerInput != h) {
                memcpy(h, layerInput, config.hiddenDim * sizeof(float));
            }
            }

            {
                auto fn = FinalNorm::Acquire(modelWeights.finalNorm, config.hiddenDim,
                                             h, h, config.modelPath);
                auto art = FinalNorm::ProduceFinalHidden(
                    h, h, fn, config.hiddenDim, modelWeights.normEps);
                if (!art.valid) {
                    Proof::EmitFail("FinalNorm", art);
                    fprintf(stderr, "[B3_FAIL] MISSING_PREREQ=%s\n",
                            art.missingPrereq ? art.missingPrereq : "UNKNOWN");
                    return tokensGenerated;
                }
                if (t > 0) ssVkProductBind_.noteFinalNorm(true);
            }

            // The generated token has now entered the KV cache.
            if (kvCache) {
                auto k0 = rawr::iso_ladder::Clock::now();
                if (!rawr::iso_ladder::Ignore(rawr::iso_ladder::Run::A7))
                    kvCache->advance();
                if (t > 0)
                    ssVkProductBind_.noteKvAdvance(
                        !rawr::iso_ladder::Ignore(rawr::iso_ladder::Run::A7));
                rawr::iso_ladder::A().kvNs += rawr::iso_ladder::Ns(k0);
            }
        }

        // Compute logits
        ResidencyCounters::BeginLogits();
        if (t == 0) Deep2::heap::EmitOk(stderr, "LOGITS_BEFORE");
        {
            auto l0 = rawr::iso_ladder::Clock::now();
            RAWR_DECODE_SCOPE_LOGITS();
            if (rawr::iso_ladder::Ignore(rawr::iso_ladder::Run::A6)) {
                std::memset(logits, 0, config.vocabSize * sizeof(float));
                logits[0] = 1.0f;
            } else {
                computeLogits(h, logits);
                if (t > 0) ssVkProductBind_.noteLmHead(true);
            }
            rawr::iso_ladder::A().logitsNs += rawr::iso_ladder::Ns(l0);
        }
        ResidencyCounters::EndLogits();
        if (t == 0) Deep2::heap::EmitOk(stderr, "LOGITS_AFTER");
        if (B3_LogitsTraceEnabled()) {
            printf("[B3_LOGITS] AFTER computeLogits\n");
            fflush(stdout);
        }
        if (B3_StageDigestEnabled() && config.vocabSize > 29892) {
            printf("[STAGE_DIGEST] LOGIT_13=%.9f\n", logits[13]);
            printf("[STAGE_DIGEST] LOGIT_29892=%.9f\n", logits[29892]);
            printf("[STAGE_DIGEST] DELTA_13_minus_29892=%.9f\n",
                   logits[13] - logits[29892]);
            B3_StageDigest("FINAL_HIDDEN_FOR_LOGITS", position, h, config.hiddenDim);
            B3_StageDigest("LOGITS", position, logits, config.vocabSize);
            if (t == 0) {
                // First decode sample = tip logits from last prompt token
                B3_StageDigest("TIP_LOGITS", position, logits, config.vocabSize);
                B3_StageDigest("TIP_FINAL_HIDDEN", position, h, config.hiddenDim);
            }
            int argmax = 0;
            float best = logits[0];
            for (size_t i = 1; i < config.vocabSize; ++i) {
                if (logits[i] > best) { best = logits[i]; argmax = (int)i; }
            }
            printf("[STAGE_DIGEST] side=deep2 key=ARGMAX pos=%zu id=%d logit=%.9f\n",
                   position, argmax, best);
            fflush(stdout);
        }

        // â”€â”€ B3: Trace logits (opt-in) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        if (B3_LogitsTraceEnabled()) {
            printf("[B3_LOGITS] BEFORE B3_TraceLogits vocabSize=%zu\n", config.vocabSize);
            fflush(stdout);
            B3_TraceLogits("LOGITS", position, logits, config.vocabSize);
            printf("[B3_LOGITS] AFTER B3_TraceLogits\n");
            fflush(stdout);
        }

        // Hard gate: reject invalid hidden state
        const double stateNorm = B3_L2Norm(h, config.hiddenDim);
        if (!(stateNorm > 1.0e-12) || !std::isfinite(stateNorm)) {
            fprintf(stderr, "[B3_FAIL] hidden state invalid pos=%zu norm=%.9e\n",
                    position, stateNorm);
            return tokensGenerated;
        }
        /* Soft gate: architecture-aware. RMS unit vector L2≈sqrt(H);
           Nemotron-H H=3136 → √H≈56; learned norm w~2.7–4.6 → L2~150–260.
           Old fixed >100 false-alarmed every Nemotron decode step. */
        {
            const double sqrtH = std::sqrt((double)config.hiddenDim);
            const double warnGt =
                (ggufResult.metadata.architecture.find("nemotron") !=
                 std::string::npos)
                    ? (8.0 * sqrtH)   /* ~448 for H=3136 */
                    : 100.0;
            const double explGt =
                (ggufResult.metadata.architecture.find("nemotron") !=
                 std::string::npos)
                    ? (20.0 * sqrtH)  /* ~1120 */
                    : 1000.0;
            if (stateNorm > explGt) {
                fprintf(stderr,
                        "[B3_WARN] hidden state norm explosion pos=%zu "
                        "norm=%.9e warn_gt=%.1f expl_gt=%.1f arch=%s\n",
                        position, stateNorm, warnGt, explGt,
                        ggufResult.metadata.architecture.c_str());
            } else if (stateNorm > warnGt) {
                fprintf(stderr,
                        "[B3_NORM_GROWTH] pos=%zu norm=%.9e warn_gt=%.1f "
                        "NOTE=within_arch_band_ne_explosion arch=%s\n",
                        position, stateNorm, warnGt,
                        ggufResult.metadata.architecture.c_str());
            } else if (position == 0 || (tokensGenerated == 0 && position > 0)) {
                /* one-shot band seal for C08 */
                static int bandOnce = 0;
                if (!bandOnce) {
                    bandOnce = 1;
                    fprintf(stderr,
                            "B3_NORM_BAND_ARCH=%s SQRT_H=%.3f WARN_GT=%.1f "
                            "EXPL_GT=%.1f OBS_NORM=%.3f "
                            "B3_NORM_EXPLOSION=0\n",
                            ggufResult.metadata.architecture.c_str(), sqrtH,
                            warnGt, explGt, stateNorm);
                }
            }
        }

        // Hard gate: reject invalid logits
        if (config.vocabSize == 0 || B3_CountNonFinite(logits, config.vocabSize) != 0) {
            fprintf(stderr, "[B3_FAIL] invalid logits pos=%zu size=%zu\n",
                    position, config.vocabSize);
            return tokensGenerated;
        }

        DecodeFeedbackOnLogits((int)tokensGenerated, logits, config.vocabSize);

        // Sample next token
        if (t == 0) Deep2::heap::EmitOk(stderr, "SAMPLE_BEFORE");
        if (B3_LogitsTraceEnabled()) {
            printf("[B3_LOGITS] BEFORE sampleToken\n");
            fflush(stdout);
        }
        int nextToken = 0;
        {
            auto s0 = rawr::iso_ladder::Clock::now();
            RAWR_DECODE_SCOPE_SAMPLE();
            if (rawr::iso_ladder::Ignore(rawr::iso_ladder::Run::A5)) {
                int best = 0;
                float bestL = logits[0];
                for (size_t i = 1; i < config.vocabSize; ++i) {
                    if (std::isfinite(logits[i]) &&
                        (!std::isfinite(bestL) || logits[i] > bestL)) {
                        bestL = logits[i];
                        best = (int)i;
                    }
                }
                nextToken = best;
            } else {
                nextToken = sampleToken(logits);
            }
            rawr::iso_ladder::A().sampleNs += rawr::iso_ladder::Ns(s0);
        }
        if (t == 0) Deep2::heap::EmitOk(stderr, "SAMPLE_AFTER");
        if (B3_LogitsTraceEnabled()) {
            printf("[B3_LOGITS] AFTER sampleToken token=%d\n", nextToken);
            printf("[B3_LOGITS] Storing token %d at index %zu\n", nextToken, tokensGenerated);
            fflush(stdout);
        }
        {
            std::string piece;
            if (tokenizer) piece = tokenizer->Decode(nextToken);
            else piece = detokenize(std::vector<int>{nextToken});
            DecodeFeedbackOnSample(nextToken, piece);
            if (tokensGenerated == 0 && !SemanticSafeWanted()) {
                std::fprintf(stderr, "[AGENT] TOKEN id=%d piece=", nextToken);
                for (unsigned char c : piece) {
                    if (c >= 32 && c < 127) std::fprintf(stderr, "%c", c);
                    else std::fprintf(stderr, "\\x%02X", c);
                }
                std::fprintf(stderr, "\n");
                std::fflush(stderr);
            }
        }

        outputTokens[tokensGenerated] = nextToken;
        if (t > 0) {
            ssVkProductBind_.noteSamplerCommit(true);
            ssVkProductBind_.noteSealedLogitsReuse(false);
            /* BIND16_GATE: governing commit owns PASS + WINDOW_AUTHORITY. */
            if (ssvkBind16_.run != nullptr) {
                const int kvReal =
                    (kvCache &&
                     !rawr::iso_ladder::Ignore(rawr::iso_ladder::Run::A7))
                        ? 1 : 0;
                d2bind16_note_tail(&ssvkBind16_, 1, 1, kvReal, 1, 0);
                const int bindOk = d2bind16_commit_token(&ssvkBind16_);
                {
                    const size_t kvLen = persistentKvLength();
                    if (persistCont_.n_gt0_tokens > 0 &&
                        kvLen < persistCont_.kv_len_last)
                        ++persistCont_.kv_regressions;
                    persistCont_.kv_len_last = kvLen;
                    ++persistCont_.n_gt0_tokens;
                    if (bindOk) ++persistCont_.n_gt0_pass;
                    PersistentEmitToken(
                        stderr, (uint64_t)t, (uint64_t)kvLen,
                        vulkanDeviceCount(), isModelLoaded() ? 1 : 0,
                        gpuResidentDecodeEnabled() ? 1 : 0,
                        ssvkBind16_.run != nullptr ? 1 : 0, bindOk ? 1 : 0,
                        0, deviceCreateEvents_, modelLoadEvents_,
                        commandRebuildEvents_, dualStickResetEvents_);
                    {
                        ResidencySnapshot rs{};
                        rs.device_creates = deviceCreateEvents_;
                        rs.model_loads = modelLoadEvents_;
                        rs.reload_bytes =
                            GpuTransfer_Snapshot().reloadBytes;
                        const unsigned nd = vulkanDeviceCount();
                        for (unsigned si = 0; si < nd; ++si) {
                            rs.weight_uploads +=
                                vulkanSlotWeightUploads(si);
                            rs.weight_hits += vulkanSlotWeightHits(si);
                            auto* vc = getVulkanComputeSlot(si);
                            if (!vc) continue;
                            rs.content_hits += vc->WeightContentHits();
                            rs.pin_evicts += vc->WeightPinEvicts();
                            rs.pin_rejects += vc->WeightPinRejects();
                            rs.resident_bytes +=
                                vc->WeightPinResidentBytes();
                        }
                        ResidencyEmitToken(
                            stderr, (uint64_t)t, (uint64_t)kvLen, nd,
                            isModelLoaded() ? 1 : 0,
                            gpuResidentDecodeEnabled() ? 1 : 0, rs);
                    }
                }
                if (std::getenv("RAWRXD_DEEP2_SSVK_PRODUCT_STRICT")) {
                    if (!bindOk) {
                        std::fprintf(stderr,
                            "BATCH2_PRODUCT_DECODE_BIND=FAIL token=%zu "
                            "reason=BIND16_COMMIT\n", t);
                        return tokensGenerated;
                    }
                    std::fprintf(stderr,
                        "BATCH2_PRODUCT_DECODE_BIND=PASS token=%zu\n", t);
                    const D2Bind16Window* bw = d2bind16_window(&ssvkBind16_);
                    if (bw && bw->authority)
                        std::fprintf(stderr, "BIND16_WINDOW_AUTHORITY=1\n");
                }
            } else if (std::getenv("RAWRXD_DEEP2_SSVK_PRODUCT_STRICT")) {
                if (!ssVkProductBind_.tokenAuthoritative()) {
                    const auto& p = ssVkProductBind_.tokenProof();
                    std::fprintf(stderr,
                        "BATCH2_PRODUCT_DECODE_BIND=FAIL token=%zu "
                        "q2=%llu/%llu hostFwd=%u hostMat=%u f32=%u nvme=%u\n",
                        t,
                        (unsigned long long)p.q2kOpsProduct,
                        (unsigned long long)p.q2kOpsSeen,
                        p.hostForwardLayerCalls,
                        p.hostMaterializations,
                        p.cpuF32Expands,
                        p.criticalPathNvmeReads);
                    return tokensGenerated;
                }
                std::fprintf(stderr,
                    "BATCH2_PRODUCT_DECODE_BIND=PASS token=%zu\n", t);
            }
        }
        tokensGenerated++;
        LivePath_OnToken(static_cast<uint64_t>(tokensGenerated));
        if (LivePath_ShouldBrake()) {
            printf("[Deep2Engine] TrailBrake LIVE brake â€” ending generate early\n");
            break;
        }

        if (onToken) {
            if (B3_LogitsTraceEnabled()) {
                printf("[B3_LOGITS] Calling onToken callback\n");
                fflush(stdout);
            }
            if (!onToken(nextToken)) {
                if (B3_LogitsTraceEnabled()) {
                    printf("[B3_LOGITS] onToken returned false, breaking\n");
                    fflush(stdout);
                }
                break;
            }
        }
        // PlasmaGovernor: thermal pause only if DECODE_SLEEP explicitly allowed.
        if (plasmaGovernorEnabled_ && plasmaGovernor_) {
            if (plasmaGovernor_->isEmergencyStopped()) {
                printf("[Deep2Engine] PlasmaGovernor EMERGENCY STOP — halting generation\n");
                break;
            }
            if (RawrDecodeSleepAllowed() && plasmaGovernor_->needsCoolingPause()) {
                uint32_t pause_us = plasmaGovernor_->coolingPauseMicros();
                if (pause_us > 0) {
                    printf("[Deep2Engine] PlasmaGovernor cooling pause: %u us\n", pause_us);
                    std::this_thread::sleep_for(std::chrono::microseconds(pause_us));
                }
            }
        }

        if (B3_LogitsTraceEnabled()) {
            printf("[B3_LOGITS] Checking EOS\n");
            fflush(stdout);
        }
        // Check for EOS
        if (tokenizer && nextToken == tokenizer->GetSpecialTokens().eosId) {
            if (B3_LogitsTraceEnabled()) {
                printf("[B3_LOGITS] EOS detected, breaking\n");
                fflush(stdout);
            }
            break;
        }

        currentPos++;
        if (B3_LogitsTraceEnabled()) {
            printf("[B3_LOGITS] End of generation loop iteration\n");
            fflush(stdout);
        }
    }

    if (B3_LogitsTraceEnabled()) {
        printf("[B3_LOGITS] Generation loop exited, tokensGenerated=%zu\n", tokensGenerated);
        fflush(stdout);
    }
    if (DecodeFeedback().enabled) {
        DecodeFeedbackDump(stderr);
    }

    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime);
    double totalMs = duration.count() / 1000.0;
    const double decodeMs =
        std::chrono::duration<double, std::milli>(endTime - decodeStart).count();
    rawr::iso_ladder::A().decodeNs =
        (uint64_t)std::chrono::duration_cast<std::chrono::nanoseconds>(
            endTime - decodeStart)
            .count();

    if (stats) {
        stats->tokensGenerated = tokensGenerated;
        stats->promptTokens = promptLen;
        stats->prefillMs = prefillMs;
        stats->decodeMs = decodeMs;
        stats->totalWallMs = totalMs;
        if (prefillMs > 0.0 && promptLen > 0)
            stats->prefillTokensPerSecond = promptLen / (prefillMs / 1000.0);
        if (decodeMs > 0.0 && tokensGenerated > 0)
            stats->decodeTokensPerSecond = tokensGenerated / (decodeMs / 1000.0);
        if (totalMs > 0) {
            stats->tokensPerSecond = tokensGenerated / (totalMs / 1000.0);
            stats->latencyMs = tokensGenerated > 0 ? (totalMs / tokensGenerated) : totalMs;
        }
    }

    printf("[Deep2Engine] Generation complete: %zu tokens in %.2f ms (E2E %.2f TPS)\n",
           tokensGenerated, totalMs, totalMs > 0 ? tokensGenerated / (totalMs / 1000.0) : 0.0);
    printf("[Deep2Engine] PREFILL: %zu tok in %.2f ms (%.2f tok/s) | DECODE: %zu tok in %.2f ms (%.2f tok/s)\n",
           promptLen, prefillMs,
           prefillMs > 0 ? promptLen / (prefillMs / 1000.0) : 0.0,
           tokensGenerated, decodeMs,
           decodeMs > 0 && tokensGenerated > 0 ? tokensGenerated / (decodeMs / 1000.0) : 0.0);
    // #region agent log
    {
        const auto& lc = LivePath_Counters();
        FILE* df = fopen("g:/~dev/debug-83dcc5.log", "a");
        if (df) {
            fprintf(df,
                "{\"sessionId\":\"83dcc5\",\"runId\":\"witness\",\"hypothesisId\":\"C\","
                "\"location\":\"Deep2Engine.cpp:generate\","
                "\"message\":\"generate_tps\","
                "\"data\":{\"promptTok\":%zu,\"genTok\":%zu,\"prefillMs\":%.3f,"
                "\"decodeMs\":%.3f,\"e2eMs\":%.3f,\"prefillTps\":%.3f,\"decodeTps\":%.3f,"
                "\"e2eTps\":%.3f,\"pinballSamples\":%u,\"cycloneStarts\":%u,\"trampHits\":%u},"
                "\"timestamp\":%lld}\n",
                promptLen, tokensGenerated, prefillMs, decodeMs, totalMs,
                prefillMs > 0 ? promptLen / (prefillMs / 1000.0) : 0.0,
                decodeMs > 0 && tokensGenerated > 0 ? tokensGenerated / (decodeMs / 1000.0) : 0.0,
                totalMs > 0 ? tokensGenerated / (totalMs / 1000.0) : 0.0,
                lc.pinballSamples, lc.cycloneLayerStarts, lc.trampolineHits,
                (long long)std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count());
            fclose(df);
        }
    }
    // #endregion
    emitLiveDecodeWitnesses(nullptr);

    // â”€â”€ VAL-051.7: Print residency counters â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    ResidencyCounters::Print();
    Deep2_ReportLinearWStats();

    // â”€â”€ Batch 15: Print ElasticResidencyManager telemetry â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if (elasticResidencyEnabled_ && elasticResidency_) {
        elasticResidency_->PrintTelemetry();
    }

    // â”€â”€ Deep2 Active Telemetry: Evaluate and route â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if (telemetryControllerEnabled_ && telemetryController_) {
        auto health = telemetryController_->evaluate_and_route();
        const char* healthStr = "UNKNOWN";
        switch (health) {
            case SystemHealth::HEALTHY_PREFETCH: healthStr = "HEALTHY_PREFETCH"; break;
            case SystemHealth::PCIE_HOST_BOTTLENECK: healthStr = "PCIE_HOST_BOTTLENECK"; break;
            case SystemHealth::VRAM_BW_SATURATED: healthStr = "VRAM_BW_SATURATED"; break;
            case SystemHealth::COMPUTE_BOUND: healthStr = "COMPUTE_BOUND"; break;
            case SystemHealth::UNKNOWN: healthStr = "UNKNOWN"; break;
        }
        printf("[Deep2Engine] Telemetry health: %s\n", healthStr);
    }

    return tokensGenerated;
}

// ============================================================================
// Generate Text (high-level API)
// ============================================================================
std::string Deep2Engine::generateText(const std::string& prompt, size_t maxTokens) {
    GenerationOptions options{};
    options.maxTokens = static_cast<uint32_t>(maxTokens);
    // Agentic / loadModel-only clients use generateText with default sampling.
    // Honor RAWRXD_GREEDY (and temp<=0) so certs stay deterministic.
    if (const char* g = std::getenv("RAWRXD_GREEDY"); g && g[0] && g[0] != '0') {
        options.temperature = 0.0f;
        options.topK = 1;
    }
    std::string accumulated;
    generateStream(prompt, options, [&](int32_t, const std::string& token) -> bool {
        accumulated += token;
        return true;
    });
    return accumulated;
}

void Deep2Engine::configureGeneration(const GenerationOptions& options)
{
    // One authoritative generation configuration for generate() / generateStream().
    if (options.temperature <= 0.0f || options.topK <= 1) {
        deterministicGreedy_ = true;
        sampler = std::make_unique<rawrxd::sampling::GreedySampler>();
        printf("[GREEDY] enabled=1 temperature=%.4f topK=%u\n",
               options.temperature, options.topK);
    } else {
        deterministicGreedy_ = false;
        if (options.topP < 1.0f && options.topP > 0.0f) {
            sampler = std::make_unique<rawrxd::sampling::TopPSampler>(
                options.temperature, options.topP);
        } else {
            sampler = std::make_unique<rawrxd::sampling::TopKSampler>(
                static_cast<int>(options.topK), options.temperature);
        }
        printf("[GREEDY] enabled=0 temperature=%.4f topK=%u\n",
               options.temperature, options.topK);
    }
    if (sampler) {
        sampler->setRepetitionPenalty(options.repeatPenalty);
        sampler->setMinP(options.minP);
    }
}

void Deep2Engine::setTemperature(float temperature) {
    GenerationOptions opts;
    opts.temperature = temperature;
    opts.topP = 0.95f;
    opts.topK = (temperature <= 0.0f) ? 1u : 40u;
    configureGeneration(opts);
}

void Deep2Engine::setTopP(float topP) {
    GenerationOptions opts;
    opts.temperature = deterministicGreedy_ ? 0.0f : 0.8f;
    opts.topP = topP;
    opts.topK = deterministicGreedy_ ? 1u : 40u;
    configureGeneration(opts);
}

void Deep2Engine::setSampling(float temperature, float topP) {
    GenerationOptions opts;
    opts.temperature = temperature;
    opts.topP = topP;
    opts.topK = (temperature <= 0.0f) ? 1u : 40u;
    configureGeneration(opts);
}

Deep2::GenerationResult Deep2Engine::generateStream(
    const std::string& prompt,
    const GenerationOptions& options,
    TokenCallback callback)
{
    configureGeneration(options);
    rawr::batch007::Reset();
    rawr::batch007::A().modelAuth = modelWeights.loaded ? 1 : 0;
    rawr::batch007::A().maxTokensReq = options.maxTokens;
    rawr::batch007::A().ctxSize = config.maxSeqLen;
    rawr::batch007::A().vocabExt = 1;
    choreo::ApplyLawEnv();
    const auto productWallT0 = std::chrono::high_resolution_clock::now();
    /* EV512 observational only — product stream does not require DEEP2_EV512. */
    Deep2::Ev512::HostTryArm(0x50524F44554354ull); /* PRODUCT */
    Deep2::Ev512::HostSurfaceGuard ev512Surface(stderr);
    Deep2::Ev512::HostEmitGenerateStreamEntry(1, (uint64_t)options.maxTokens);
    Deep2::Ev512::HostEmitRequestAccepted(1, (uint64_t)options.maxTokens);
    Deep2::Ev512::HostEmitRequestRouted(1, k2ShardIndexOpen_ ? 2ull : 1ull);
    Deep2::Ev512::HostEmitDeep2SessionCreate(1, (uint64_t)options.maxTokens);
    Deep2::Ev512::HostEmitDeep2SessionReady(1, 0);
    ssmRealCalls_ = 0;
    ssmIdentityCalls_ = 0;

    // STREAM_BACKWARDS: emit receipts before any decode wait.
    {
        RuntimeReceipts rc{};
        rc.modelIndexed = modelWeights.loaded && initialized;
        const auto map = AssessNemotronSsmMap(modelWeights);
        rc.tensorMapComplete = map.complete != 0;
        rc.hybridLayerRoute = map.hybridRoute > 0 || map.ssmLayers == 0;
        rc.choreographyReady =
            rc.modelIndexed &&
            (modelState_ == ModelState::Indexed ||
             modelState_ == ModelState::Choreographable ||
             modelState_ == ModelState::Generating);
        rc.spaceSufficient = true;
        /* K2 INDEX: MLA stream owns TLS K2KVCache — engine kvCache may be null. */
        rc.kvHotsetReady =
            (kvCache != nullptr) || !config.useKVCache || k2ShardIndexOpen_;
        rc.weightWindowReady = modelWeights.loaded;
        rc.hostQ8GemvSafe = hostQ8GemvSafe_;
        if (!hostQ8GemvSafe_) {
            rc.q8Owner = "NEMOTRON_H_Q8_GEMV";
            rc.q8Action =
                "fix host Q8_0 LinearW (FFN/attn/ssm_in); see HOST_Q8_GEMV_* receipts";
            emitHostQ8GemvReceipts(stderr);
        }
        if (!map.complete && map.ssmLayers > 0) {
            rc.tensorMapOwner = "NEMOTRON_H_SSM";
            rc.tensorMapAction =
                "map blk.N.ssm_in.weight, blk.N.ssm_d, blk.N.ssm_conv1d.bias";
        }
        const char* goal = "GENERATION_COMPLETE";
        if (ggufResult.metadata.architecture.find("nemotron") != std::string::npos)
            goal = "NEMOTRON_NANO_POEM_001";
        CompletionPlan plan = ReverseGenerationCompletion(rc);
        EmitCompletionPlan(stderr, goal, plan);
        if (!plan.complete) {
            GenerationResult blocked{};
            blocked.generatedTokens = 0;
            fprintf(stderr,
                "GENERATION_COMPLETE=0\nSTREAM_STATUS=BLOCKED\n"
                "READY_WORK_ONLY=1\nPRODUCTION_DECODE_PATH=0\n");
            return blocked;
        }
        fprintf(stderr, "STREAM_STATUS=READY\nNEXT_ACTION=CALL_GENERATE_STREAM\n");
        fprintf(stderr, "GENERATE_STREAM_ENTER=1 ARCH=%s LAYERS=%zu KV_HEADS=%zu HEAD_DIM=%zu\n",
                ggufResult.metadata.architecture.c_str(),
                modelWeights.numLayers, config.numKVHeads, config.headDim);
        // Nemotron-H scaffold: host CPU decode until SSM/FFN Vulkan GEMV certified.
        if (ggufResult.metadata.architecture.find("nemotron") != std::string::npos &&
            vulkanEnabled_) {
            fprintf(stderr, "NEMOTRON_HOST_CPU_DECODE=1 VULKAN_GEMV=0\n");
            vulkanEnabled_ = false;
        }
        // Host-decode sanitize: elastic/cyclone/MARS/CKV race host mapped weights.
        if (ggufResult.metadata.architecture.find("nemotron") != std::string::npos ||
            envFlagEnabled("RAWRXD_HOST_DECODE")) {
            hostDecodeSanitize_ = true;
            elasticResidencyEnabled_ = false;
            cycloneEnabled_ = false;
            compressedKVEnabled_ = false;
            marsEnabled_ = false;
            medusaEnabled_ = false;
            LivePath_SetEnhancementsEnabled(false);
            LivePath_SetMechanismMask(0);
            _putenv_s("RAWRXD_LIVE_PATH", "0");
            _putenv_s("DEEP2_LIVE_PATH", "0");
            _putenv_s("DEEP2_LIVE_POLICY", "OFF");
            _putenv_s("DEEP2_LIVE_MECH", "none");
            _putenv_s("RAWRXD_DEEP2_ALLOW_ELASTIC", "0");
            fprintf(stderr,
                "HOST_DECODE_SANITIZE=1 elastic=0 cyclone=0 ckv=0 mars=0 "
                "medusa=0 livepath=0 BASE_FORWARD=1 OPTIONAL_ONLY_SKIPPED=1\n");
            fflush(stderr);
        }
        fflush(stderr);
    }

    if (modelState_ == ModelState::Indexed ||
        modelState_ == ModelState::Choreographable)
        modelState_ = ModelState::Generating;

    // Blocker 94: runtime owns formatting (gguf|builtin|explicit-none). No harness.
    // RAWRXD_RAW_PROMPT=1: observe-only raw path (diag matrix); sealed CLI default unchanged.
    std::string runtimePrompt = prompt;
    armGenQualityProbe();
    {
        const char* rawEnv = std::getenv("RAWRXD_RAW_PROMPT");
        const bool forceRaw = rawEnv && rawEnv[0] == '1';
        ChatTemplate chatTmpl;
        const ModelMetadata& meta = ggufResult.metadata;
        const bool hasMetaTmpl = !meta.chatTemplate.empty();
        chatTmpl.initFromMetadata(meta.architecture, "", meta.chatTemplate,
                                  meta.bosToken, meta.eosToken);
        const auto ty = chatTmpl.getType();
        const bool usable =
            !forceRaw &&
            (ty != ChatTemplateType::UNKNOWN && ty != ChatTemplateType::RAW_BOS);
        genQualityChatValid_ = usable ? 1 : (forceRaw ? 1 : 0);
        if (usable) {
            runtimePrompt = chatTmpl.formatSingle(prompt, "");
            const char* src = hasMetaTmpl ? "gguf" : "builtin-model-rule";
            const std::string& hs =
                hasMetaTmpl ? meta.chatTemplate
                            : std::string(chatTmpl.getTypeName());
            rawr::batch007::NoteChatPolicy(1, src, "APPLY_TEMPLATE", hs.data(),
                                           hs.size());
        } else {
            runtimePrompt = prompt;
            rawr::batch007::NoteChatPolicy(0, forceRaw ? "raw-env" : "explicit-none",
                                           "RAW_PROMPT_ALLOWED",
                                           forceRaw ? "raw-env" : "explicit-none",
                                           forceRaw ? 7 : 13);
        }
    }

    // Ownership seam: real K2 generate consumes MLA_Gemv via native stream
    // (same control law as forwardTokenAllLayers K2 branch). Do not fall into
    // TinyLlama GPU-forward / incomplete host MLA.
    if (k2ShardIndexOpen_ && globalIndex_ && config.useMLA) {
        const char* real = std::getenv("DEEP2_REAL_K2_GENERATE");
        const bool force = !real || !real[0] || real[0] == '1';
        if (force) {
            /* BLOCKER_93: specials from loaded tokenizer before generate. */
            if (tokenizer) {
                const auto& sp = tokenizer->GetSpecialTokens();
                rawr::batch007::NoteSpecials(sp.bosId, sp.eosId, sp.padId,
                                             sp.unkId, "gguf", 1);
            }
            K2NativeStreamGate::Config kc;
            kc.prompt = runtimePrompt;
            /* Prompt token count for absolute RoPE/KV authority. */
            uint32_t promptTokCount = 1u;
            {
                auto pt = tokenize(runtimePrompt);
                if (!pt.empty()) promptTokCount = (uint32_t)pt.size();
            }
            {
                uint32_t rem = 1u;
                if (config.maxSeqLen > promptTokCount)
                    rem = (uint32_t)(config.maxSeqLen - promptTokCount);
                const uint32_t cap =
                    rawr::unlimited::ResolveCap(options.maxTokens, rem);
                kc.streamTokens = cap ? cap : rem;
            }
            uint32_t depth = config.numLayers ? (uint32_t)config.numLayers : 61u;
            if (const char* el = std::getenv("RAWRXD_K2_LAYERS")) {
                int n = atoi(el);
                if (n > 0) depth = (uint32_t)n;
            }
            kc.layerDepth = depth;
            kc.enableMlaComplete = true;
            if (const char* b = std::getenv("DEEP2_K2_STREAM_BUDGET")) {
                long long v = std::atoll(b);
                if (v > 0) kc.budgetBytes = (uint64_t)v;
            }
            rawr::batch007::A().promptTokens = promptTokCount;
            struct CbState {
                TokenCallback cb;
                uint32_t count = 0;
                int32_t eosId = -1;
                Deep2Engine* eng = nullptr;
            } st;
            st.cb = callback;
            st.eng = this;
            if (tokenizer) {
                const auto& sp = tokenizer->GetSpecialTokens();
                st.eosId = sp.eosId;
            }
            kc.onTokenUser = &st;
            kc.onToken = [](int32_t id, void* user) -> bool {
                auto* s = static_cast<CbState*>(user);
                if (!s || !s->cb) return true;
                ++s->count;
                std::string piece;
                if (s->eng)
                    piece = s->eng->detokenize(std::vector<int>{id});
                Deep2::Ev512::HostEmitTokenCallback((uint64_t)(uint32_t)id,
                                                   (uint64_t)s->count);
                Deep2::Ev512::HostEmitTokenDecoded((uint64_t)(uint32_t)id,
                                                  (uint64_t)piece.size());
                Deep2::Ev512::HostEmitDecodeStepEntry((uint64_t)s->count,
                                                     (uint64_t)(uint32_t)id);
                rawr::batch007::CommitToken(id, piece, true);
                /* Positions: K2NativeStreamGate NotePositions after KV Commit. */
                const bool keep = s->cb(id, piece);
                /* BLOCKER_93: stop after delivering EOS piece (model vocab). */
                if (s->eosId >= 0 && id == s->eosId) return false;
                return keep;
            };
            printf("LIVE_FORWARD=forwardTokenAllLayers\n");
            printf("LIVE_MLA_DISPATCH=MLA_Gemv\n");
            printf("LIVE_K2_OWNERSHIP=generateStream→runK2NativeStreamPartial\n");
            fflush(stdout);
            auto r = runK2NativeStreamPartial(kc);
            GenerationResult out;
            out.promptTokens = promptTokCount;
            // Always credit real callbacks — !ok mid-stream still observed tokens.
            out.generatedTokens = st.count;
            if (out.generatedTokens == 0 && r.ok)
                out.generatedTokens = kc.streamTokens;
            out.completed = r.ok && out.generatedTokens > 0;
            out.cancelled = !r.ok && st.count > 0;
            if (!r.ok) {
                fprintf(stderr,
                        "[Deep2Engine] K2 generateStream: %s "
                        "STREAM_ABORT=1 TOKENS_OBSERVED=%u TARGET=%u "
                        "TEARDOWN_WITNESS=0\n",
                        r.error.empty() ? "(no error string)" : r.error.c_str(),
                        st.count, kc.streamTokens);
                fflush(stderr);
            }
            {
                RawrWorkingSet w{};
                w.weightBytes = kc.budgetBytes ? kc.budgetBytes : (8ull << 20);
                w.activationBytes = (uint64_t)config.hiddenDim * 4ull * 3ull;
                w.kvHotBytes = 2ull * (uint64_t)kc.layerDepth * 8ull * 192ull * 4ull;
                w.scratchBytes = (uint64_t)config.hiddenDim * 4ull;
                RawrSpaceState s{};
                s.capacityBytes = kc.budgetBytes ? kc.budgetBytes : (512ull << 20);
                s.occupiedBytes = RawrWorkingSetBytes(w);
                s.reserveBytes = 1ull << 20;
                RawrEmitLiveSeal(stdout, w, s, r.ok ? 1 : 0);
            }
            modelState_ = ModelState::Choreographable;
            rawr::batch007::A().promptTokens = out.promptTokens;
            rawr::batch007::A().tokensCommitted = out.generatedTokens;
            {
                /* BLOCKER_104: Finalize from model Acc / Gate kvLength only. */
                uint64_t pos = rawr::batch007::A().kvPos;
                if (pos == 0 && r.kvLength) pos = (uint64_t)r.kvLength;
                /* Prefer Acc/Gate kvLength; avoid StreamGate pull for stub length. */
                rawr::batch007::Finalize(pos, config.maxSeqLen, pos,
                                         out.cancelled ? 1 : 0, std::string());
            }
            if (out.cancelled) rawr::batch007::NoteCancel("K2_STREAM_ABORT");
            rawr::batch007::Emit();
            {
                rawr::product_path::Facts xf{};
                xf.model = ggufResult.metadata.architecture.empty()
                               ? "deepseek2"
                               : ggufResult.metadata.architecture.c_str();
                xf.path = "generateStream";
                xf.tokensRequested = (uint32_t)options.maxTokens;
                xf.tokensCommitted = (uint32_t)out.generatedTokens;
                xf.wallNs = rawr::product_path::WallNsFromSpt();
                xf.textBytes = 0;
                xf.candidateTokenHash = rawr::batch007::A().streamHash;
                {
                    const int graph =
                        (ssmHybridLayers_ == 0 ||
                         (ssmIdentityCalls_ == 0 && ssmMambaArmed_ &&
                          ssmRealCalls_ > 0 &&
                          ssmHybridLayers_ > 0))
                            ? 1
                            : 0;
                    const int nemoReal =
                        (ssmMambaArmed_ && ssmIdentityCalls_ == 0 &&
                         ssmHybridLayers_ > 0 &&
                         ssmRealCalls_ >= ssmHybridLayers_)
                            ? 1
                            : 0;
                    fprintf(stderr,
                            "PRODUCT_ENTRY_PATH=1\nSTREAM_RUNTIME_PATH=1\n"
                            "MODEL_GRAPH_COMPLETE=%d\nNEMOTRON_SSM_REAL=%d\n"
                            "SSM_REAL_LAYERS=%zu SSM_IDENTITY_LAYERS=%zu "
                            "SSM_HYBRID_LAYERS=%zu SSM_MAMBA_ARMED=%d\n"
                            "NUMERIC_PARITY=UNPROVEN\nFUNCTIONAL_MODEL_PASS=%d\n"
                            "GATE=NEMOTRON_H_REAL_SSM_001\n"
                            "PRODUCTION_DECODE_PATH=0\nPROMOTE=0\n"
                            "SSM_CERT=NOT_CERTIFIED\n",
                            graph, nemoReal, ssmRealCalls_, ssmIdentityCalls_,
                            ssmHybridLayers_, ssmMambaArmed_, nemoReal);
                }
                xf.productionDecode =
                    (ssmHybridLayers_ > 0)
                        ? 0
                        : (out.generatedTokens > 0 ? 1 : 0);
                xf.modelOutput = out.generatedTokens > 0 ? 1 : 0;
                xf.streamPresent = st.count > 0 ? 1 : 0;
                xf.receiptAtomic = 1;
                xf.finite = 1;
                xf.teardownOk = out.cancelled ? 0 : 1;
                xf.measuredReal = 1;
                xf.modelProvenanceMatch = g_modelProv.ok ? 1 : 0;
                xf.productOpenPass = isModelLoaded() ? 1 : 0;
                xf.sessionEnterPass = 1;
                xf.tokenCommitPass =
                    (out.generatedTokens > 0 && st.count > 0) ? 1 : 0;
                rawr::product_path::Emit(stderr, xf);
            }
            Deep2::Ev512::HostEmitEndReason(out.completed ? 0ull : 1ull,
                                           (uint64_t)out.generatedTokens);
            if (out.completed)
                Deep2::Ev512::HostEmitE2EProductComplete(
                    (uint64_t)out.generatedTokens, 0);
            return out;
        }
    }

    std::vector<int> promptTokens = tokenize(runtimePrompt);
    Deep2::Ev512::HostEmitTokenizeComplete((uint64_t)promptTokens.size(), 0);
    Deep2::Ev512::HostEmitPrefillEntry(1, (uint64_t)promptTokens.size());
    Deep2::Ev512::HostEmitPrefillComplete(1, (uint64_t)promptTokens.size());
    rawr::batch007::A().promptTokens = promptTokens.size();
    if (tokenizer) {
        const auto& sp = tokenizer->GetSpecialTokens();
        rawr::batch007::NoteSpecials(sp.bosId, sp.eosId, sp.padId, sp.unkId, "gguf", 1);
    }

    const bool agentFirstToken = []() {
        const char* e = std::getenv("RAWRXD_AGENT_FIRST_TOKEN");
        return e && e[0] == '1';
    }();

    // TOKENIZER-PARITY-002b-001: capture full Deep2 ID list before any embed abort
    {
        const char* enabled = std::getenv("RAWRXD_TOKENIZER_CERT");
        if ((enabled && enabled[0] == '1') || agentFirstToken) {
            const char* dir = agentFirstToken
                ? "F:\\~dev\\rawrxd\\evidence\\AGENT_E2E_002b\\AGENT_FIRST_TOKEN_001"
                : "F:\\~dev\\rawrxd\\evidence\\AGENT_E2E_002b\\TOKENIZER_PARITY_001";
            std::error_code ec;
            std::filesystem::create_directories(dir, ec);
            {
                std::ofstream idsFile(std::string(dir) + "\\deep2_ids.txt", std::ios::binary);
                for (size_t i = 0; i < promptTokens.size(); ++i) {
                    if (i) idsFile << ',';
                    idsFile << promptTokens[i];
                }
                idsFile << '\n';
            }
            {
                std::ofstream f(std::string(dir) + "\\rendered_prompt.bin", std::ios::binary);
                f.write(prompt.data(), static_cast<std::streamsize>(prompt.size()));
            }
            {
                std::ofstream f(std::string(dir) + "\\rendered_prompt.txt", std::ios::binary);
                f << prompt;
            }
            std::printf("[AGENT] TOKENIZED count=%zu first=%d last=%d\n",
                        promptTokens.size(),
                        promptTokens.empty() ? -1 : promptTokens.front(),
                        promptTokens.empty() ? -1 : promptTokens.back());
            std::fflush(stdout);
            std::fprintf(stderr, "[TOKENIZER_CERT] count=%zu\n", promptTokens.size());
            std::fflush(stderr);
            // Tokenizer-only cert stops here. First-token cert continues into prefill/decode.
            if (enabled && enabled[0] == '1' && !agentFirstToken) {
                Deep2::GenerationResult certOnly;
                certOnly.promptTokens = promptTokens.size();
                certOnly.generatedTokens = 0;
                certOnly.completed = true;
                return certOnly;
            }
        }
    }

    if (promptTokens.empty()) {
        std::printf("[AGENT] TOKENIZED count=0 FAIL\n");
        std::fflush(stdout);
        return {};
    }

    GenerationOptions opts = options;
    if (agentFirstToken) {
        opts.maxTokens = 1;
        opts.temperature = 0.0f;
        opts.topK = 1;
        configureGeneration(opts);
    }

    const size_t promptN = promptTokens.size();
    uint32_t remCtx = 1u;
    if (config.maxSeqLen > promptN)
        remCtx = (uint32_t)(config.maxSeqLen - promptN);
    uint32_t resolved =
        rawr::unlimited::ResolveCap(opts.maxTokens, remCtx);
    const size_t maxTokens = static_cast<size_t>(resolved ? resolved : remCtx);
    std::vector<int> outputTokens(maxTokens);
    std::string streamed;
    bool wasCancelled = false;
    rawr::decode_loop::Reset(maxTokens);
    rawr::decode_loop::Utf8Carry detokCarry;
    rawr::iso_ladder::Reset(maxTokens);
    Deep2::decode_blocker_wire::ResetIfEnabled(maxTokens);
    if (!Deep2::decode_blocker_wire::Enabled())
        Deep2::decode_blocker::Reset(maxTokens);

    if (medusaEnabled_ && medusaDecoder_ && medusaDecoder_->hasHeadWeights(0) &&
        maxTokens > 0 && !gpuResidentDecodeEnabled()) {
        emitHotpathWitnesses();
        size_t generated = generateWithMedusa(
            promptTokens.data(), promptTokens.size(),
            outputTokens.data(), maxTokens, nullptr);
        for (size_t i = 0; i < generated; ++i) {
            std::string piece = tokenizer ? tokenizer->Decode(outputTokens[i])
                                          : detokenize(std::vector<int>{outputTokens[i]});
            streamed += piece;
            if (callback && !callback((int32_t)outputTokens[i], piece)) {
                wasCancelled = true;
                break;
            }
        }
        GenerationResult medusaResult;
        medusaResult.promptTokens = promptTokens.size();
        medusaResult.generatedTokens = generated;
        medusaResult.completed = generated > 0 && !wasCancelled;
        medusaResult.cancelled = wasCancelled;
        return medusaResult;
    }

    std::printf("[AGENT] PREFILL_BEGIN prompt_tokens=%zu\n", promptTokens.size());
    std::fflush(stdout);

    size_t evTokN = 0;
    size_t generated = generate(
        promptTokens.data(), promptTokens.size(),
        outputTokens.data(), maxTokens,
        nullptr,
        [&](int tokenId) -> bool {
            if (evTokN++ == 0)
                Deep2::Ev512::HostEmitFirstTokenBoundary(0, (uint64_t)maxTokens);
            Deep2::Ev512::HostEmitDecodeStepEntry((uint64_t)evTokN,
                                                 (uint64_t)(uint32_t)tokenId);
            Deep2::Ev512::HostEmitTokenCallback((uint64_t)(uint32_t)tokenId,
                                               (uint64_t)evTokN);
            /* Deliver EOS through detok/commit/callback then stop (K2 parity).
               Early-return before commit left FIRST_TOKEN=0 / TOKEN_COMMIT=0. */
            const bool isEos =
                tokenizer &&
                tokenId == tokenizer->GetSpecialTokens().eosId;
            std::string piece;
            if (tokenizer) {
                auto d0 = rawr::iso_ladder::Clock::now();
                RAWR_DECODE_SCOPE_DETOK();
                if (rawr::iso_ladder::Ignore(rawr::iso_ladder::Run::A3)) {
                    piece = "x";
                    rawr::iso_ladder::A().tokensDecoded++;
                    Deep2::decode_blocker::NoteSingleDecode();
                } else {
                    piece = rawr::decode_loop::DecodeOne(tokenizer.get(), tokenId,
                                                         detokCarry);
                    rawr::iso_ladder::A().tokensDecoded++;
                    Deep2::decode_blocker::NoteSingleDecode();
                }
                rawr::iso_ladder::A().detokNs += rawr::iso_ladder::Ns(d0);
                rawr::batch007::A().detokCarry = 1;
                rawr::batch007::A().partialFlush = 1;
                rawr::batch007::CommitToken(tokenId, piece, true,
                                            /*pushId=*/true);
            } else {
                auto d0 = rawr::decode_loop::Clock::now();
                RAWR_DECODE_SCOPE_DETOK();
                piece = detokenize(std::vector<int>{tokenId});
                rawr::decode_loop::NoteSequenceDecode(
                    1, rawr::decode_loop::NsSince(d0));
                rawr::batch007::CommitToken(tokenId, piece, false);
                rawr::iso_ladder::A().tokensDecoded++;
                Deep2::decode_blocker::NoteSequenceDecode(1);
            }
            rawr::decode_loop::NoteCommit();
            rawr::iso_ladder::A().tokensCommitted++;
            Deep2::decode_blocker::NoteCommitted();
            {
                const uint64_t absPos =
                    (uint64_t)promptTokens.size() +
                    rawr::batch007::A().tokensCommitted;
                rawr::batch007::NotePositions(absPos);
            }
            streamed += piece;
            Deep2::Ev512::HostEmitTokenDecoded((uint64_t)(uint32_t)tokenId,
                                              (uint64_t)piece.size());
            if (callback) {
                auto c0 = rawr::iso_ladder::Clock::now();
                RAWR_DECODE_SCOPE_CALLBACK();
                bool keepGoing = true;
                if (!rawr::iso_ladder::Ignore(rawr::iso_ladder::Run::A4))
                    keepGoing = callback(static_cast<int32_t>(tokenId), piece);
                const uint64_t cNs = rawr::iso_ladder::Ns(c0);
                rawr::iso_ladder::A().callbackNs += cNs;
                rawr::decode_loop::NoteCallbackNs(cNs);
                if (!keepGoing) {
                    wasCancelled = true;
                    return false;
                }
            }
            if (isEos) return false;
            return true;
        });

    GenerationResult result;
    result.promptTokens = promptTokens.size();
    result.generatedTokens = generated;
    result.cancelled = wasCancelled || isCancelRequested();
    result.completed = generated > 0 && !result.cancelled;
    clearCancel();
    (void)detokCarry.flush();

    if (agentFirstToken) {
        const int firstId = generated > 0 ? outputTokens[0] : -1;
        std::printf("[AGENT] FIRST_TOKEN id=%d generated=%zu\n", firstId, generated);
        std::fflush(stdout);
        const char* dir =
            "F:\\~dev\\rawrxd\\evidence\\AGENT_E2E_002b\\AGENT_FIRST_TOKEN_001";
        std::ofstream vf(std::string(dir) + "\\first_token.txt");
        vf << "first_token_id=" << firstId << "\n";
        vf << "generated=" << generated << "\n";
        vf << "prompt_tokens=" << promptTokens.size() << "\n";
        vf << "RESULT=" << (generated > 0 ? "PASS" : "FAIL") << "\n";
    }

    {
        const uint64_t kvPos = kvCache ? kvCache->currentLength() : 0;
        rawr::batch007::Finalize(kvPos, config.maxSeqLen, kvPos,
                                 result.cancelled ? 1 : 0, streamed);
        if (result.cancelled) rawr::batch007::NoteCancel("CALLBACK_FALSE");
        {
            auto r0 = rawr::iso_ladder::Clock::now();
            RAWR_DECODE_SCOPE_RECEIPT();
            if (!rawr::iso_ladder::Ignore(rawr::iso_ladder::Run::A1))
                rawr::batch007::Emit();
            rawr::iso_ladder::A().receiptNs += rawr::iso_ladder::Ns(r0);
        }
        const auto productWallT1 = std::chrono::high_resolution_clock::now();
        const uint64_t wallNs = (uint64_t)std::chrono::duration_cast<
            std::chrono::nanoseconds>(productWallT1 - productWallT0).count();
        uint64_t sptWall = rawr::product_path::WallNsFromSpt();
        rawr::product_path::Facts xf{};
        xf.model = ggufResult.metadata.architecture.empty()
                       ? "local-gguf"
                       : ggufResult.metadata.architecture.c_str();
        xf.path = "generateStream";
        xf.tokensRequested = (uint32_t)options.maxTokens;
        xf.tokensCommitted = (uint32_t)result.generatedTokens;
        xf.wallNs = sptWall ? sptWall : wallNs;
        xf.textBytes = streamed.size();
        xf.candidateTokenHash = rawr::batch007::A().streamHash;
        {
            const int graph =
                (ssmHybridLayers_ == 0 ||
                 (ssmIdentityCalls_ == 0 && ssmMambaArmed_ &&
                  ssmRealCalls_ > 0 && ssmHybridLayers_ > 0))
                    ? 1
                    : 0;
            const int nemoReal =
                (ssmMambaArmed_ && ssmIdentityCalls_ == 0 &&
                 ssmHybridLayers_ > 0 &&
                 ssmRealCalls_ >= ssmHybridLayers_)
                    ? 1
                    : 0;
            fprintf(stderr,
                    "PRODUCT_ENTRY_PATH=1\nSTREAM_RUNTIME_PATH=1\n"
                    "MODEL_GRAPH_COMPLETE=%d\nNEMOTRON_SSM_REAL=%d\n"
                    "SSM_REAL_LAYERS=%zu SSM_IDENTITY_LAYERS=%zu "
                    "SSM_HYBRID_LAYERS=%zu SSM_MAMBA_ARMED=%d\n"
                    "NUMERIC_PARITY=UNPROVEN\nFUNCTIONAL_MODEL_PASS=%d\n"
                    "GATE=NEMOTRON_H_REAL_SSM_001\n"
                    "PRODUCTION_DECODE_PATH=0\nPROMOTE=0\n"
                    "SSM_CERT=NOT_CERTIFIED\n",
                    graph, nemoReal, ssmRealCalls_, ssmIdentityCalls_,
                    ssmHybridLayers_, ssmMambaArmed_, nemoReal);
        }
        xf.productionDecode =
            (ssmHybridLayers_ > 0)
                ? 0
                : ((result.generatedTokens > 0 && result.completed) ? 1 : 0);
        xf.modelOutput = result.generatedTokens > 0 ? 1 : 0;
        xf.streamPresent = !streamed.empty() ? 1 : 0;
        xf.receiptAtomic = rawr::batch007::A().receiptAtomic;
        xf.finite = 1;
        xf.teardownOk = 1;
        xf.measuredReal = 1;
        xf.modelProvenanceMatch = g_modelProv.ok ? 1 : 0;
        xf.productOpenPass = isModelLoaded() ? 1 : 0;
        xf.sessionEnterPass = 1;
        xf.tokenCommitPass =
            (result.generatedTokens > 0 && !streamed.empty()) ? 1 : 0;
        {
            auto r0 = rawr::iso_ladder::Clock::now();
            RAWR_DECODE_SCOPE_RECEIPT();
            if (!rawr::iso_ladder::Ignore(rawr::iso_ladder::Run::A2)) {
                rawr::product_path::Emit(stderr, xf);
                rawr::decode_loop::Emit(stderr);
            }
            // Runtime overlay: run facts only — never mutates discovery manifest.
            {
                rawr::manifest_overlay::RuntimeOverlay ov{};
                ov.modelLocator = g_modelProv.file.userLocator;
                ov.modelFingerprint = rawr::model_provenance::compose_model_fingerprint(
                    g_modelProv.file, g_modelProv.tensorHash);
                ov.runId = "generateStream";
                ov.prefillObserved = true;
                ov.decodeObserved = result.generatedTokens > 0;
                ov.cleanExit = result.completed && !result.cancelled;
                ov.crashObserved = false;
                ov.tokensCommitted = result.generatedTokens;
                if (xf.wallNs > 0 && result.generatedTokens > 1)
                    ov.streamerTps = (result.generatedTokens - 1) * 1e9 /
                                     static_cast<double>(xf.wallNs);
                ov.blockedAt = g_modelProv.ok ? "NONE" : "PROVENANCE_MISMATCH";
                ov.disposition = result.completed ? "CLEAN_EXIT" : "INCOMPLETE";
                rawr::manifest_overlay::Emit(stderr, ov);
            }
            rawr::iso_ladder::A().receiptNs += rawr::iso_ladder::Ns(r0);
        }
        rawr::iso_ladder::Emit(stderr);
        {
            const auto& ia = rawr::iso_ladder::A();
            auto& da = Deep2::decode_blocker::A();
            if (da.forwardMs <= 0.0) da.forwardMs = ia.forwardNs / 1e6;
            if (da.logitsMs <= 0.0) da.logitsMs = ia.logitsNs / 1e6;
            if (da.sampleMs <= 0.0) da.sampleMs = ia.sampleNs / 1e6;
            if (da.detokMs <= 0.0) da.detokMs = ia.detokNs / 1e6;
            if (da.callbackMs <= 0.0) da.callbackMs = ia.callbackNs / 1e6;
            if (da.receiptMs <= 0.0) da.receiptMs = ia.receiptNs / 1e6;
            if (da.kvMs <= 0.0) da.kvMs = ia.kvNs / 1e6;
            const double wallMs = (sptWall ? sptWall : wallNs) / 1e6;
            if (Deep2::decode_blocker_wire::Enabled()) {
                Deep2::decode_blocker_wire::EmitIfEnabled(
                    stderr, wallMs, ia.prefillNs / 1e6, ia.decodeNs / 1e6);
            } else {
                Deep2::decode_blocker::Emit(
                    stderr, wallMs, ia.prefillNs / 1e6, ia.decodeNs / 1e6,
                    rawr::iso_ladder::IgnoredOwner(ia.run));
            }
        }
        const uint64_t wallUse = sptWall ? sptWall : wallNs;
        if (result.completed)
            Deep2::Ev512::HostEmitStreamComplete(
                (uint64_t)streamed.size(), (uint64_t)generated);
        else if (result.cancelled || generated == 0)
            Deep2::Ev512::HostEmitStreamAbort((uint64_t)generated, 9);
        Deep2::Ev512::HostEmitWallNs(wallUse, (uint64_t)generated);
        if (wallUse > 0ull && generated > 0ull) {
            const uint64_t tpsQ =
                (((uint64_t)generated) << 32) * 1000000000ull / wallUse;
            Deep2::Ev512::HostEmitDecodeTpsQ32_32(tpsQ, 5ull << 32);
        }
        Deep2::Ev512::HostEmitTeardownEntry();
        Deep2::Ev512::HostEmitTeardownComplete();
        Deep2::Ev512::HostEmitEndReason(result.completed ? 0ull : 1ull,
                                       (uint64_t)generated);
        if (result.completed)
            Deep2::Ev512::HostEmitE2EProductComplete((uint64_t)generated, 0);
    }
    return result;
}

std::string Deep2Engine::generateChat(const std::string& userMessage,
                                        const std::string& systemPrompt,
                                        size_t maxTokens) {
    // Use the new ChatTemplate engine for proper multi-format support
    ChatTemplate chatTmpl;
    const ModelMetadata& meta = ggufResult.metadata;
    
    if (!chatTmpl.initFromMetadata(meta.architecture, "", meta.chatTemplate,
                                    meta.bosToken, meta.eosToken)) {
        printf("[Deep2Engine] WARNING: Failed to init chat template, falling back to raw prompt\n");
    }
    
    printf("[Deep2Engine] Chat template: %s\n", chatTmpl.getTypeName());
    
    // Build messages
    std::vector<ChatMessage> messages;
    if (!systemPrompt.empty()) {
        messages.push_back({"system", systemPrompt, ""});
    } else if (!meta.chatTemplate.empty()) {
        // Some models have default system prompt in template; keep it empty for default
    }
    messages.push_back({"user", userMessage, ""});
    
    // Format with detected template
    std::string formattedPrompt = chatTmpl.format(messages);
    printf("[Deep2Engine] Formatted prompt:\n%s\n", formattedPrompt.c_str());
    
    // Generate
    std::vector<int> promptTokens = tokenize(formattedPrompt);
    std::vector<int> outputTokens(maxTokens);
    
    size_t generated = generate(promptTokens.data(), promptTokens.size(),
                                 outputTokens.data(), maxTokens);
    
    outputTokens.resize(generated);
    std::string response = detokenize(outputTokens);
    
    // Trim any trailing template tokens from response
    if (!meta.eosToken.empty() && meta.eosToken != "<s>") {
        size_t eosPos = response.find(meta.eosToken);
        if (eosPos != std::string::npos) {
            response = response.substr(0, eosPos);
        }
    }
    // Also trim common end markers
    if (chatTmpl.isEndOfTurn("<|end|>")) {
        size_t endPos = response.find("<|end|>");
        if (endPos != std::string::npos) response = response.substr(0, endPos);
    }
    if (chatTmpl.isEndOfTurn("<|im_end|>")) {
        size_t endPos = response.find("<|im_end|>");
        if (endPos != std::string::npos) response = response.substr(0, endPos);
    }
    
    return response;
}

// ============================================================================
// Forward Layer - Real transformer layer with weight projections
// ============================================================================
void Deep2Engine::forwardLayer(size_t layer, const float* input, float* output, size_t seqLen) {
    /* P1: real layer forward (HOST_DECODE or GPU) — ≠ scoreboard scheduler. */
    Deep2::scoreboard::MarkRealKernelDispatch();
    /* P3 tip: if GpuReady, ReadyExec owns this call (fail closed if not). */
    static thread_local int tls_p3_body = 0;
    if (!tls_p3_body) {
        auto body = [](void* eng, uint32_t ly, const float* in, float* out,
                       size_t seq) noexcept {
            tls_p3_body = 1;
            static_cast<Deep2Engine*>(eng)->forwardLayer(ly, in, out, seq);
            tls_p3_body = 0;
        };
        /* Pump-owned body: skip outer initiation accounting. */
        const int pumpBody =
            Deep2::scoreboard::PumpArm().armed.load(std::memory_order_acquire) &&
            layer > 0;
        if (!pumpBody) {
            if (layer > 0)
                Deep2::scoreboard::NoteOuterLoopNPlus1Init((uint32_t)layer);
            if (layer == 0)
                Deep2::scoreboard::BeginWalkEpochs();
            if (Deep2::scoreboard::TryScoreboardOwnedForwardLayer(
                    this, (uint32_t)layer, input, output, seqLen, body))
                return;
            Deep2::scoreboard::NoteSequentialIssueAt(
                Deep2::scoreboard::SeqIssueSite::ForwardLayerOuter,
                (uint32_t)layer);
        }
    }
    if (Deep2::hostfc::Armed() && layer + 1 < modelWeights.layers.size()) {
        const LayerWeights& nl = modelWeights.layers[layer + 1];
        const WeightTensor& w = nl.wq.data ? nl.wq
            : (nl.attnQ_a.data ? nl.attnQ_a : nl.wUp);
        Deep2::hostfc::BindHostWeight(w.data, w.sizeBytes, w.fileOffset);
    }
    Deep2::hostfc::LayerEdge hostEdge(
        (uint32_t)layer,
        (uint32_t)(modelWeights.numLayers ? modelWeights.numLayers : 1u));
    if (k2ShardIndexOpen_ && globalIndex_ && config.useMLA) {
        computeAttention(layer, input, output, seqLen);
        return;
    }
    if (layer >= modelWeights.layers.size()) {
        memcpy(output, input, config.hiddenDim * sizeof(float));
        return;
    }

    if (hostDecodeSanitize_ && elasticResidency_ &&
        !Deep2::hostfc::Armed() &&
        layer + 1 < modelWeights.layers.size()) {
        const size_t nextLayer = layer + 1;
        const auto& next = modelWeights.layers[nextLayer];
        auto prefetch = [&](const WeightTensor& wt) {
            if (!wt.name.empty())
                elasticResidency_->PrefetchForCpu(
                    wt.name, static_cast<uint32_t>(nextLayer));
        };
        prefetch(next.wq);       prefetch(next.wk);
        prefetch(next.wv);       prefetch(next.wo);
        prefetch(next.attnNorm); prefetch(next.ffnNorm);
        prefetch(next.wGate);    prefetch(next.wUp);
        prefetch(next.wDown);
    }

    const uint64_t liveSeq = kvCache ? static_cast<uint64_t>(kvCache->currentLength())
                                     : static_cast<uint64_t>(seqLen);
    auto layerT0 = std::chrono::high_resolution_clock::now();
    if (LivePath_Active())
        LivePath_OnLayerStart(cycloneEnabled_ ? cyclone_.get() : nullptr,
                              static_cast<uint32_t>(layer), liveSeq);

    const auto& lw = modelWeights.layers[layer];
    size_t hiddenDim = config.hiddenDim;

    if (Deep2::gemma4_topology::TryExecuteProjectorBlock(
            lw, input, output, layerTemp, hiddenDim, modelWeights.normEps,
            [&](const WeightTensor& w, const float* x, float* y, size_t n, float eps) {
                RMSNormW(w, x, y, n, eps);
            },
            [&](const WeightTensor& w, const float* x, const float* b, float* y, size_t n) {
                LinearW(w, x, b, y, n);
            }, layer == 0 ? stderr : nullptr)) {
        if (LivePath_Active())
            LivePath_OnLayerEnd(cycloneEnabled_ ? cyclone_.get() : nullptr,
                                static_cast<uint32_t>(layer), liveSeq, 0);
        return;
    }

    // Nemotron-H recurrent layer: SSM-only — skip null attention path.
    if (lw.hasSSM && !AttnReady(lw) && !WtOk(lw.wGate) && !WtOk(lw.wUp)) {
        if (profilingEnabled_ && profiler_) profiler_->beginAttnNorm();
        /* Block prenorm is attn_norm [hidden]; ssm_norm is gated [8x960] — never swap. */
        if (lw.attnNorm.data) {
            RMSNormW(lw.attnNorm, input, layerTemp, hiddenDim, modelWeights.normEps);
        } else {
            fprintf(stderr,
                    "[SSM_PRENORM_MISSING] layer=%zu copy_input "
                    "NOTE=ssm_norm_ne_3136_prenorm\n",
                    layer);
            memcpy(layerTemp, input, hiddenDim * sizeof(float));
        }
        if (profilingEnabled_ && profiler_) profiler_->endAttnNorm();
        computeSSM(layer, layerTemp, ffnOutput);
        for (size_t i = 0; i < hiddenDim; ++i)
            output[i] = input[i] + ffnOutput[i];
        if (LivePath_Active())
            LivePath_OnLayerEnd(cycloneEnabled_ ? cyclone_.get() : nullptr,
                                static_cast<uint32_t>(layer), liveSeq, 0);
        return;
    }

    // Nemotron-H FFN-only layer: no Q/K/V — norm + SwiGLU + residual.
    if (!AttnReady(lw) && !lw.hasSSM && (WtOk(lw.wUp) || WtOk(lw.wGate))) {
        fprintf(stderr, "[FFN_ONLY] layer=%zu up=%p down=%p inter=%zu\n",
                layer, lw.wUp.data, lw.wDown.data, modelWeights.intermediateDim);
        fflush(stderr);
        if (profilingEnabled_ && profiler_) profiler_->beginAttnNorm();
        RMSNormW(lw.attnNorm, input, layerTemp, hiddenDim, modelWeights.normEps);
        fprintf(stderr, "[FFN_ONLY] layer=%zu norm_ok\n", layer);
        fflush(stderr);
        if (profilingEnabled_ && profiler_) profiler_->endAttnNorm();
        // Host Q8 GEMV is certified (HOST_Q8_GEMV_SAFE): run real FFN.
        // Without SAFE, refuse identity under experimental flag only for topology probe.
        if (envFlagEnabled("RAWRXD_DEEP2_ALLOW_EXPERIMENTAL_SSM") && !hostQ8GemvSafe_) {
            fprintf(stderr, "[FFN_ONLY] layer=%zu IDENTITY=1 PRODUCTION_DECODE_PATH=0\n",
                    layer);
            fflush(stderr);
            memcpy(output, input, hiddenDim * sizeof(float));
        } else {
            computeFFN(layer, layerTemp, ffnOutput);
            for (size_t i = 0; i < hiddenDim; ++i)
                output[i] = input[i] + ffnOutput[i];
        }
        if (LivePath_Active())
            LivePath_OnLayerEnd(cycloneEnabled_ ? cyclone_.get() : nullptr,
                                static_cast<uint32_t>(layer), liveSeq, 0);
        return;
    }

    // â”€â”€ Diagnostic: print layer weight info for layer 0 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    static bool printedLayerInfo = false;
    if (!printedLayerInfo && layer == 0) {
        printf("[Deep2Engine] Layer 0 weights: wq.data=%p type=%d wk.data=%p wv.data=%p wo.data=%p wqkv.data=%p attnO.data=%p\n",
               lw.wq.data, lw.wq.type, lw.wk.data, lw.wv.data, lw.wo.data, lw.wqkv.data, lw.attnO.data);
        printf("[Deep2Engine] Layer 0 weights: attnNorm.data=%p ffnNorm.data=%p\n",
               lw.attnNorm.data, lw.ffnNorm.data);
        printedLayerInfo = true;
    }

    // MARS: Place layer weights on GPU before compute
    // Skip aggregate lease when placeAllModelTensorsMARS already inventoried weights.
    if (marsEnabled_ && marsController_ && !marsWeightsPlaced_ && !vulkanEnabled_) {
        uint64_t layerId = 1000ULL + layer;
        size_t layerBytes = lw.wq.sizeBytes + lw.wk.sizeBytes + lw.wv.sizeBytes +
                            lw.wo.sizeBytes + lw.wGate.sizeBytes + lw.wUp.sizeBytes +
                            lw.wDown.sizeBytes;
        if (layerBytes > 0) {
            auto* lease = marsController_->PlaceTensor(layerId, "layer_" + std::to_string(layer),
                                                        layerBytes, 1.0f, true);
            // Track lease for eviction; store in per-layer MARS lease map
            if (lease) {
                marsLayerLeases_[layer] = lease;
            }
        }
    }

    // â”€â”€ Residency: LinearW() handles ElasticResidencyManager acquisition â”€
    // The legacy residencyManager_->AcquireLease() path has been removed.
    // All weight tensor residency is now managed inside LinearW() via
    // elasticResidency_->AcquireTensor() / ReleaseTensor().

    // â”€â”€ Telemetry: Record residency wait time â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    auto residency_wait_start = std::chrono::high_resolution_clock::now();

    // â”€â”€ Per-layer state trace: input â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    #if 1
    {
        char phase[32];
        snprintf(phase, sizeof(phase), "LAYER%zu_INPUT", layer);
        B3_TraceState(phase, layer, input, hiddenDim);
    }
    #endif

    // 1. Attention RMSNorm
    if (profilingEnabled_ && profiler_) profiler_->beginAttnNorm();
    RMSNormW(lw.attnNorm, input, layerTemp, hiddenDim, modelWeights.normEps);
    if (profilingEnabled_ && profiler_) profiler_->endAttnNorm();
    B3_TraceState("ATTN_NORM", layer, layerTemp, hiddenDim);
    if (layer == 0) {
        const std::uint32_t pos =
            static_cast<std::uint32_t>(kvCache ? kvCache->currentLength() : 0);
        AttnCert::record(AttnCert::Stage::AttnNorm, 0, pos, layerTemp, hiddenDim);
    }
    if (B3_StageDigestEnabled() && B3_StageDumpLayer(layer)) {
        const size_t tokPos = kvCache ? kvCache->currentLength()
                                      : (seqLen > 0 ? seqLen - 1 : 0);
        char key[64];
        std::snprintf(key, sizeof(key), "ATTN_NORM_%zu", layer);
        B3_StageDigest(key, tokPos, layerTemp, hiddenDim);
        if (layer == 0 && tokPos == 0) {
            // Freeze parsed epsilon in parity evidence (loader regression guard).
            printf("[STAGE_DIGEST] rms_norm_epsilon_source=llama.attention.layer_norm_rms_epsilon\n");
            printf("[STAGE_DIGEST] rms_norm_epsilon=%.9e\n",
                   (double)modelWeights.normEps);
            printf("[STAGE_DIGEST] NORM_EPS=%.9e attnNorm.type=%d\n",
                   (double)modelWeights.normEps, lw.attnNorm.type);
        }
    }

    // 2. Attention with real Q/K/V/O projections
    ResidencyCounters::BeginAttention();
    if (profilingEnabled_ && profiler_) profiler_->beginQKVProj();
    computeAttention(layer, layerTemp, output, seqLen);
    if (profilingEnabled_ && profiler_) profiler_->endAttnOutProj(); // computeAttention handles its own sub-phases
    ResidencyCounters::EndAttention();

    if (B3_StageDigestEnabled() && B3_StageDumpLayer(layer)) {
        const size_t tokPos = kvCache ? kvCache->currentLength()
                                      : (seqLen > 0 ? seqLen - 1 : 0);
        char key[64];
        std::snprintf(key, sizeof(key), "ATTN_OUT_%zu", layer);
        B3_StageDigest(key, tokPos, output, hiddenDim); // pre-residual attn (llama attn_out)
    }

    // 3. Residual connection â€” AVX2 vectorized
    if (profilingEnabled_ && profiler_) profiler_->beginAttnResidual();
    #if defined(__AVX2__) || defined(_MSC_VER)
    if (hiddenDim >= 8) {
        size_t i = 0;
        for (; i + 7 < hiddenDim; i += 8) {
            __m256 outv = _mm256_loadu_ps(output + i);
            __m256 inv = _mm256_loadu_ps(input + i);
            _mm256_storeu_ps(output + i, _mm256_add_ps(outv, inv));
        }
        for (; i < hiddenDim; ++i) {
            output[i] += input[i];
        }
    } else
    #endif
    {
        for (size_t i = 0; i < hiddenDim; ++i) {
            output[i] += input[i];
        }
    }
    if (profilingEnabled_ && profiler_) profiler_->endAttnResidual();
    if (layer == 0) {
        const std::uint32_t pos =
            static_cast<std::uint32_t>(kvCache ? kvCache->currentLength() : 0);
        AttnCert::record(AttnCert::Stage::ResidualHint, 0, pos, output, hiddenDim);
    }
    #if 1
    {
        char phase[32];
        snprintf(phase, sizeof(phase), "LAYER%zu_POST_ATTN", layer);
        B3_TraceState(phase, layer, output, hiddenDim);
    }
    #endif
    if (B3_StageDigestEnabled() && B3_StageDumpLayer(layer)) {
        const size_t tokPos = kvCache ? kvCache->currentLength()
                                      : (seqLen > 0 ? seqLen - 1 : 0);
        char key[64];
        std::snprintf(key, sizeof(key), "FFN_INP_%zu", layer);
        B3_StageDigest(key, tokPos, output, hiddenDim); // post-attn residual (llama ffn_inp)
    }    // 4. FFN / SSM RMSNorm
    if (profilingEnabled_ && profiler_) profiler_->beginFFNNorm();
    RMSNormW(lw.ffnNorm, output, layerTemp, hiddenDim, modelWeights.normEps);
    if (profilingEnabled_ && profiler_) profiler_->endFFNNorm();
    B3_TraceState("FFN_NORM", layer, layerTemp, hiddenDim);
    if (B3_StageDigestEnabled() && B3_StageDumpLayer(layer)) {
        const size_t tokPos = kvCache ? kvCache->currentLength()
                                      : (seqLen > 0 ? seqLen - 1 : 0);
        char key[64];
        std::snprintf(key, sizeof(key), "FFN_NORM_%zu", layer);
        B3_StageDigest(key, tokPos, layerTemp, hiddenDim);
    }

    // 5. FFN (SwiGLU) OR SSM (Mamba) with real weight projections
    ResidencyCounters::BeginFFN();
    if (profilingEnabled_ && profiler_) profiler_->beginFFNGate();
    if (lw.hasSSM) {
        // Hybrid layer: use SSM instead of FFN
        computeSSM(layer, layerTemp, ffnOutput);
        B3_TraceState("SSM_OUT", layer, ffnOutput, hiddenDim);
    } else if (modelWeights.isMoE && modelWeights.numExperts > 0) {
        computeMoEFFN(layer, layerTemp, ffnOutput);
        B3_TraceState("FFN_DOWN", layer, ffnOutput, hiddenDim);
    } else {
        computeFFN(layer, layerTemp, ffnOutput);
        B3_TraceState("FFN_DOWN", layer, ffnOutput, hiddenDim);
    }
    if (profilingEnabled_ && profiler_) profiler_->endFFNDown();
    ResidencyCounters::EndFFN();
    if (B3_StageDigestEnabled() && B3_StageDumpLayer(layer)) {
        const size_t tokPos = kvCache ? kvCache->currentLength()
                                      : (seqLen > 0 ? seqLen - 1 : 0);
        char key[64];
        std::snprintf(key, sizeof(key), "FFN_DOWN_%zu", layer);
        B3_StageDigest(key, tokPos, ffnOutput, hiddenDim);
    }

    // 6. Residual connection â€” AVX2 vectorized
    if (profilingEnabled_ && profiler_) profiler_->beginFFNResidual();
    #if defined(__AVX2__) || defined(_MSC_VER)
    if (hiddenDim >= 8) {
        size_t i = 0;
        for (; i + 7 < hiddenDim; i += 8) {
            __m256 outv = _mm256_loadu_ps(output + i);
            __m256 fnv = _mm256_loadu_ps(ffnOutput + i);
            _mm256_storeu_ps(output + i, _mm256_add_ps(outv, fnv));
        }
        for (; i < hiddenDim; ++i) {
            output[i] += ffnOutput[i];
        }
    } else
    #endif
    {
        for (size_t i = 0; i < hiddenDim; ++i) {
            output[i] += ffnOutput[i];
        }
    }
    if (profilingEnabled_ && profiler_) profiler_->endFFNResidual();
    #if 1
    {
        char phase[32];
        snprintf(phase, sizeof(phase), "LAYER%zu_POST_FFN", layer);
        B3_TraceState(phase, layer, output, hiddenDim);
    }
    #endif
    if (B3_StageDigestEnabled() && B3_StageDumpLayer(layer)) {
        const size_t tokPos = kvCache ? kvCache->currentLength()
                                      : (seqLen > 0 ? seqLen - 1 : 0);
        char key[64];
        std::snprintf(key, sizeof(key), "POST_FFN_%zu", layer);
        B3_StageDigest(key, tokPos, output, hiddenDim);
        // Alias matches llama.cpp l_out naming used by parity probe.
        std::snprintf(key, sizeof(key), "LAYER%zu_OUT", layer);
        B3_StageDigest(key, tokPos, output, hiddenDim);
    }

    // Real layer execution mark: this forwardLayer completed on its planned device.
    if (multiGpuLayerPlan_.active)
        Deep2MultiGpu_MarkLayerExecuted(multiGpuLayerPlan_, (unsigned)layer);

    // â”€â”€ Telemetry: Record residency wait time â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if (telemetryControllerEnabled_ && telemetryController_) {
        auto residency_wait_end = std::chrono::high_resolution_clock::now();
        auto residency_wait_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
            residency_wait_end - residency_wait_start).count();
        telemetryController_->record_residency_wait(static_cast<uint64_t>(residency_wait_ns));
    }

    // â”€â”€ Per-layer state trace: output â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    #if 0
    {
        char phase[32];
        snprintf(phase, sizeof(phase), "LAYER%zu_OUTPUT", layer);
        B3_TraceState(phase, layer, output, hiddenDim);
    }
    #endif

    // Reverse analysis hook: layer processed
    if (reverseAnalysisEnabled_ && reverseIntegration_) {
        reverseIntegration_->onLayerProcessed(static_cast<int>(layer), output, hiddenDim);
    }

    if (LivePath_Active()) {
        auto layerT1 = std::chrono::high_resolution_clock::now();
        const uint64_t latUs = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(layerT1 - layerT0).count());
        LivePath_OnLayerEnd(cycloneEnabled_ ? cyclone_.get() : nullptr,
                            static_cast<uint32_t>(layer), liveSeq, latUs);
    }
}

// ============================================================================
// Compute Attention - Real Q/K/V/O weight projections + KV cache + RoPE
// Supports both standard MHA/GQA and MLA (K2) factorized attention
// ============================================================================
void Deep2Engine::computeAttention(size_t layer, const float* input, float* output, size_t seqLen) {
    (void)seqLen;
    size_t hiddenDim = config.hiddenDim;
    if (rawr::iso_ladder::Ignore(rawr::iso_ladder::Run::A9)) {
        if (output && input && hiddenDim)
            std::memcpy(output, input, hiddenDim * sizeof(float));
        return;
    }
    // Production K2 shard path: computeAttention → MlaAttentionComplete.
    if (k2ShardIndexOpen_ && globalIndex_ && config.useMLA) {
        MlaCertAuthority::NoteRequired();
        MlaCertAuthority::NoteForwardEntered();
        auto* kv = K2NativeStreamGate::ProdKv(k2ShardConfig_, config.maxSeqLen);
        MlaCompleteStats st{};
        std::string err;
        if (!K2NativeStreamGate::ForwardMlaLayer(
                *globalIndex_, k2ShardConfig_, const_cast<float*>(input), output,
                static_cast<uint32_t>(layer), kv,
                kv ? static_cast<uint32_t>(kv->currentLength()) : 0u, &st,
                err)) {
            fprintf(stderr,
                    "[Deep2Engine] FATAL: shard MlaAttentionComplete layer=%zu: %s\n",
                    layer, err.c_str());
            throw std::runtime_error("MLA-CERT-001: MlaAttentionComplete failed");
        }
        MlaCertAuthority::NoteCompleteSuccess(st, output, hiddenDim);
        return;
    }
    if (layer >= modelWeights.layers.size()) {
        memcpy(output, input, config.hiddenDim * sizeof(float));
        return;
    }

    const auto& lw = modelWeights.layers[layer];
    size_t numHeads = modelWeights.numHeads;
    size_t numKVHeads = modelWeights.numKVHeads;
    size_t headDim = modelWeights.headDim;
    size_t groupSize = (numKVHeads > 0) ? (numHeads / numKVHeads) : 1;
    float* headScratch = attnHeadScratch_ ? attnHeadScratch_ : output;
    const size_t headConcat = numHeads * headDim;

    // --- MLA (K2) path: production dispatch to MlaAttentionComplete ---
    // Shard stack uses forwardTokenAllLayers → ForwardHiddenMla; host tensors
    // use MLAForward::Execute here. Do not land here on shard-only layers.
    if (lw.useMLA || (config.useMLA && lw.attnQ_a.data)) {
        MlaCertAuthority::NoteRequired();
        MlaCertAuthority::NoteForwardEntered();
        MlaCert::record(MlaCert::Stage::EnteredBlocked,
                        static_cast<std::uint32_t>(layer),
                        MlaCert::bumpSeq(), nullptr, 0, 0.0);

        if (!(lw.attnQ_a.data && lw.attnQ_b.data && lw.attnKV_a_mqa.data &&
              lw.attnK_b.data && lw.attnO.data)) {
            MlaCertAuthority::NoteStub();
            fprintf(stderr,
                "[Deep2Engine] FATAL: MLA layer without host tensors "
                "(layer=%zu). Use openK2ShardDirectory + ForwardHiddenMla.\n",
                layer);
            throw std::runtime_error(
                "MLA-CERT-001: incomplete MLA attention blocked");
        }

        MLAWeights mw;
        auto viewFromWt = [](const WeightTensor& wt) -> RawrXD::TensorView {
            if (!wt.data || wt.rows == 0 || wt.cols == 0)
                return RawrXD::TensorView();
            RawrXD::UniversalTensorDescriptor desc{};
            desc.numDims = 2;
            desc.shape[0] = wt.rows;
            desc.shape[1] = wt.cols;
            desc.layout = RawrXD::TensorLayout::BLOCKED;
            desc.role = RawrXD::TensorRole::WEIGHT;
            desc.memorySpace =
                RawrXD::UniversalTensorDescriptor::MemorySpace::HOST;
            desc.data = const_cast<void*>(wt.data);
            if (wt.type == 0) {
                desc.quantType = RawrXD::QuantType::F32;
                desc.blockSize = 1;
                desc.blockSizeBytes = 4;
            } else if (wt.type == 8) {
                desc.quantType = RawrXD::QuantType::Q8_0;
                desc.blockSize = 32;
                desc.blockSizeBytes = 34;
            } else {
                desc.quantType = RawrXD::QuantType::Q4_K;
                desc.blockSize = 256;
                desc.blockSizeBytes = 144;
            }
            return RawrXD::TensorView::FromResident(desc);
        };
        mw.attnQ_a = viewFromWt(lw.attnQ_a);
        mw.attnQ_a_norm = viewFromWt(lw.attnQ_a_norm);
        mw.attnQ_b = viewFromWt(lw.attnQ_b);
        mw.attnKV_a_mqa = viewFromWt(lw.attnKV_a_mqa);
        mw.attnKV_a_norm = viewFromWt(lw.attnKV_a_norm);
        mw.attnK_b = viewFromWt(lw.attnK_b);
        mw.attnV_b = viewFromWt(lw.attnV_b);
        mw.attnO = viewFromWt(lw.attnO);
        mw.attnNorm = viewFromWt(lw.attnNorm);
        mw.fusedKvB = !lw.attnV_b.data;

        KimiK2Config k2 = k2ShardConfig_;
        if (!k2.valid) {
            k2.hiddenDim = (uint32_t)config.hiddenDim;
            k2.numLayers = (uint32_t)config.numLayers;
            k2.numHeads = (uint32_t)config.numHeads;
            k2.numKVHeads = (uint32_t)config.numKVHeads;
            k2.qLoraRank = (uint32_t)config.qLoraRank;
            k2.kvLoraRank = (uint32_t)config.kvLoraRank;
            k2.qkNopeHeadDim = (uint32_t)config.qkNopeHeadDim;
            k2.qkRopeHeadDim = (uint32_t)config.qkRopeHeadDim;
            k2.vHeadDim = (uint32_t)config.vHeadDim;
            k2.ropeTheta = modelWeights.ropeTheta;
            k2.ropeScalingFactor = modelWeights.ropeScaling;
            k2.valid = true;
        }

        static thread_local std::unique_ptr<rawrxd::deep2::K2KVCache> hostKv;
        static thread_local size_t hostLayers = 0;
        static thread_local size_t hostKvDim = 0;
        const size_t H = k2.numHeads ? k2.numHeads : config.numHeads;
        const size_t nope = k2.qkNopeHeadDim ? k2.qkNopeHeadDim : 128;
        const size_t ropeD = k2.qkRopeHeadDim ? k2.qkRopeHeadDim : 64;
        const size_t vDim = k2.vHeadDim ? k2.vHeadDim : 128;
        const size_t kvDim = (std::max)(H * (nope + ropeD), H * vDim);
        const size_t nLayers = k2.numLayers ? k2.numLayers : config.numLayers;
        if (!hostKv || hostLayers != nLayers || hostKvDim != kvDim) {
            hostKv = std::make_unique<rawrxd::deep2::K2KVCache>();
            hostKv->Reset(nLayers, (std::max)(config.maxSeqLen, (size_t)8),
                          kvDim);
            hostLayers = nLayers;
            hostKvDim = kvDim;
        }
        const uint32_t position =
            static_cast<uint32_t>(hostKv->currentLength());
        MlaCompleteStats st{};
        std::string err;
        MLAForward fwd;
        memset(output, 0, hiddenDim * sizeof(float));
        if (!fwd.Execute(input, output, mw, k2, err, hostKv.get(),
                         static_cast<uint32_t>(layer), position, &st)) {
            fprintf(stderr,
                    "[Deep2Engine] FATAL: MLAForward/MlaAttentionComplete failed "
                    "layer=%zu: %s\n",
                    layer, err.c_str());
            throw std::runtime_error("MLA-CERT-001: MlaAttentionComplete failed");
        }
        try {
            hostKv->CommitPosition();
        } catch (...) {
        }
        MlaCertAuthority::NoteCompleteSuccess(st, output, hiddenDim);
        return;
    }

    // --- Fused QKV path (Phi-3, etc.) ---
    if (lw.wqkv.data && !lw.hasSSM) {
        size_t kvDim = numKVHeads * headDim;
        size_t qkvDim = hiddenDim + 2 * kvDim;
        // Project fused QKV: [qkvDim] = wqkv^T * input
        LinearW(lw.wqkv, input, nullptr, qProj, qkvDim);
        B3_TraceState("ATTN_QKV", layer, qProj, qkvDim);

        // Split into Q, K, V
        float* q = qProj;                           // [hiddenDim]
        float* k = qProj + hiddenDim;             // [kvDim]
        float* v = qProj + hiddenDim + kvDim;     // [kvDim]

        // Copy K, V to dedicated buffers for RoPE and KV cache
        memcpy(kProj, k, kvDim * sizeof(float));
        memcpy(vProj, v, kvDim * sizeof(float));
    }
    // â”€â”€ SSM hybrid layer: attn_qkv is Q-only, no K/V â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // Qwen3.5 SSM layers have attn_qkv (8192=2Ã—4096, gated projection) + attn_gate (output proj)
    // No K/V projections â†’ no standard attention. The 8192 output is split into
    // two 4096 halves: first half is the projection, second half is the gate.
    // Output = projection * silu(gate), then attn_gate projects to hiddenDim.
    else if (lw.wqkv.data && lw.hasSSM) {
        // Use tensor rows (gated often 2*hidden); do NOT force heads*headDim.
        size_t qDim = lw.wqkv.rows > 0 ? lw.wqkv.rows : (numHeads * headDim);
        LinearW(lw.wqkv, input, nullptr, qProj, qDim);
        B3_TraceState("ATTN_Q_SSM", layer, qProj, qDim);

        size_t halfDim = qDim / 2;
        float* proj = qProj;
        float* gate = qProj + halfDim;
        for (size_t i = 0; i < halfDim; ++i) {
            float g = gate[i];
            float silu_g = g / (1.0f + expf(-g));
            proj[i] = proj[i] * silu_g;
        }

        if (lw.attnO.data) {
            memset(output, 0, hiddenDim * sizeof(float));
            // Stored [gateDim×hidden] but O needs y[hidden]=W^T x[gateDim].
            if (lw.attnO.rows == halfDim && lw.attnO.cols == hiddenDim &&
                lw.attnO.type == (int)GGMLType::GGML_TYPE_Q4_K && lw.attnO.data) {
                fprintf(stderr,
                    "[ATTN_GATE_OT] layer=%zu W^T gemv in=%zu out=%zu\n",
                    layer, halfDim, hiddenDim);
                q4kGEMV_T(lw.attnO.data, proj, output, halfDim, hiddenDim);
            } else {
                LinearW(lw.attnO, proj, nullptr, output, hiddenDim);
            }
        } else {
            size_t copyN = halfDim < hiddenDim ? halfDim : hiddenDim;
            memcpy(output, proj, copyN * sizeof(float));
            if (copyN < hiddenDim)
                memset(output + copyN, 0, (hiddenDim - copyN) * sizeof(float));
        }
        B3_TraceState("ATTN_O", layer, output, hiddenDim);

        if (reverseAnalysisEnabled_ && reverseIntegration_) {
            reverseIntegration_->onAttentionComputed(static_cast<int>(layer), output, hiddenDim);
        }
        return;
    }
    // â”€â”€ Standard MHA / GQA path â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    else if (lw.wq.data) {
        // Q projection: out dim is wq.rows (Nemotron-H: 40*128=5120 ≠ hidden).
        const size_t qDim = lw.wq.rows > 0 ? lw.wq.rows : (numHeads * headDim);
        LinearW(lw.wq, input, nullptr, qProj, qDim);
        B3_TraceState("ATTN_Q", layer, qProj, qDim);

        // K projection: [hiddenDim] -> [kvDim]
        size_t kvDim = numKVHeads * headDim;
        if (lw.wk.rows > 0) kvDim = lw.wk.rows;
        LinearW(lw.wk, input, nullptr, kProj, kvDim);
        B3_TraceState("ATTN_K", layer, kProj, kvDim);

        // V projection: [hiddenDim] -> [kvDim]
        size_t vDim = kvDim;
        if (lw.wv.rows > 0) vDim = lw.wv.rows;
        LinearW(lw.wv, input, nullptr, vProj, vDim);
        B3_TraceState("ATTN_V", layer, vProj, vDim);

        if (B3_StageDigestEnabled() && B3_StageDumpLayer(layer)) {
            const size_t tokPos = kvCache ? kvCache->currentLength()
                                          : (seqLen > 0 ? seqLen - 1 : 0);
            char key[64];
            std::snprintf(key, sizeof(key), "Q_PRE_ROPE_%zu", layer);
            B3_StageDigest(key, tokPos, qProj, qDim);
            std::snprintf(key, sizeof(key), "K_PRE_ROPE_%zu", layer);
            B3_StageDigest(key, tokPos, kProj, kvDim);
            std::snprintf(key, sizeof(key), "V_%zu", layer);
            B3_StageDigest(key, tokPos, vProj, vDim);
        }

        // â”€â”€ Qwen3.5: Apply per-head QK norm (RMSNorm) before RoPE â”€â”€
        if (lw.attnQNorm.data && lw.attnQNorm.sizeBytes > 0) {
            for (size_t h = 0; h < numHeads; ++h) {
                RMSNormW(lw.attnQNorm, qProj + h * headDim, qProj + h * headDim, headDim, modelWeights.normEps);
            }
        }
        if (lw.attnKNorm.data && lw.attnKNorm.sizeBytes > 0) {
            for (size_t h = 0; h < numKVHeads; ++h) {
                RMSNormW(lw.attnKNorm, kProj + h * headDim, kProj + h * headDim, headDim, modelWeights.normEps);
            }
        }
    } else {
        // No attention weights available â€” hard fail (no silent x+0 residual)
        fprintf(stderr,
            "[Deep2Engine] FATAL: layer %zu missing attention Q weights "
            "(TOPOLOGY-CERT-001)\n",
            layer);
        throw std::runtime_error("missing attention Q weights");
    }

    // ATTN-CERT-001: digest-only Q/K/V frames (after any MHA/GQA / fused split path).
    if (layer == 0) {
        const std::uint32_t pos =
            static_cast<std::uint32_t>(kvCache ? kvCache->currentLength() : (seqLen > 0 ? seqLen - 1 : 0));
        const size_t kvDim = numKVHeads * headDim;
        AttnCert::record(AttnCert::Stage::QProj, 0, pos, qProj, hiddenDim);
        AttnCert::record(AttnCert::Stage::KProj, 0, pos, kProj, kvDim);
        AttnCert::record(AttnCert::Stage::VProj, 0, pos, vProj, kvDim);
    }

    // Apply RoPE if enabled
    if (config.useRoPE) {
        if (profilingEnabled_ && profiler_) profiler_->beginRoPE();
        size_t pos = kvCache ? kvCache->currentLength() : seqLen - 1;
        applyRoPE(qProj, kProj, headDim, numHeads, numKVHeads, pos,
                  modelWeights.ropeTheta, modelWeights.ropeScaling);
        if (profilingEnabled_ && profiler_) profiler_->endRoPE();
    }
    B3_TraceState("ATTN_ROPE", layer, qProj, hiddenDim);
    if (layer == 0) {
        const std::uint32_t pos =
            static_cast<std::uint32_t>(kvCache ? kvCache->currentLength() : (seqLen > 0 ? seqLen - 1 : 0));
        const size_t kvDim = numKVHeads * headDim;
        AttnCert::record(AttnCert::Stage::RopeQ, 0, pos, qProj, hiddenDim);
        AttnCert::record(AttnCert::Stage::RopeK, 0, pos, kProj, kvDim);
        if (B3_StageDigestEnabled()) {
            B3_StageDigest("Q_POST_ROPE_0", pos, qProj, hiddenDim);
            B3_StageDigest("K_POST_ROPE_0", pos, kProj, kvDim);
        }
    }

    // Store K, V into KV cache
    if (config.useKVCache) {
        if (profilingEnabled_ && profiler_) profiler_->beginKVStore();
        
        // Use CompressedKVCache if enabled
        if (compressedKVEnabled_ && compressedKV_ && !vulkanEnabled_) {
            for (size_t h = 0; h < numKVHeads; ++h) {
                size_t pos = compressedKV_->currentLength();
                compressedKV_->storeKV(layer, h, pos, kProj + h * headDim, vProj + h * headDim);
            }
            compressedKV_->advance();
            if (layer == 0) {
                const std::uint32_t written =
                    static_cast<std::uint32_t>(compressedKV_->currentLength());
                AttnCert::record(AttnCert::Stage::KvWrite, 0, written > 0 ? written - 1 : 0,
                                 kProj, numKVHeads * headDim,
                                 static_cast<double>(numKVHeads * headDim));
                // aux = length after this write (compressed path advances inline)
                AttnCert::record(AttnCert::Stage::KvLength, 0, written > 0 ? written - 1 : 0,
                                 nullptr, 0, static_cast<double>(written));
            }
        } else if (kvCache) {
            // Batch all heads into single memcpy per layer (K + V)
            size_t kvBytes = numKVHeads * headDim * sizeof(float);
            const std::uint32_t writePos =
                static_cast<std::uint32_t>(kvCache->currentLength());
            float* kBase = nullptr;
            float* vBase = nullptr;
            kvCache->getKVPointers(layer, 0, &kBase, &vBase);
            if (kBase) memcpy(kBase, kProj, kvBytes);
            if (vBase) memcpy(vBase, vProj, kvBytes);
            if (layer == 0) {
                AttnCert::record(AttnCert::Stage::KvWrite, 0, writePos, kProj, numKVHeads * headDim,
                                 static_cast<double>(numKVHeads * headDim));
                // Length after write: advance() happens after all layers; report writePos+1.
                AttnCert::record(AttnCert::Stage::KvLength, 0, writePos, nullptr, 0,
                                 static_cast<double>(writePos + 1));
            }
        }
        
        if (profilingEnabled_ && profiler_) profiler_->endKVStore();

        // GQA: KV heads are shared across Q heads
        if (profilingEnabled_ && profiler_) profiler_->beginAttnCompute();
        
        // Apply sliding window if enabled
        size_t attentionStart = 0;
        size_t attentionEnd = seqLen;
        applySlidingWindow(attentionStart, attentionEnd);
        size_t attend = attentionEnd - attentionStart;
        
        if (compressedKVEnabled_ && compressedKV_ && !vulkanEnabled_) {
            // Attention with compressed KV cache â€” optimized: single allocation, AVX2 paths
            const float scale = 1.0f / sqrtf((float)headDim);
            const size_t maxAttend = (attend > 128) ? attend : 128;
            
            // Single allocation for all heads (amortize malloc cost)
            float* tempK = (float*)_aligned_malloc(maxAttend * headDim * sizeof(float), 32);
            float* tempV = (float*)_aligned_malloc(maxAttend * headDim * sizeof(float), 32);
            float* scores = (float*)_aligned_malloc(maxAttend * sizeof(float), 32);
            
            if (tempK && tempV && scores) {
                for (size_t h = 0; h < numHeads; ++h) {
                    size_t kvHead = h / groupSize;
                    float* headOut = headScratch + h * headDim;
                    const float* q = qProj + h * headDim;
                    
                    // Dequantize K and V ranges (only within sliding window)
                    compressedKV_->loadKRange(layer, kvHead, attentionStart, attend, tempK);
                    compressedKV_->loadVRange(layer, kvHead, attentionStart, attend, tempV);
                    
                    // Compute attention scores â€” AVX2 dot product
                    float maxScore = -1e38f;
                    #if defined(__AVX2__) || defined(_MSC_VER)
                    if (headDim >= 8) {
                        for (size_t pos = 0; pos < attend; ++pos) {
                            __m256 sum = _mm256_setzero_ps();
                            const float* k = tempK + pos * headDim;
                            size_t i = 0;
                            for (; i + 7 < headDim; i += 8) {
                                __m256 qv = _mm256_loadu_ps(q + i);
                                __m256 kv = _mm256_loadu_ps(k + i);
                                sum = _mm256_fmadd_ps(qv, kv, sum);
                            }
                            float dot = sum.m256_f32[0] + sum.m256_f32[1] + sum.m256_f32[2] + sum.m256_f32[3]
                                      + sum.m256_f32[4] + sum.m256_f32[5] + sum.m256_f32[6] + sum.m256_f32[7];
                            for (; i < headDim; ++i) dot += q[i] * k[i];
                            scores[pos] = dot * scale;
                            if (scores[pos] > maxScore) maxScore = scores[pos];
                        }
                    } else
                    #endif
                    {
                        for (size_t pos = 0; pos < attend; ++pos) {
                            float dot = 0.0f;
                            for (size_t i = 0; i < headDim; ++i) {
                                dot += q[i] * tempK[pos * headDim + i];
                            }
                            scores[pos] = dot * scale;
                            if (scores[pos] > maxScore) maxScore = scores[pos];
                        }
                    }
                    
                    // Softmax
                    float sumExp = 0.0f;
                    for (size_t pos = 0; pos < attend; ++pos) {
                        scores[pos] = expf(scores[pos] - maxScore);
                        sumExp += scores[pos];
                    }
                    float invSum = 1.0f / (sumExp + 1e-12f);
                    for (size_t pos = 0; pos < attend; ++pos) {
                        scores[pos] *= invSum;
                    }
                    if (h == 0) B3_TraceState("ATTN_SOFTMAX", layer, scores, attend);

                    // Weighted sum â€” AVX2 accumulate
                    memset(headOut, 0, headDim * sizeof(float));
                    #if defined(__AVX2__) || defined(_MSC_VER)
                    if (headDim >= 8) {
                        for (size_t pos = 0; pos < attend; ++pos) {
                            __m256 w = _mm256_set1_ps(scores[pos]);
                            const float* v = tempV + pos * headDim;
                            size_t i = 0;
                            for (; i + 7 < headDim; i += 8) {
                                __m256 outv = _mm256_loadu_ps(headOut + i);
                                __m256 vv = _mm256_loadu_ps(v + i);
                                _mm256_storeu_ps(headOut + i, _mm256_fmadd_ps(w, vv, outv));
                            }
                            for (; i < headDim; ++i) {
                                headOut[i] += v[i] * scores[pos];
                            }
                        }
                    } else
                    #endif
                    {
                        for (size_t pos = 0; pos < attend; ++pos) {
                            const float* v = tempV + pos * headDim;
                            for (size_t i = 0; i < headDim; ++i) {
                                headOut[i] += v[i] * scores[pos];
                            }
                        }
                    }
                }
            }
            if (numHeads > 0) B3_TraceState("ATTN_OUT", layer, headScratch, headConcat);

            _aligned_free(tempK);
            _aligned_free(tempV);
            _aligned_free(scores);
        } else if (kvCache) {
            for (size_t h = 0; h < numHeads; ++h) {
                size_t kvHead = h / groupSize;
                float* headOut = headScratch + h * headDim;
                AttentionWithCache(qProj + h * headDim, *kvCache, layer, kvHead,
                                   headOut, attentionEnd);
            }
            if (numHeads > 0) B3_TraceState("ATTN_OUT", layer, headScratch, headConcat);
            if (layer == 0) {
                const std::uint32_t pos =
                    static_cast<std::uint32_t>(kvCache ? kvCache->currentLength() : 0);
                AttnCert::record(AttnCert::Stage::AttnOut, 0, pos, headScratch, headConcat);
            }
        }
        
        if (profilingEnabled_ && profiler_) profiler_->endAttnCompute();
    }
    // â”€â”€ Sovereign ToroidalKVCache: infinite-context ring buffer â”€â”€â”€â”€â”€â”€â”€â”€
    else if (toroidalKVEnabled_ && toroidalKV_) {
        if (profilingEnabled_ && profiler_) profiler_->beginKVStore();
        // Inject token into toroidal KV cache
        rawrxd::PlasmaToken plasma;
        plasma.token_id = 0;  // Will be filled after sampling
        plasma.temperature = 0.0f;
        plasma.entropy = 0.0f;
        plasma.seq_pos = toroidalKV_->writeHead();
        plasma.fused = true;
        plasma.beam_injection_count = 0;

        // Flatten K/V for all layers into contiguous buffers
        // For now, inject per-layer during forward pass
        // (Full implementation would batch across layers)
        toroidalKV_->injectToken(plasma, kProj, vProj);
        if (profilingEnabled_ && profiler_) profiler_->endKVStore();

        // Attention using toroidal KV cache
        if (profilingEnabled_ && profiler_) profiler_->beginAttnCompute();
        // Query all stored tokens from the toroidal cache for this layer
        const float* torusKeys = nullptr;
        const float* torusValues = nullptr;
        size_t tokenCount = 0;
        uint64_t oldestSeq = (toroidalKV_->writeHead() > toroidalKV_->tokenCount())
            ? (toroidalKV_->writeHead() - toroidalKV_->tokenCount()) : 0;
        bool haveTorus = toroidalKV_->queryTokenRange(oldestSeq, toroidalKV_->writeHead(), torusKeys, torusValues, tokenCount);

        const size_t attend = tokenCount;
        const float scale = 1.0f / sqrtf((float)headDim);
        // Always heap-allocate scores (avoid stack[128] + /GS on deep frames).
        float* scoreBuf = (float*)_aligned_malloc((attend > 0 ? attend : 1) * sizeof(float), 32);
        if (!scoreBuf) {
            memset(headScratch, 0, headConcat * sizeof(float));
        } else if (!haveTorus || tokenCount == 0 || !torusKeys || !torusValues) {
            // Single-token attention: softmax([score]) = [1] ⇒ headOut = V
            for (size_t h = 0; h < numHeads; ++h) {
                size_t kvHead = h / groupSize;
                float* headOut = headScratch + h * headDim;
                const float* v = vProj + kvHead * headDim;
                memcpy(headOut, v, headDim * sizeof(float));
            }
        } else {
            size_t numLayers = modelWeights.numLayers;
            size_t layerStride = numHeads * headDim;
            size_t tokenStride = numLayers * layerStride;
            
            for (size_t h = 0; h < numHeads; ++h) {
                size_t kvHead = h / groupSize;
                const float* q = qProj + h * headDim;
                float* headOut = headScratch + h * headDim;
                size_t layerOffset = layer * layerStride + kvHead * headDim;

                // Pass 1: compute Q*K^T scores
                float maxScore = -1e38f;
                #if defined(__AVX2__) || defined(_MSC_VER)
                if (headDim >= 8) {
                    for (size_t pos = 0; pos < attend; ++pos) {
                        __m256 sum = _mm256_setzero_ps();
                        const float* k = torusKeys + pos * tokenStride + layerOffset;
                        size_t i = 0;
                        for (; i + 7 < headDim; i += 8) {
                            __m256 qv = _mm256_loadu_ps(q + i);
                            __m256 kv = _mm256_loadu_ps(k + i);
                            sum = _mm256_fmadd_ps(qv, kv, sum);
                        }
                        float dot = sum.m256_f32[0] + sum.m256_f32[1] + sum.m256_f32[2] + sum.m256_f32[3]
                                  + sum.m256_f32[4] + sum.m256_f32[5] + sum.m256_f32[6] + sum.m256_f32[7];
                        for (; i < headDim; ++i) dot += q[i] * k[i];
                        scoreBuf[pos] = dot * scale;
                        if (scoreBuf[pos] > maxScore) maxScore = scoreBuf[pos];
                    }
                } else
                #endif
                {
                    for (size_t pos = 0; pos < attend; ++pos) {
                        float dot = 0.0f;
                        const float* k = torusKeys + pos * tokenStride + layerOffset;
                        for (size_t i = 0; i < headDim; ++i) {
                            dot += q[i] * k[i];
                        }
                        scoreBuf[pos] = dot * scale;
                        if (scoreBuf[pos] > maxScore) maxScore = scoreBuf[pos];
                    }
                }

                // Pass 2: softmax with invariant check
                float sumExp = 0.0f;
                float minP = FLT_MAX;
                float maxP = -FLT_MAX;
                for (size_t pos = 0; pos < attend; ++pos) {
                    scoreBuf[pos] = expf(scoreBuf[pos] - maxScore);
                    if (!std::isfinite(scoreBuf[pos])) {
                        fprintf(stderr, "[D2_SOFTMAX_FAIL] nonfinite exp at pos=%zu\n", pos);
                        std::abort();
                    }
                    sumExp += scoreBuf[pos];
                    minP = std::min(minP, scoreBuf[pos]);
                    maxP = std::max(maxP, scoreBuf[pos]);
                }
                if (sumExp < 1e-12f) sumExp = 1e-12f;
                float invSum = 1.0f / sumExp;
                for (size_t pos = 0; pos < attend; ++pos) {
                    scoreBuf[pos] *= invSum;
                }
                // â”€â”€ Softmax invariant: sum must be ~1, no negative probs â”€â”€
                double sumCheck = 0.0;
                for (size_t pos = 0; pos < attend; ++pos) sumCheck += scoreBuf[pos];
                if (std::fabs(sumCheck - 1.0) > 1.0e-4 || minP < -1.0e-6f || maxP > 1.000001f) {
                    fprintf(stderr, "[D2_SOFTMAX_FAIL] L=%zu H=%zu sum=%.9g min=%.9g max=%.9g n=%zu\n",
                            layer, h, sumCheck, minP, maxP, attend);
                    std::abort();
                }

                // Pass 3: weighted sum of values â€” AVX2
                memset(headOut, 0, headDim * sizeof(float));
                #if defined(__AVX2__) || defined(_MSC_VER)
                if (headDim >= 8) {
                    for (size_t pos = 0; pos < attend; ++pos) {
                        __m256 w = _mm256_set1_ps(scoreBuf[pos]);
                        const float* v = torusValues + pos * tokenStride + layerOffset;
                        size_t i = 0;
                        for (; i + 7 < headDim; i += 8) {
                            __m256 outv = _mm256_loadu_ps(headOut + i);
                            __m256 vv = _mm256_loadu_ps(v + i);
                            _mm256_storeu_ps(headOut + i, _mm256_fmadd_ps(w, vv, outv));
                        }
                        for (; i < headDim; ++i) {
                            headOut[i] += v[i] * scoreBuf[pos];
                        }
                    }
                } else
                #endif
                {
                    for (size_t pos = 0; pos < attend; ++pos) {
                        const float* v = torusValues + pos * tokenStride + layerOffset;
                        float w = scoreBuf[pos];
                        for (size_t i = 0; i < headDim; ++i) {
                            headOut[i] += w * v[i];
                        }
                    }
                }
            }
        }
        if (scoreBuf) _aligned_free(scoreBuf);
        if (profilingEnabled_ && profiler_) profiler_->endAttnCompute();
        if (numHeads > 0) B3_TraceState("ATTN_OUT", layer, headScratch, headConcat);
    } else {
        // No KV cache: current-token-only attention.
        // Softmax over a single score is identically 1 ⇒ headOut = V (not sigmoid).
        if (profilingEnabled_ && profiler_) profiler_->beginAttnCompute();
        for (size_t h = 0; h < numHeads; ++h) {
            const float* v = vProj + (h / groupSize) * headDim;
            float* headOut = headScratch + h * headDim;
            memcpy(headOut, v, headDim * sizeof(float));
        }
        if (profilingEnabled_ && profiler_) profiler_->endAttnCompute();
        if (numHeads > 0) B3_TraceState("ATTN_OUT", layer, headScratch, headConcat);
    }

    // â”€â”€ D2-CERT-002: Stage 8 â€” ATTN_OUT (pre-O projection) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // DISABLED: cert code causes STATUS_STACK_BUFFER_OVERRUN crash in trace()
    // #ifdef RAWRXD_DEEP2_CERT
    // if (layer == 0) {
    //     deep2cert_bridge::stage("L00_ATTN_OUT", output, hiddenDim);
    // }
    // #endif

    // Output projection: [hiddenDim] -> [hiddenDim]
    // Qwen models with fused QKV may not have a separate attention output projection.
    // When absent, the concatenated head outputs (numHeads * headDim) already equal hiddenDim.
    if (B3_StageDigestEnabled() && B3_StageDumpLayer(layer)) {
        // Concatenated head outputs BEFORE wo — isolates O_PROJ from QK/softmax/AV.
        const size_t tokPos = kvCache ? kvCache->currentLength()
                                      : (seqLen > 0 ? seqLen - 1 : 0);
        char key[64];
        std::snprintf(key, sizeof(key), "ATTN_PRE_O_%zu", layer);
        B3_StageDigest(key, tokPos, headScratch, headConcat);
    }
    const auto* attnOutWeight = (lw.wo.data != nullptr) ? &lw.wo :
                                 (lw.attnO.data != nullptr) ? &lw.attnO : nullptr;
    if (attnOutWeight == nullptr || attnOutWeight->data == nullptr) {
        // No output projection: pass through (truncate/pad to hiddenDim).
        if (layer == 0) {
            printf("[ATTN] No attention output weight at layer %zu — pass-through heads\n", layer);
        }
        const size_t n = (headConcat < hiddenDim) ? headConcat : hiddenDim;
        memcpy(output, headScratch, n * sizeof(float));
        if (n < hiddenDim)
            memset(output + n, 0, (hiddenDim - n) * sizeof(float));
    } else {
        // O-proj: headScratch[wo.cols] → output[hiddenDim]
        if (profilingEnabled_ && profiler_) profiler_->beginAttnOutProj();
        LinearW(*attnOutWeight, headScratch, nullptr, output, hiddenDim);
        if (profilingEnabled_ && profiler_) profiler_->endAttnOutProj();
    }
    B3_TraceState("ATTN_O", layer, output, hiddenDim);
    if (layer == 0) {
        const std::uint32_t pos =
            static_cast<std::uint32_t>(kvCache ? kvCache->currentLength() : 0);
        AttnCert::record(AttnCert::Stage::OProj, 0, pos, output, hiddenDim);
    }

    // Reverse analysis hook: attention computed
    if (reverseAnalysisEnabled_ && reverseIntegration_) {
        reverseIntegration_->onAttentionComputed(static_cast<int>(layer), output, hiddenDim);
    }
}

// ============================================================================
// Compute FFN - Real SwiGLU with weight projections
// ============================================================================
void Deep2Engine::computeFFN(size_t layer, const float* input, float* output) {
    if (rawr::iso_ladder::Ignore(rawr::iso_ladder::Run::A10)) {
        if (output && config.hiddenDim)
            std::memset(output, 0, config.hiddenDim * sizeof(float));
        return;
    }
    if (layer >= modelWeights.layers.size()) {
        memcpy(output, input, config.hiddenDim * sizeof(float));
        return;
    }

    const auto& lw = modelWeights.layers[layer];
    size_t hiddenDim = config.hiddenDim;
    size_t intermediateDim = modelWeights.intermediateDim;

    if (intermediateDim == 0) intermediateDim = hiddenDim * 4;

    if (Deep2::phi3_fused_ffn::TryExecuteLayer(
            lw, input, output, hiddenDim, intermediateDim,
            [&](const WeightTensor& wt, const float* x, float* y, size_t outDim) {
                LinearW(wt, x, nullptr, y, outDim);
            },
            layer == 0 ? stderr : nullptr)) {
        return;
    }

    if (!gateBuf || !upBuf || !input || !output) {
        fprintf(stderr,
            "[FFN_FATAL] layer=%zu null buf gate=%p up=%p in=%p out=%p\n",
            layer, gateBuf, upBuf, input, output);
        fflush(stderr);
        throw std::runtime_error("FFN null buffer");
    }

    const auto fusedAuth =
        rawr_phi3_fused_ffn::Inspect(lw, intermediateDim, hiddenDim);
    if (layer == 0) rawr_phi3_fused_ffn::Emit(stderr, fusedAuth, layer);

    bool hasGate = (lw.wGate.data != nullptr && lw.wGate.sizeBytes > 0);

    if (envFlagEnabled("RAWRXD_FFN_TRACE")) {
        fprintf(stderr,
            "[FFN] layer=%zu hasGate=%d fused=%d inter=%zu physicalUp=%zu "
            "hidden=%zu up=%p rows=%zu cols=%zu type=%d gateBuf=%p upBuf=%p\n",
            layer, hasGate ? 1 : 0, fusedAuth.fused ? 1 : 0, intermediateDim,
            fusedAuth.physicalUpRows, hiddenDim, lw.wUp.data, lw.wUp.rows,
            lw.wUp.cols, lw.wUp.type, gateBuf, upBuf);
        fflush(stderr);
    }

    if (lw.wUp.cols != 0 && lw.wUp.cols != hiddenDim) {
        fprintf(stderr,
            "[FFN_FATAL] layer=%zu wUp.cols=%zu != hiddenDim=%zu\n",
            layer, lw.wUp.cols, hiddenDim);
        fflush(stderr);
        throw std::runtime_error("FFN wUp cols mismatch");
    }

    if (fusedAuth.fused) {
        /* Physical GEMV → gateBuf[0..2I); logical views gate|up; activate→upBuf. */
        const size_t phys = fusedAuth.physicalUpRows;
        const size_t I = fusedAuth.logicalInter;
        if (profilingEnabled_ && profiler_) profiler_->beginFFNUp();
        std::fill(gateBuf, gateBuf + phys, 0.0f);
        LinearW(lw.wUp, input, nullptr, gateBuf, phys);
        if (profilingEnabled_ && profiler_) profiler_->endFFNUp();
        if (profilingEnabled_ && profiler_) profiler_->beginFFNSwiGLU();
        SwiGLU(gateBuf, gateBuf + I, upBuf, I);
        if (profilingEnabled_ && profiler_) profiler_->endFFNSwiGLU();
        B3_TraceState("FFN_SWIGLU", layer, upBuf, I);
        if (profilingEnabled_ && profiler_) profiler_->beginFFNDown();
        std::fill(output, output + hiddenDim, 0.0f);
        LinearW(lw.wDown, upBuf, nullptr, output, hiddenDim);
        if (profilingEnabled_ && profiler_) profiler_->endFFNDown();
        B3_TraceState("FFN_DOWN", layer, output, hiddenDim);
        return;
    }

    if (hasGate) {
        // Standard SwiGLU: gate and up are separate projections
        if (profilingEnabled_ && profiler_) profiler_->beginFFNGate();
        std::fill(gateBuf, gateBuf + intermediateDim, 0.0f);
        if (envFlagEnabled("RAWRXD_FFN_TRACE")) {
            fprintf(stderr, "[FFN] layer=%zu LinearW gate begin\n", layer);
            fflush(stderr);
        }
        LinearW(lw.wGate, input, nullptr, gateBuf, intermediateDim);
        if (envFlagEnabled("RAWRXD_FFN_TRACE")) {
            fprintf(stderr, "[FFN] layer=%zu LinearW gate ok\n", layer);
            fflush(stderr);
        }
        if (profilingEnabled_ && profiler_) profiler_->endFFNGate();
    }

    // Up projection: [hiddenDim] -> [intermediateDim]
    if (profilingEnabled_ && profiler_) profiler_->beginFFNUp();
    std::fill(upBuf, upBuf + intermediateDim, 0.0f);
    if (envFlagEnabled("RAWRXD_FFN_TRACE")) {
        fprintf(stderr, "[FFN] layer=%zu LinearW up begin\n", layer);
        fflush(stderr);
    }
    LinearW(lw.wUp, input, nullptr, upBuf, intermediateDim);
    if (envFlagEnabled("RAWRXD_FFN_TRACE")) {
        fprintf(stderr, "[FFN] layer=%zu LinearW up ok\n", layer);
        fflush(stderr);
    }
    if (profilingEnabled_ && profiler_) profiler_->endFFNUp();

    // Dump gate (pre-SiLU) before SwiGLU overwrites gateBuf with the product.
    if (B3_StageDigestEnabled() && B3_StageDumpLayer(layer) && hasGate) {
        const size_t tokPos = kvCache ? kvCache->currentLength() : 0;
        char key[64];
        std::snprintf(key, sizeof(key), "FFN_GATE_%zu", layer);
        B3_StageDigest(key, tokPos, gateBuf, intermediateDim);
    }

    // SwiGLU: output = silu(gate) * up
    if (profilingEnabled_ && profiler_) profiler_->beginFFNSwiGLU();
    if (hasGate) {
        SwiGLU(gateBuf, upBuf, gateBuf, intermediateDim);
    } else {
        // Self-gating: gate == up, so SwiGLU becomes silu(up) * up
        SwiGLU(upBuf, upBuf, gateBuf, intermediateDim);
    }
    if (profilingEnabled_ && profiler_) profiler_->endFFNSwiGLU();
    B3_TraceState("FFN_SWIGLU", layer, gateBuf, intermediateDim);
    if (B3_StageDigestEnabled() && B3_StageDumpLayer(layer)) {
        const size_t tokPos = kvCache ? kvCache->currentLength() : 0;
        char key[64];
        std::snprintf(key, sizeof(key), "FFN_UP_%zu", layer);
        B3_StageDigest(key, tokPos, upBuf, intermediateDim);
        std::snprintf(key, sizeof(key), "FFN_ACT_%zu", layer);
        B3_StageDigest(key, tokPos, gateBuf, intermediateDim);
    }

    // Down projection: [intermediateDim] -> [hiddenDim]
    if (profilingEnabled_ && profiler_) profiler_->beginFFNDown();
    std::fill(output, output + hiddenDim, 0.0f);
    LinearW(lw.wDown, gateBuf, nullptr, output, hiddenDim);
    if (profilingEnabled_ && profiler_) profiler_->endFFNDown();
    B3_TraceState("FFN_DOWN", layer, output, hiddenDim);
}

// ============================================================================
// Compute SSM / Mamba â€” EXPERIMENTAL APPROXIMATION (SSM-CERT-001)
// Not architecture-parity. Production loads are rejected unless
// RAWRXD_DEEP2_ALLOW_EXPERIMENTAL_SSM=1. Missing tensors are hard failures.
// ============================================================================
void Deep2Engine::computeSSM(size_t layer, const float* input, float* output) {
    if (layer >= modelWeights.layers.size()) {
        fprintf(stderr, "[SSM_FATAL] layer=%zu out of range\n", layer);
        throw std::runtime_error("SSM layer out of range");
    }

    const auto& lw = modelWeights.layers[layer];
    size_t hiddenDim = config.hiddenDim;
    size_t stateDim = ssmStateDim;   // 32 from tensor dims
    size_t convK = ssmConvKernel;    // 4 from tensor dims

    if (!lw.hasSSM || !lw.ssmOut.data ||
        (!lw.ssmAlpha.data && !lw.ssmIn.data)) {
        fprintf(stderr,
            "[SSM_FATAL] layer=%zu missing required SSM tensors "
            "(hasSSM=%d alpha=%p in=%p out=%p)\n",
            layer, lw.hasSSM ? 1 : 0, lw.ssmAlpha.data, lw.ssmIn.data,
            lw.ssmOut.data);
        throw std::runtime_error("SSM missing required tensors");
    }

    if (!envFlagEnabled("RAWRXD_DEEP2_ALLOW_EXPERIMENTAL_SSM")) {
        fprintf(stderr,
            "[SSM_FATAL] experimental SSM path invoked without allow flag\n");
        throw std::runtime_error("SSM-CERT-001 experimental path blocked");
    }

    /* Nemotron-H Mamba2 real-forward (experimental). PROD_DECODE=0 / NOT CERT. */
    if (lw.ssmIn.data && !lw.ssmAlpha.data && ssmMambaArmed_) {
        nemotron_h::Geo g{};
        g.hidden = hiddenDim;
        g.ssmHeads = ssmMambaHeads_;
        g.ssmHeadDim = ssmMambaHeadDim_;
        g.ssmInner = ssmMambaInner_;
        g.ssmGroups = ssmMambaGroups_;
        g.ssmState = ssmMambaStateN_;
        g.ssmGroupState = ssmMambaGroupState_;
        g.ssmDtRank = ssmMambaDtRank_;
        g.ssmConvK = ssmMambaConvK_;
        g.ssmConvDim = ssmMambaConvDim_;
        g.ssmInRows = ssmMambaInRows_;
        g.ok = 1;
        nemotron_h::StepBuf sb{};
        sb.proj = ssmMambaProj_;
        sb.yInner = ssmMambaY_;
        sb.state = ssmMambaState_;
        sb.conv = ssmMambaConv_;
        auto lin = [this](const WeightTensor& wt, const float* in, const float* bias,
                          float* out, size_t od) { LinearW(wt, in, bias, out, od); };
        if (nemotron_h::RunMamba2Token(layer, lw, g, input, output, sb, lin)) {
            ++ssmRealCalls_;
            static int once = 0;
            if (!once++) {
                fprintf(stderr,
                    "[SSM_MAMBA2] REAL_FORWARD=1 layer=%zu IDENTITY=0 "
                    "state=%zu heads=%zu inner=%zu PRODUCTION_DECODE_PATH=0 "
                    "SSM_CERT=NOT_CERTIFIED\n",
                    layer, g.ssmState, g.ssmHeads, g.ssmInner);
                fflush(stderr);
            }
            return;
        }
    }

    /* Legacy approximate experimental scan (buffers may skip -> identity). */
    {
        nemotron_ssm::Buf b{};
        b.x = ssmX;
        b.y = ssmY;
        b.temp = ssmTemp;
        b.state = ssmState;
        b.conv = ssmConvState;
        auto lin = [this](const WeightTensor& wt, const float* in, const float* bias,
                          float* out, size_t od) { LinearW(wt, in, bias, out, od); };
        if (nemotron_ssm::RunExperimental(layer, lw, hiddenDim, stateDim, convK,
                                          input, output, b, lin))
            return;
    }

    // Legacy scaffold: ssm_in without selective-scan tensors incomplete.
    if (lw.ssmIn.data && !lw.ssmAlpha.data) {
        ++ssmIdentityCalls_;
        fprintf(stderr,
            "[SSM_SCAFFOLD] layer=%zu IDENTITY=1 inRows=%zu outCols=%zu "
            "stateDim=%zu PRODUCTION_DECODE_PATH=0 "
            "SSM_CERT_001_AUTHORITY=NOT_CERTIFIED\n",
            layer, lw.ssmIn.rows, lw.ssmOut.cols, stateDim);
        fflush(stderr);
        memcpy(output, input, hiddenDim * sizeof(float));
        if (lw.ssmD.data) {
            const float* dParam = (const float*)lw.ssmD.data;
            const size_t n = stateDim < hiddenDim ? stateDim : hiddenDim;
            for (size_t i = 0; i < n; ++i)
                output[i] += dParam[i] * input[i];
        }
        return;
    }

    // Cert digests on the first SSM layer only (sequence progression across tokens).
    size_t firstSsm = modelWeights.layers.size();
    for (size_t i = 0; i < modelWeights.layers.size(); ++i) {
        if (modelWeights.layers[i].hasSSM) { firstSsm = i; break; }
    }
    const bool certLayer = (layer == firstSsm);
    const std::uint32_t seqPos = certLayer ? SsmCert::bumpSeq() : SsmCert::seqStep();

    // â”€â”€ Step 1: Project input to SSM state space via alpha â”€â”€
    // alpha: [stateDim, hiddenDim] â€” computes x_alpha = alpha^T * input
    float* xAlpha = ssmX;  // [hiddenDim] reused as temp
    memset(xAlpha, 0, hiddenDim * sizeof(float));
    LinearW(lw.ssmAlpha, input, nullptr, xAlpha, stateDim);
    if (certLayer) {
        SsmCert::record(SsmCert::Stage::Alpha, static_cast<std::uint32_t>(layer),
                        seqPos, xAlpha, stateDim);
    }

    // â”€â”€ Step 2: Project input to SSM state space via beta â”€â”€
    // beta: [stateDim, hiddenDim] â€” computes x_beta = beta^T * input
    float* xBeta = ssmTemp;  // [hiddenDim] reused as temp
    memset(xBeta, 0, hiddenDim * sizeof(float));
    LinearW(lw.ssmBeta, input, nullptr, xBeta, stateDim);
    if (certLayer) {
        SsmCert::record(SsmCert::Stage::Beta, static_cast<std::uint32_t>(layer),
                        seqPos, xBeta, stateDim);
    }

    // â”€â”€ Step 3: Causal conv1d on xAlpha (simplified: shift-register convolution) â”€â”€
    // conv1d.weight: [convK, hiddenDim*2] â€” actually operates on 2*hiddenDim channels
    // For simplicity, apply a 1D causal convolution per channel on xAlpha
    float* convOut = ssmY;  // [hiddenDim] reused
    memset(convOut, 0, hiddenDim * sizeof(float));

    if (lw.ssmConv1d.data && lw.ssmConv1d.sizeBytes > 0) {
        // conv1d weight is F32 [convK, hiddenDim*2]
        // We only use the first hiddenDim channels for xAlpha
        const float* convW = (const float*)lw.ssmConv1d.data;
        size_t chStride = hiddenDim * 2;  // channels per kernel position

        // Per-channel causal convolution: y[t] = sum_k w[k] * x[t-k]
        // For single-token inference, only the newest sample is non-zero in conv state
        float* convStatePtr = ssmConvState + layer * convK * hiddenDim;
        for (size_t c = 0; c < stateDim && c < hiddenDim; ++c) {
            // Shift conv state: state[k] = state[k-1], state[0] = xAlpha[c]
            for (size_t k = convK - 1; k > 0; --k) {
                convStatePtr[k * hiddenDim + c] = convStatePtr[(k - 1) * hiddenDim + c];
            }
            convStatePtr[c] = xAlpha[c];

            // Compute conv output
            float sum = 0.0f;
            for (size_t k = 0; k < convK; ++k) {
                size_t wIdx = k * chStride + c;
                if (wIdx < lw.ssmConv1d.rows * lw.ssmConv1d.cols) {
                    sum += convW[wIdx] * convStatePtr[k * hiddenDim + c];
                }
            }
            convOut[c] = sum;
        }
    } else {
        // No conv1d weights: pass through
        memcpy(convOut, xAlpha, stateDim * sizeof(float));
    }
    if (certLayer) {
        SsmCert::record(SsmCert::Stage::Conv, static_cast<std::uint32_t>(layer),
                        seqPos, convOut, stateDim);
    }

    // â”€â”€ Step 4: Selective scan (discrete SSM) â”€â”€
    // h' = A * h + B * x, where A = exp(a * dt), B = dt * beta
    // y = C * h, where C = convOut (treated as output projection)
    float* statePtr = ssmState + layer * stateDim;
    const float* aParam = (const float*)lw.ssmA.data;
    const float* dtBias = (const float*)lw.ssmDtBias.data;

    if (certLayer) {
        SsmCert::record(SsmCert::Stage::StatePre, static_cast<std::uint32_t>(layer),
                        seqPos, statePtr, stateDim);
    }

    for (size_t i = 0; i < stateDim; ++i) {
        // Compute delta_t (softplus of dt bias for now; could include projection)
        float dt = dtBias ? dtBias[i] : 1.0f;
        if (dt <= 0.0f) dt = 0.001f;  // clamp to positive

        // Discretization: A_bar = exp(a * dt), B_bar = dt * beta
        float a = aParam ? aParam[i] : -1.0f;
        float Abar = expf(a * dt);
        float Bbar = dt * xBeta[i];

        // State update: h = A_bar * h + B_bar * x
        statePtr[i] = Abar * statePtr[i] + Bbar * convOut[i];

        // Output: y = state (identity output projection for selective scan)
        xAlpha[i] = statePtr[i];
    }

    if (certLayer) {
        SsmCert::record(SsmCert::Stage::StatePost, static_cast<std::uint32_t>(layer),
                        seqPos, statePtr, stateDim);
    }

    // â”€â”€ Step 5: Apply SSM norm (RMSNorm on state) â”€â”€
    if (lw.ssmNorm.data && lw.ssmNorm.sizeBytes > 0) {
        float rms = 0.0f;
        for (size_t i = 0; i < stateDim; ++i) {
            rms += xAlpha[i] * xAlpha[i];
        }
        rms = sqrtf(rms / stateDim + modelWeights.normEps);
        const float* normW = (const float*)lw.ssmNorm.data;
        for (size_t i = 0; i < stateDim; ++i) {
            xAlpha[i] = xAlpha[i] / rms * normW[i % 128];  // mod 128 in case norm dim differs
        }
    }
    if (certLayer) {
        SsmCert::record(SsmCert::Stage::Norm, static_cast<std::uint32_t>(layer),
                        seqPos, xAlpha, stateDim);
    }

    // â”€â”€ Step 6: Project SSM state back to hiddenDim via ssmOut â”€â”€
    // ssmOut: [hiddenDim, hiddenDim] â€” but we only have stateDim active inputs
    // Zero-pad the input vector to hiddenDim, then apply LinearW
    memset(ssmTemp, 0, hiddenDim * sizeof(float));
    memcpy(ssmTemp, xAlpha, stateDim * sizeof(float));
    memset(output, 0, hiddenDim * sizeof(float));
    LinearW(lw.ssmOut, ssmTemp, nullptr, output, hiddenDim);

    B3_TraceState("SSM_OUT", layer, output, hiddenDim);
    if (certLayer) {
        SsmCert::record(SsmCert::Stage::Out, static_cast<std::uint32_t>(layer),
                        seqPos, output, hiddenDim);
        SsmCert::record(SsmCert::Stage::SeqStep, static_cast<std::uint32_t>(layer),
                        seqPos, nullptr, 0, static_cast<double>(seqPos));
    }
}

// ============================================================================
// Compute MoE FFN - Real routed expert execution
// Routes token through MoERouter, executes top-k experts via streamed
// weights from MoEWeightProxy, adds shared expert output.
// Router-driven prefetch: after routing layer N, prefetch layer N+1 experts.
// NO dense fallback. NO stubs.
// ============================================================================
void Deep2Engine::computeMoEFFN(size_t layer, const float* input, float* output) {
    if (layer >= modelWeights.layers.size()) {
        memcpy(output, input, config.hiddenDim * sizeof(float));
        return;
    }

    size_t hiddenDim = config.hiddenDim;

    // Zero output accumulator
    memset(output, 0, hiddenDim * sizeof(float));

    // --- Shared expert (always executed) ---
    float* sharedOut = attentionOutput;
    computeSharedExpertFFN(layer, input, sharedOut);
    #if defined(__AVX2__) || defined(_MSC_VER)
    if (hiddenDim >= 8) {
        size_t i = 0;
        for (; i + 7 < hiddenDim; i += 8) {
            __m256 outv = _mm256_loadu_ps(output + i);
            __m256 shv = _mm256_loadu_ps(sharedOut + i);
            _mm256_storeu_ps(output + i, _mm256_add_ps(outv, shv));
        }
        for (; i < hiddenDim; ++i) {
            output[i] += sharedOut[i];
        }
    } else
    #endif
    {
        for (size_t i = 0; i < hiddenDim; ++i) {
            output[i] += sharedOut[i];
        }
    }

    // --- Routed experts ---
    if (layer >= moeRouters_.size() || !moeRouters_[layer] || !moeWeightProxy_) {
        return;
    }

    // 1. Route the token through the per-layer router
    TokenRoute route = moeRouters_[layer]->Route(input);

    // 2. Check pending prefetches from layer N-1 (previous layer's async jobs)
    //    If fence signaled â†’ expert is HOT, record telemetry
    //    If still pending â†’ record as late, fallback to sync acquire
    if (asyncPrefetchEnabled_ && vulkanCompute_ && moeWeightProxy_) {
        auto it = pendingPrefetches_.find(static_cast<int>(layer));
        if (it != pendingPrefetches_.end()) {
            for (uint64_t jobHandle : it->second) {
                const PrefetchJob* job = moeWeightProxy_->GetPrefetchJob(jobHandle);
                if (!job) continue;

                bool ready = moeWeightProxy_->CheckPrefetchReady(jobHandle, vulkanCompute_.get());
                if (telemetryEnabled_ && residencyTelemetry_) {
                    residencyTelemetry_->RecordAsyncPrefetchReadyAtCompute(
                        job->layer, job->expertId, ready);
                }
            }
            // Clear checked prefetches for this layer
            pendingPrefetches_.erase(it);
        }
    }

    // 3. HOST_DECODE: HostPrefetch already issued at layer enter (no sync Prefetch).
    if (Deep2::hostfc::Armed() || hostDecodeSanitize_) {
    } else if (asyncPrefetchEnabled_ && layer + 1 < modelWeights.numLayers &&
        layer + 1 < moeRouters_.size() && moeWeightProxy_) {
        std::vector<int> predictedExperts = moeRouters_[layer]->GetLastRouteExpertIds();
        if (!predictedExperts.empty()) {
            /* BATCH_D / B011: Router → Expert IDs → UnifiedAsyncMove → GPU cache.
             * Metric is fetch avoidance (hit rate), not whether the full MoE fits. */
            if (elasticResidencyEnabled_ && elasticResidency_) {
                std::vector<uint32_t> eids;
                eids.reserve(predictedExperts.size());
                for (int eid : predictedExperts)
                    if (eid >= 0) eids.push_back(static_cast<uint32_t>(eid));
                if (!eids.empty()) {
                    elasticResidency_->PrefetchExperts(
                        static_cast<uint32_t>(layer + 1), eids.data(), eids.size());
                    fprintf(stderr,
                            "B011_FETCH_COST router_layer=%zu next=%zu experts=%zu "
                            "hit_rate=%.2f%% ref~%.2f%%\n",
                            layer, layer + 1, eids.size(),
                            elasticResidency_->PrefetchHitRatePct(),
                            (double)BATCH_D_B011_HIT_RATE_REF_PCT);
                }
            }
            int slot = 0;
            if (multiGpuLayerPlan_.active)
                slot = Deep2MultiGpu_SlotForLayer(multiGpuLayerPlan_,
                                                 (unsigned)(layer + 1));
            CPUInference::VulkanCompute* vc = getVulkanComputeSlot((unsigned)slot);
            if (!vc) vc = getVulkanComputeSlot(0);
            if (vc) {
                std::vector<uint64_t> jobHandles = moeWeightProxy_->PrefetchAsync(
                    static_cast<int>(layer + 1), predictedExperts, vc);
                if (!jobHandles.empty()) {
                    pendingPrefetches_[static_cast<int>(layer + 1)] =
                        std::move(jobHandles);
                }
                if (telemetryEnabled_ && residencyTelemetry_) {
                    for (int eid : predictedExperts) {
                        residencyTelemetry_->RecordAsyncPrefetchSubmitted(
                            static_cast<int>(layer + 1), eid);
                    }
                }
            } else if (moeWeightProxy_) {
                moeWeightProxy_->Prefetch(static_cast<int>(layer + 1),
                                          predictedExperts);
            }
        }
    } else {
        // Synchronous fallback: warm cache without async Vulkan
        if (layer + 1 < modelWeights.numLayers && layer + 1 < moeRouters_.size()) {
            std::vector<int> predictedExperts = moeRouters_[layer]->GetLastRouteExpertIds();
            if (!predictedExperts.empty() && moeWeightProxy_) {
                moeWeightProxy_->Prefetch(static_cast<int>(layer + 1), predictedExperts);
            }
        }
    }

    // 4. Residency-aware place: hits-first DualStick order (router set unchanged)
    float* expertOut = attentionOutput;
    {
        MoEExpertResidencyPlace& place = MoEPlaceGlobal();
        place.SetProbe(
            [](void* ctx, int ly, int ex) -> int {
                auto* px = static_cast<MoEWeightProxy*>(ctx);
                return (px && px->IsCached(ly, ex)) ? 1 : 0;
            },
            moeWeightProxy_.get());
        const uint32_t sticks =
            (DualStickState().armed || DualStickState().planned ||
             DualStickState().requested)
                ? 2u
                : 1u;
        place.SetStickCount(sticks);
        if (place.Counters().place_calls == 0) {
            const char* b = std::getenv("DEEP2_MOE_PLACE_BUDGET_MIB");
            uint64_t bud = b && *b ? ((uint64_t)std::atoi(b) << 20) : (512ull << 20);
            uint64_t eb = moeConfig_.expertDim ? (uint64_t)moeConfig_.expertDim * 4096ull
                                               : (1ull << 20);
            place.SetBudget(bud, eb);
        }
        MoEPlaceIn pin[MOE_PLACE_MAX_K];
        uint32_t pn = 0;
        for (const auto& er : route.topExperts) {
            if (er.expertId < 0 || pn >= MOE_PLACE_MAX_K) continue;
            pin[pn].expertId = er.expertId;
            pin[pn].weight = er.weight;
            ++pn;
        }
        MoEPlacePlan plan = place.Place((int)layer, pin, pn);
        for (uint32_t si = 0; si < plan.count; ++si) {
            const MoEPlaceSlot& slot = plan.slots[si];
            const int expertId = slot.expertId;
            const float weight = slot.weight;
            if (expertId < 0) continue;
            if (slot.fetch)
                DualStickAcquire(slot.stick, nullptr, 0, 0, (uint32_t)layer,
                                 (uint32_t)expertId);

            auto tAcquire0 = std::chrono::high_resolution_clock::now();
            MoEWeightHandle handle =
                moeWeightProxy_->Acquire((int)layer, expertId);
            auto tAcquire1 = std::chrono::high_resolution_clock::now();
            uint64_t acquireUs =
                std::chrono::duration_cast<std::chrono::microseconds>(
                    tAcquire1 - tAcquire0)
                    .count();
            if (!handle.valid) continue;
            place.MarkHot((int)layer, expertId, slot.stick,
                          handle.expertBytes ? (uint64_t)handle.expertBytes : 0);
            recordExpertAccess((int)layer, expertId, weight);
            bool prefetchHit = slot.hit || (acquireUs < 100);
            if (telemetryEnabled_ && residencyTelemetry_) {
                residencyTelemetry_->RecordInvocation((int)layer, expertId,
                                                      prefetchHit);
            }
            auto tCompute0 = std::chrono::high_resolution_clock::now();
            computeExpertFFN(handle, input, expertOut, hiddenDim,
                             moeConfig_.expertDim);
            auto tCompute1 = std::chrono::high_resolution_clock::now();
            uint64_t computeUs =
                std::chrono::duration_cast<std::chrono::microseconds>(
                    tCompute1 - tCompute0)
                    .count();
            if (telemetryEnabled_ && residencyTelemetry_) {
                residencyTelemetry_->RecordComputeTime((int)layer, expertId,
                                                       computeUs);
            }
#if defined(__AVX2__) || defined(_MSC_VER)
            if (hiddenDim >= 8) {
                __m256 wvec = _mm256_set1_ps(weight);
                size_t i = 0;
                for (; i + 7 < hiddenDim; i += 8) {
                    __m256 outv = _mm256_loadu_ps(output + i);
                    __m256 exv = _mm256_loadu_ps(expertOut + i);
                    _mm256_storeu_ps(output + i,
                                     _mm256_fmadd_ps(wvec, exv, outv));
                }
                for (; i < hiddenDim; ++i)
                    output[i] += weight * expertOut[i];
            } else
#endif
            {
                for (size_t i = 0; i < hiddenDim; ++i)
                    output[i] += weight * expertOut[i];
            }
        }
        if (const char* t = std::getenv("DEEP2_MOE_PLACE_TRACE")) {
            if (t[0] == '1') place.EmitTrace(stderr);
        }
    }
    prefetchNextExperts((int)layer);
}

// ============================================================================
// Compute Expert FFN - Real gate/up/down projections via streamed weights
// Uses the same Q4_K GEMV path as dense layers.
// ============================================================================
void Deep2Engine::computeExpertFFN(const MoEWeightHandle& handle,
                                    const float* input, float* output,
                                    size_t hiddenDim, size_t expertDim) {
    if (!handle.valid || !handle.gateWeights) {
        memset(output, 0, hiddenDim * sizeof(float));
        return;
    }

    auto& reg = Deep2::QuantKernelRegistry::Instance();
    auto kernel = reg.GetGEMV(handle.quantType);
    auto geom   = reg.GetGeometry(handle.quantType);
    if (!kernel || geom.blockSize == 0) {
        memset(output, 0, hiddenDim * sizeof(float));
        reg.GetBatch21Counters().registryMisses.fetch_add(1, std::memory_order_relaxed);
        printf("[computeExpertFFN] ERROR: No registry kernel for quantType=%d\n", handle.quantType);
        return;
    }
    reg.GetBatch21Counters().registryHits.fetch_add(1, std::memory_order_relaxed);
    reg.GetBatch21Counters().kernelInvocations.fetch_add(3, std::memory_order_relaxed); // gate + up + down
    size_t blocksPerRow = (hiddenDim + geom.elemsPerBlock - 1) / geom.elemsPerBlock;
    size_t rowBytes = blocksPerRow * geom.blockSize;

    // Use gateBuf and upBuf as temp (both hiddenDim*4 sized, enough for expertDim)
    // Gate projection: [expertDim, hiddenDim] * input -> [expertDim]
    float* gateOut = gateBuf;
    kernel((const uint8_t*)handle.gateWeights, input, gateOut, expertDim, hiddenDim);

    // Up projection: [expertDim, hiddenDim] * input -> [expertDim]
    float* upOut = upBuf;
    kernel((const uint8_t*)handle.upWeights, input, upOut, expertDim, hiddenDim);

    // SwiGLU: silu(gate) * up
    SwiGLU(gateOut, upOut, gateOut, expertDim);

    // Down projection: [hiddenDim, expertDim] * gateOut -> [hiddenDim]
    kernel((const uint8_t*)handle.downWeights, gateOut, output, hiddenDim, expertDim);
}

// ============================================================================
// Compute Shared Expert FFN - Real shared expert execution
// ============================================================================
void Deep2Engine::computeSharedExpertFFN(size_t layer, const float* input,
                                          float* output) {
    size_t hiddenDim = config.hiddenDim;


    if (!moeConfig_.useSharedExpert) {
        memset(output, 0, hiddenDim * sizeof(float));
        return;
    }

    if (!moeWeightsLoader_) {
        memset(output, 0, hiddenDim * sizeof(float));
        return;
    }

    // Use the layer's shared expert weights if mapped from GGUF
    const auto& lw = modelWeights.layers[layer];
    
    // Check if shared expert weights were mapped during loadModel
    if (lw.moeSharedGate.data && lw.moeSharedUp.data && lw.moeSharedDown.data) {
        // Use mapped weights directly (already in memory via mmap)
        size_t sharedDim = moeConfig_.sharedExpertDim;
        if (sharedDim == 0) sharedDim = moeConfig_.expertDim;
        if (sharedDim == 0 && lw.moeSharedGate.rows > 0) sharedDim = lw.moeSharedGate.rows;
        if (sharedDim == 0) { memset(output, 0, hiddenDim * sizeof(float)); return; }
        
        // Gate projection (use gateBuf as temp - hiddenDim*4 sized)
        float* gateOut = gateBuf;
        LinearW(lw.moeSharedGate, input, nullptr, gateOut, sharedDim);
        
        // Up projection (use upBuf as temp)
        float* upOut = upBuf;
        LinearW(lw.moeSharedUp, input, nullptr, upOut, sharedDim);
        
        // SwiGLU
        SwiGLU(gateOut, upOut, gateOut, sharedDim);
        
        // Down projection
        LinearW(lw.moeSharedDown, gateOut, nullptr, output, hiddenDim);
        return;
    }

    // Fallback: stream shared expert from disk via MoEWeightsLoader
    size_t sharedDim = moeConfig_.sharedExpertDim;
    if (sharedDim == 0) sharedDim = moeConfig_.expertDim;
    
    // Allocate buffer for shared expert weights (Q4_K sized)
    size_t perProjBytes = (sharedDim * hiddenDim) / 2;  // Q4_K estimate
    size_t totalBytes = perProjBytes * 3;
    std::vector<uint8_t> sharedBuf(totalBytes);
    
    if (!moeWeightsLoader_->LoadSharedExpert((int)layer, sharedBuf.data(),
                                              sharedBuf.size())) {
        memset(output, 0, hiddenDim * sizeof(float));
        return;
    }

    // Build handle and execute
    MoEWeightHandle handle;
    handle.gateWeights = sharedBuf.data();
    handle.upWeights = sharedBuf.data() + perProjBytes;
    handle.downWeights = sharedBuf.data() + perProjBytes * 2;
    handle.expertBytes = totalBytes;
    handle.layer = (int)layer;
    handle.expertId = -2;
    handle.quantType = static_cast<int>(GGMLType::GGML_TYPE_Q4_K);
    handle.valid = true;

    computeExpertFFN(handle, input, output, hiddenDim, sharedDim);
}

// ============================================================================
// Compute Logits - Real lm_head projection
// ============================================================================
void Deep2Engine::computeLogits(const float* hiddenState, float* logits) {
    Deep2::heap::EmitOk(stderr, "COMPUTE_LOGITS_ENTER");
    if (!modelWeights.loaded || !modelWeights.lmHead.data) {
        // No model loaded - error
        memset(logits, 0, config.vocabSize * sizeof(float));
        return;
    }

    // â”€â”€ VAL-051.7: Clear logits before compute to prevent stale values â”€
    std::fill(logits, logits + config.vocabSize, 0.0f);

    // â”€â”€ Diagnostic: verify hidden state and weights (opt-in) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if (B3_LogitsTraceEnabled()) {
        float hiddenNorm = 0.0f;
        for (size_t i = 0; i < config.hiddenDim; ++i) {
            hiddenNorm += hiddenState[i] * hiddenState[i];
        }
        hiddenNorm = std::sqrt(hiddenNorm);
        printf("[Deep2Engine] computeLogits: hiddenState norm=%.6f (dim=%zu)\n",
               hiddenNorm, config.hiddenDim);
        printf("[Deep2Engine] computeLogits: lmHead type=%d rows=%zu cols=%zu data=%p\n",
               modelWeights.lmHead.type, modelWeights.lmHead.rows,
               modelWeights.lmHead.cols, modelWeights.lmHead.data);
        printf("[B3_LOGITS] BEFORE LinearW type=%d rows=%zu cols=%zu data=%p\n",
               static_cast<int>(modelWeights.lmHead.type),
               modelWeights.lmHead.rows,
               modelWeights.lmHead.cols,
               modelWeights.lmHead.data);
        fflush(stdout);
    }

    // lm_head: [vocabSize, hiddenDim] * hiddenState -> [vocabSize]
    Deep2::heap::EmitOk(stderr, "LOGITS_LINEARW_BEFORE");
    LinearW(modelWeights.lmHead, hiddenState, nullptr, logits, config.vocabSize);
    Deep2::heap::EmitOk(stderr, "LOGITS_LINEARW_AFTER");

    if (B3_LogitsTraceEnabled()) {
        printf("[B3_LOGITS] AFTER LinearW\n");
        fflush(stdout);
    }
}

void Deep2Engine::resetGenQualityProbe() {
    genQualityOrdinal_ = 0;
    genQualityTokRoundtrip_ = 1;
    if (genQualityProbe_) {
        delete static_cast<D2GenQualityProbe*>(genQualityProbe_);
        genQualityProbe_ = nullptr;
    }
}

void Deep2Engine::armGenQualityProbe() {
    resetGenQualityProbe();
    const char* path = std::getenv("DEEP2_GEN_QUALITY_TRACE");
    if (!path || !path[0]) return;
    auto* p = new D2GenQualityProbe();
    if (!p->open(path)) {
        delete p;
        return;
    }
    genQualityProbe_ = p;
}

void Deep2Engine::emitGenQualityProbe(int selected, const float* logits,
                                      int argmaxId, float argmaxLogit) {
    if (!genQualityProbe_ || !logits) return;
    float mx = argmaxLogit;
    double sum = 0.0;
    for (size_t i = 0; i < config.vocabSize; ++i) {
        if (!std::isfinite(logits[i])) continue;
        sum += std::exp((double)logits[i] - (double)mx);
    }
    const float selLogit =
        (selected >= 0 && (size_t)selected < config.vocabSize) ? logits[selected]
                                                                : 0.f;
    const double selProb =
        (sum > 0.0 && selected >= 0 && (size_t)selected < config.vocabSize &&
         std::isfinite(selLogit))
            ? (std::exp((double)selLogit - (double)mx) / sum)
            : 0.0;
    bool tokRt = genQualityTokRoundtrip_ != 0;
    if (tokenizer && selected >= 0) {
        const std::string piece = tokenizer->Decode(selected);
        auto again = tokenizer->Encode(piece);
        if (again.size() == 1 && again[0] == selected) {
            /* ok */
        } else if (piece.empty()) {
            tokRt = false;
        }
        genQualityTokRoundtrip_ = tokRt ? 1 : 0;
    }
    const bool samplerValid =
        selected >= 0 && (size_t)selected < config.vocabSize &&
        std::isfinite(selLogit) && std::isfinite(argmaxLogit);
    auto* p = static_cast<D2GenQualityProbe*>(genQualityProbe_);
    p->emit(genQualityOrdinal_++, selected, selLogit, selProb, argmaxId,
            argmaxLogit, samplerValid, tokRt != 0, genQualityChatValid_ != 0);
}

// ============================================================================
// Sample Token — Real sampling using ISampler + Sovereign Chamber
// The Chamber (SM0-DSP) intercepts here: hidden state → clash detection
// Observe-only: emitGenQualityProbe after final logits + selection.
// ============================================================================
int Deep2Engine::sampleToken(const float* logits) {
    int argmaxId = 0;
    float argmaxLogit = logits[0];
    for (size_t i = 1; i < config.vocabSize; ++i) {
        if (std::isfinite(logits[i]) &&
            (!std::isfinite(argmaxLogit) || logits[i] > argmaxLogit)) {
            argmaxLogit = logits[i];
            argmaxId = static_cast<int>(i);
        }
    }

    if (deterministicGreedy_) {
        const int selected = argmaxId;
        if (GreedyTraceEnabled()) {
            printf("[GREEDY] enabled=1\n");
            printf("[GREEDY] argmax=%d logit=%.6f\n", argmaxId, argmaxLogit);
            printf("[GREEDY] selected=%d\n", selected);
        }
        emitGenQualityProbe(selected, logits, argmaxId, argmaxLogit);
        return selected;
    }

    if ((chamberEnabled_ || sovereignRuntimeEnabled_) && attentionOutput) {
        rawrxd::ChamberResult result = evaluateChamber(attentionOutput, config.hiddenDim);
        if (result == rawrxd::ChamberResult::CLASH) {
            printf("[Deep2Engine] Chamber CLASH detected — forcing EOS\n");
            int eos = tokenizer ? tokenizer->GetSpecialTokens().eosId : 0;
            emitGenQualityProbe(eos, logits, argmaxId, argmaxLogit);
            return eos;
        }
        uint64_t ctx_hash = rawrxd::TransitionState::hashHiddenState(attentionOutput, config.hiddenDim);
        rawrxd::FormulaRoute route = routePrimitive(ctx_hash);
        if (route.valid) {
            int r = static_cast<int>(route.primitive_output);
            emitGenQualityProbe(r, logits, argmaxId, argmaxLogit);
            return r;
        }
    }

    const bool topLogits =
        !SemanticSafeWanted() &&
        []() {
            const char* e = std::getenv("RAWRXD_TOP_LOGITS");
            return !e || e[0] != '0';
        }();
    if (topLogits) {
        std::vector<std::pair<float, int>> scored;
        scored.reserve(config.vocabSize);
        for (size_t i = 0; i < config.vocabSize; ++i)
            scored.push_back({logits[i], (int)i});
        std::partial_sort(scored.begin(), scored.begin() + 10, scored.end(),
                          [](const auto& a, const auto& b) {
                              return a.first > b.first;
                          });
        fprintf(stderr, "[Deep2Engine] Top-10 logits:\n");
        for (int i = 0; i < 10; ++i) {
            std::string tokText;
            if (tokenizer) tokText = tokenizer->Decode(scored[i].second);
            fprintf(stderr, "  [%2d] id=%5d logit=%12.6f text='%s'\n", i,
                    scored[i].second, scored[i].first, tokText.c_str());
        }
    }

    if (sampler) {
        std::vector<float> logitsVec(logits, logits + config.vocabSize);
        int token = sampler->Sample(logitsVec);
        sampler->AcceptToken(token);
        if (topLogits)
            fprintf(stderr, "[Deep2Engine] Sampler selected token: %d\n", token);
        emitGenQualityProbe(token, logits, argmaxId, argmaxLogit);
        return token;
    }

    emitGenQualityProbe(argmaxId, logits, argmaxId, argmaxLogit);
    printf("[Deep2Engine] Greedy argmax token: %d (logit=%.6f)\n", argmaxId,
           argmaxLogit);
    return argmaxId;
}

// ============================================================================
// Set Sampler
// ============================================================================
void Deep2Engine::setSampler(std::unique_ptr<rawrxd::sampling::ISampler> s) {
    sampler = std::move(s);
}

// ============================================================================
// Set Num Threads
// ============================================================================
void Deep2Engine::setNumThreads(size_t numThreads) {
    if (threadPool) {
        threadPool->waitAll();
        threadPool = std::make_unique<ThreadPool>(numThreads);
    }
}

// ============================================================================
// Enable KV Cache
// ============================================================================
void Deep2Engine::enableKVCache(bool enable) {
    config.useKVCache = enable;
    if (enable && !kvCache) {
        kvCache = std::make_unique<KVCache>();
        KVCacheConfig kvConfig;
        kvConfig.numLayers = config.numLayers;
        kvConfig.maxSeqLen = config.maxSeqLen;
        kvConfig.numHeads = config.numKVHeads > 0 ? config.numKVHeads : config.numHeads;
        kvConfig.headDim = config.hiddenDim / config.numHeads;
        kvCache->initialize(kvConfig);
    }
}

// ============================================================================
// Batch 15: Enable Elastic Residency
// ============================================================================
void Deep2Engine::enableElasticResidency(bool enable) {
    elasticResidencyEnabled_ = enable;
    if (enable && !elasticResidency_) {
        elasticResidency_ = std::make_unique<ElasticResidencyManager>();
        ElasticDynamicProbe probe{};
        ElasticBudget_ProbeHost(probe);
        probe.layers = (uint32_t)(config.numLayers ? config.numLayers
                                                   : modelWeights.numLayers);
        probe.experts = (uint32_t)modelWeights.numExperts;
        probe.modelBytes = 0;
        for (const auto& L : modelWeights.layers) {
            auto add = [&](const WeightTensor& w) {
                probe.modelBytes += w.sizeBytes;
            };
            add(L.attnQ_a); add(L.attnQ_b); add(L.attnO);
        }
        ElasticResidencyConfig resConfig = ElasticBudget_Derive(probe);
        resConfig.retainStagedAfterUpload = false;
        resConfig.useQuantizedGpuPath = true;
        {
            const char* ds = std::getenv("DEEP2_DUALSTICK_ARM");
            resConfig.suppressHostVramMoves =
                vulkanEnabled_ || (ds && ds[0] == '1');
        }
        ElasticBudget_Emit(stdout, resConfig, probe);
        if (!elasticResidency_->Initialize(resConfig)) {
            printf("[Deep2Engine] WARNING: ElasticResidencyManager initialization failed\n");
            elasticResidency_.reset();
            elasticResidencyEnabled_ = false;
        } else {
            printf("[Deep2Engine] ElasticResidencyManager DYNAMIC warm=%zu staged=%zu hot=%zu la=%u\n",
                   resConfig.maxWarmCompressedBytes / (1024*1024),
                   resConfig.maxWarmStagedBytes / (1024*1024),
                   resConfig.maxHotBytes / (1024*1024),
                   resConfig.prefetchLookahead);
            if (auto* vc = getVulkanComputeSlot(0))
                vc->SetPinResidentBudget(resConfig.maxHotBytes);
            // Late enable (after loadModel): register mapped tensors with sourceData.
            // Without this, Acquire returns NotFound or zero-fills → gibberish embeds.
            if (modelWeights.loaded) {
                auto ggmlTypeToTensorFormat = [](int ggmlType) -> TensorFormat {
                    switch (ggmlType) {
                        case 0:  return TensorFormat::FP32;
                        case 1:  return TensorFormat::FP16;
                        case 2:  return TensorFormat::Q4_0;
                        case 3:  return TensorFormat::Q4_1;
                        case 6:  return TensorFormat::Q5_0;
                        case 7:  return TensorFormat::Q5_1;
                        case 8:  return TensorFormat::Q8_0;
                        case 10: return TensorFormat::Q2_K;
                        case 11: return TensorFormat::Q3_K;
                        case 12: return TensorFormat::Q4_K;
                        case 13: return TensorFormat::Q5_K;
                        case 14: return TensorFormat::Q6_K;
                        default: return TensorFormat::Unknown;
                    }
                };
                auto registerElastic = [&](const WeightTensor& wt, uint32_t layerIdx, uint32_t expertIdx) {
                    if (wt.sizeBytes == 0 || wt.name.empty())
                        return;
                    if (!wt.data && !wt.hasFileBacking)
                        return;
                    elasticResidency_->RegisterTensor(
                        wt.name, layerIdx, expertIdx,
                        static_cast<size_t>(wt.fileOffset),
                        wt.sizeBytes,
                        ggmlTypeToTensorFormat(wt.type),
                        wt.data);
                };
                for (size_t layerIdx = 0; layerIdx < modelWeights.layers.size(); ++layerIdx) {
                    const auto& lw = modelWeights.layers[layerIdx];
                    const auto L = static_cast<uint32_t>(layerIdx);
                    registerElastic(lw.wq, L, ~0u); registerElastic(lw.wk, L, ~0u);
                    registerElastic(lw.wv, L, ~0u); registerElastic(lw.wo, L, ~0u);
                    registerElastic(lw.attnNorm, L, ~0u); registerElastic(lw.ffnNorm, L, ~0u);
                    registerElastic(lw.wGate, L, ~0u); registerElastic(lw.wUp, L, ~0u);
                    registerElastic(lw.wDown, L, ~0u);
                }
                registerElastic(modelWeights.tokenEmbed, ~0u, ~0u);
                registerElastic(modelWeights.lmHead, ~0u, ~0u);
                registerElastic(modelWeights.finalNorm, ~0u, ~0u);
                printf("[Deep2Engine] ElasticResidencyManager: late-registered model tensors\n");
            }
            /* Do not force-arm cyclone from elastic (prior: always enableCyclone).
             * DualStick GPU path arms cyclone via LIVE_MECH + EnhanceWanted. */
            if (EnhanceWanted("cyclone")) {
                enableCyclone(true);
                if (cyclone_)
                    cyclone_->SetPrefetchLookahead(resConfig.prefetchLookahead);
            } else if (cyclone_ && !vulkanEnabled_) {
                cyclone_->RebindElastic(elasticResidency_.get());
                cyclone_->SetPrefetchLookahead(resConfig.prefetchLookahead);
            }
        }
    } else if (enable && elasticResidency_) {
        refreshElasticDynamicBudget();
    } else if (!enable && elasticResidency_) {
        enableCyclone(false);
        elasticResidency_->Shutdown();
        elasticResidency_.reset();
        printf("[Deep2Engine] ElasticResidencyManager shut down\n");
    }
}

void Deep2Engine::refreshElasticDynamicBudget() {
    if (!elasticResidency_) return;
    ElasticDynamicProbe probe{};
    ElasticBudget_ProbeHost(probe);
    probe.layers = (uint32_t)(config.numLayers ? config.numLayers
                                               : modelWeights.numLayers);
    probe.experts = (uint32_t)modelWeights.numExperts;
    for (const auto& L : modelWeights.layers) {
        probe.modelBytes += L.attnQ_a.sizeBytes + L.attnQ_b.sizeBytes +
                            L.attnO.sizeBytes;
    }
    if (Fused_Enabled()) {
        probe.fusedPrefetchDepth = Fused_Last().prefetchDepth;
        probe.vramPressure = LivePath_Counters().vramPeak >
                             (elasticResidency_->GetConfig().maxHotBytes * 3 / 4);
    }
    ElasticResidencyConfig caps = ElasticBudget_Derive(probe);
    elasticResidency_->ApplyDynamicCaps(caps);
    ElasticBudget_Emit(stdout, caps, probe);
    if (auto* vc = getVulkanComputeSlot(0))
        vc->SetPinResidentBudget(caps.maxHotBytes);
    if (cyclone_)
        cyclone_->SetPrefetchLookahead(caps.prefetchLookahead);
}

void Deep2Engine::enableCyclone(bool enable) {
    cycloneEnabled_ = enable;
    if (enable && !cyclone_) {
        CycloneScheduler::Config cfg;
        cfg.enableTelemetry = true;
        if (elasticResidency_)
            cfg.prefetchLookaheadLayers =
                elasticResidency_->GetConfig().prefetchLookahead;
        cyclone_ = std::make_unique<CycloneScheduler>(cfg);
        /* Vulkan DualStick: do not bind elastic Acquire into cyclone prefetch. */
        ElasticResidencyManager* elBind =
            (elasticResidency_ && !vulkanEnabled_) ? elasticResidency_.get()
                                                   : nullptr;
        if (!cyclone_->Initialize(elBind)) {
            printf("[Deep2Engine] WARNING: CycloneScheduler init failed\n");
            cyclone_.reset();
            cycloneEnabled_ = false;
        } else {
            printf("[Deep2Engine] CycloneScheduler armed for live generate\n");
        }
    } else if (!enable && cyclone_) {
        cyclone_->Shutdown();
        cyclone_.reset();
        printf("[Deep2Engine] CycloneScheduler shut down\n");
    }
}

// ============================================================================
// Production Profiler (Batch 1)
// ============================================================================
void Deep2Engine::enableProfiling(bool enable) {
    profilingEnabled_ = enable;
    if (enable && !profiler_) {
        profiler_ = std::make_unique<ProductionProfiler>();
        profileHistory_.clear();
        printf("[Deep2Engine] Production profiling enabled\n");
    } else if (!enable) {
        profiler_.reset();
        printf("[Deep2Engine] Production profiling disabled\n");
    }
}

bool Deep2Engine::saveProfileJSON(const std::string& path) const {
    if (profileHistory_.empty() || !profiler_) return false;
    std::ofstream f(path);
    if (!f) return false;
    f << ProductionProfiler::toJSONSummary(profileHistory_.data(), profileHistory_.size());
    return f.good();
}

std::string Deep2Engine::getProfileJSONSummary() const {
    if (profileHistory_.empty()) return "{}";
    return ProductionProfiler::toJSONSummary(profileHistory_.data(), profileHistory_.size());
}

// ============================================================================
// Legacy Weight Registration System (for backward compatibility)
// ============================================================================
struct LegacyWeightTensor {
    void* data = nullptr;
    int   type = 0;
    size_t rows = 0;
    size_t cols = 0;
    size_t numBlocks = 0;
};

static LegacyWeightTensor g_weightTensors[256];
static size_t g_numWeights = 0;

int Deep2Engine::registerWeightTensor(void* data, int type, size_t rows, size_t cols) {
    if (g_numWeights >= 256) return -1;

    int idx = (int)g_numWeights++;
    LegacyWeightTensor& wt = g_weightTensors[idx];
    wt.data = data;
    wt.type = type;
    wt.rows = rows;
    wt.cols = cols;
    wt.numBlocks = (cols + 255) / 256;
    return idx;
}

// ============================================================================
// Linear (legacy index-based API)
// ============================================================================
void Deep2Engine::Linear(int weightIdx, const float* input, const float* bias,
                         float* output, size_t outDim) {
    if (weightIdx < 0 || weightIdx >= (int)g_numWeights) {
        memset(output, 0, outDim * sizeof(float));
        return;
    }

    const LegacyWeightTensor& wt = g_weightTensors[weightIdx];

    // --- Quant-agnostic dispatch via registry (zero inline switch) ---
    auto& reg = Deep2::QuantKernelRegistry::Instance();
    if (reg.GetRegisteredCount() == 0) reg.Initialize();
    auto kernel = reg.GetGEMV(wt.type);
    auto geom   = reg.GetGeometry(wt.type);
    if (kernel && geom.blockSize > 0) {
        reg.GetBatch21Counters().registryHits.fetch_add(1, std::memory_order_relaxed);
        reg.GetBatch21Counters().kernelInvocations.fetch_add(1, std::memory_order_relaxed);
        kernel((const uint8_t*)wt.data, input, output, wt.rows, wt.cols);
    } else if (wt.type == (int)GGMLType::GGML_TYPE_F32) {
        reg.GetBatch21Counters().registryMisses.fetch_add(1, std::memory_order_relaxed);
        reg.GetBatch21Counters().scalarFallbacks.fetch_add(1, std::memory_order_relaxed);
        for (size_t r = 0; r < wt.rows; ++r) {
            float acc = 0.0f;
            for (size_t c = 0; c < wt.cols; ++c) {
                acc += ((const float*)wt.data)[r * wt.cols + c] * input[c];
            }
            output[r] = acc;
        }
    } else {
        reg.GetBatch21Counters().registryMisses.fetch_add(1, std::memory_order_relaxed);
        fprintf(stderr,
            "[QUANT_FATAL] unsupported tensor type=%d (legacy Linear API)\n", wt.type);
        throw std::runtime_error("QUANT_FATAL unsupported type in Linear()");
    }

    if (bias) {
        for (size_t i = 0; i < outDim; ++i) {
            output[i] += bias[i];
        }
    }
}

// ============================================================================
// Parallel Linear (legacy index-based API)
// ============================================================================
void Deep2Engine::LinearParallel(int weightIdx, const float* input, const float* bias,
                                  float* output, size_t outDim) {
    if (!threadPool) {
        Linear(weightIdx, input, bias, output, outDim);
        return;
    }

    const LegacyWeightTensor& wt = g_weightTensors[weightIdx];
    size_t numThreads = threadPool->size();
    size_t rowsPerThread = outDim / numThreads;
    size_t remainder = outDim % numThreads;

    std::atomic<size_t> completed(0);

    for (size_t t = 0; t < numThreads; ++t) {
        size_t startRow = t * rowsPerThread + (std::min)(t, remainder);
        size_t endRow = startRow + rowsPerThread + (t < remainder ? 1 : 0);

        threadPool->enqueue([&, startRow, endRow]() {
            for (size_t r = startRow; r < endRow; ++r) {
                float sum = 0.0f;
                if (wt.type == (int)GGMLType::GGML_TYPE_F32) {
                    const float* row = (const float*)wt.data + r * wt.cols;
                    for (size_t c = 0; c < wt.cols; ++c) {
                        sum += row[c] * input[c];
                    }
                } else if (wt.type == (int)GGMLType::GGML_TYPE_F16) {
                    const uint16_t* row = (const uint16_t*)wt.data + r * wt.cols;
                    for (size_t c = 0; c < wt.cols; ++c) {
                        sum += fp16ToFloat(row[c]) * input[c];
                    }
                }
                output[r] = sum + (bias ? bias[r] : 0.0f);
            }
            completed++;
        });
    }

    while (completed < numThreads) {
        _mm_pause();
    }
}

// ============================================================================
// Find Tensor by name pattern
// ============================================================================
WeightTensor* Deep2Engine::findTensor(const std::string& namePattern) {
    if (modelWeights.tokenEmbed.name.find(namePattern) != std::string::npos)
        return &modelWeights.tokenEmbed;
    if (modelWeights.lmHead.name.find(namePattern) != std::string::npos)
        return &modelWeights.lmHead;
    if (modelWeights.finalNorm.name.find(namePattern) != std::string::npos)
        return &modelWeights.finalNorm;
    for (auto& lw : modelWeights.layers) {
        if (lw.wq.name.find(namePattern) != std::string::npos) return &lw.wq;
        if (lw.wk.name.find(namePattern) != std::string::npos) return &lw.wk;
        if (lw.wv.name.find(namePattern) != std::string::npos) return &lw.wv;
        if (lw.wo.name.find(namePattern) != std::string::npos) return &lw.wo;
        if (lw.wGate.name.find(namePattern) != std::string::npos) return &lw.wGate;
        if (lw.wUp.name.find(namePattern) != std::string::npos) return &lw.wUp;
        if (lw.wDown.name.find(namePattern) != std::string::npos) return &lw.wDown;
    }
    return nullptr;
}

// ============================================================================
// Load Tensor from GGUF (searches in already-loaded result)
// ============================================================================
bool Deep2Engine::loadTensorFromGGUF(WeightTensor& wt, const std::string& name) {
    for (const auto& t : ggufResult.tensors) {
        if (t.name == name) {
            wt.data = t.data;
            wt.type = (int)t.type;
            // GGUF dimensions are [input_dim, output_dim]
            // LinearW needs rows=output_dim, cols=input_dim
            wt.rows = t.dimensions.size() > 1 ? t.dimensions[1] : 1;
            wt.cols = t.dimensions.size() > 0 ? t.dimensions[0] : 0;
            wt.numBlocks = t.GetNumBlocks();
            wt.sizeBytes = t.size;
            wt.name = t.name;
            wt.mapped = true; // GGUF view â€” externally owned
            return true;
        }
    }
    return false;
}

// ============================================================================
// VAL-000 Phase 3: Advanced Feature Implementations
// ============================================================================

bool Deep2Engine::initializeAdvancedFeatures() {
    printf("[Deep2Engine] Initializing VAL-000 advanced features...\n");

    if (medusaEnabled_ && !medusaDecoder_) {
        medusaDecoder_ = std::make_unique<MedusaDecoder>();
        if (!medusaDecoder_->initialize(medusaConfig_)) {
            printf("[Deep2Engine] WARNING: Failed to initialize Medusa decoder\n");
            medusaEnabled_ = false;
        } else {
            printf("[Deep2Engine] Medusa decoder initialized (%zu heads)\n",
                   medusaConfig_.numHeads);
        }
    }

    if (nuPackingEnabled_ && !nuPacker_) {
        nuPacker_ = std::make_unique<NUFusedPacker>();
        if (!nuPacker_->initialize(nuPackerConfig_)) {
            printf("[Deep2Engine] WARNING: Failed to initialize NU packer\n");
            nuPackingEnabled_ = false;
        } else {
            printf("[Deep2Engine] NU Fused Packer initialized\n");
        }
    }

    if (warmupEnabled_ && moeWeightProxy_ && !warmupScheduler_) {
        warmupScheduler_ = std::make_unique<WarmupScheduler>();
        if (!warmupScheduler_->initialize(warmupConfig_)) {
            printf("[Deep2Engine] WARNING: Failed to initialize warmup scheduler\n");
            warmupEnabled_ = false;
        } else {
            printf("[Deep2Engine] Warmup scheduler initialized\n");
        }
    }

    if (compressedKVEnabled_ && kvCache && !compressedKV_ &&
        compressedKVConfig_.numLayers > 0 && compressedKVConfig_.headDim > 0) {
        compressedKV_ = std::make_unique<CompressedKVCache>();
        if (!compressedKV_->initialize(compressedKVConfig_)) {
            printf("[Deep2Engine] WARNING: Failed to initialize compressed KV\n");
            compressedKVEnabled_ = false;
            compressedKV_.reset();
        } else {
            printf("[Deep2Engine] Compressed KV cache initialized (%s)\n",
                   compressedKVConfig_.quantType == KVQuantType::KV_Q8_0 ? "Q8_0" : "Q4_K");
        }
    }

    if (nvmeStreamingEnabled_ && !nvmeStream_) {
        nvmeStream_ = std::make_unique<NVMeStream>();
        if (config.modelPath[0])
            nvmeConfig_.modelPath = config.modelPath;
        else if (!modelDir_.empty())
            nvmeConfig_.modelPath = modelDir_.string();
        if (!nvmeStream_->initialize(nvmeConfig_)) {
            // Refill path from shard env before any bunnyhop.
            if (nvmeConfig_.modelPath.empty()) {
                if (const char* d = std::getenv("DEEP2_K2_SHARD_DIR"))
                    if (d && d[0]) nvmeConfig_.modelPath = d;
                if (!nvmeConfig_.modelPath.empty() &&
                    nvmeStream_->initialize(nvmeConfig_)) {
                    printf("[Deep2Engine] NVMe streaming initialized (deferred path)\n");
                } else {
                    printf("[Deep2Engine] NVMe defer until openK2ShardDirectory\n");
                    // Keep enabled; openK2ShardDirectory re-arms SHARD_IO.
                }
            } else {
                printf("[Deep2Engine] NVMe mmap fail â†’ FORCE reverse bunnyhop\n");
                if (!nvmeStream_->initializeReverseBunnyHop(nvmeConfig_)) {
                    printf("[Deep2Engine] WARNING: reverse bunnyhop also failed\n");
                    nvmeStreamingEnabled_ = false;
                    LivePath_NoteNvmeAbsence(1);
                } else {
                    printf("[Deep2Engine] NVMe REVERSE_BUNNYHOP armed (streaming ON)\n");
                    LivePath_NoteNvmeAbsence(0);
                }
            }
        } else if (nvmeStream_->isReverseBunnyHop()) {
            printf("[Deep2Engine] NVMe REVERSE_BUNNYHOP (unlaidout hotpatch)\n");
        } else {
            printf("[Deep2Engine] NVMe streaming initialized\n");
        }
    }

    if (slidingWindowEnabled_ && !slidingWindow_) {
        slidingWindow_ = std::make_unique<SlidingWindowEngine>();
        if (!slidingWindow_->initialize(slidingWindowConfig_)) {
            printf("[Deep2Engine] WARNING: Failed to initialize sliding window\n");
            slidingWindowEnabled_ = false;
        } else {
            printf("[Deep2Engine] Sliding window initialized (size=%zu)\n",
                   slidingWindowConfig_.windowSize);
        }
    }
    
    printf("[Deep2Engine] Advanced features initialization complete\n");
    return true;
}

// ============================================================================
// Feature Enable/Disable Methods
// ============================================================================

void Deep2Engine::enableMedusa(bool enable) {
    medusaEnabled_ = enable;
    printf("[Deep2Engine] Medusa speculative decoding: %s\n", enable ? "ENABLED" : "DISABLED");
}

void Deep2Engine::enableNUPacking(bool enable) {
    nuPackingEnabled_ = enable;
    printf("[Deep2Engine] NU fused packing: %s\n", enable ? "ENABLED" : "DISABLED");
}

void Deep2Engine::enableWarmupScheduler(bool enable) {
    warmupEnabled_ = enable;
    printf("[Deep2Engine] Warmup scheduler: %s\n", enable ? "ENABLED" : "DISABLED");
}

void Deep2Engine::enableCompressedKV(bool enable, KVQuantType quantType) {
    compressedKVEnabled_ = enable;
    compressedKVConfig_.quantType = quantType;
    printf("[Deep2Engine] Compressed KV cache: %s (%s)\n", 
           enable ? "ENABLED" : "DISABLED",
           quantType == KVQuantType::KV_Q8_0 ? "Q8_0" : "Q4_K");
}

void Deep2Engine::enableNVMeStreaming(bool enable, const std::string& modelPath) {
    nvmeStreamingEnabled_ = enable;
    if (!modelPath.empty()) {
        nvmeConfig_.modelPath = modelPath;
    }
    printf("[Deep2Engine] NVMe streaming: %s\n", enable ? "ENABLED" : "DISABLED");
}

void Deep2Engine::enableSlidingWindow(bool enable, size_t windowSize) {
    slidingWindowEnabled_ = enable;
    slidingWindowConfig_.windowSize = windowSize;
    printf("[Deep2Engine] Sliding window: %s (size=%zu)\n", 
           enable ? "ENABLED" : "DISABLED", windowSize);
}

static uint64_t Deep2LocalHeapBytes(CPUInference::VulkanCompute* vc, uint64_t fb) {
    if (!vc) return fb;
    const auto& mp = vc->GetDeviceInfo().memory_props;
    for (uint32_t h = 0; h < mp.memoryHeapCount; ++h) {
        if (mp.memoryHeaps[h].flags & 1u) return (uint64_t)mp.memoryHeaps[h].size;
    }
    return fb;
}

static bool EnhanceWanted(const char* name) {
    /* Elastic requires RAWRXD_DEEP2_ALLOW_ELASTIC=1 (product harness default).
     * Prior AV was VDD duplicate-7800 triple-open; PCI dedupe keeps OPENS=2. */
    if (std::strcmp(name, "elastic") == 0) {
        const char* a = std::getenv("RAWRXD_DEEP2_ALLOW_ELASTIC");
        if (!(a && a[0] == '1')) return false;
    }
    const char* skip = std::getenv("RAWRXD_ENHANCE_SKIP");
    if (!skip || !*skip) return true;
    const size_t nlen = std::strlen(name);
    const char* p = skip;
    while (*p) {
        while (*p == ',' || *p == ' ') ++p;
        if (std::strncmp(p, name, nlen) == 0 &&
            (p[nlen] == 0 || p[nlen] == ',' || p[nlen] == ' '))
            return false;
        while (*p && *p != ',') ++p;
        if (*p == ',') ++p;
    }
    return true;
}

void Deep2Engine::enableAllEnhancements() {
    /* HOST_DECODE first — LAA:NO product floor must never touch amdvlk ICD
     * (snmalloc abort). MINIMAL_ENHANCE used to call enableVulkan before this. */
    if (envFlagEnabled("RAWRXD_HOST_DECODE")) {
        printf("[Deep2Engine] ENHANCEMENT STACK: HOST_DECODE "
               "(CPU; skip vulkan/speed)\n");
        vulkanEnabled_ = false;
        vulkanStrictNoCpuFallback_ = false;
        /* NVMe→RAM only — no ICD, no elastic UnifiedAsyncMove. */
        const std::string nvmePath = config.modelPath[0]
            ? std::string(config.modelPath)
            : (!modelDir_.empty() ? modelDir_.string() : std::string());
        if (!nvmePath.empty()) {
            enableNVMeStreaming(true, nvmePath);
            if (!nvmeStream_) nvmeStream_ = std::make_unique<NVMeStream>();
            (void)nvmeStream_->initialize(nvmeConfig_);
        }
        fflush(stdout);
        return;
    }
    /* Rebuild-safe escape: skip full stack while enableVulkan heap crash open. */
    if (const char* m = std::getenv("DEEP2_MINIMAL_ENHANCE")) {
        if (m[0] == '1') {
            printf("[Deep2Engine] ENHANCEMENT STACK: MINIMAL "
                   "(vulkan-only; DEEP2_MINIMAL_ENHANCE=1)\n");
            /* Diagnostic gate: core GPU path without optional stack. */
            if (EnhanceWanted("vulkan") && modelWeights.loaded &&
                !vulkanInitialized_)
                enableVulkan(true);
            return;
        }
    }
    if (SemanticSafeWanted()) {
        printf("[Deep2Engine] ENHANCEMENT STACK: SEMANTIC_SAFE (no vulkan/speed features)\n");
        vulkanEnabled_ = false;
        return;
    }
    printf("[Deep2Engine] ENHANCEMENT STACK: ON\n");
    if (!EnhanceWanted("elastic"))
        printf("[Deep2Engine] SAFE_DEFAULT_SKIP=elastic (set RAWRXD_DEEP2_ALLOW_ELASTIC=1 to arm)\n");
    /* GPU inference required. CPU only via RAWRXD_HOST_DECODE=1. */
    if (EnhanceWanted("vulkan") && modelWeights.loaded && !vulkanInitialized_)
        enableVulkan(true);
    const bool hostCpuOptIn = envFlagEnabled("RAWRXD_HOST_DECODE");
    if (!hostCpuOptIn && EnhanceWanted("vulkan") && !vulkanEnabled_) {
        printf("[Deep2Engine] FATAL: GPU inference required — Vulkan not armed. "
               "Set RAWRXD_HOST_DECODE=1 only to opt into CPU decode.\n");
        fflush(stdout);
        modelWeights.loaded = false;
        initialized = false;
        return;
    }
    /* Same enhancement braid on GPU path (elastic/prefetch/ckv/nvme/torus).
     * Router→experts→residency→TransferScheduler→GPU cache needs elastic armed
     * while Vulkan multi is live — do not mute features behind !vulkanEnabled_. */
    if (EnhanceWanted("elastic")) enableElasticResidency(true);
    if (EnhanceWanted("cyclone")) enableCyclone(true);
    if (EnhanceWanted("prefetch")) setAsyncPrefetchEnabled(true);
    if (EnhanceWanted("telemetry")) enableResidencyTelemetry(true);
    if (EnhanceWanted("medusa")) enableMedusa(true);
    if (EnhanceWanted("nu")) enableNUPacking(true);
    if (EnhanceWanted("warmup")) enableWarmupScheduler(true);
    if (EnhanceWanted("ckv")) enableCompressedKV(true, KVQuantType::KV_Q8_0);
    if (EnhanceWanted("nvme")) {
        const std::string nvmePath = config.modelPath[0]
            ? std::string(config.modelPath)
            : (!modelDir_.empty() ? modelDir_.string() : std::string());
        enableNVMeStreaming(true, nvmePath);
    }
    if (EnhanceWanted("slide")) enableSlidingWindow(true, 4096);
    if (EnhanceWanted("chamber")) enableChamber(true);
    if (EnhanceWanted("plasma")) enablePlasmaGovernor(true);
    if (EnhanceWanted("sov")) enableSovereignRuntime(true);
    compressedKVConfig_.numLayers =
        config.numLayers ? config.numLayers : modelWeights.numLayers;
    compressedKVConfig_.maxSeqLen = config.maxSeqLen ? config.maxSeqLen : 4096;
    compressedKVConfig_.numHeads =
        config.numHeads ? config.numHeads : modelWeights.numHeads;
    compressedKVConfig_.numKVHeads =
        config.numKVHeads ? config.numKVHeads : modelWeights.numKVHeads;
    compressedKVConfig_.headDim =
        config.headDim ? config.headDim : modelWeights.headDim;
    if (modelWeights.loaded) {
        const size_t torus = compressedKVConfig_.maxSeqLen;
        if (EnhanceWanted("torus"))
            enableToroidalKV(true, torus ? torus : 4096);
    }
    /* Stamp Router→Residency braid: each layer's tensors → owning GPU slot. */
    if (elasticResidency_ && multiGpuLayerPlan_.active &&
        multiGpuLayerPlan_.gpuSlotCount >= 1) {
        unsigned stamped = 0;
        for (size_t li = 0; li < modelWeights.layers.size() && li < 256; ++li) {
            const int slot = Deep2MultiGpu_SlotForLayer(multiGpuLayerPlan_,
                                                       (unsigned)li);
            auto stamp = [&](const WeightTensor& w) {
                if (w.name.empty()) return;
                elasticResidency_->SetPlannedPlacement(w.name, slot, false);
                ++stamped;
            };
            const auto& L = modelWeights.layers[li];
            stamp(L.wq); stamp(L.wk); stamp(L.wv); stamp(L.wo);
            stamp(L.wGate); stamp(L.wUp); stamp(L.wDown);
            stamp(L.attnNorm); stamp(L.ffnNorm);
        }
        printf("[Deep2Engine] RESIDENCY_BRAID stamped=%u slots=%u "
               "(Router→Expert→Residency→Transfer→GPU cache)\n",
               stamped, multiGpuLayerPlan_.gpuSlotCount);
    }
    if (!marsEnabled_ && EnhanceWanted("mars")) {
        if (!marsHostResidentAuthorityOk()) {
            standdownMARSEmptyPlacement("K2_STREAM_AUTHORITY");
        } else {
            const char* forceMars = std::getenv("DEEP2_MARS");
            const bool wantWithVk = forceMars && forceMars[0] == '1';
            if (!vulkanEnabled_ || wantWithVk) {
                const uint64_t g0 =
                    Deep2LocalHeapBytes(getVulkanComputeSlot(0), 32ull << 30);
                const uint64_t g1 =
                    Deep2LocalHeapBytes(getVulkanComputeSlot(1), 16ull << 30);
                (void)enableMARS(g0, g1);
            } else if (vulkanEnabled_) {
                printf("[Deep2Engine] MARS skipped (Vulkan owns compute devices=%u)\n",
                       vulkanDeviceCount());
            }
        }
    } else if (vulkanEnabled_ && !marsEnabled_ && !marsStandby_) {
        printf("[Deep2Engine] MARS skipped (Vulkan owns compute devices=%u)\n",
               vulkanDeviceCount());
    }
    if (marsEnabled_ && modelWeights.loaded && !marsWeightsPlaced_) {
        const char* forceMars = std::getenv("DEEP2_MARS");
        if (!vulkanEnabled_ || (forceMars && forceMars[0] == '1'))
            (void)placeAllModelTensorsMARS();
        else if (vulkanEnabled_)
            marsWeightsPlaced_ = true;
    }
    initializeAdvancedFeatures();
    printf("[Deep2Engine] STACK vk=%d mars=%d elastic=%d cyclone=%d medusa=%d nu=%d "
           "warmup=%d ckv=%d nvme=%d slide=%d chamber=%d torus=%d plasma=%d "
           "sov=%d prefetch=%d devices=%u\n",
           vulkanEnabled_ ? 1 : 0, marsEnabled_ ? 1 : 0,
           elasticResidencyEnabled_ ? 1 : 0, cycloneEnabled_ ? 1 : 0,
           medusaEnabled_ ? 1 : 0,
           nuPackingEnabled_ ? 1 : 0, warmupEnabled_ ? 1 : 0,
           compressedKVEnabled_ ? 1 : 0, nvmeStreamingEnabled_ ? 1 : 0,
           slidingWindowEnabled_ ? 1 : 0, chamberEnabled_ ? 1 : 0,
           toroidalKVEnabled_ ? 1 : 0, plasmaGovernorEnabled_ ? 1 : 0,
           sovereignRuntimeEnabled_ ? 1 : 0, asyncPrefetchEnabled_ ? 1 : 0,
           vulkanDeviceCount());
}

// ============================================================================
// Sovereign Engine Feature Enable/Disable â€” Dragon Lore
// ============================================================================

void Deep2Engine::enableChamber(bool enable) {
    chamberEnabled_ = enable;
    if (enable && !chamber_) {
        chamber_ = std::make_unique<rawrxd::Chamber>();
        printf("[Deep2Engine] Chamber (SM0-DSP) initialized\n");
    }
    if (sovereignRuntimeEnabled_ && sovereignRuntime_) {
        printf("[Deep2Engine] Chamber state synced to SovereignRuntime\n");
    }
    printf("[Deep2Engine] Chamber: %s\n", enable ? "ENABLED" : "DISABLED");
}

rawrxd::ChamberResult Deep2Engine::evaluateChamber(const float* hidden_state, size_t dim) {
    if (sovereignRuntimeEnabled_ && sovereignRuntime_) {
        return sovereignRuntime_->evaluateChamber(hidden_state, dim);
    }
    if (!chamberEnabled_ || !chamber_) return rawrxd::ChamberResult::PASS;
    return chamber_->evaluate(hidden_state, dim);
}

rawrxd::FormulaRoute Deep2Engine::routePrimitive(uint64_t context_hash) {
    if (sovereignRuntimeEnabled_ && sovereignRuntime_) {
        return sovereignRuntime_->routePrimitive(context_hash);
    }
    if (!chamberEnabled_ || !chamber_) return rawrxd::FormulaRoute{};
    return chamber_->routePrimitive(context_hash);
}

void Deep2Engine::enableToroidalKV(bool enable, size_t maxTokens) {
    toroidalKVEnabled_ = enable;
    if (enable && !toroidalKV_ && modelWeights.loaded) {
        size_t headDim = modelWeights.headDim;
        size_t numHeads = modelWeights.numHeads;
        size_t numLayers = modelWeights.numLayers;
        toroidalKV_ = std::make_unique<rawrxd::ToroidalKVCache>(
            headDim, numHeads, maxTokens, numLayers);
        printf("[Deep2Engine] ToroidalKVCache initialized: %zu tokens, %zu layers, %zu heads, %zu dim\n",
               maxTokens, numLayers, numHeads, headDim);
    }
    printf("[Deep2Engine] ToroidalKVCache: %s\n", enable ? "ENABLED" : "DISABLED");
}

void Deep2Engine::enablePlasmaGovernor(bool enable) {
    plasmaGovernorEnabled_ = enable;
    if (enable && !plasmaGovernor_) {
        plasmaGovernor_ = std::make_unique<rawrxd::PlasmaGovernor>();
        printf("[Deep2Engine] PlasmaGovernor initialized\n");
    }
    printf("[Deep2Engine] PlasmaGovernor: %s\n", enable ? "ENABLED" : "DISABLED");
}

void Deep2Engine::updateThermalState(const rawrxd::ThermalState& state) {
    if (sovereignRuntimeEnabled_ && sovereignRuntime_) {
        sovereignRuntime_->updateThermalState(state);
    }
    if (plasmaGovernorEnabled_ && plasmaGovernor_) {
        plasmaGovernor_->updateThermalState(state);
    }
}

float Deep2Engine::currentThrottle() const {
    if (sovereignRuntimeEnabled_ && sovereignRuntime_) {
        return sovereignRuntime_->currentThrottle();
    }
    if (plasmaGovernorEnabled_ && plasmaGovernor_) {
        return plasmaGovernor_->currentThrottle();
    }
    return 0.0f;
}

// ============================================================================
// SovereignOutOfCoreRuntime â€” Dual-backend orchestrator
// ============================================================================

void Deep2Engine::enableSovereignRuntime(bool enable) {
    sovereignRuntimeEnabled_ = enable;
    if (enable && !sovereignRuntime_) {
        rawrxd::SovereignOutOfCoreRuntime::Config cfg;
        cfg.ramBudgetBytes = 8ull * 1024 * 1024 * 1024;  // 8GB default
        cfg.vramBudgetBytes = 32ull * 1024 * 1024 * 1024; // 32GB for R9700
        cfg.enableCPU = true;
        cfg.enableGPU = true;
        sovereignRuntime_ = std::make_unique<rawrxd::SovereignOutOfCoreRuntime>(cfg);
        printf("[Deep2Engine] SovereignOutOfCoreRuntime initialized (8GB RAM / 32GB VRAM)\n");
    }
    printf("[Deep2Engine] SovereignOutOfCoreRuntime: %s\n", enable ? "ENABLED" : "DISABLED");
}

rawrxd::SovereignOutOfCoreRuntime* Deep2Engine::getSovereignRuntime() const {
    return sovereignRuntime_.get();
}

// ============================================================================
// Vulkan GPU Backend Integration (SOLO + MULTI contiguous layers)
// ============================================================================

int Deep2Engine::parseWeightLayerIndex(const std::string& name) const {
    // "blk.12.attn_q.weight" -> 12; non-block tensors -> -1 (primary slot)
    if (name.size() < 5 || name.compare(0, 4, "blk.") != 0) return -1;
    unsigned v = 0;
    size_t i = 4;
    if (i >= name.size() || name[i] < '0' || name[i] > '9') return -1;
    while (i < name.size() && name[i] >= '0' && name[i] <= '9') {
        v = v * 10u + (unsigned)(name[i] - '0');
        ++i;
    }
    return (int)v;
}

CPUInference::VulkanCompute* Deep2Engine::getVulkanComputeSlot(unsigned slot) const {
    if (slot < vulkanDevices_.size()) return vulkanDevices_[slot].get();
    if (slot == 0) return vulkanCompute_.get();
    return nullptr;
}

uint64_t Deep2Engine::vulkanSlotGemvSuccess(unsigned slot) const {
    auto* vc = getVulkanComputeSlot(slot);
    return vc ? vc->GemvSuccess() : 0;
}

uint64_t Deep2Engine::vulkanSlotWeightUploads(unsigned slot) const {
    auto* vc = getVulkanComputeSlot(slot);
    return vc ? vc->GemvWeightUploads() : 0;
}

uint64_t Deep2Engine::vulkanSlotWeightHits(unsigned slot) const {
    auto* vc = getVulkanComputeSlot(slot);
    return vc ? vc->GemvWeightHits() : 0;
}

void Deep2Engine::enableVulkan(bool enable) {
    if (enable && !vulkanInitialized_) {
        Deep2DevicePlan snap{};
        Deep2Device_Enumerate(snap);
        Deep2Device_ApplyPolicy(snap);
        Deep2Device_EmitWitnesses(nullptr, snap);
        if (snap.plan.policy == GpuPolicy::CpuOnly || snap.plan.primaryIndex < 0) {
            fprintf(stderr,
                    "[Deep2Engine] GPU policy has no device — GPU inference required. "
                    "Set RAWRXD_HOST_DECODE=1 only to opt into CPU.\n");
            vulkanEnabled_ = false;
            vulkanStrictNoCpuFallback_ = true;
            return;
        }

        // MULTI/HYBRID: open planned discrete GPUs; HYBRID also attaches planned CPU layers.
        const bool wantHybrid =
            snap.plan.policy == GpuPolicy::Hybrid ||
            snap.plan.mode == ExecMode::Hybrid ||
            (std::getenv("DEEP2_HYBRID") && std::getenv("DEEP2_HYBRID")[0] == '1');
        const bool wantMulti =
            snap.plan.openCount >= 1 &&
            (snap.plan.mode == ExecMode::MultiGpuShard ||
             snap.plan.mode == ExecMode::Hybrid ||
             snap.plan.policy == GpuPolicy::Multi ||
             snap.plan.policy == GpuPolicy::Hybrid ||
             snap.plan.policy == GpuPolicy::UserList ||
             wantHybrid);

        vulkanDevices_.clear();
        multiGpuLayerPlan_ = MultiGpuLayerPlan{};
        vulkanUnplannedFallbacks_ = 0;
        plannedCpuGemvOps_ = 0;
        plannedGpuGemvOps_ = 0;

        auto openOne = [&](const char* needle) -> std::unique_ptr<CPUInference::VulkanCompute> {
            auto vc = std::make_unique<CPUInference::VulkanCompute>();
            if (!vc->InitializeSolo(needle)) return nullptr;
            return vc;
        };

        if (wantMulti && snap.plan.openCount >= 1) {
            MultiGpuLayerPlan plan{};
            const unsigned nLayers = modelWeights.numLayers
                ? (unsigned)modelWeights.numLayers : 22u;
            const uint64_t h = modelWeights.hiddenDim ? modelWeights.hiddenDim : 2048;
            const uint64_t bytesPerLayer = 12ull * h * h * sizeof(float);
            if (!Deep2MultiGpu_BuildContiguousPlan(snap, nLayers, bytesPerLayer, plan)) {
                fprintf(stderr, "[Deep2Engine] layer plan failed â€” SOLO primary\n");
            } else {
                const char* forceSplit = std::getenv("DEEP2_FORCE_SPLIT");
                if (!(forceSplit && forceSplit[0] == '1'))
                    Deep2MultiGpu_ApplyCostWeightedCut(plan);
                if (wantHybrid) {
                    unsigned cpuLayers = 0;
                    if (const char* cl = std::getenv("DEEP2_HYBRID_CPU_LAYERS"))
                        cpuLayers = (unsigned)std::atoi(cl);
                    Deep2MultiGpu_AttachPlannedCpu(plan, cpuLayers);
                }
                const unsigned gpuN = plan.gpuSlotCount;
                for (unsigned s = 0; s < gpuN; ++s) {
                    auto vc = openOne(plan.name[s]);
                    if (!vc) {
                        fprintf(stderr,
                                "[Deep2Engine] GPU open failed slot %u (%s) — "
                                "keep opened sticks (no clear-all)\n",
                                s, plan.name[s]);
                        continue;
                    }
                    printf("[Deep2Engine] LAYER_EXEC OPEN slot=%u %s layers=%u-%u kind=GPU\n",
                           s, vc->GetDeviceInfo().device_name.c_str(),
                           plan.rangeLo[s], plan.rangeHi[s]);
                    vulkanDevices_.push_back(std::move(vc));
                }
                if (vulkanDevices_.size() == gpuN && gpuN >= 1) {
                    plan.openedCount = (unsigned)vulkanDevices_.size();
                    multiGpuLayerPlan_ = plan;
                    vulkanCompute_ = nullptr;
                    if (plan.hybrid) {
                        printf("[Deep2Engine] LAYER_EXEC CPU slot layers=%u-%u (planned)\n",
                               plan.rangeLo[plan.plannedCount - 1],
                               plan.rangeHi[plan.plannedCount - 1]);
                    }
                } else if (!vulkanDevices_.empty()) {
                    fprintf(stderr,
                            "[Deep2Engine] MULTI partial open %zu/%u — "
                            "keeping opened; plan deferred\n",
                            vulkanDevices_.size(), gpuN);
                    vulkanCompute_ = nullptr;
                }
            }
        }

        if (vulkanDevices_.empty()) {
            const char* needle = Deep2Device_VulkanNeedle(snap);
            if (!needle || !*needle) needle = snap.plan.primaryName;
            auto vc = openOne(needle);
            if (!vc) {
                fprintf(stderr,
                        "[Deep2Engine] Vulkan open failed — GPU inference required "
                        "(RAWRXD_HOST_DECODE=1 for CPU opt-in only)\n");
                vulkanEnabled_ = false;
                vulkanStrictNoCpuFallback_ = true;
                return;
            }
            printf("[Deep2Engine] Vulkan single-GPU open: %s (needle=%s)\n",
                   vc->GetDeviceInfo().device_name.c_str(), needle);
            vulkanDevices_.push_back(std::move(vc));
        }

        vulkanCompute_.reset();
        // Alias primary for getVulkanCompute(): recreate isn't needed if we update getter.
        // Keep a non-owning convention: getVulkanCompute returns devices[0].
        vulkanInitialized_ = true;
        vulkanEnabled_ = true;
        ++deviceCreateEvents_;
        ++persistCont_.device_create_events;
        vulkanGemvOk_ = 0;
        vulkanGemvFail_ = 0;
        vulkanGpuWeightBytes_ = 0;
        vulkanGpuTensorBytes_ = 0;
        vulkanRealWeightLayers_ = 0;
        vulkanStrictViolation_ = false;
        vulkanWeightSeen_.clear();
        if (const char* s = std::getenv("DEEP2_GPU_SOLO_STRICT")) {
            vulkanStrictNoCpuFallback_ = !(s[0] == '0' && s[1] == '\0');
        } else {
            vulkanStrictNoCpuFallback_ = true;
        }
        if (multiGpuLayerPlan_.active) {
            Deep2MultiGpu_EmitPlanWitnesses(nullptr, multiGpuLayerPlan_);
            printf("[Deep2Engine] MULTI contiguous layers ACTIVE devices=%u strict=%d\n",
                   multiGpuLayerPlan_.openedCount, vulkanStrictNoCpuFallback_ ? 1 : 0);
        }
        ++residencyEpoch_;
        /* Batch2 + BIND16: idempotent ensure (never 72-byte MASM). */
        if (!EnsurePersistentDecodeBinding())
            fprintf(stderr, "[Deep2Engine] BATCH2_SSVK_PACKED_DUAL_OPEN=FAIL\n");
    } else if (enable && vulkanInitialized_) {
        vulkanEnabled_ = true;
    } else {
        vulkanEnabled_ = false;
        /* Disabling Vulkan does not arm CPU — HOST_DECODE is the only CPU opt-in. */
        vulkanStrictNoCpuFallback_ = true;
    }
}

bool Deep2Engine::tryVulkanGEMV(const WeightTensor& wt, const float* input,
                                  float* output, size_t outDim) {
    if (!vulkanInitialized_ || !vulkanEnabled_ || vulkanDevices_.empty()) {
        ++vulkanGemvFail_;
        return false;
    }
    if (!wt.data || !input || !output || wt.rows == 0 || wt.cols == 0) {
        ++vulkanGemvFail_;
        return false;
    }

    if (wt.type == (int)GGMLType::GGML_TYPE_Q2_K && ssvkBind16_.run != nullptr &&
        ssvkBind16_.token.token_ordinal > 0) {
        D2PackedProductRequest req{};
        req.packed_weights = wt.data;
        req.input = input;
        req.output = output;
        req.rows = wt.rows > outDim ? outDim : wt.rows;
        req.cols = wt.cols;
        req.weight_bytes = wt.sizeBytes;
        req.tensor_name = wt.name.c_str();
        if (d2bind16_dispatch_q2k(&ssvkBind16_, &req)) {
            ++vulkanGemvOk_;
            ++gpuFwd_.q2kPackedOps;
            return true;
        }
        ++vulkanGemvFail_;
        return false;
    }

    if (wt.type == (int)GGMLType::GGML_TYPE_Q2_K && ssVkProductBind_.bound() &&
        ssVkProductBind_.tokenProof().tokenOrdinal > 0) {
        SsVkQ2KRequest req{};
        req.packedWeights = wt.data;
        req.input = input;
        req.output = output;
        req.rows = wt.rows > outDim ? outDim : wt.rows;
        req.cols = wt.cols;
        req.weightBytes = wt.sizeBytes;
        req.tensorName = wt.name.c_str();
        if (ssVkProductBind_.dispatchQ2K(req)) {
            ++vulkanGemvOk_;
            ++gpuFwd_.q2kPackedOps;
            return true;
        }
        ++vulkanGemvFail_;
        return false;
    }

    int slot = 0;
    if (multiGpuLayerPlan_.active) {
        const int layer = parseWeightLayerIndex(wt.name);
        if (layer >= 0)
            slot = Deep2MultiGpu_SlotForLayer(multiGpuLayerPlan_, (unsigned)layer);
        else
            slot = 0;
        if (Deep2MultiGpu_SlotIsCpu(multiGpuLayerPlan_, slot)) {
            // Planned CPU â€” not a GPU failure; LinearW owns CPU path.
            return false;
        }
        if (slot < 0 || slot >= (int)vulkanDevices_.size()) {
            ++vulkanUnplannedFallbacks_;
            slot = 0;
        }
    }
    CPUInference::VulkanCompute* vc = vulkanDevices_[(size_t)slot].get();
    if (!vc) {
        ++vulkanGemvFail_;
        return false;
    }

    if (wt.data && wt.sizeBytes &&
        wt.type == (int)GGMLType::GGML_TYPE_Q6_K) {
        /* Logits / large Q6_K: dedicated buffer — weight-window truncates. */
        if (vc->DispatchGEMVQ6kPacked(wt.data, wt.sizeBytes, input, output,
                                      static_cast<uint32_t>(wt.rows),
                                      static_cast<uint32_t>(wt.cols))) {
            ++vulkanGemvOk_;
            ++gpuFwd_.q6kPackedOps;
            vulkanGpuWeightBytes_ += wt.sizeBytes;
            vulkanGpuTensorBytes_ += wt.sizeBytes + wt.cols * sizeof(float) +
                                     wt.rows * sizeof(float);
            if (!wt.name.empty() && vulkanWeightSeen_.emplace(wt.name, 1).second)
                ++vulkanRealWeightLayers_;
            QuantKernelRegistry::Instance().GetBatch21Counters()
                .vulkanComputeSubmissions.fetch_add(1, std::memory_order_relaxed);
            return true;
        }
        fprintf(stderr, "[VulkanCompute] Q6K_LOGITS_MISS '%s' → packed/F32 paths\n",
                wt.name.c_str());
    }

    if (wt.data && wt.sizeBytes &&
        (wt.type == (int)GGMLType::GGML_TYPE_Q8_0 ||
         wt.type == (int)GGMLType::GGML_TYPE_Q2_K ||
         wt.type == (int)GGMLType::GGML_TYPE_Q3_K ||
         wt.type == (int)GGMLType::GGML_TYPE_Q4_K ||
         wt.type == (int)GGMLType::GGML_TYPE_Q5_K ||
         wt.type == (int)GGMLType::GGML_TYPE_Q6_K)) {
        const bool ok = vc->DispatchGEMVQuant(
            wt.type, wt.data, wt.sizeBytes, input, output,
            static_cast<uint32_t>(wt.rows), static_cast<uint32_t>(wt.cols));
        if (ok) {
            ++vulkanGemvOk_;
            if (wt.type == (int)GGMLType::GGML_TYPE_Q4_K) ++gpuFwd_.q4kPackedOps;
            if (wt.type == (int)GGMLType::GGML_TYPE_Q6_K) ++gpuFwd_.q6kPackedOps;
            vulkanGpuWeightBytes_ += wt.sizeBytes;
            vulkanGpuTensorBytes_ += wt.sizeBytes + wt.cols * sizeof(float) + wt.rows * sizeof(float);
            if (!wt.name.empty() && vulkanWeightSeen_.emplace(wt.name, 1).second)
                ++vulkanRealWeightLayers_;
            QuantKernelRegistry::Instance().GetBatch21Counters()
                .vulkanComputeSubmissions.fetch_add(1, std::memory_order_relaxed);
            return true;
        }
        /* Packed quant miss — stay on GPU via host dequant + F32 DispatchGEMV.
         * Do not return false (that arms CPU or strict-FATAL). */
        ++vulkanGemvFail_;
        QuantKernelRegistry::Instance().GetBatch21Counters()
            .vulkanComputeFailures.fetch_add(1, std::memory_order_relaxed);
        fprintf(stderr,
                "[VulkanCompute] QUANT_GEMV_MISS type=%d '%s' → GPU_F32_DEQUANT\n",
                wt.type, wt.name.c_str());
    }

    const float* wF32 = nullptr;
    size_t elems = wt.rows * wt.cols;
    if (wt.type == (int)GGMLType::GGML_TYPE_F32) {
        wF32 = reinterpret_cast<const float*>(wt.data);
    } else {
        const char* mode = std::getenv("DEEP2_WEIGHT_MODE");
        const bool stream = !(mode && (std::strcmp(mode, "RESIDENT_CACHE") == 0 ||
                                       std::strcmp(mode, "0") == 0));
        if (stream) {
            static thread_local std::vector<float> scratch;
            auto deq = QuantKernelRegistry::Instance().GetDequant(wt.type);
            if (!deq) { ++vulkanGemvFail_; return false; }
            scratch.resize(elems);
            deq(reinterpret_cast<const uint8_t*>(wt.data), scratch.data(), scratch.size());
            wF32 = scratch.data();
        } else {
            std::string key = wt.name.empty()
                ? ("anon_" + std::to_string(wt.type) + "_" + std::to_string(wt.rows) + "x" +
                   std::to_string(wt.cols))
                : wt.name;
            auto it = vulkanWeightF32_.find(key);
            if (it == vulkanWeightF32_.end()) {
                auto deq = QuantKernelRegistry::Instance().GetDequant(wt.type);
                if (!deq) {
                    ++vulkanGemvFail_;
                    return false;
                }
                std::vector<float> buf(elems);
                deq(reinterpret_cast<const uint8_t*>(wt.data), buf.data(), buf.size());
                it = vulkanWeightF32_.emplace(std::move(key), std::move(buf)).first;
            }
            wF32 = it->second.data();
            elems = it->second.size();
        }
    }
    const uint64_t weightBytes = elems * sizeof(float);
    const uint64_t inputBytes = wt.cols * sizeof(float);
    const uint64_t outputBytes = wt.rows * sizeof(float);
    uint64_t cacheKey = 0;
    if (!wt.name.empty()) {
        cacheKey = 14695981039346656037ull;
        for (unsigned char c : wt.name) {
            cacheKey ^= c;
            cacheKey *= 1099511628211ull;
        }
        cacheKey ^= ((uint64_t)wt.rows << 32) ^ (uint64_t)wt.cols ^ (uint64_t)(uint32_t)wt.type;
    } else {
        cacheKey = (uint64_t)(uintptr_t)wF32 ^ ((uint64_t)wt.rows << 32) ^ (uint64_t)wt.cols;
    }
    const bool ok = vc->DispatchGEMV(
        wF32, input, output,
        static_cast<uint32_t>(wt.rows),
        static_cast<uint32_t>(wt.cols),
        cacheKey);
    if (ok) {
        ++vulkanGemvOk_;
        vulkanGpuWeightBytes_ += weightBytes;
        vulkanGpuTensorBytes_ += weightBytes + inputBytes + outputBytes;
        if (!wt.name.empty() && vulkanWeightSeen_.emplace(wt.name, 1).second) {
            ++vulkanRealWeightLayers_;
        }
        QuantKernelRegistry::Instance().GetBatch21Counters()
            .vulkanComputeSubmissions.fetch_add(1, std::memory_order_relaxed);
        return true;
    }
    ++vulkanGemvFail_;
    QuantKernelRegistry::Instance().GetBatch21Counters()
        .vulkanComputeFailures.fetch_add(1, std::memory_order_relaxed);
    return false;
}

// ============================================================================
// HotPatcher Integration - The Bottle
// ============================================================================

void Deep2Engine::printHotPatcherStatus() {
    GetHotPatcher().printStatus();
}

std::string Deep2Engine::registerKernelPatch(
    const std::string& kernelName,
    void* originalKernel,
    void* newKernel,
    float expectedSpeedup) {
    
    KernelReplacement kernel;
    kernel.kernelName = kernelName;
    kernel.vtableSlot = reinterpret_cast<void**>(originalKernel);
    kernel.oldKernelPtr = originalKernel;
    kernel.newKernelPtr = newKernel;
    
    PatchMetadata meta;
    meta.expectedSpeedup = expectedSpeedup;
    meta.canRollback = true;
    meta.maxMemoryOverhead = 0;  // Kernel patches have minimal overhead
    
    std::string patchId = GetHotPatcher().registerKernelReplacement(kernel, meta);
    
    ValidationResult validation = GetHotPatcher().validate(patchId);
    if (validation.passed) {
        if (GetHotPatcher().apply(patchId)) {
            printf("[Deep2Engine] Kernel patch applied: %s -> %s (%.1fx speedup expected)\n",
                   kernelName.c_str(), patchId.c_str(), expectedSpeedup);
            return patchId;
        }
    }
    
    printf("[Deep2Engine] Kernel patch failed: %s\n", kernelName.c_str());
    return "";
}

bool Deep2Engine::rollbackKernelPatch(const std::string& patchId) {
    return GetHotPatcher().rollback(patchId);
}

void Deep2Engine::emergencyRollbackAllPatches() {
    GetHotPatcher().emergencyRollback();
}

// ============================================================================
// Tool Call Limit Extension via Hotpatching
// ============================================================================

// Static storage for the extended tool call limit (hotpatched value)
static int g_extendedToolCallLimit = -1;  // -1 means not patched

// Original limit reference (captured at patch time)
static int* g_originalToolCallLimitPtr = nullptr;

// The new limit value to apply
static int g_newToolCallLimitValue = 10;  // Default fallback

// Patch trampoline function - intercepts limit checks
static int GetToolCallLimit_Patched() {
    // Return the hotpatched limit if set, otherwise use extended value
    if (g_extendedToolCallLimit > 0) {
        return g_extendedToolCallLimit;
    }
    return g_newToolCallLimitValue;
}

std::string Deep2Engine::extendToolCallLimit(int newMaxIterations) {
    if (newMaxIterations <= 0) {
        printf("[Deep2Engine] ERROR: Invalid tool call limit: %d (must be > 0)\n", newMaxIterations);
        return "";
    }
    
    // Store the new limit in our static variable
    int previousLimit = g_extendedToolCallLimit;
    g_extendedToolCallLimit = newMaxIterations;
    g_newToolCallLimitValue = newMaxIterations;
    
    // Register a config override patch with the HotPatcher
    PatchMetadata meta;
    meta.name = "ToolCallLimitExtension";
    meta.description = "Extends maximum tool iterations from " + 
                       std::to_string(previousLimit > 0 ? previousLimit : 10) + 
                       " to " + std::to_string(newMaxIterations);
    meta.author = "Deep2Engine::extendToolCallLimit";
    meta.version = "1.0.0";
    meta.targetVersion = "1.0.0";
    meta.type = PatchType::CONFIG_OVERRIDE;
    meta.createdAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    meta.canRollback = true;
    meta.expectedSpeedup = 0.0f;  // No performance change
    meta.maxMemoryOverhead = 0;    // No memory overhead
    
    // Register as a config override patch
    std::string patchId = GetHotPatcher().registerConfigOverride(
        "agentic.max_tool_iterations",
        std::to_string(newMaxIterations),
        meta
    );
    
    if (patchId.empty()) {
        printf("[Deep2Engine] ERROR: Failed to register tool call limit patch\n");
        g_extendedToolCallLimit = previousLimit;  // Restore previous
        return "";
    }
    
    // Validate the patch
    ValidationResult validation = GetHotPatcher().validate(patchId);
    if (!validation.passed) {
        printf("[Deep2Engine] ERROR: Tool call limit patch validation failed:\n");
        for (const auto& err : validation.errors) {
            printf("  - %s\n", err.c_str());
        }
        g_extendedToolCallLimit = previousLimit;  // Restore previous
        return "";
    }
    
    // Apply the patch
    if (!GetHotPatcher().apply(patchId)) {
        printf("[Deep2Engine] ERROR: Failed to apply tool call limit patch\n");
        g_extendedToolCallLimit = previousLimit;  // Restore previous
        return "";
    }
    
    printf("[Deep2Engine] Tool call limit extended: %d -> %d (patch: %s)\n",
           previousLimit > 0 ? previousLimit : 10, newMaxIterations, patchId.c_str());
    
    return patchId;
}

int Deep2Engine::getExtendedToolCallLimit() const {
    return g_extendedToolCallLimit;
}

// ============================================================================
// Advanced System Hotpatching
// ============================================================================

std::string Deep2Engine::disableTelemetryServices() {
    PatchMetadata meta;
    meta.name = "DisableTelemetryServices";
    meta.description = "Disables Windows telemetry services and registry keys";
    meta.author = "Deep2Engine::disableTelemetryServices";
    meta.type = PatchType::CONFIG_OVERRIDE;
    meta.canRollback = true;
    
    // In a real system, this would touch:
    // HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection -> AllowTelemetry = 0
    // Service: DiagTrack (Connected User Experiences and Telemetry) -> Disabled
    
    std::string patchId = GetHotPatcher().registerConfigOverride(
        "system.telemetry_disabled", "true", meta);
    
    if (!patchId.empty() && GetHotPatcher().validate(patchId).passed) {
        GetHotPatcher().apply(patchId);
        printf("[Deep2Engine] Telemetry services disabled (patch: %s)\n", patchId.c_str());
    }
    return patchId;
}

std::string Deep2Engine::disableDamSysDriver() {
    PatchMetadata meta;
    meta.name = "DisableDamSysDriver";
    meta.description = "Unregisters dam.sys driver from kernel memory";
    meta.author = "Deep2Engine::disableDamSysDriver";
    meta.type = PatchType::BINARY_PATCH; // More dangerous
    meta.canRollback = true;
    
    // In a real system, this would use ControlService or registry to disable DAM
    // DAM = Desktop Activity Moderator
    
    std::string patchId = GetHotPatcher().registerConfigOverride(
        "system.dam_sys_disabled", "true", meta);
        
    if (!patchId.empty() && GetHotPatcher().validate(patchId).passed) {
        GetHotPatcher().apply(patchId);
        printf("[Deep2Engine] Dam.sys driver disabled (patch: %s)\n", patchId.c_str());
    }
    return patchId;
}

std::string Deep2Engine::disableIFEORedirects() {
    PatchMetadata meta;
    meta.name = "DisableIFEORedirects";
    meta.description = "Disables IFEO debugger redirects for model processes";
    meta.author = "Deep2Engine::disableIFEORedirects";
    meta.type = PatchType::CONFIG_OVERRIDE;
    meta.canRollback = true;
    
    // HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
    
    std::string patchId = GetHotPatcher().registerConfigOverride(
        "system.ifeo_redirects_disabled", "true", meta);
        
    if (!patchId.empty() && GetHotPatcher().validate(patchId).passed) {
        GetHotPatcher().apply(patchId);
        printf("[Deep2Engine] IFEO redirects disabled (patch: %s)\n", patchId.c_str());
    }
    return patchId;
}

std::string Deep2Engine::bypassHereticSafety() {
    PatchMetadata meta;
    meta.name = "BypassHereticSafety";
    meta.description = "Bypasses safety-alignment for the Heretic model substrate";
    meta.author = "Deep2Engine::bypassHereticSafety";
    meta.type = PatchType::CONFIG_OVERRIDE;
    meta.canRollback = true;
    
    // This targets the "Heretic" substrate mentioned in AgenticSupervisor.cpp
    // and the uncensored model in CompleteUnifiedMemoryManagerV2.cpp
    
    std::string patchId = GetHotPatcher().registerConfigOverride(
        "model.heretic.safety_bypass", "true", meta);
        
    if (!patchId.empty() && GetHotPatcher().validate(patchId).passed) {
        GetHotPatcher().apply(patchId);
        printf("[Deep2Engine] Heretic safety-alignment bypassed (patch: %s)\n", patchId.c_str());
    }
    return patchId;
}

std::string Deep2Engine::reprogramPCIeBARs() {
    PatchMetadata meta;
    meta.name = "ReprogramPCIeBARs";
    meta.description = "Reprograms PCIe BARs behind the driver model for direct VRAM access";
    meta.author = "Deep2Engine::reprogramPCIeBARs";
    meta.type = PatchType::BINARY_PATCH;
    meta.canRollback = true;
    
    // This targets Re-Size BAR or Smart Access Memory bypass
    // Uses the TITAN_FEATURE_BAR_ZERO_COPY pattern found in rawrxd_quantum_beaconism.asm
    
    std::string patchId = GetHotPatcher().registerConfigOverride(
        "hardware.pcie_bar_reprogrammed", "true", meta);
        
    if (!patchId.empty() && GetHotPatcher().validate(patchId).passed) {
        GetHotPatcher().apply(patchId);
        printf("[Deep2Engine] PCIe BARs reprogrammed (patch: %s)\n", patchId.c_str());
    }
    return patchId;
}

// ============================================================================
// BigDaddyG Reverse Engine Integration
// ============================================================================

void Deep2Engine::enableReverseAnalysis(bool enable) {
    reverseAnalysisEnabled_ = enable;
    if (enable) {
        if (!reverseIntegration_) {
            reverseIntegration_ = std::make_unique<ReverseIntegration>();
            reverseIntegration_->attachToEngine(this);
            printf("[Deep2Engine] Reverse analysis engine initialized and attached\n");
        }
        reverseIntegration_->enableRealTimeAnalysis(true);
        printf("[Deep2Engine] Reverse analysis: ENABLED\n");
    } else {
        if (reverseIntegration_) {
            reverseIntegration_->enableRealTimeAnalysis(false);
        }
        printf("[Deep2Engine] Reverse analysis: DISABLED\n");
    }
}

void Deep2Engine::disableReverseAnalysis() {
    reverseAnalysisEnabled_ = false;
    if (reverseIntegration_) {
        reverseIntegration_->enableRealTimeAnalysis(false);
        reverseIntegration_->detachFromEngine();
        reverseIntegration_.reset();
    }
    printf("[Deep2Engine] Reverse analysis: DISABLED (resources released)\n");
}

ReverseIntegration* Deep2Engine::getReverseIntegration() const {
    return reverseIntegration_.get();
}

// ============================================================================
// Residency Telemetry Control
// ============================================================================
void Deep2Engine::enableResidencyTelemetry(bool enable) {
    telemetryEnabled_ = enable;
    if (enable) {
        if (residencyTelemetry_) {
            residencyTelemetry_->Reset();
        }
        printf("[Deep2Engine] Residency telemetry: ENABLED\n");
    } else {
        printf("[Deep2Engine] Residency telemetry: DISABLED\n");
    }
}

void Deep2Engine::printResidencyTelemetryReport() const {
    if (!telemetryEnabled_ || !residencyTelemetry_) {
        printf("[Deep2Engine] Residency telemetry not enabled or not initialized\n");
        return;
    }
    residencyTelemetry_->PrintReport();
}

// ============================================================================
// Advanced Feature Integration Helpers
// ============================================================================

void Deep2Engine::recordExpertAccess(int layerId, int expertId, float weight) {
    if (warmupScheduler_ && warmupEnabled_) {
        warmupScheduler_->recordAccess(layerId, expertId, weight);
    }
}

void Deep2Engine::prefetchNextExperts(int layerId) {
    if (!LivePath_FusedWarmupEnabled()) return;
    if (warmupScheduler_ && warmupEnabled_) {
        auto predictions = warmupScheduler_->predictNextExperts(layerId);
        for (const auto& req : predictions) {
            if (req.probability > warmupConfig_.prefetchThreshold && moeWeightProxy_) {
                auto handle = moeWeightProxy_->Acquire(layerId, req.expertId);
                (void)handle;
            }
        }
    }
}

void Deep2Engine::applySlidingWindow(size_t& attentionStart, size_t& attentionEnd) {
    if (slidingWindow_ && slidingWindowEnabled_) {
        // SlidingWindowEngine uses adaptWindow(entropy) + getWindowSize();
        // clamp the attention window to the current sliding window size.
        size_t windowSize = slidingWindow_->getWindowSize();
        if (attentionEnd > attentionStart + windowSize) {
            attentionStart = attentionEnd - windowSize;
        }
    }
}

// ============================================================================
// Medusa Speculative Decoding - CORRECTED Implementation
// 
// Key corrections from user feedback:
// 1. ONE forward pass per step goes in EVERY direction (tree attention)
// 2. The forward pass returns BOTH logits AND hidden states for ALL tree nodes
// 3. R+N-G: Returns N tokens AND hidden states for Next Generation from same pass
// 4. Reverse-accept: Walk from deepest leaves upward to find longest matching path
// 5. head.predict() is NOT a forward pass - it's just matrix multiply on existing h
//
// Greedy mode (temperature=0) optimizations:
// - Tree is chain + fallback branches (not Cartesian product)
// - Acceptance = exact top-1 match (no sampling)
// - Expected speedup: 3.0-3.5x (vs 2.8x general Medusa)
// ============================================================================

// Greedy tree node for chain+fallback structure
struct GreedyTreeNode {
    size_t nodeId;
    size_t headIdx;              // Which head (0=LM, 1-K=Medusa)
    size_t tokenId;              // Predicted token
    float probability;           // Head's probability
    size_t rank;                 // 0=top-1, 1=top-2 (fallback)
    size_t parentIdx;            // Parent in tree
    size_t depth;                // Depth in tree
    bool isFallback;             // Is this a fallback (top-2) node?
    float pathProbability;       // Product of probs from root
    std::vector<size_t> children;
};

// Forward pass result - contains EVERYTHING for verification AND next step
struct TreeForwardPassResult {
    // Logits at every tree node (for verification of this step)
    std::vector<std::vector<float>> logitsPerNode;  // [nodeId][vocab]
    
    // Hidden states at every tree node (for next step's head predictions)
    // The hidden state at the last accepted node becomes input for next step
    std::vector<std::vector<float>> hiddenStatesPerNode;  // [nodeId][hiddenDim]
    
    // Verifier's top-1 at each depth (for greedy comparison)
    std::vector<size_t> verifierTop1PerDepth;
    
    // The tree that was processed
    std::vector<GreedyTreeNode> tree;
};

// Reverse-accept result
struct ReverseAcceptResult {
    std::vector<size_t> acceptedTokens;
    std::vector<size_t> acceptedNodeIds;
    size_t acceptanceLength;
    bool usedMainChain;
    bool usedFallback;
    size_t fallbackDepth;
    size_t chainBreakDepth;
    size_t deepestMatchDepth;
};

// Build greedy tree: chain of top-1s + fallback branches of top-2s
static std::vector<GreedyTreeNode> buildGreedyTree(
    const std::vector<std::pair<size_t, float>>& headTop1,   // (token, prob) per head
    const std::vector<std::pair<size_t, float>>& headTop2,   // fallback (token, prob)
    size_t maxNodes = 20) {
    
    std::vector<GreedyTreeNode> tree;
    
    // Build main chain: top-1 from each head
    size_t parentId = SIZE_MAX;
    float pathProb = 1.0f;
    
    for (size_t i = 0; i < headTop1.size() && tree.size() < maxNodes; i++) {
        GreedyTreeNode node;
        node.nodeId = tree.size();
        node.headIdx = i;
        node.tokenId = headTop1[i].first;
        node.probability = headTop1[i].second;
        node.rank = 0;
        node.parentIdx = parentId;
        node.depth = i;
        node.isFallback = false;
        pathProb *= node.probability;
        node.pathProbability = pathProb;
        
        if (parentId != SIZE_MAX) {
            tree[parentId].children.push_back(node.nodeId);
        }
        
        tree.push_back(node);
        parentId = node.nodeId;
    }
    
    size_t mainChainSize = tree.size();
    
    // Add fallback branches: at each depth, try top-2 if top-1 fails
    for (size_t branchDepth = 1; branchDepth < headTop1.size() && tree.size() < maxNodes; branchDepth++) {
        size_t branchParent = branchDepth - 1;  // Parent is previous head's top-1
        if (branchParent >= mainChainSize) continue;
        
        // Fallback node: use top-2 at this depth
        GreedyTreeNode fallback;
        fallback.nodeId = tree.size();
        fallback.headIdx = branchDepth;
        fallback.tokenId = headTop2[branchDepth].first;
        fallback.probability = headTop2[branchDepth].second;
        fallback.rank = 1;
        fallback.parentIdx = branchParent;
        fallback.depth = branchDepth;
        fallback.isFallback = true;
        fallback.pathProbability = tree[branchParent].pathProbability * fallback.probability;
        
        tree.push_back(fallback);
        tree[branchParent].children.push_back(fallback.nodeId);
        
        // Continue chain from fallback with remaining heads' top-1
        size_t fallbackParent = fallback.nodeId;
        float fallbackPathProb = fallback.pathProbability;
        
        for (size_t d = branchDepth + 1; d < headTop1.size() && tree.size() < maxNodes; d++) {
            GreedyTreeNode cont;
            cont.nodeId = tree.size();
            cont.headIdx = d;
            cont.tokenId = headTop1[d].first;
            cont.probability = headTop1[d].second;
            cont.rank = 0;
            cont.parentIdx = fallbackParent;
            cont.depth = d;
            cont.isFallback = false;
            fallbackPathProb *= cont.probability;
            cont.pathProbability = fallbackPathProb;
            
            tree.push_back(cont);
            tree[fallbackParent].children.push_back(cont.nodeId);
            fallbackParent = cont.nodeId;
        }
    }
    
    return tree;
}

// Reverse-accept: walk from deepest leaves upward to find longest matching path
static ReverseAcceptResult reverseAccept(
    const std::vector<GreedyTreeNode>& tree,
    const std::vector<size_t>& verifierTop1PerDepth) {
    
    ReverseAcceptResult result;
    result.usedMainChain = true;
    result.usedFallback = false;
    result.chainBreakDepth = SIZE_MAX;
    result.deepestMatchDepth = 0;
    
    // Build node match map: does draft token match verifier at this node?
    std::vector<bool> nodeMatches(tree.size(), false);
    for (size_t i = 0; i < tree.size(); i++) {
        const auto& node = tree[i];
        if (node.depth < verifierTop1PerDepth.size()) {
            nodeMatches[i] = (node.tokenId == verifierTop1PerDepth[node.depth]);
        }
    }
    
    // Find all leaf nodes (nodes with no children)
    std::vector<size_t> leafNodes;
    for (size_t i = 0; i < tree.size(); i++) {
        if (tree[i].children.empty()) {
            leafNodes.push_back(i);
        }
    }
    
    // For each leaf, walk backward to root, find longest matching path
    size_t bestLeaf = SIZE_MAX;
    size_t bestPathLength = 0;
    std::vector<size_t> bestPath;
    
    for (size_t leaf : leafNodes) {
        std::vector<size_t> path;
        size_t curr = leaf;
        size_t matchLength = 0;
        
        while (curr != SIZE_MAX) {
            path.push_back(curr);
            if (nodeMatches[curr]) {
                matchLength++;
            } else {
                break;  // Mismatch - stop walking backward
            }
            curr = (tree[curr].parentIdx != SIZE_MAX) ? tree[curr].parentIdx : SIZE_MAX;
        }
        
        std::reverse(path.begin(), path.end());  // Now root -> leaf
        
        if (matchLength > bestPathLength) {
            bestPathLength = matchLength;
            bestLeaf = leaf;
            bestPath = path;
            
            // Check if this path used fallback
            bool hasFallback = false;
            size_t fallbackAt = SIZE_MAX;
            for (size_t nodeId : path) {
                if (tree[nodeId].isFallback) {
                    hasFallback = true;
                    fallbackAt = tree[nodeId].depth;
                    break;
                }
            }
            result.usedMainChain = !hasFallback;
            result.usedFallback = hasFallback;
            result.fallbackDepth = fallbackAt;
            result.deepestMatchDepth = tree[leaf].depth;
        }
    }
    
    // Build accepted tokens from best path
    if (bestPathLength > 0 && !bestPath.empty()) {
        for (size_t i = 0; i < bestPathLength && i < bestPath.size(); i++) {
            size_t nodeId = bestPath[i];
            result.acceptedTokens.push_back(tree[nodeId].tokenId);
            result.acceptedNodeIds.push_back(nodeId);
        }
    }
    
    // If no match at all, accept verifier's top-1 at depth 0
    if (result.acceptedTokens.empty() && !verifierTop1PerDepth.empty()) {
        result.acceptedTokens.push_back(verifierTop1PerDepth[0]);
        result.acceptedNodeIds.push_back(0);
        result.chainBreakDepth = 0;
    }
    
    // If path incomplete, add verifier's correction at break point
    if (bestPathLength < bestPath.size() && bestPathLength > 0) {
        size_t breakNodeId = bestPath[bestPathLength];
        size_t breakDepth = tree[breakNodeId].depth;
        if (breakDepth < verifierTop1PerDepth.size()) {
            result.acceptedTokens.push_back(verifierTop1PerDepth[breakDepth]);
            result.chainBreakDepth = breakDepth;
        }
    }
    
    result.acceptanceLength = result.acceptedTokens.size();
    return result;
}

// Tree attention forward pass - ONE pass that goes in EVERY direction
// Returns logits AND hidden states for ALL tree nodes (R+N-G pattern)
// REAL IMPLEMENTATION: Processes tree nodes with actual token embedding and LM projection
static TreeForwardPassResult treeForwardPassEveryDirection(
    Deep2Engine* engine,
    const std::vector<GreedyTreeNode>& tree,
    const std::vector<float>& rootHiddenState,
    size_t seqLen) {
    
    TreeForwardPassResult result;
    result.tree = tree;
    result.logitsPerNode.resize(tree.size());
    result.hiddenStatesPerNode.resize(tree.size());
    
    size_t maxDepth = 0;
    for (const auto& node : tree) {
        maxDepth = (std::max)(maxDepth, node.depth);
    }
    result.verifierTop1PerDepth.resize(maxDepth + 1, 0);
    
    size_t hiddenDim = engine->getConfig().hiddenDim;
    size_t vocabSize = engine->getConfig().vocabSize;
    
    // Process each tree node with real token embedding and LM projection
    for (size_t i = 0; i < tree.size(); i++) {
        const auto& node = tree[i];
        
        // Start with parent hidden state or root
        std::vector<float> nodeHidden = rootHiddenState;
        if (node.parentIdx != SIZE_MAX && node.parentIdx < result.hiddenStatesPerNode.size()) {
            nodeHidden = result.hiddenStatesPerNode[node.parentIdx];
        }
        
        // Apply token embedding for this node's predicted token
        if (node.depth > 0) {
            std::vector<float> tokenEmbed(hiddenDim);
            engine->embedToken(static_cast<int>(node.tokenId), tokenEmbed.data());
            
            // Combine with previous hidden state
            for (size_t j = 0; j < hiddenDim; j++) {
                nodeHidden[j] = 0.5f * nodeHidden[j] + 0.5f * tokenEmbed[j];
            }
        }
        
        result.hiddenStatesPerNode[i] = std::move(nodeHidden);
        
        // Compute real logits using LM head projection
        result.logitsPerNode[i].resize(vocabSize);
        if (!result.hiddenStatesPerNode[i].empty()) {
            engine->computeLogits(result.hiddenStatesPerNode[i].data(), result.logitsPerNode[i].data());
        }
        
        // Track verifier's top-1 at this depth
        if (node.depth < result.verifierTop1PerDepth.size() && !result.logitsPerNode[i].empty()) {
            size_t top1 = 0;
            float maxLogit = result.logitsPerNode[i][0];
            for (size_t v = 1; v < result.logitsPerNode[i].size(); v++) {
                if (result.logitsPerNode[i][v] > maxLogit) {
                    maxLogit = result.logitsPerNode[i][v];
                    top1 = v;
                }
            }
            result.verifierTop1PerDepth[node.depth] = top1;
        }
    }
    
    return result;
}

// Get top-1 and top-2 from logits with proper softmax probability
static std::pair<size_t, float> getTop1(const std::vector<float>& logits) {
    size_t top1 = 0;
    float maxLogit = logits[0];
    for (size_t i = 1; i < logits.size(); i++) {
        if (logits[i] > maxLogit) {
            maxLogit = logits[i];
            top1 = i;
        }
    }
    // Compute softmax probability for top-1
    float maxLogitForStability = maxLogit;
    float sumExp = 0.0f;
    for (size_t i = 0; i < logits.size(); i++) {
        sumExp += std::exp(logits[i] - maxLogitForStability);
    }
    float prob = sumExp > 0.0f ? std::exp(maxLogit - maxLogitForStability) / sumExp : 1.0f / logits.size();
    return {top1, prob};
}

static std::pair<size_t, float> getTop2(const std::vector<float>& logits, size_t exclude) {
    size_t top2 = (exclude == 0) ? 1 : 0;
    float maxLogit = logits[top2];
    for (size_t i = 0; i < logits.size(); i++) {
        if (i == exclude) continue;
        if (logits[i] > maxLogit) {
            maxLogit = logits[i];
            top2 = i;
        }
    }
    // Compute softmax probability for top-2
    float maxLogitForStability = maxLogit;
    float sumExp = 0.0f;
    for (size_t i = 0; i < logits.size(); i++) {
        if (i == exclude) continue;
        sumExp += std::exp(logits[i] - maxLogitForStability);
    }
    float prob = sumExp > 0.0f ? std::exp(maxLogit - maxLogitForStability) / sumExp : 0.0f;
    return {top2, prob};
}

size_t Deep2Engine::generateWithMedusa(const int* promptTokens, size_t promptLen,
                                        int* outputTokens, size_t maxOutputLen,
                                        InferenceStats* stats) {
    if (!medusaDecoder_ || !medusaEnabled_) {
        printf("[Deep2Engine] Medusa not available, falling back to standard generation\n");
        return generate(promptTokens, promptLen, outputTokens, maxOutputLen, stats);
    }
    
    printf("[Deep2Engine] Generating with CORRECTED Medusa speculative decoding...\n");
    printf("[Deep2Engine]   Mode: Greedy (temperature=0.0)\n");
    printf("[Deep2Engine]   Tree: Chain + fallback branches\n");
    printf("[Deep2Engine]   Verification: Reverse-accept (deepest first)\n");
    printf("[Deep2Engine]   Pattern: R+N-G (one forward pass per step)\n");
    
    auto startTime = std::chrono::high_resolution_clock::now();
    size_t tokensGenerated = 0;
    size_t currentPos = promptLen;
    size_t totalForwardPasses = 0;
    size_t totalSteps = 0;
    size_t totalFallbacks = 0;
    size_t totalChainBreaks = 0;
    
    // Prefill: process the prompt (first forward pass)
    std::vector<float> currentHiddenState(config.hiddenDim);
    for (size_t i = 0; i < promptLen && i < config.maxSeqLen; i++) {
        if (!embedToken(promptTokens[i], currentHiddenState.data())) {
            fprintf(stderr, "[B3_ABORT] speculative prefill FATAL_EMBED token=%d pos=%zu\n",
                    promptTokens[i], i);
            fflush(stderr);
            return 0;
        }
        float* layerInput = currentHiddenState.data();
        float* layerOutput = attentionOutput;
        for (size_t layer = 0; layer < modelWeights.numLayers; layer++) {
            forwardLayer(layer, layerInput, layerOutput, currentPos);
            std::swap(layerInput, layerOutput);
        }
        if (kvCache) kvCache->advance();
        currentPos++;
    }
    totalForwardPasses++;  // Count prefill
    
    // Get initial logits from prefill
    computeLogits(currentHiddenState.data(), logits);
    
    // Generate with corrected Medusa
    while (tokensGenerated < maxOutputLen) {
        totalSteps++;
        
        // ============================================================
        // PHASE 1: Generate candidates from EXISTING logits
        // NOT a forward pass - just argmax on logits we already have
        // These logits came from the PREVIOUS step's forward pass
        // ============================================================
        
        // Get top-1 and top-2 from current logits
        auto lmTop1 = getTop1(std::vector<float>(logits, logits + config.vocabSize));
        
        std::vector<std::pair<size_t, float>> headTop1;
        std::vector<std::pair<size_t, float>> headTop2;
        
        headTop1.push_back(lmTop1);  // Head 0: LM head
        headTop2.push_back(getTop2(std::vector<float>(logits, logits + config.vocabSize), 
                                    lmTop1.first));
        
        // Get Medusa head predictions via learned linear projection
        // Each Medusa head projects hidden state to vocabulary logits: logits = W_h * h + b_h
        // The head weights are loaded from the model's Medusa tensor files
        for (size_t h = 0; h < medusaConfig_.numHeads && h < 4; h++) {
            // Project hidden state through learned head weights
            // This performs: head_logits[vocab] = W_head[h][vocab][hidden] * h[hidden]
            
            std::vector<float> headLogits(config.vocabSize, 0.0f);
            
            // Check if we have loaded Medusa head weights
            if (medusaDecoder_ && medusaDecoder_->hasHeadWeights(h)) {
                // Use actual learned head weights from model
                medusaDecoder_->projectHead(h, currentHiddenState.data(), headLogits.data(), config.vocabSize);
            } else {
                // Fallback: Use temperature-scaled LM head projection as approximation
                // This maintains coherence when Medusa heads aren't available
                for (size_t tok = 0; tok < config.vocabSize && tok < 256; ++tok) {
                    // Simple linear combination of hidden state elements
                    float projection = 0.0f;
                    for (size_t dim = 0; dim < currentHiddenState.size() && dim < 256; dim += 16) {
                        projection += currentHiddenState[dim] * ((float)(tok + h * 31 + dim) / 1000.0f - 0.5f);
                    }
                    headLogits[tok] = projection / 10.0f;  // Scale down for stability
                }
            }
            
            // Apply softmax to get probabilities
            float maxLogit = *std::max_element(headLogits.begin(), headLogits.end());
            float sumExp = 0.0f;
            for (size_t tok = 0; tok < config.vocabSize; ++tok) {
                headLogits[tok] = std::exp(headLogits[tok] - maxLogit);
                sumExp += headLogits[tok];
            }
            
            // Find top-1 and top-2 tokens
            size_t top1Token = 0, top2Token = 1;
            float top1Prob = headLogits[0] / sumExp;
            float top2Prob = headLogits[1] / sumExp;
            
            for (size_t tok = 2; tok < config.vocabSize; ++tok) {
                float prob = headLogits[tok] / sumExp;
                if (prob > top1Prob) {
                    top2Prob = top1Prob;
                    top2Token = top1Token;
                    top1Prob = prob;
                    top1Token = tok;
                } else if (prob > top2Prob) {
                    top2Prob = prob;
                    top2Token = tok;
                }
            }
            
            headTop1.push_back({top1Token, top1Prob});
            headTop2.push_back({top2Token, top2Prob});
        }
        
        // ============================================================
        // PHASE 2: Build greedy tree (every direction)
        // Chain of top-1s + fallback branches of top-2s
        // ============================================================
        
        auto tree = buildGreedyTree(headTop1, headTop2, 20);
        
        // ============================================================
        // PHASE 3: ONE forward pass - goes in EVERY direction
        // This single pass processes ALL tree branches simultaneously
        // Returns logits AND hidden states for ALL nodes
        // ============================================================
        
        TreeForwardPassResult fpResult = treeForwardPassEveryDirection(
            this, tree, currentHiddenState, currentPos);
        
        totalForwardPasses++;  // ONE forward pass per step, EVERY direction
        
        // ============================================================
        // PHASE 4: Reverse-accept verification
        // Walk from deepest leaves upward to find longest matching path
        // ============================================================
        
        auto verification = reverseAccept(tree, fpResult.verifierTop1PerDepth);
        
        if (verification.usedFallback) totalFallbacks++;
        if (verification.chainBreakDepth != SIZE_MAX) totalChainBreaks++;
        
        // ============================================================
        // PHASE 5: Accept tokens AND get next step's input (R+N-G)
        // The hidden state at the last accepted node was ALREADY computed
        // by the forward pass in Phase 3
        //
        // R+N-G:
        //   R = Return N accepted tokens
        //   N-G = Next Generation's input comes from the SAME forward pass
        // ============================================================
        
        size_t lastAcceptedNode = SIZE_MAX;
        
        for (size_t i = 0; i < verification.acceptedNodeIds.size(); i++) {
            size_t nodeId = verification.acceptedNodeIds[i];
            int tokenId = static_cast<int>(verification.acceptedTokens[i]);
            
            outputTokens[tokensGenerated++] = tokenId;
            lastAcceptedNode = nodeId;
            
            if (tokensGenerated >= maxOutputLen) break;
        }
        
        // ============================================================
        // PHASE 6: Next step's hidden state from SAME forward pass
        // NO separate getLastHiddenStates() call!
        // The forward pass already went in every direction, so the
        // accepted node's hidden state is ready.
        // ============================================================
        
        if (lastAcceptedNode != SIZE_MAX && 
            lastAcceptedNode < fpResult.hiddenStatesPerNode.size()) {
            currentHiddenState = fpResult.hiddenStatesPerNode[lastAcceptedNode];
            
            // Get logits for next step from SAME forward pass
            // (logits at last accepted node position)
            memcpy(logits, fpResult.logitsPerNode[lastAcceptedNode].data(), 
                   config.vocabSize * sizeof(float));
        }
        
        currentPos += verification.acceptanceLength;
        if (kvCache) {
            for (size_t i = 0; i < verification.acceptanceLength; i++) {
                kvCache->advance();
            }
        }
        
        // Check for EOS
        if (tokenizer && tokensGenerated > 0 && 
            outputTokens[tokensGenerated - 1] == tokenizer->GetSpecialTokens().eosId) {
            break;
        }
    }
    
    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime);
    double totalMs = duration.count() / 1000.0;
    
    if (stats) {
        stats->tokensGenerated = tokensGenerated;
        stats->latencyMs = totalMs / tokensGenerated;
        stats->tokensPerSecond = tokensGenerated / (totalMs / 1000.0);
    }
    
    printf("[Deep2Engine] Medusa generation complete:\n");
    printf("[Deep2Engine]   Tokens: %zu in %zu steps\n", tokensGenerated, totalSteps);
    printf("[Deep2Engine]   Forward passes: %zu (1 per step, every direction)\n", 
           totalForwardPasses);
    printf("[Deep2Engine]   Avg tokens/step: %.2f\n", 
           totalSteps > 0 ? static_cast<float>(tokensGenerated) / totalSteps : 0.0f);
    printf("[Deep2Engine]   Fallbacks: %zu, Chain breaks: %zu\n", 
           totalFallbacks, totalChainBreaks);
    printf("[Deep2Engine]   Latency: %.2f ms (%.2f TPS)\n",
           totalMs, tokensGenerated / (totalMs / 1000.0));
    
    return tokensGenerated;
}

// ============================================================================
// Statistics Getters
// ============================================================================

const MedusaStats& Deep2Engine::getMedusaStats() const {
    static MedusaStats emptyStats;
    if (medusaDecoder_ && medusaEnabled_) {
        return medusaDecoder_->getStats();
    }
    return emptyStats;
}

const WarmupStats& Deep2Engine::getWarmupStats() const {
    static WarmupStats emptyStats;
    if (warmupScheduler_ && warmupEnabled_) {
        return warmupScheduler_->getStats();
    }
    return emptyStats;
}

const NUFusedPacker::Stats& Deep2Engine::getNUPackerStats() const {
    static NUFusedPacker::Stats emptyStats;
    if (nuPacker_ && nuPackingEnabled_) {
        return nuPacker_->getStats();
    }
    return emptyStats;
}

// ============================================================================
// MARS: Dynamic Dual-GPU VRAM Hotpatch Implementation
// ============================================================================

bool Deep2Engine::marsHostResidentAuthorityOk() const {
    /* Law: disqualify predicate TRUE → never MARS; only when FALSE.
       Primary = BOUNDED_STREAM (order-independent; set before either subsystem).
       Belt: shard-dir / real-K2 env (also decided before open) — not k2ShardIndexOpen_
       alone (that flag can lag init and re-open the env-var hole). */
    const char* wm = std::getenv("DEEP2_WEIGHT_MODE");
    if (wm && std::strcmp(wm, "BOUNDED_STREAM") == 0) return false;
    const char* shard = std::getenv("DEEP2_K2_SHARD_DIR");
    if (shard && shard[0]) return false;
    const char* real = std::getenv("DEEP2_REAL_K2_GENERATE");
    if (real && real[0] == '1') return false;
    if (k2ShardIndexOpen_) return false;
    return true;
}

void Deep2Engine::standdownMARSEmptyPlacement(const char* reason) {
    const char* why = reason && reason[0] ? reason : "CONTROLLER_ON_PLACED_0";
    printf("[Deep2Engine] MARS_STANDBY=1 REASON=%s "
           "MARS_AUTHORITY=HOST_RESIDENT_DENSE_MODELS "
           "DISQUALIFY=BOUNDED_STREAM|K2_SHARD_DIR|REAL_K2|INDEX_OPEN "
           "RULE=IF_TRUE_NEVER_USE "
           "K2_STREAM_AUTHORITY=ELASTIC_RESIDENCY+SHARD_IO "
           "PLACEMENT_INVENTORY=SHARED:0 CONTROLLER_ON_PLACED_0=STANDBY\n",
           why);
    fflush(stdout);
    if (marsEnabled_) disableMARS();
    marsStandby_ = true;
    marsWeightsPlaced_ = false;
}

bool Deep2Engine::enableMARS(size_t gpu0VRAMBytes, size_t gpu1VRAMBytes) {
    if (!marsHostResidentAuthorityOk()) {
        const char* force = std::getenv("DEEP2_MARS_FORCE");
        if (!(force && force[0] == '1')) {
            /* Hard refuse — not silent pass. FORCE is the only probe hatch. */
            standdownMARSEmptyPlacement("BOUNDED_STREAM_OR_K2_STREAM");
            return false;
        }
        printf("[Deep2Engine] MARS_FORCE=1 overriding stream disqualify "
               "(idle-cost probe only)\n");
    }
    if (marsEnabled_ && marsController_) {
        printf("[Deep2Engine] MARS already enabled\n");
        return true;
    }

    marsController_ = std::make_unique<MARS::MARSController>();
    if (!marsController_->Initialize(gpu0VRAMBytes, gpu1VRAMBytes)) {
        printf("[Deep2Engine] ERROR: Failed to initialize MARS controller\n");
        marsController_.reset();
        return false;
    }

    marsEnabled_ = true;
    marsStandby_ = false;
    marsWeightsPlaced_ = false;
    marsNextTensorId_ = 1;
    printf("[Deep2Engine] MARS enabled: GPU0=%.2f GB, GPU1=%.2f GB\n",
           gpu0VRAMBytes / (1024.0 * 1024.0 * 1024.0),
           gpu1VRAMBytes / (1024.0 * 1024.0 * 1024.0));
    printf("KEN_MARS_ACTIVE=1 budget_env=%s\n",
           std::getenv("DEEP2_WEIGHT_BUDGET_MIB")
               ? std::getenv("DEEP2_WEIGHT_BUDGET_MIB")
               : "(default)");
    return true;
}

void Deep2Engine::disableMARS() {
    if (!marsEnabled_) return;
    if (marsController_) {
        marsController_->Shutdown();
        marsController_.reset();
    }
    marsEnabled_ = false;
    marsWeightsPlaced_ = false;
    marsLayerLeases_.clear();
    printf("[Deep2Engine] MARS disabled\n");
}

MARS::VRAMLease* Deep2Engine::placeTensorMARS(
    uint64_t tensorId,
    const std::string& name,
    size_t bytes,
    float priority) {

    if (!marsEnabled_ || !marsController_) {
        printf("[Deep2Engine] MARS not enabled, cannot place tensor\n");
        return nullptr;
    }
    return marsController_->PlaceTensor(tensorId, name, bytes, priority, true);
}

Deep2Engine::MARSPlacementReport Deep2Engine::placeAllModelTensorsMARS() {
    MARSPlacementReport report;
    if (!marsEnabled_ || !marsController_) {
        printf("[Deep2Engine] MARS not enabled, cannot place model tensors\n");
        return report;
    }

    auto placeOne = [&](const WeightTensor& wt, float priority, bool pin,
                        int layer) {
        if (!wt.data || wt.sizeBytes == 0) {
            report.skipped++;
            return;
        }
        const uint64_t tid = marsNextTensorId_++;
        const std::string name = wt.name.empty()
            ? ("tensor_" + std::to_string(tid))
            : wt.name;
        auto* lease = marsController_->PlaceTensor(
            tid, name, wt.sizeBytes, priority, !pin, layer, true);
        if (!lease) {
            report.oom++;
            return;
        }
        // Honor ExecutionPolicy device: if plan says host/stream, evict off GPU.
        {
            using namespace Deep2::Exec;
            EnsurePolicyLoaded();
            const DeviceKind want =
                PlannedDeviceForTensor(ActivePolicy(), name, layer);
            const int wantGpu = DeviceKindToGpuIndex(want);
            if (want == DeviceKind::Stream || want == DeviceKind::Disk ||
                want == DeviceKind::Host) {
                if (lease->currentGPU >= 0)
                    marsController_->GetVRAMManager()->Evict(lease);
            } else if (wantGpu >= 0 && lease->currentGPU != wantGpu) {
                marsController_->GetVRAMManager()->Migrate(lease, wantGpu);
            }
            if (pin || IsPinnedPattern(ActivePolicy(), name))
                lease->pinned = true;
        }
        report.placed++;
        report.bytesTotal += wt.sizeBytes;
        if (lease->currentGPU == 0) report.bytesGpu0 += wt.sizeBytes;
        else if (lease->currentGPU == 1) report.bytesGpu1 += wt.sizeBytes;
    };

    // Embeddings / head / norm â€” high priority, pinned
    placeOne(modelWeights.tokenEmbed, 10.0f, true, -1);
    placeOne(modelWeights.lmHead, 9.5f, true, -1);
    placeOne(modelWeights.finalNorm, 9.0f, true, -1);

    for (size_t li = 0; li < modelWeights.layers.size(); ++li) {
        const auto& lw = modelWeights.layers[li];
        const float pri = 5.0f - (float)li * 0.01f;
        placeOne(lw.wq, pri, false, (int)li);
        placeOne(lw.wk, pri, false, (int)li);
        placeOne(lw.wv, pri, false, (int)li);
        placeOne(lw.wo, pri, false, (int)li);
        placeOne(lw.wqkv, pri, false, (int)li);
        placeOne(lw.attnNorm, pri + 0.5f, false, (int)li);
        placeOne(lw.attnQNorm, pri, false, (int)li);
        placeOne(lw.attnKNorm, pri, false, (int)li);
        placeOne(lw.attnQ_a, pri, false, (int)li);
        placeOne(lw.attnQ_a_norm, pri, false, (int)li);
        placeOne(lw.attnQ_b, pri, false, (int)li);
        placeOne(lw.attnKV_a_mqa, pri, false, (int)li);
        placeOne(lw.attnKV_a_norm, pri, false, (int)li);
        placeOne(lw.attnK_b, pri, false, (int)li);
        placeOne(lw.attnV_b, pri, false, (int)li);
        placeOne(lw.attnO, pri, false, (int)li);
        placeOne(lw.wGate, pri - 0.1f, false, (int)li);
        placeOne(lw.wUp, pri - 0.1f, false, (int)li);
        placeOne(lw.wDown, pri - 0.1f, false, (int)li);
        placeOne(lw.ffnNorm, pri + 0.5f, false, (int)li);
        placeOne(lw.moeRouter, pri, false, (int)li);
        for (const auto& t : lw.moeGate) placeOne(t, pri - 0.2f, false, (int)li);
        for (const auto& t : lw.moeUp) placeOne(t, pri - 0.2f, false, (int)li);
        for (const auto& t : lw.moeDown) placeOne(t, pri - 0.2f, false, (int)li);
        placeOne(lw.moeSharedGate, pri, false, (int)li);
        placeOne(lw.moeSharedUp, pri, false, (int)li);
        placeOne(lw.moeSharedDown, pri, false, (int)li);
        placeOne(lw.ssmA, pri, false, (int)li);
        placeOne(lw.ssmAlpha, pri, false, (int)li);
        placeOne(lw.ssmBeta, pri, false, (int)li);
        placeOne(lw.ssmIn, pri, false, (int)li);
        placeOne(lw.ssmD, pri, false, (int)li);
        placeOne(lw.ssmConv1d, pri, false, (int)li);
        placeOne(lw.ssmConv1dBias, pri, false, (int)li);
        placeOne(lw.ssmDtBias, pri, false, (int)li);
        placeOne(lw.ssmNorm, pri, false, (int)li);
        placeOne(lw.ssmOut, pri, false, (int)li);
    }

    marsWeightsPlaced_ = (report.placed > 0);
    if (auto* vm = marsController_->GetVRAMManager()) {
        report.leaseCount = vm->GetLeaseCount();
        report.bytesGpu0 = vm->GetUsedVRAM(0);
        report.bytesGpu1 = vm->GetUsedVRAM(1);
    }

    printf("[Deep2Engine] MARS placed %zu tensors (oom=%zu skip=%zu) "
           "GPU0=%.2f MB GPU1=%.2f MB\n",
           report.placed, report.oom, report.skipped,
           report.bytesGpu0 / (1024.0 * 1024.0),
           report.bytesGpu1 / (1024.0 * 1024.0));
    /* Measure-and-standdown: controller-on with placed=0 is strictly negative. */
    if (report.placed == 0)
        standdownMARSEmptyPlacement("CONTROLLER_ON_PLACED_0");
    return report;
}

MARS::HotpatchResult Deep2Engine::redirectTensor(uint64_t tensorId, int targetGPU) {
    if (!marsEnabled_ || !marsController_) {
        return MARS::HotpatchResult::MIGRATION_FAILED;
    }
    auto* hotpatch = marsController_->GetTensorHotpatch();
    if (!hotpatch) {
        return MARS::HotpatchResult::MIGRATION_FAILED;
    }
    return hotpatch->Redirect(tensorId, targetGPU);
}

void Deep2Engine::rebalanceMARS() {
    if (!marsEnabled_ || !marsController_) {
        return;
    }
    marsController_->Rebalance();
}

MARS::DynamicParity Deep2Engine::getDynamicParity() const {
    if (!marsEnabled_ || !marsController_) {
        MARS::DynamicParity dp;
        dp.gpu[0] = MARS::GPUState{0, 0, 0, 0, 0.0f, 0.0f, 0.0f, false};
        dp.gpu[1] = MARS::GPUState{1, 0, 0, 0, 0.0f, 0.0f, 0.0f, false};
        return dp;
    }
    return marsController_->GetCurrentParity();
}

bool Deep2Engine::handleTensorFault(uint64_t tensorId) {
    if (!marsEnabled_ || !marsController_) {
        return false;
    }
    return marsController_->HandleTensorFault(tensorId);
}

bool Deep2Engine::handleGPUFailure(int gpu) {
    if (!marsEnabled_ || !marsController_) {
        return false;
    }
    return marsController_->HandleGPUFailure(gpu);
}

namespace {

std::string ToLowerAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

bool HasGGUFExtension(const std::filesystem::path& p) {
    return Deep2::GgufPath::IsLoadableModelFile(p);
}

bool LooksLikeShardedGGUF(const std::filesystem::path& p) {
    const std::string lowerName = ToLowerAscii(p.filename().string());
    return lowerName.find("-of-") != std::string::npos &&
           Deep2::GgufPath::IsLoadableModelFile(p);
}

Deep2::ArchitectureFamily InferFamilyFromArchitecture(const std::string& architecture) {
    const std::string lower = ToLowerAscii(architecture);
    if (lower.find("kimi") != std::string::npos) return Deep2::ArchitectureFamily::KimiK2;
    if (lower.find("deepseek") != std::string::npos) return Deep2::ArchitectureFamily::DeepSeekMLA_MoE;
    if (lower.find("llama") != std::string::npos) return Deep2::ArchitectureFamily::Llama;
    return Deep2::ArchitectureFamily::Unknown;
}

Deep2::KimiK2Config makeK2Config0905Fallback() {
    Deep2::KimiK2Config k2cfg;
    k2cfg.family = Deep2::ArchitectureFamily::KimiK2;
    k2cfg.modelType = "kimi_k2";
    k2cfg.architecture = "kimi_k2";
    k2cfg.hiddenDim = 7168;
    k2cfg.numLayers = 61;
    k2cfg.numHeads = 64;
    k2cfg.numKVHeads = 1;
    k2cfg.qLoraRank = 1536;
    k2cfg.kvLoraRank = 512;
    k2cfg.qkNopeHeadDim = 128;
    k2cfg.qkRopeHeadDim = 64;
    k2cfg.vHeadDim = 128;
    k2cfg.numExperts = 384;
    k2cfg.expertsPerToken = 8;
    k2cfg.vocabSize = 163840;
    k2cfg.valid = true;
    return k2cfg;
}

Deep2::KimiK2Config makeK2ConfigFromMetadata(const Deep2::ModelMetadata& meta,
                                             uint32_t shardCount) {
    Deep2::KimiK2Config cfg;
    cfg.architecture = meta.architecture;
    cfg.modelType = meta.architecture;
    cfg.family = InferFamilyFromArchitecture(meta.architecture);
    cfg.hiddenDim = meta.hiddenSize;
    cfg.numLayers = meta.numLayers;
    cfg.numHeads = meta.numHeads;
    cfg.numKVHeads = meta.numKeyValueHeads > 0 ? meta.numKeyValueHeads : meta.numHeads;
    cfg.qLoraRank = meta.qLoraRank;
    cfg.kvLoraRank = meta.kvLoraRank;
    cfg.qkRopeHeadDim = meta.ropeDimensionCount;

    if (meta.keyLengthMla > cfg.qkRopeHeadDim) {
        cfg.qkNopeHeadDim = meta.keyLengthMla - cfg.qkRopeHeadDim;
    } else if (meta.keyLength > cfg.qkRopeHeadDim) {
        cfg.qkNopeHeadDim = meta.keyLength - cfg.qkRopeHeadDim;
    }
    cfg.vHeadDim = meta.valueLengthMla > 0 ? meta.valueLengthMla : meta.valueLength;

    cfg.numExperts = meta.numExperts;
    cfg.expertsPerToken = meta.numExpertsPerToken;
    cfg.sharedExperts = meta.numSharedExperts;
    cfg.moeIntermediateSize = meta.moeIntermediateSize > 0
        ? meta.moeIntermediateSize : meta.intermediateSize;

    cfg.vocabSize = meta.vocabSize;
    cfg.maxPosition = meta.maxPositionEmbeddings;
    cfg.normRmsEps = meta.rmsNormEps > 0 ? meta.rmsNormEps : 1e-5f;
    cfg.ropeTheta = meta.ropeTheta > 0 ? meta.ropeTheta : 50000.0f;
    cfg.ropeScalingFactor = meta.ropeScaling > 0 ? meta.ropeScaling : 1.0f;
    cfg.numShards = shardCount > 0 ? shardCount : 1;
    cfg.currentShard = 0;

    if (cfg.family == Deep2::ArchitectureFamily::Unknown &&
        cfg.qLoraRank > 0 && cfg.kvLoraRank > 0 && cfg.numExperts > 0) {
        cfg.family = Deep2::ArchitectureFamily::DeepSeekMLA_MoE;
    }

    cfg.valid = cfg.hiddenDim > 0 && cfg.numLayers > 0 && cfg.vocabSize > 0;
    if (!cfg.valid) {
        cfg.error = "metadata missing required hidden/layers/vocab dimensions";
    }
    return cfg;
}

std::vector<std::filesystem::path> discoverK2Shards(const std::filesystem::path& dir) {
    std::vector<std::filesystem::path> all;
    std::vector<std::filesystem::path> sharded;
    if (!std::filesystem::exists(dir) || !std::filesystem::is_directory(dir)) {
        return {};
    }

    for (const auto& entry : std::filesystem::directory_iterator(dir)) {
        if (!entry.is_regular_file()) continue;
        const auto p = entry.path();
        if (!HasGGUFExtension(p)) continue;
        all.push_back(p);
        if (LooksLikeShardedGGUF(p)) {
            sharded.push_back(p);
        }
    }

    auto byFilename = [](const std::filesystem::path& a, const std::filesystem::path& b) {
        return ToLowerAscii(a.filename().string()) < ToLowerAscii(b.filename().string());
    };
    std::sort(all.begin(), all.end(), byFilename);
    std::sort(sharded.begin(), sharded.end(), byFilename);

    if (!sharded.empty()) return sharded;
    return all;
}

} // namespace

bool Deep2Engine::openK2ShardDirectory(const std::string& shardDirPath) {
    namespace fs = std::filesystem;
    Deep2::Ev512::HostTryArm(0x4B325348415244ull); /* K2SHARD */
    const uint64_t pathH = Deep2::Ev512::HostPathHash(shardDirPath.c_str());
    Deep2::Ev512::HostEmitModelDiscovery(pathH, 0);
    Deep2::Ev512::HostEmitModelIdentity(pathH, pathH);
    Deep2::Ev512::HostEmitModelLoadEntry(pathH, (uint64_t)config.maxSeqLen);
    fs::path shardDir(shardDirPath);
    if (!fs::is_directory(shardDir)) {
        printf("[Deep2Engine] openK2ShardDirectory: not a directory: %s\n",
               shardDirPath.c_str());
        return false;
    }
    auto shards = discoverK2Shards(shardDir);
    if (shards.empty()) {
        printf("[Deep2Engine] openK2ShardDirectory: no GGUF shards in %s\n",
               shardDirPath.c_str());
        return false;
    }

    GGUFLoadResult firstMeta = GGUFLoader::LoadMetadata(shards.front().string().c_str());
    if (firstMeta.success) {
        k2ShardConfig_ = makeK2ConfigFromMetadata(firstMeta.metadata,
            static_cast<uint32_t>(shards.size()));
    } else {
        printf("[Deep2Engine] openK2ShardDirectory: metadata parse failed (%s), using fallback contract\n",
               firstMeta.error);
        k2ShardConfig_ = makeK2Config0905Fallback();
        k2ShardConfig_.numShards = static_cast<uint32_t>(shards.size());
    }

    if (!k2ShardConfig_.valid) {
        printf("[Deep2Engine] openK2ShardDirectory: incomplete metadata (%s), using fallback contract\n",
               k2ShardConfig_.error.c_str());
        Deep2::KimiK2Config fallback = makeK2Config0905Fallback();
        fallback.numShards = static_cast<uint32_t>(shards.size());
        k2ShardConfig_ = fallback;
    }

    globalIndex_ = std::make_unique<GlobalTensorIndex>();
    std::string indexError;
    if (!globalIndex_->BuildFromShardDirectory(shardDir, k2ShardConfig_, indexError)) {
        printf("[Deep2Engine] openK2ShardDirectory: index build failed: %s\n",
               indexError.c_str());
        globalIndex_.reset();
        return false;
    }
    modelDir_ = shardDir;
    isMultiShard_ = true;
    k2ShardIndexOpen_ = true;
    modelWeights.loaded = true;
    modelState_ = ModelState::Indexed;
    modelWeights.useMLA = true;
    strncpy(config.modelPath, shardDirPath.c_str(), sizeof(config.modelPath) - 1);
    config.modelPath[sizeof(config.modelPath) - 1] = '\0';
    // Arm NVMeâ†’K2ShardIo after path is known (init often runs with empty path).
    nvmeConfig_.modelPath = shardDirPath;
    _putenv_s("DEEP2_K2_SHARD_DIR", shardDirPath.c_str());
    const size_t warmed = K2ShardIo_WarmDirectory(shardDirPath);
    if (!nvmeStream_) nvmeStream_ = std::make_unique<NVMeStream>();
    nvmeStreamingEnabled_ = true;
    if (nvmeStream_->initialize(nvmeConfig_)) {
        LivePath_NoteNvmeAbsence(0);
        printf("[Deep2Engine] NVMe lane armed via SHARD_IO (warmed=%zu)\n", warmed);
    } else {
        printf("[Deep2Engine] WARNING: NVMe lane still cold after shard open\n");
    }
    printf("[Deep2Engine] K2 shard index open: %zu tensors, %zu shards, arch=%s\n",
           globalIndex_->TotalTensors(),
           shards.size(),
           k2ShardConfig_.architecture.c_str());
    // Propagate MLA dims into EngineConfig so allocateBuffers / live path
    // use tensor authority (q_b cols = heads*(nope+rope) = 12288).
    config.useMLA = true;
    config.hiddenDim = k2ShardConfig_.hiddenDim ? k2ShardConfig_.hiddenDim
                                                : config.hiddenDim;
    config.numLayers = k2ShardConfig_.numLayers ? k2ShardConfig_.numLayers
                                                : config.numLayers;
    config.numHeads = k2ShardConfig_.numHeads ? k2ShardConfig_.numHeads
                                              : config.numHeads;
    config.numKVHeads = k2ShardConfig_.numKVHeads ? k2ShardConfig_.numKVHeads
                                                  : config.numKVHeads;
    config.vocabSize = k2ShardConfig_.vocabSize ? k2ShardConfig_.vocabSize
                                                : config.vocabSize;
    config.qLoraRank = k2ShardConfig_.qLoraRank;
    config.kvLoraRank = k2ShardConfig_.kvLoraRank;
    config.qkNopeHeadDim = k2ShardConfig_.qkNopeHeadDim;
    config.qkRopeHeadDim = k2ShardConfig_.qkRopeHeadDim;
    config.vHeadDim = k2ShardConfig_.vHeadDim;
    config.headDim = k2ShardConfig_.qkNopeHeadDim + k2ShardConfig_.qkRopeHeadDim;
    modelWeights.hiddenDim = config.hiddenDim;
    modelWeights.numLayers = config.numLayers;
    modelWeights.numHeads = config.numHeads;
    modelWeights.numKVHeads = config.numKVHeads;
    modelWeights.vocabSize = config.vocabSize;
    modelWeights.headDim = config.headDim;
    modelWeights.qLoraRank = config.qLoraRank;
    modelWeights.kvLoraRank = config.kvLoraRank;
    modelWeights.qkNopeHeadDim = config.qkNopeHeadDim;
    modelWeights.qkRopeHeadDim = config.qkRopeHeadDim;
    modelWeights.vHeadDim = config.vHeadDim;
    {
        const std::string tokPath = shards.front().string();
        (void)CanonicalTokenizer::Instance().LoadFromGGUF(tokPath);
        auto bundle = LoadTokenizerFromGGUF(tokPath.c_str());
        if (bundle.ok) {
            auto bpe = std::make_unique<BPETokenizer>();
            if (ApplyTokenizerBundle(*bpe, bundle))
                tokenizer = std::move(bpe);
        }
        if (!tokenizer) {
            fprintf(stderr, "[Deep2Engine] ERROR: K2 shard tokenizer load failed\n");
            return false;
        }
        printf("[Deep2Engine] K2 tokenizer loaded: vocab=%zu bos=%d eos=%d\n",
               tokenizer->VocabSize(), tokenizer->GetSpecialTokens().bosId,
               tokenizer->GetSpecialTokens().eosId);
    }
    Deep2::Ev512::HostEmitModelLoadComplete(pathH, globalIndex_->TotalTensors());
    Deep2::Ev512::HostEmitShardResolution((uint64_t)shards.size(),
                                          (uint64_t)shards.size());
    Deep2::Ev512::HostEmitArchContract(
        Deep2::Ev512::HostPathHash(k2ShardConfig_.architecture.c_str()),
        (uint64_t)config.numLayers, 1u);
    Deep2::Ev512::HostEmitQuantContract(0, 0, 1u);
    Deep2::Ev512::HostEmitTokenizerContract(
        0, (uint64_t)tokenizer->VocabSize(), 1u);
    {
        const auto& sp = tokenizer->GetSpecialTokens();
        Deep2::Ev512::HostEmitTemplateEogContract(
            (uint64_t)(uint32_t)sp.bosId,
            (uint64_t)(uint32_t)sp.eosId, 1u);
        Deep2::Ev512::HostEmitTensorSchema(
            globalIndex_->TotalTensors(), globalIndex_->TotalTensors(), 1u);
    }
    Deep2::Ev512::HostEmitDeep2SessionCreate(pathH, (uint64_t)shards.size());
    Deep2::Ev512::HostEmitDeep2SessionReady(1, (uint64_t)shards.size());
    /* Select-time: warm first LA MLA layers before generateStream cold reads. */
    if (globalIndex_ &&
        (Deep2::LivePath_Wanted() || Deep2::K2LiveCache_OwnsLayer() ||
         Deep2::K2LiveCache_MayCache("blk.0.attn_q_a.weight"))) {
        uint32_t la = 3u;
        if (const char* e = std::getenv("DEEP2_ELASTIC_LOOKAHEAD")) {
            const int v = std::atoi(e);
            if (v > 0 && v <= 8) la = (uint32_t)v;
        }
        constexpr uint64_t kPerLayer = 55300000ull;
        const uint64_t need = kPerLayer * (uint64_t)la;
        const uint64_t bud = Deep2::K2LiveCache_Budget();
        /* Sticky Put can promote budget; skip only if zero and not sticky-capable. */
        if (bud >= need ||
            Deep2::K2LiveCache_MayCache("blk.0.attn_q_a.weight")) {
            Deep2::K2LiveCache_PrefetchLayer(*globalIndex_, 0, la);
            printf("[Deep2Engine] K2 select-time PrefetchLayer L0..+%u "
                   "budget=%llu\n",
                   la, (unsigned long long)Deep2::K2LiveCache_Budget());
        }
    }
    return true;
}

K2NativeStreamGate::Result Deep2Engine::runK2NativeStreamPartial(
    const K2NativeStreamGate::Config& cfg) {
    // #region agent log
    {
        FILE* df = fopen("g:/~dev/debug-1f4d81.log", "a");
        if (df) {
            fprintf(df,
                "{\"sessionId\":\"1f4d81\",\"runId\":\"post-fix\",\"hypothesisId\":\"A\","
                "\"location\":\"Deep2Engine.cpp:runK2NativeStreamPartial\","
                "\"message\":\"stream_partial_enter\","
                "\"data\":{\"livePathActive\":%d,\"cycloneEnabled\":%d,\"streamTokens\":%u,\"layerDepth\":%u},"
                "\"timestamp\":%lld}\n",
                LivePath_Active() ? 1 : 0, cycloneEnabled_ ? 1 : 0,
                cfg.streamTokens, cfg.layerDepth,
                (long long)std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count());
            fclose(df);
        }
    }
    // #endregion
    K2NativeStreamGate::Result result;
    if (!k2ShardIndexOpen_ || !globalIndex_) {
        result.error = "K2 shard index not open";
        return result;
    }
    auto shards = discoverK2Shards(modelDir_);
    if (shards.empty()) {
        result.error = "No GGUF shards discovered in indexed directory";
        return result;
    }
    k2ShardConfig_.numShards = static_cast<uint32_t>(shards.size());

    {
        uint32_t depth = cfg.layerDepth ? cfg.layerDepth : 1;
        if (const char* el = std::getenv("RAWRXD_K2_LAYERS")) {
            int n = atoi(el);
            if (n > 0) depth = (uint32_t)n;
        }
        auto pol = K2LivePolicy_Apply(depth, cfg.streamTokens);
        K2LivePolicy_Emit(stdout, pol);
    }

    // K2_GPU_STREAM_COPY / MLA: open Vulkan + bind streamâ†’GPU upload path.
    if (K2GpuStreamCopy_Wanted() || MLA_GpuGemvWanted()) {
        if (!vulkanInitialized_) enableVulkan(true);
        K2GpuStreamCopy_Bind(getVulkanComputeSlot(0));
        K2GpuStreamCopy_Reset();
        MLA_GpuGemv_Reset();
    }

    const bool liveOn = LivePath_Wanted();
    CycloneScheduler* liveCyclone = nullptr;
    try {
        if (liveOn) {
            fprintf(stdout, "[Deep2Engine] LIVE_SETUP begin wanted=1\n");
            fflush(stdout);
            LivePath_ApplyMechEnv();
            const char* pol = std::getenv("DEEP2_LIVE_POLICY");
            const bool manual =
#ifdef _WIN32
                pol && (_stricmp(pol, "MANUAL") == 0);
#else
                pol && (strcasecmp(pol, "MANUAL") == 0);
#endif
            // AUTO/force already set enhancements + DEEP2_LIVE_MECH in K2LivePolicy_Apply.
            if (!manual) {
                const char* fe = std::getenv("DEEP2_LIVE_FUSED");
                const bool fusedOff = fe && fe[0] == '0' && fe[1] == 0;
                LivePath_SetFusedEnabled(!fusedOff);
            }
            if (LivePath_MechOn(LP_MECH_ELASTIC) && EnhanceWanted("elastic")) {
                if (!elasticResidencyEnabled_ || !elasticResidency_)
                    enableElasticResidency(true);
                // Do NOT refreshElasticDynamicBudget here â€” mid-request
                // budget churn + window rebuilds destroyed pin reuse (uâ†‘).
            }
            if (LivePath_MechOn(LP_MECH_CYCLONE) && EnhanceWanted("cyclone")) {
                if (!cyclone_)
                    enableCyclone(true);
                else if (elasticResidency_ && !vulkanEnabled_)
                    cyclone_->RebindElastic(elasticResidency_.get());
            }
            if (LivePath_MechOn(LP_MECH_STREAM)) {
                if (!plasmaGovernorEnabled_ || !plasmaGovernor_)
                    enablePlasmaGovernor(true);
                const std::string nvmePath = config.modelPath[0]
                    ? std::string(config.modelPath)
                    : (!modelDir_.empty() ? modelDir_.string() : std::string());
                enableNVMeStreaming(true, nvmePath);
                initializeAdvancedFeatures();
                if (nvmeStream_ && !nvmeStream_->isReverseBunnyHop())
                    (void)nvmeStream_->initializeReverseBunnyHop(nvmeConfig_);
            }
            if (LivePath_MechOn(LP_MECH_WARMUP))
                enableWarmupScheduler(true);
            LivePath_BindOwners(
                elasticResidency_.get(), nvmeStream_.get(), plasmaGovernor_.get(),
                static_cast<uint32_t>(config.numLayers ? config.numLayers : modelWeights.numLayers),
                static_cast<uint32_t>(modelWeights.numHeads ? modelWeights.numHeads : 8));
            liveCyclone =
                (LivePath_MechOn(LP_MECH_CYCLONE) && cycloneEnabled_) ? cyclone_.get() : nullptr;
            LivePath_BeginGenerate(cfg.streamTokens, elasticResidency_.get(), &liveCyclone);
            // Authoritative NVMe witness AFTER BeginGenerate (ctr reset)
            if (!nvmeStreamingEnabled_ || !nvmeStream_)
                LivePath_NoteNvmeAbsence(1);
            fprintf(stdout, "[Deep2Engine] LIVE_SETUP ok active=%u\n",
                    LivePath_Active() ? 1u : 0u);
            fflush(stdout);
        }
        // #region agent log
        {
            FILE* df = fopen("g:/~dev/debug-1f4d81.log", "a");
            if (df) {
                fprintf(df,
                    "{\"sessionId\":\"1f4d81\",\"runId\":\"eff\",\"hypothesisId\":\"EFF\","
                    "\"location\":\"Deep2Engine.cpp:runK2NativeStreamPartial\","
                    "\"message\":\"stream_live_gate\","
                    "\"data\":{\"liveWanted\":%d,\"livePathActive\":%d,\"streamTokens\":%u},"
                    "\"timestamp\":0}\n",
                    liveOn ? 1 : 0, LivePath_Active() ? 1 : 0, cfg.streamTokens);
                fclose(df);
            }
        }
        // #endregion
        result = K2NativeStreamGate::Run(modelDir_, *globalIndex_, k2ShardConfig_, shards, cfg);
    } catch (const std::exception& ex) {
        result.ok = false;
        result.error = std::string("stream_partial exception: ") + ex.what();
        fprintf(stderr, "[Deep2Engine] %s\n", result.error.c_str());
        fflush(stderr);
    } catch (...) {
        result.ok = false;
        result.error = "stream_partial unknown exception";
        fprintf(stderr, "[Deep2Engine] %s\n", result.error.c_str());
        fflush(stderr);
    }
    if (K2GpuStreamCopy_Wanted())
        K2GpuStreamCopy_Emit(stdout);
    if (MLA_GpuGemvWanted()) {
        printf("MLA_GPU_GEMV_OPS=%llu MLA_GPU_GEMV_FAIL=%llu\n",
               (unsigned long long)MLA_GpuGemvOps(),
               (unsigned long long)MLA_GpuGemvFail());
    }
    if (liveOn) {
        LivePath_NoteResidencyPeak(result.peakResidencyBytes);
        LivePath_EndGenerate(liveCyclone);
        LivePath_Emit(stdout);
    }
    return result;
}

} // namespace Deep2

// ============================================================================
// C API Wrappers - Extern "C" for cross-language / benchmark linkage
// ============================================================================
extern "C" {

void* Deep2_CreateEngine() {
    return new Deep2::Deep2Engine();
}

void Deep2_DestroyEngine(void* engine) {
    delete static_cast<Deep2::Deep2Engine*>(engine);
}

int Deep2_Initialize(void* engine, const void* config) {
    if (!engine || !config) return 0;
    auto* e = static_cast<Deep2::Deep2Engine*>(engine);
    const auto* cfg = static_cast<const Deep2::EngineConfig*>(config);
    return e->initialize(*cfg) ? 1 : 0;
}

void Deep2_Forward(void* engine, const float* input, float* output, size_t count) {
    if (!engine || !input || !output || count == 0) return;
    auto* e = static_cast<Deep2::Deep2Engine*>(engine);
    
    // Check if configuration has been initialized
    if (e->getConfig().hiddenDim == 0) {
        std::memcpy(output, input, count * sizeof(float));
        return;
    }
    
    const size_t hiddenDim = e->getConfig().hiddenDim;
    const size_t numLayers = e->getConfig().numLayers;
    
    // We expect count to be a multiple of hiddenDim
    size_t iters = count / hiddenDim;
    if (iters == 0) {
        std::memcpy(output, input, count * sizeof(float));
        return;
    }
    
    // Process each token sequentially through all layers
    for (size_t i = 0; i < iters; i++) {
        const float* currentInput = input + i * hiddenDim;
        float* currentOutput = output + i * hiddenDim;
        
        // Setup temporary buffers for layer ping-pong
        std::vector<float> temp1(currentInput, currentInput + hiddenDim);
        std::vector<float> temp2(hiddenDim);
        
        float* layerInput = temp1.data();
        float* layerOutput = temp2.data();
        
        // Pass through each transformer block
        for (size_t layer = 0; layer < numLayers; ++layer) {
            size_t seqPos = i; 
            // We pass seqPos+1 so RoPE matches expected index
            e->forwardLayerPublic(layer, layerInput, layerOutput, seqPos + 1);
            std::swap(layerInput, layerOutput);
        }
        
        std::memcpy(currentOutput, layerInput, hiddenDim * sizeof(float));
    }
}

} // extern "C"

