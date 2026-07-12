// ============================================================================
// TransformerLayerRuntime.cpp - Tensor-backed Transformer Block Implementation
// ============================================================================

#include "transformer_layer_runtime.hpp"
#include "tensor_view.hpp"  // For TensorView definition

#include <cmath>
#include <algorithm>
#include <cstring>

// Sovereign Kernel Integration
extern "C" {
    #include "../src/asm/Sovereign_KernelDispatch.h"
}

namespace RawrXD {
namespace Runtime {

// ============================================================================
// Global Kernel Table (initialized once, shared across all layers)
// ============================================================================
static Sovereign_KernelTable g_kernelTable;
static bool g_kernelsInitialized = false;
static bool g_kernelsAvailable = false;

bool InitializeSovereignKernels() {
    if (g_kernelsInitialized) return g_kernelsAvailable;
    
    int result = Sovereign_InitKernelTable(&g_kernelTable);
    if (result != 0) {
        g_kernelsAvailable = false;
        g_kernelsInitialized = true;
        return false;
    }
    
    g_kernelsAvailable = true;
    g_kernelsInitialized = true;
    return true;
}

bool AreSovereignKernelsAvailable() {
    if (!g_kernelsInitialized) {
        InitializeSovereignKernels();
    }
    return g_kernelsAvailable;
}

const Sovereign_KernelTable* GetSovereignKernelTable() {
    if (!g_kernelsInitialized) {
        InitializeSovereignKernels();
    }
    return g_kernelsAvailable ? &g_kernelTable : nullptr;
}

// ============================================================================
// Utility Functions
// ============================================================================
static inline float Sigmoid(float x) {
    return 1.0f / (1.0f + std::exp(-x));
}

static inline float SiLU(float x) {
    return x * Sigmoid(x);
}

// ============================================================================
// Layer Binding
// ============================================================================
bool TransformerLayerRuntime::BindLayer(uint32_t layerIndex,
                                        const TensorView& inputNorm,
                                        const TensorView& qProj,
                                        const TensorView& kProj,
                                        const TensorView& vProj,
                                        const TensorView& oProj,
                                        const TensorView& postNorm,
                                        const TensorView& gateProj,
                                        const TensorView& upProj,
                                        const TensorView& downProj) {
    m_layerIndex = layerIndex;
    
    // Store tensor view pointers
    m_inputNorm = &inputNorm;
    m_qProj = &qProj;
    m_kProj = &kProj;
    m_vProj = &vProj;
    m_oProj = &oProj;
    m_postNorm = &postNorm;
    m_gateProj = &gateProj;
    m_upProj = &upProj;
    m_downProj = &downProj;
    
    // Infer configuration from tensor shapes
    if (inputNorm.IsValid()) {
        m_config.hiddenSize = inputNorm.Cols() > 0 ? inputNorm.Cols() : inputNorm.Rows();
    }
    
    // For Q/K/V projections, assume standard MHA with equal heads
    // qProj shape: [hidden_size, hidden_size] means num_heads = hidden_size / head_dim
    // Default to head_dim = 64 (standard), then num_heads = hidden_size / 64
    if (m_config.hiddenSize > 0) {
        m_config.headDim = 64;  // Standard head dimension
        m_config.numHeads = m_config.hiddenSize / m_config.headDim;
        m_config.numKVHeads = m_config.numHeads;  // MHA by default
    }
    
    if (kProj.IsValid()) {
        uint32_t kCols = kProj.Cols();
        if (m_config.headDim > 0) {
            uint32_t inferredKVHeads = kCols / m_config.headDim;
            if (inferredKVHeads > 0 && inferredKVHeads <= m_config.numHeads) {
                m_config.numKVHeads = inferredKVHeads;
                m_config.useGQA = (m_config.numKVHeads != m_config.numHeads);
                m_config.useMQA = (m_config.numKVHeads == 1);
            }
        }
    }
    
    if (gateProj.IsValid()) {
        m_config.intermediateSize = gateProj.Cols();
    }
    
    m_isBound = ValidateTensors();
    return m_isBound;
}

bool TransformerLayerRuntime::ValidateTensors() const {
    if (!m_inputNorm || !m_inputNorm->IsValid()) return false;
    if (!m_qProj || !m_qProj->IsValid()) return false;
    if (!m_kProj || !m_kProj->IsValid()) return false;
    if (!m_vProj || !m_vProj->IsValid()) return false;
    if (!m_oProj || !m_oProj->IsValid()) return false;
    if (!m_postNorm || !m_postNorm->IsValid()) return false;
    if (!m_gateProj || !m_gateProj->IsValid()) return false;
    if (!m_upProj || !m_upProj->IsValid()) return false;
    if (!m_downProj || !m_downProj->IsValid()) return false;
    
    // Validate shapes match configuration
    // Input norm should be [hidden_size]
    if (m_inputNorm->Rows() != m_config.hiddenSize && m_inputNorm->Cols() != m_config.hiddenSize) {
        return false;
    }
    
    // Q projection should have hidden_size columns
    if (m_qProj->Cols() != m_config.hiddenSize) {
        return false;
    }
    
    return true;
}

// ============================================================================
// Forward Pass
// ============================================================================
bool TransformerLayerRuntime::Forward(const float* input,
                                       uint32_t seqLen,
                                       uint32_t position,
                                       float* output,
                                       float* keyCache,
                                       float* valueCache,
                                       uint32_t maxSeqLen) const {
    if (!m_isBound) return false;
    
    const uint32_t hiddenSize = m_config.hiddenSize;
    const uint32_t numHeads = m_config.numHeads;
    const uint32_t numKVHeads = m_config.numKVHeads;
    const uint32_t headDim = m_config.headDim;
    const uint32_t intermediateSize = m_config.intermediateSize;
    
    // Temporary buffers
    std::vector<float> tempBuffer(hiddenSize);
    std::vector<float> normBuffer(hiddenSize);
    std::vector<float> qBuffer(hiddenSize);
    std::vector<float> kBuffer(numKVHeads * headDim);
    std::vector<float> vBuffer(numKVHeads * headDim);
    std::vector<float> attnOutBuffer(hiddenSize);
    std::vector<float> mlpBuffer(hiddenSize);
    std::vector<float> gateBuffer(intermediateSize);
    std::vector<float> upBuffer(intermediateSize);
    std::vector<float> downBuffer(hiddenSize);
    
    // ------------------------------------------------------------------------
    // Step 1: Input RMSNorm
    // ------------------------------------------------------------------------
    // Read norm weights
    if (!ReadWeightVector(*m_inputNorm, normBuffer.data(), hiddenSize)) {
        return false;
    }
    
    // Apply RMSNorm: x * rsqrt(mean(x^2) + eps) * weight
    ComputeRMSNorm(input, tempBuffer.data(), hiddenSize, m_config.rmsNormEps);
    for (uint32_t i = 0; i < hiddenSize; ++i) {
        tempBuffer[i] *= normBuffer[i];
    }
    
    // ------------------------------------------------------------------------
    // Step 2: Q, K, V Projections
    // ------------------------------------------------------------------------
    // Read projection weights and compute
    std::vector<float> qWeights(hiddenSize * hiddenSize);
    std::vector<float> kWeights(hiddenSize * numKVHeads * headDim);
    std::vector<float> vWeights(hiddenSize * numKVHeads * headDim);
    
    if (!ReadWeightMatrix(*m_qProj, qWeights.data(), hiddenSize, hiddenSize)) return false;
    if (!ReadWeightMatrix(*m_kProj, kWeights.data(), hiddenSize, numKVHeads * headDim)) return false;
    if (!ReadWeightMatrix(*m_vProj, vWeights.data(), hiddenSize, numKVHeads * headDim)) return false;
    
    // Q = input * Wq
    ComputeMatMul(tempBuffer.data(), qWeights.data(), qBuffer.data(),
                  1, hiddenSize, hiddenSize);
    
    // K = input * Wk
    ComputeMatMul(tempBuffer.data(), kWeights.data(), kBuffer.data(),
                  1, numKVHeads * headDim, hiddenSize);
    
    // V = input * Wv
    ComputeMatMul(tempBuffer.data(), vWeights.data(), vBuffer.data(),
                  1, numKVHeads * headDim, hiddenSize);
    
    // ------------------------------------------------------------------------
    // Step 3: Apply RoPE (Rotary Position Embeddings)
    // ------------------------------------------------------------------------
    ApplyRoPE(qBuffer.data(), kBuffer.data(), numHeads, numKVHeads, headDim,
              position, m_config.ropeTheta);
    
    // ------------------------------------------------------------------------
    // Step 4: Store K, V in cache
    // ------------------------------------------------------------------------
    if (keyCache && valueCache && position < maxSeqLen) {
        // keyCache layout: [maxSeqLen, numKVHeads, headDim]
        // valueCache layout: [maxSeqLen, numKVHeads, headDim]
        uint32_t kvStride = numKVHeads * headDim;
        std::memcpy(keyCache + position * kvStride, kBuffer.data(), 
                    kvStride * sizeof(float));
        std::memcpy(valueCache + position * kvStride, vBuffer.data(),
                    kvStride * sizeof(float));
    }
    
    // ------------------------------------------------------------------------
    // Step 5: Attention Computation (Optimized)
    // ------------------------------------------------------------------------
    // For each head, compute attention with all cached keys/values
    // This is a simplified single-token attention for inference
    
    for (uint32_t h = 0; h < numHeads; ++h) {
        uint32_t kvHead = h / (numHeads / std::max(1u, numKVHeads));  // GQA mapping
        
        float* qHead = qBuffer.data() + h * headDim;
        float* outHead = attnOutBuffer.data() + h * headDim;
        
        // Compute attention scores for all positions
        std::vector<float> attnScores(seqLen);
        float scale = 1.0f / std::sqrt(static_cast<float>(headDim));
        
        for (uint32_t pos = 0; pos < seqLen; ++pos) {
            // Q @ K^T for this position
            float* kHead = keyCache + pos * numKVHeads * headDim + kvHead * headDim;
            float qk = 0.0f;
            for (uint32_t i = 0; i < headDim; ++i) {
                qk += qHead[i] * kHead[i];
            }
            attnScores[pos] = qk * scale;
        }
        
        // Softmax over positions
        ComputeSoftmax(attnScores.data(), seqLen);
        
        // Weighted sum of values for each dimension
        for (uint32_t d = 0; d < headDim; ++d) {
            float sum = 0.0f;
            for (uint32_t pos = 0; pos < seqLen; ++pos) {
                float* vHead = valueCache + pos * numKVHeads * headDim + kvHead * headDim;
                sum += attnScores[pos] * vHead[d];
            }
            outHead[d] = sum;
        }
    }
    
    // ------------------------------------------------------------------------
    // Step 6: Output Projection
    // ------------------------------------------------------------------------
    std::vector<float> oWeights(hiddenSize * hiddenSize);
    if (!ReadWeightMatrix(*m_oProj, oWeights.data(), hiddenSize, hiddenSize)) return false;
    
    ComputeMatMul(attnOutBuffer.data(), oWeights.data(), tempBuffer.data(),
                  1, hiddenSize, hiddenSize);
    
    // Residual connection
    AccumulateResidual(input, tempBuffer.data(), hiddenSize);
    
    // ------------------------------------------------------------------------
    // Step 7: Post-Attention RMSNorm
    // ------------------------------------------------------------------------
    std::vector<float> postNormWeights(hiddenSize);
    if (!ReadWeightVector(*m_postNorm, postNormWeights.data(), hiddenSize)) return false;
    
    ComputeRMSNorm(tempBuffer.data(), normBuffer.data(), hiddenSize, m_config.rmsNormEps);
    for (uint32_t i = 0; i < hiddenSize; ++i) {
        normBuffer[i] *= postNormWeights[i];
    }
    
    // ------------------------------------------------------------------------
    // Step 8: MLP (Gate + Up projections)
    // ------------------------------------------------------------------------
    std::vector<float> gateWeights(hiddenSize * intermediateSize);
    std::vector<float> upWeights(hiddenSize * intermediateSize);
    
    if (!ReadWeightMatrix(*m_gateProj, gateWeights.data(), hiddenSize, intermediateSize)) return false;
    if (!ReadWeightMatrix(*m_upProj, upWeights.data(), hiddenSize, intermediateSize)) return false;
    
    // gate = SiLU(input * Wgate)
    ComputeMatMul(normBuffer.data(), gateWeights.data(), gateBuffer.data(),
                  1, intermediateSize, hiddenSize);
    ComputeSiLU(gateBuffer.data(), gateBuffer.data(), intermediateSize);
    
    // up = input * Wup
    ComputeMatMul(normBuffer.data(), upWeights.data(), upBuffer.data(),
                  1, intermediateSize, hiddenSize);
    
    // gate * up (element-wise)
    for (uint32_t i = 0; i < intermediateSize; ++i) {
        gateBuffer[i] *= upBuffer[i];
    }
    
    // ------------------------------------------------------------------------
    // Step 9: Down Projection
    // ------------------------------------------------------------------------
    std::vector<float> downWeights(intermediateSize * hiddenSize);
    if (!ReadWeightMatrix(*m_downProj, downWeights.data(), intermediateSize, hiddenSize)) return false;
    
    ComputeMatMul(gateBuffer.data(), downWeights.data(), output,
                  1, hiddenSize, intermediateSize);
    
    // Final residual connection
    AccumulateResidual(tempBuffer.data(), output, hiddenSize);
    
    return true;
}

// ============================================================================
// Internal Compute Kernels (with Sovereign acceleration)
// ============================================================================
void TransformerLayerRuntime::ComputeRMSNorm(const float* input,
                                              float* output,
                                              uint32_t size,
                                              float eps) const {
    // Try Sovereign kernel first
    const Sovereign_KernelTable* kernels = GetSovereignKernelTable();
    if (kernels && kernels->rms_norm_f32) {
        // Use identity weights (1.0) for base RMSNorm
        alignas(64) float weights[8192];
        alignas(64) float tempInput[8192];
        for (uint32_t i = 0; i < size && i < 8192; ++i) {
            weights[i] = 1.0f;
            tempInput[i] = input[i];
        }
        kernels->rms_norm_f32(tempInput, weights, output, static_cast<uint64_t>(size), eps);
        return;
    }
    
    // Scalar fallback
    float sumSq = 0.0f;
    for (uint32_t i = 0; i < size; ++i) {
        sumSq += input[i] * input[i];
    }
    float rms = std::sqrt(sumSq / size + eps);
    float scale = 1.0f / rms;
    
    // Normalize
    for (uint32_t i = 0; i < size; ++i) {
        output[i] = input[i] * scale;
    }
}

void TransformerLayerRuntime::ComputeMatMul(const float* A, const float* B, float* C,
                                             uint32_t M, uint32_t N, uint32_t K) const {
    // C[M,N] = A[M,K] @ B[K,N]
    // Here M is always 1 for single token
    for (uint32_t n = 0; n < N; ++n) {
        float sum = 0.0f;
        for (uint32_t k = 0; k < K; ++k) {
            sum += A[k] * B[k * N + n];
        }
        C[n] = sum;
    }
}

void TransformerLayerRuntime::ComputeAttention(const float* query,
                                             const float* key,
                                             const float* value,
                                             float* output,
                                             uint32_t seqLen,
                                             uint32_t numHeads,
                                             uint32_t numKVHeads,
                                             uint32_t headDim) const {
    // Simplified attention - full implementation in Forward()
    (void)query; (void)key; (void)value; (void)output;
    (void)seqLen; (void)numHeads; (void)numKVHeads; (void)headDim;
}

void TransformerLayerRuntime::ApplyRoPE(float* query,
                                         float* key,
                                         uint32_t numHeads,
                                         uint32_t numKVHeads,
                                         uint32_t headDim,
                                         uint32_t position,
                                         float theta) const {
    // Try Sovereign kernel first
    const Sovereign_KernelTable* kernels = GetSovereignKernelTable();
    if (kernels && kernels->rope_apply_f32) {
        // Apply RoPE to query using Sovereign kernel
        alignas(64) float freqCache[8192];
        kernels->rope_apply_f32(query, freqCache, position + 1, headDim, numHeads);
        // Apply RoPE to key using Sovereign kernel
        kernels->rope_apply_f32(key, freqCache, position + 1, headDim, numKVHeads);
        return;
    }
    
    // Scalar fallback - Rotary Position Embedding
    // For each head and each pair of dimensions (2i, 2i+1)
    
    float invFreq[64];  // Max head dim / 2
    for (uint32_t i = 0; i < headDim / 2; ++i) {
        invFreq[i] = 1.0f / std::pow(theta, 2.0f * i / headDim);
    }
    
    float cosVal = std::cos(position * invFreq[0]);
    float sinVal = std::sin(position * invFreq[0]);
    
    // Apply to query
    for (uint32_t h = 0; h < numHeads; ++h) {
        for (uint32_t i = 0; i < headDim; i += 2) {
            float x0 = query[h * headDim + i];
            float x1 = query[h * headDim + i + 1];
            float freq = position * invFreq[i / 2];
            float c = std::cos(freq);
            float s = std::sin(freq);
            query[h * headDim + i] = x0 * c - x1 * s;
            query[h * headDim + i + 1] = x0 * s + x1 * c;
        }
    }
    
    // Apply to key (only for KV heads)
    for (uint32_t h = 0; h < numKVHeads; ++h) {
        for (uint32_t i = 0; i < headDim; i += 2) {
            float x0 = key[h * headDim + i];
            float x1 = key[h * headDim + i + 1];
            float freq = position * invFreq[i / 2];
            float c = std::cos(freq);
            float s = std::sin(freq);
            key[h * headDim + i] = x0 * c - x1 * s;
            key[h * headDim + i + 1] = x0 * s + x1 * c;
        }
    }
}

void TransformerLayerRuntime::ComputeSiLU(const float* input, float* output, uint32_t size) const {
    for (uint32_t i = 0; i < size; ++i) {
        output[i] = SiLU(input[i]);
    }
}

void TransformerLayerRuntime::ComputeSoftmax(float* data, uint32_t size) const {
    // Find max for numerical stability
    float maxVal = data[0];
    for (uint32_t i = 1; i < size; ++i) {
        if (data[i] > maxVal) maxVal = data[i];
    }
    
    // Compute exp and sum
    float sum = 0.0f;
    for (uint32_t i = 0; i < size; ++i) {
        data[i] = std::exp(data[i] - maxVal);
        sum += data[i];
    }
    
    // Normalize
    float invSum = 1.0f / sum;
    for (uint32_t i = 0; i < size; ++i) {
        data[i] *= invSum;
    }
}

void TransformerLayerRuntime::AccumulateResidual(const float* residual, float* output, uint32_t size) const {
    // Try Sovereign kernel first
    const Sovereign_KernelTable* kernels = GetSovereignKernelTable();
    if (kernels && kernels->residual_add_f32) {
        // Copy residual to temp buffer since kernel expects non-const
        alignas(64) float tempResidual[8192];
        for (uint32_t i = 0; i < size && i < 8192; ++i) {
            tempResidual[i] = residual[i];
        }
        kernels->residual_add_f32(output, tempResidual, output, static_cast<uint64_t>(size));
        return;
    }
    
    // Scalar fallback
    for (uint32_t i = 0; i < size; ++i) {
        output[i] += residual[i];
    }
}

// ============================================================================
// TensorView Read Helpers
// ============================================================================
bool TransformerLayerRuntime::ReadWeightMatrix(const TensorView& view, float* output,
                                                uint32_t rows, uint32_t cols) const {
    if (!view.IsValid()) return false;
    
    // Dequantize row by row
    for (uint32_t r = 0; r < rows; ++r) {
        size_t dequantized = view.DequantizeRow(r, output + r * cols, cols);
        if (dequantized != cols) {
            return false;
        }
    }
    return true;
}

bool TransformerLayerRuntime::ReadWeightVector(const TensorView& view, float* output,
                                                uint32_t size) const {
    if (!view.IsValid()) return false;
    
    // For 1D tensors, treat as single row
    size_t dequantized = view.DequantizeRow(0, output, size);
    return dequantized == size;
}

// ============================================================================
// TransformerModelRuntime Implementation
// ============================================================================
bool TransformerModelRuntime::Initialize(const std::vector<TransformerLayerConfig>& layerConfigs) {
    m_layers.clear();
    
    for (size_t i = 0; i < layerConfigs.size(); ++i) {
        auto layer = std::make_unique<TransformerLayerRuntime>();
        m_layers.push_back(std::move(layer));
    }
    
    // Allocate KV cache if we have layers
    if (!m_layers.empty()) {
        const auto& config = layerConfigs[0];
        m_maxSeqLen = config.maxPosition;
        m_numKVHeads = config.numKVHeads;
        m_headDim = config.headDim;
        
        // keyCache: [maxSeqLen, numKVHeads, headDim]
        // valueCache: [maxSeqLen, numKVHeads, headDim]
        size_t kvCacheSize = static_cast<size_t>(m_maxSeqLen) * m_numKVHeads * m_headDim;
        m_keyCache.resize(kvCacheSize, 0.0f);
        m_valueCache.resize(kvCacheSize, 0.0f);
    }
    
    m_initialized = !m_layers.empty();
    return m_initialized;
}

bool TransformerModelRuntime::BindLayer(uint32_t layerIndex,
                                        const TensorView& inputNorm,
                                        const TensorView& qProj, const TensorView& kProj,
                                        const TensorView& vProj, const TensorView& oProj,
                                        const TensorView& postNorm,
                                        const TensorView& gateProj, const TensorView& upProj,
                                        const TensorView& downProj) {
    if (layerIndex >= m_layers.size()) return false;
    
    return m_layers[layerIndex]->BindLayer(layerIndex, inputNorm, qProj, kProj, vProj, oProj,
                                             postNorm, gateProj, upProj, downProj);
}

bool TransformerModelRuntime::Forward(const float* input, uint32_t seqLen,
                                       uint32_t position, float* output) {
    if (!m_initialized || m_layers.empty()) return false;
    
    // Use first layer's config for buffer sizing
    const uint32_t hiddenSize = m_layers[0]->GetConfig().hiddenSize;
    
    std::vector<float> layerInput(input, input + hiddenSize);
    std::vector<float> layerOutput(hiddenSize);
    
    // Pass through each layer
    for (size_t i = 0; i < m_layers.size(); ++i) {
        if (!m_layers[i]->Forward(layerInput.data(), seqLen, position,
                                    layerOutput.data(),
                                    m_keyCache.data(), m_valueCache.data(),
                                    m_maxSeqLen)) {
            return false;
        }
        
        // Output becomes input for next layer
        layerInput = layerOutput;
    }
    
    // Copy final output
    std::memcpy(output, layerOutput.data(), hiddenSize * sizeof(float));
    return true;
}

bool TransformerModelRuntime::EmbedToken(uint32_t tokenId, float* embedding) {
    if (!m_tokenEmbeddings || !m_tokenEmbeddings->IsValid()) return false;
    
    // Dequantize the embedding row for this token
    size_t dequantized = m_tokenEmbeddings->DequantizeRow(tokenId, embedding, 
                                                            m_tokenEmbeddings->Cols());
    return dequantized > 0;
}

bool TransformerModelRuntime::ProjectToLogits(const float* hidden, float* logits) {
    if (!m_outputNorm || !m_outputWeight) return false;
    if (!m_outputNorm->IsValid() || !m_outputWeight->IsValid()) return false;
    
    // Apply output norm
    uint32_t hiddenSize = m_outputNorm->Cols() > 0 ? m_outputNorm->Cols() : m_outputNorm->Rows();
    std::vector<float> normWeights(hiddenSize);
    
    // Read norm weights directly
    size_t dequantized = m_outputNorm->DequantizeRow(0, normWeights.data(), hiddenSize);
    if (dequantized != hiddenSize) {
        return false;
    }
    
    std::vector<float> normed(hiddenSize);
    for (uint32_t i = 0; i < hiddenSize; ++i) {
        normed[i] = hidden[i] * normWeights[i];
    }
    
    // Project to logits: logits[vocab] = normed[hidden] @ W[hidden, vocab]
    uint32_t vocabSize = m_outputWeight->Rows();
    
    // Read output weight matrix and compute
    for (uint32_t v = 0; v < vocabSize; ++v) {
        std::vector<float> weightRow(hiddenSize);
        size_t dequantized = m_outputWeight->DequantizeRow(v, weightRow.data(), hiddenSize);
        if (dequantized != hiddenSize) return false;
        
        float sum = 0.0f;
        for (uint32_t h = 0; h < hiddenSize; ++h) {
            sum += normed[h] * weightRow[h];
        }
        logits[v] = sum;
    }
    
    return true;
}

} // namespace Runtime
} // namespace RawrXD
