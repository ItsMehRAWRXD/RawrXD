// ============================================================================
// Transformer Bridge Implementation
// ============================================================================

#include "transformer_bridge.hpp"
#include <chrono>
#include <iostream>
#include <cmath>
#include <cstring>

namespace RawrXD {
namespace CLI {

TransformerBridge::TransformerBridge() = default;
TransformerBridge::~TransformerBridge() = default;

bool TransformerBridge::Initialize(const ModelContext& modelContext) {
    if (!modelContext.IsLoaded()) {
        std::cerr << "[TransformerBridge] ModelContext not loaded" << std::endl;
        return false;
    }

    const auto& arch = modelContext.GetArchitecture();
    m_hiddenSize = arch.hiddenSize;
    m_numHeads = arch.numHeads;
    m_numKVHeads = arch.numKVHeads > 0 ? arch.numKVHeads : arch.numHeads;
    m_headDim = m_hiddenSize / m_numHeads;
    m_numLayers = arch.numLayers;
    m_vocabSize = arch.vocabSize;
    m_maxSeqLen = arch.contextLength;

    std::cout << "[TransformerBridge] Initializing with architecture:" << std::endl;
    std::cout << "  Hidden size: " << m_hiddenSize << std::endl;
    std::cout << "  Num heads: " << m_numHeads << std::endl;
    std::cout << "  Num KV heads: " << m_numKVHeads << std::endl;
    std::cout << "  Head dim: " << m_headDim << std::endl;
    std::cout << "  Num layers: " << m_numLayers << std::endl;
    std::cout << "  Vocab size: " << m_vocabSize << std::endl;
    std::cout << "  Max seq len: " << m_maxSeqLen << std::endl;

    // Initialize KV cache
    m_kvCache = std::make_unique<KVCache>();
    m_kvCache->Resize(m_maxSeqLen, m_numKVHeads, m_headDim);

    // Initialize Sovereign kernels
    if (!InitializeKernels()) {
        std::cerr << "[TransformerBridge] Warning: Failed to initialize kernel acceleration" << std::endl;
        // Continue without kernels
    }

    // Initialize runtime model
    m_modelRuntime = std::make_unique<Runtime::TransformerModelRuntime>();

    // Create layer configs
    std::vector<Runtime::TransformerLayerConfig> layerConfigs;
    for (uint32_t i = 0; i < m_numLayers; ++i) {
        Runtime::TransformerLayerConfig config;
        config.hiddenSize = m_hiddenSize;
        config.numHeads = m_numHeads;
        config.numKVHeads = m_numKVHeads;
        config.headDim = m_headDim;
        config.intermediateSize = arch.intermediateSize;
        config.rmsNormEps = arch.rmsNormEps;
        config.ropeTheta = arch.ropeTheta;
        config.maxPosition = m_maxSeqLen;
        config.useGQA = (m_numKVHeads != m_numHeads);
        config.useMQA = (m_numKVHeads == 1);
        layerConfigs.push_back(config);
    }

    if (!m_modelRuntime->Initialize(layerConfigs)) {
        std::cerr << "[TransformerBridge] Failed to initialize model runtime" << std::endl;
        return false;
    }

    // Bind all layers
    if (!BindAllLayers(modelContext)) {
        std::cerr << "[TransformerBridge] Failed to bind layers" << std::endl;
        return false;
    }

    // Set model-level tensors
    auto embedView = CreateTensorView(modelContext, "token_embd.weight");
    auto outputNormView = CreateTensorView(modelContext, "norm.weight");
    auto outputWeightView = CreateTensorView(modelContext, "output.weight");

    m_modelRuntime->SetTokenEmbeddings(embedView);
    m_modelRuntime->SetOutputNorm(outputNormView);
    m_modelRuntime->SetOutputWeight(outputWeightView);

    m_initialized = true;
    std::cout << "[TransformerBridge] Initialization complete" << std::endl;
    return true;
}

bool TransformerBridge::ExecuteToken(
    uint32_t tokenId,
    uint32_t position,
    uint32_t seqLen,
    float* logits
) {
    if (!m_initialized || !m_modelRuntime) {
        std::cerr << "[TransformerBridge] Not initialized" << std::endl;
        return false;
    }

    auto start = std::chrono::high_resolution_clock::now();

    // Embedding lookup
    std::vector<float> embedding(m_hiddenSize);
    if (!m_modelRuntime->EmbedToken(tokenId, embedding.data())) {
        std::cerr << "[TransformerBridge] Embedding lookup failed" << std::endl;
        return false;
    }

    auto embedEnd = std::chrono::high_resolution_clock::now();

    // Forward through all layers
    std::vector<float> hidden(m_hiddenSize);
    std::memcpy(hidden.data(), embedding.data(), m_hiddenSize * sizeof(float));

    // KV cache pointers (flattened layout)
    float* keyCache = m_kvCache->k_cache.data();
    float* valueCache = m_kvCache->v_cache.data();

    if (!m_modelRuntime->Forward(hidden.data(), seqLen, position, hidden.data())) {
        std::cerr << "[TransformerBridge] Forward pass failed" << std::endl;
        return false;
    }

    auto forwardEnd = std::chrono::high_resolution_clock::now();

    // Output projection to logits
    if (!m_modelRuntime->ProjectToLogits(hidden.data(), logits)) {
        std::cerr << "[TransformerBridge] Output projection failed" << std::endl;
        return false;
    }

    auto end = std::chrono::high_resolution_clock::now();

    // Update telemetry
    m_telemetry.embeddingTimeUs = std::chrono::duration_cast<std::chrono::microseconds>(
        embedEnd - start).count();
    m_telemetry.totalTimeUs = std::chrono::duration_cast<std::chrono::microseconds>(
        end - start).count();
    m_telemetry.attentionTimeUs = std::chrono::duration_cast<std::chrono::microseconds>(
        forwardEnd - embedEnd).count();

    return true;
}

void TransformerBridge::ResetCache() {
    if (m_kvCache) {
        m_kvCache->Clear();
    }
}

uint32_t TransformerBridge::GetNumLayers() const {
    return m_initialized ? m_numLayers : 0;
}

uint32_t TransformerBridge::GetHiddenSize() const {
    return m_initialized ? m_hiddenSize : 0;
}

uint32_t TransformerBridge::GetVocabSize() const {
    return m_initialized ? m_vocabSize : 0;
}

Runtime::TensorView TransformerBridge::CreateTensorView(
    const ModelContext& ctx,
    const std::string& tensorName
) const {
    const TensorEntry* entry = ctx.GetTensor(tensorName);
    const void* data = ctx.GetTensorData(tensorName);

    Runtime::TensorView view;
    if (entry && data) {
        // Map CLI TensorType to Runtime GGMLType
        Runtime::GGMLType ggmlType = Runtime::GGMLType::F32;
        switch (entry->type) {
            case TensorType::F32: ggmlType = Runtime::GGMLType::F32; break;
            case TensorType::F16: ggmlType = Runtime::GGMLType::F16; break;
            case TensorType::Q2_K: ggmlType = Runtime::GGMLType::Q2_K; break;
            case TensorType::Q4_K: ggmlType = Runtime::GGMLType::Q4_K; break;
            case TensorType::Q6_K: ggmlType = Runtime::GGMLType::Q6_K; break;
            case TensorType::Q8_0: ggmlType = Runtime::GGMLType::Q8_0; break;
            default: ggmlType = Runtime::GGMLType::F32; break;
        }

        Runtime::TensorData tensorData;
        tensorData.type = ggmlType;
        tensorData.shape = entry->shape.dimensions;
        tensorData.provenance.source = ctx.GetPath();
        tensorData.provenance.quantized = (entry->type != TensorType::F32 && entry->type != TensorType::F16);
        tensorData.provenance.sourceType = ggmlType;

        // For quantized types, we need to store the raw data
        if (tensorData.provenance.quantized) {
            tensorData.rawData.resize(entry->size);
            std::memcpy(tensorData.rawData.data(), data, entry->size);
        } else {
            // F32 data (dequantize F16 if needed)
            size_t numElements = entry->NumElements();
            tensorData.f32Data.resize(numElements);
            if (entry->type == TensorType::F16) {
                // Convert F16 to F32
                const uint16_t* f16Data = static_cast<const uint16_t*>(data);
                for (size_t i = 0; i < numElements; ++i) {
                    uint16_t h = f16Data[i];
                    uint32_t sign = (h >> 15) & 0x1;
                    uint32_t exp = (h >> 10) & 0x1F;
                    uint32_t mant = h & 0x3FF;
                    if (exp == 0) {
                        tensorData.f32Data[i] = sign ? -0.0f : 0.0f;
                    } else if (exp == 31) {
                        tensorData.f32Data[i] = sign ? -INFINITY : INFINITY;
                    } else {
                        int32_t e = static_cast<int32_t>(exp) - 15 + 127;
                        uint32_t f32 = (sign << 31) | (static_cast<uint32_t>(e) << 23) | (mant << 13);
                        std::memcpy(&tensorData.f32Data[i], &f32, sizeof(float));
                    }
                }
            } else {
                // F32 data
                std::memcpy(tensorData.f32Data.data(), data, numElements * sizeof(float));
            }
        }

        view = Runtime::TensorView(&tensorData);
    }

    return view;
}

bool TransformerBridge::BindAllLayers(const ModelContext& ctx) {
    for (uint32_t layerIdx = 0; layerIdx < m_numLayers; ++layerIdx) {
        std::string prefix = "blk." + std::to_string(layerIdx) + ".";

        auto inputNorm = CreateTensorView(ctx, prefix + "attn_norm.weight");
        auto qProj = CreateTensorView(ctx, prefix + "attn_q.weight");
        auto kProj = CreateTensorView(ctx, prefix + "attn_k.weight");
        auto vProj = CreateTensorView(ctx, prefix + "attn_v.weight");
        auto oProj = CreateTensorView(ctx, prefix + "attn_output.weight");
        auto postNorm = CreateTensorView(ctx, prefix + "ffn_norm.weight");
        auto gateProj = CreateTensorView(ctx, prefix + "ffn_gate.weight");
        auto upProj = CreateTensorView(ctx, prefix + "ffn_up.weight");
        auto downProj = CreateTensorView(ctx, prefix + "ffn_down.weight");

        if (!m_modelRuntime->BindLayer(layerIdx, inputNorm, qProj, kProj, vProj,
                                       oProj, postNorm, gateProj, upProj, downProj)) {
            std::cerr << "[TransformerBridge] Failed to bind layer " << layerIdx << std::endl;
            return false;
        }
    }

    return true;
}

// ============================================================================
// Sovereign Kernel Integration
// ============================================================================

bool TransformerBridge::InitializeKernels() {
    // Allocate kernel table
    m_kernelTable = new Sovereign_KernelTable();
    
    // Initialize kernel table from Sovereign dispatch
    int result = Sovereign_InitKernelTable(m_kernelTable);
    if (result != 0) {
        std::cerr << "[TransformerBridge] Failed to initialize kernel table: " << result << std::endl;
        delete m_kernelTable;
        m_kernelTable = nullptr;
        m_kernelsAvailable = false;
        return false;
    }
    
    // Validate critical kernels are available
    if (!m_kernelTable->rms_norm_f32) {
        std::cerr << "[TransformerBridge] RMSNorm kernel not available" << std::endl;
    }
    if (!m_kernelTable->layer_norm_f32) {
        std::cerr << "[TransformerBridge] LayerNorm kernel not available" << std::endl;
    }
    if (!m_kernelTable->residual_add_f32) {
        std::cerr << "[TransformerBridge] ResidualAdd kernel not available" << std::endl;
    }
    if (!m_kernelTable->rope_apply_f32) {
        std::cerr << "[TransformerBridge] RoPE kernel not available" << std::endl;
    }
    
    m_kernelsAvailable = true;
    std::cout << "[TransformerBridge] Kernel acceleration initialized" << std::endl;
    return true;
}

bool TransformerBridge::ApplyRMSNorm(float* input, float* output, size_t n_elements, float epsilon) {
    if (m_kernelsAvailable && m_kernelTable && m_kernelTable->rms_norm_f32) {
        // Use Sovereign kernel
        alignas(64) float weights[8192];
        for (size_t i = 0; i < n_elements && i < 8192; ++i) {
            weights[i] = 1.0f;
        }
        m_kernelTable->rms_norm_f32(input, weights, output, static_cast<uint64_t>(n_elements), epsilon);
        return true;
    }
    
    // Scalar fallback
    float sum_squares = 0.0f;
    for (size_t i = 0; i < n_elements; ++i) {
        sum_squares += input[i] * input[i];
    }
    float rms = std::sqrt(sum_squares / static_cast<float>(n_elements) + epsilon);
    float scale = 1.0f / rms;
    for (size_t i = 0; i < n_elements; ++i) {
        output[i] = input[i] * scale;
    }
    return true;
}

bool TransformerBridge::ApplyLayerNorm(float* input, float* output, size_t n_elements, float epsilon) {
    if (m_kernelsAvailable && m_kernelTable && m_kernelTable->layer_norm_f32) {
        // Use Sovereign kernel
        alignas(64) float gamma[8192];
        alignas(64) float beta[8192];
        for (size_t i = 0; i < n_elements && i < 8192; ++i) {
            gamma[i] = 1.0f;
            beta[i] = 0.0f;
        }
        m_kernelTable->layer_norm_f32(input, gamma, beta, output, static_cast<uint64_t>(n_elements), epsilon);
        return true;
    }
    
    // Scalar fallback
    float mean = 0.0f;
    for (size_t i = 0; i < n_elements; ++i) {
        mean += input[i];
    }
    mean /= static_cast<float>(n_elements);
    
    float variance = 0.0f;
    for (size_t i = 0; i < n_elements; ++i) {
        float diff = input[i] - mean;
        variance += diff * diff;
    }
    variance /= static_cast<float>(n_elements);
    
    float scale = 1.0f / std::sqrt(variance + epsilon);
    for (size_t i = 0; i < n_elements; ++i) {
        output[i] = (input[i] - mean) * scale;
    }
    return true;
}

bool TransformerBridge::ApplyResidualAdd(float* input, float* residual, float* output, size_t n_elements) {
    if (m_kernelsAvailable && m_kernelTable && m_kernelTable->residual_add_f32) {
        // Use Sovereign kernel
        m_kernelTable->residual_add_f32(input, residual, output, static_cast<uint64_t>(n_elements));
        return true;
    }
    
    // Scalar fallback
    for (size_t i = 0; i < n_elements; ++i) {
        output[i] = input[i] + residual[i];
    }
    return true;
}

bool TransformerBridge::ApplyRoPE(float* tensor, size_t seq_len, size_t head_dim, size_t num_heads) {
    if (m_kernelsAvailable && m_kernelTable && m_kernelTable->rope_apply_f32) {
        // Use Sovereign kernel (freq_cache is nullptr for on-the-fly computation)
        alignas(64) float freq_cache[8192];
        m_kernelTable->rope_apply_f32(tensor, freq_cache, seq_len, head_dim, num_heads);
        return true;
    }
    
    // Scalar fallback - simplified RoPE
    for (size_t pos = 0; pos < seq_len; ++pos) {
        for (size_t h = 0; h < num_heads; ++h) {
            for (size_t d = 0; d < head_dim; d += 2) {
                size_t idx = pos * num_heads * head_dim + h * head_dim + d;
                if (d + 1 < head_dim) {
                    float x0 = tensor[idx];
                    float x1 = tensor[idx + 1];
                    
                    // Compute rotation angle
                    float theta = std::pow(10000.0f, -2.0f * static_cast<float>(d) / static_cast<float>(head_dim));
                    float angle = pos * theta;
                    float cos_a = std::cos(angle);
                    float sin_a = std::sin(angle);
                    
                    // Apply rotation
                    tensor[idx] = x0 * cos_a - x1 * sin_a;
                    tensor[idx + 1] = x0 * sin_a + x1 * cos_a;
                }
            }
        }
    }
    return true;
}

} // namespace CLI
} // namespace RawrXD
