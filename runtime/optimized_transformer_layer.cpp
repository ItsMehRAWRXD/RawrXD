// ============================================================================
// optimized_transformer_layer.cpp - FlashAttention-Integrated Implementation
// ============================================================================

#include "optimized_transformer_layer.hpp"
#include <iostream>
#include <chrono>

namespace RawrXD {
namespace Runtime {

// ============================================================================
// OptimizedTransformerLayer Implementation
// ============================================================================
OptimizedTransformerLayer::OptimizedTransformerLayer() = default;
OptimizedTransformerLayer::~OptimizedTransformerLayer() = default;

bool OptimizedTransformerLayer::InitializeFlashAttention() {
    if (!m_isBound) return false;
    
    FlashAttentionConfig config;
    config.Initialize(
        m_config.headDim,
        m_config.numHeads,
        m_config.numKVHeads
    );
    
    m_flash_attn_initialized = m_flash_attention.Initialize(config);
    return m_flash_attn_initialized;
}

bool OptimizedTransformerLayer::Forward(
    const float* input,
    uint32_t seqLen,
    uint32_t position,
    float* output,
    float* keyCache,
    float* valueCache,
    uint32_t maxSeqLen
) const {
    if (!m_isBound) return false;
    
    #ifdef _WIN32
    uint64_t start_cycles = __rdtsc();
    #else
    auto start_time = std::chrono::high_resolution_clock::now();
    #endif
    
    const uint32_t hiddenSize = m_config.hiddenSize;
    const uint32_t numHeads = m_config.numHeads;
    const uint32_t numKVHeads = m_config.numKVHeads;
    const uint32_t headDim = m_config.headDim;
    const uint32_t intermediateSize = m_config.intermediateSize;
    
    // Temporary buffers (use thread_local for cache efficiency)
    thread_local std::vector<float> tempBuffer;
    thread_local std::vector<float> normBuffer;
    thread_local std::vector<float> qBuffer;
    thread_local std::vector<float> kBuffer;
    thread_local std::vector<float> vBuffer;
    thread_local std::vector<float> attnOutBuffer;
    thread_local std::vector<float> mlpBuffer;
    thread_local std::vector<float> gateBuffer;
    thread_local std::vector<float> upBuffer;
    
    // Ensure buffer sizes
    tempBuffer.resize(hiddenSize);
    normBuffer.resize(hiddenSize);
    qBuffer.resize(hiddenSize);
    kBuffer.resize(numKVHeads * headDim);
    vBuffer.resize(numKVHeads * headDim);
    attnOutBuffer.resize(hiddenSize);
    mlpBuffer.resize(hiddenSize);
    gateBuffer.resize(intermediateSize);
    upBuffer.resize(intermediateSize);
    
    // ------------------------------------------------------------------------
    // Step 1: Input RMSNorm
    // ------------------------------------------------------------------------
    if (!ReadWeightVector(*m_inputNorm, normBuffer.data(), hiddenSize)) return false;
    ComputeRMSNorm(input, tempBuffer.data(), hiddenSize, m_config.rmsNormEps);
    for (uint32_t i = 0; i < hiddenSize; ++i) {
        tempBuffer[i] *= normBuffer[i];
    }
    
    // ------------------------------------------------------------------------
    // Step 2: Q/K/V Projection (Optimized)
    // ------------------------------------------------------------------------
    uint64_t qkv_cycles = 0;
    if (!ComputeQKVOptimized(tempBuffer.data(), qBuffer.data(), kBuffer.data(), vBuffer.data(), &qkv_cycles)) {
        return false;
    }
    m_perf_stats.qkv_cycles += qkv_cycles;
    
    // ------------------------------------------------------------------------
    // Step 3: Apply RoPE
    // ------------------------------------------------------------------------
    ApplyRoPE(qBuffer.data(), kBuffer.data(), numHeads, numKVHeads, headDim, position, m_config.ropeTheta);
    
    // ------------------------------------------------------------------------
    // Step 4: Store K/V in cache
    // ------------------------------------------------------------------------
    if (keyCache && valueCache && position < maxSeqLen) {
        uint32_t kvStride = numKVHeads * headDim;
        std::memcpy(keyCache + position * kvStride, kBuffer.data(), kvStride * sizeof(float));
        std::memcpy(valueCache + position * kvStride, vBuffer.data(), kvStride * sizeof(float));
    }
    
    // ------------------------------------------------------------------------
    // Step 5: Attention (FlashAttention if available)
    // ------------------------------------------------------------------------
    uint64_t attn_cycles = 0;
    if (m_flash_attn_initialized && seqLen > 0) {
        // Use FlashAttention
        // Need to create a temporary KVCache view from the raw cache
        // For now, fall back to standard attention
        if (!ComputeAttentionOptimized(qBuffer.data(), keyCache, valueCache, seqLen, attnOutBuffer.data(), &attn_cycles)) {
            return false;
        }
    } else {
        // Standard attention
        for (uint32_t h = 0; h < numHeads; ++h) {
            uint32_t kvHead = h / (numHeads / std::max(1u, numKVHeads));
            float* qHead = qBuffer.data() + h * headDim;
            float* outHead = attnOutBuffer.data() + h * headDim;
            
            std::vector<float> attnScores(seqLen);
            float scale = 1.0f / std::sqrt(static_cast<float>(headDim));
            
            for (uint32_t pos = 0; pos < seqLen; ++pos) {
                float* kHead = keyCache + pos * numKVHeads * headDim + kvHead * headDim;
                float qk = 0.0f;
                for (uint32_t i = 0; i < headDim; ++i) {
                    qk += qHead[i] * kHead[i];
                }
                attnScores[pos] = qk * scale;
            }
            
            ComputeSoftmax(attnScores.data(), seqLen);
            
            for (uint32_t d = 0; d < headDim; ++d) {
                float sum = 0.0f;
                for (uint32_t pos = 0; pos < seqLen; ++pos) {
                    float* vHead = valueCache + pos * numKVHeads * headDim + kvHead * headDim;
                    sum += attnScores[pos] * vHead[d];
                }
                outHead[d] = sum;
            }
        }
    }
    m_perf_stats.attention_cycles += attn_cycles;
    
    // ------------------------------------------------------------------------
    // Step 6: Output Projection
    // ------------------------------------------------------------------------
    std::vector<float> oWeights(hiddenSize * hiddenSize);
    if (!ReadWeightMatrix(*m_oProj, oWeights.data(), hiddenSize, hiddenSize)) return false;
    
    ComputeMatMul(attnOutBuffer.data(), oWeights.data(), tempBuffer.data(), 1, hiddenSize, hiddenSize);
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
    // Step 8: MLP (Optimized)
    // ------------------------------------------------------------------------
    uint64_t mlp_cycles = 0;
    if (!ComputeMLPOptimized(normBuffer.data(), mlpBuffer.data(), &mlp_cycles)) {
        return false;
    }
    m_perf_stats.mlp_cycles += mlp_cycles;
    
    // Final residual
    AccumulateResidual(tempBuffer.data(), mlpBuffer.data(), hiddenSize);
    std::memcpy(output, mlpBuffer.data(), hiddenSize * sizeof(float));
    
    // Update stats
    #ifdef _WIN32
    m_perf_stats.total_cycles += __rdtsc() - start_cycles;
    #else
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time);
    // Convert to approximate cycles (assuming 3GHz)
    m_perf_stats.total_cycles += duration.count() * 3;
    #endif
    m_perf_stats.tokens_processed++;
    
    return true;
}

bool OptimizedTransformerLayer::ComputeQKVOptimized(
    const float* normed_input,
    float* q_out,
    float* k_out,
    float* v_out,
    uint64_t* cycles_out
) const {
    #ifdef _WIN32
    uint64_t start = __rdtsc();
    #endif
    
    const uint32_t hiddenSize = m_config.hiddenSize;
    const uint32_t numKVHeads = m_config.numKVHeads;
    const uint32_t headDim = m_config.headDim;
    
    // Use QuantizedMatMul for Q4_K weights
    if (!QuantizedMatMul::Compute(*m_qProj, normed_input, q_out, hiddenSize, hiddenSize)) {
        return false;
    }
    if (!QuantizedMatMul::Compute(*m_kProj, normed_input, k_out, hiddenSize, numKVHeads * headDim)) {
        return false;
    }
    if (!QuantizedMatMul::Compute(*m_vProj, normed_input, v_out, hiddenSize, numKVHeads * headDim)) {
        return false;
    }
    
    #ifdef _WIN32
    if (cycles_out) *cycles_out = __rdtsc() - start;
    #endif
    
    return true;
}

bool OptimizedTransformerLayer::ComputeAttentionOptimized(
    const float* q,
    const float* k_cache,
    const float* v_cache,
    uint32_t seq_len,
    float* output,
    uint64_t* cycles_out
) const {
    // This would integrate with FlashAttention
    // For now, return false to fall back to standard attention
    (void)q; (void)k_cache; (void)v_cache; (void)seq_len; (void)output; (void)cycles_out;
    return false;
}

bool OptimizedTransformerLayer::ComputeMLPOptimized(
    const float* normed_input,
    float* output,
    uint64_t* cycles_out
) const {
    #ifdef _WIN32
    uint64_t start = __rdtsc();
    #endif
    
    const uint32_t hiddenSize = m_config.hiddenSize;
    const uint32_t intermediateSize = m_config.intermediateSize;
    
    thread_local std::vector<float> gateBuffer;
    thread_local std::vector<float> upBuffer;
    gateBuffer.resize(intermediateSize);
    upBuffer.resize(intermediateSize);
    
    // Gate projection
    if (!QuantizedMatMul::Compute(*m_gateProj, normed_input, gateBuffer.data(), hiddenSize, intermediateSize)) {
        return false;
    }
    
    // Up projection
    if (!QuantizedMatMul::Compute(*m_upProj, normed_input, upBuffer.data(), hiddenSize, intermediateSize)) {
        return false;
    }
    
    // SiLU activation: gate * sigmoid(gate)
    for (uint32_t i = 0; i < intermediateSize; ++i) {
        gateBuffer[i] = SiLU(gateBuffer[i]);
    }
    
    // Element-wise multiply
    for (uint32_t i = 0; i < intermediateSize; ++i) {
        gateBuffer[i] *= upBuffer[i];
    }
    
    // Down projection
    if (!QuantizedMatMul::Compute(*m_downProj, gateBuffer.data(), output, intermediateSize, hiddenSize)) {
        return false;
    }
    
    #ifdef _WIN32
    if (cycles_out) *cycles_out = __rdtsc() - start;
    #endif
    
    return true;
}

// ============================================================================
// OptimizedTransformerModel Implementation
// ============================================================================
OptimizedTransformerModel::OptimizedTransformerModel() = default;
OptimizedTransformerModel::~OptimizedTransformerModel() = default;

bool OptimizedTransformerModel::Initialize(const std::vector<TransformerLayerConfig>& layerConfigs) {
    m_layers.clear();
    m_optimized_layers.clear();
    
    for (size_t i = 0; i < layerConfigs.size(); ++i) {
        auto layer = std::make_unique<OptimizedTransformerLayer>();
        if (!layer->InitializeFlashAttention()) {
            std::cerr << "[OptimizedModel] Failed to initialize FlashAttention for layer " << i << std::endl;
        }
        m_optimized_layers.push_back(std::move(layer));
        // Also add to base class vector for compatibility
        m_layers.push_back(std::make_unique<TransformerLayerRuntime>());
    }
    
    // Allocate KV cache
    if (!m_optimized_layers.empty()) {
        const auto& config = layerConfigs[0];
        m_maxSeqLen = config.maxPosition;
        m_numKVHeads = config.numKVHeads;
        m_headDim = config.headDim;
        
        size_t kvCacheSize = static_cast<size_t>(m_maxSeqLen) * m_numKVHeads * m_headDim;
        m_keyCache.resize(kvCacheSize, 0.0f);
        m_valueCache.resize(kvCacheSize, 0.0f);
    }
    
    m_initialized = !m_optimized_layers.empty();
    return m_initialized;
}

bool OptimizedTransformerModel::Forward(const float* input, uint32_t seqLen, uint32_t position, float* output) {
    if (!m_initialized || m_optimized_layers.empty()) return false;
    
    const uint32_t hiddenSize = m_optimized_layers[0]->GetConfig().hiddenSize;
    
    std::vector<float> layerInput(input, input + hiddenSize);
    std::vector<float> layerOutput(hiddenSize);
    
    for (size_t i = 0; i < m_optimized_layers.size(); ++i) {
        if (!m_optimized_layers[i]->Forward(
            layerInput.data(), seqLen, position,
            layerOutput.data(),
            m_keyCache.data(), m_valueCache.data(), m_maxSeqLen)) {
            return false;
        }
        layerInput.swap(layerOutput);
    }
    
    std::memcpy(output, layerInput.data(), hiddenSize * sizeof(float));
    return true;
}

OptimizedTransformerModel::ModelPerfStats OptimizedTransformerModel::GetModelPerfStats() const {
    ModelPerfStats stats;
    
    for (const auto& layer : m_optimized_layers) {
        const auto& layerStats = layer->GetPerfStats();
        stats.total_cycles += layerStats.total_cycles;
        stats.total_tokens += layerStats.tokens_processed;
    }
    
    if (stats.total_tokens > 0) {
        // Assuming 3GHz CPU
        float total_seconds = stats.total_cycles / (3.0f * 1e9f);
        stats.avg_tokens_per_sec = stats.total_tokens / total_seconds;
    }
    
    // Estimate peak memory (simplified)
    if (!m_optimized_layers.empty()) {
        const auto& config = m_optimized_layers[0]->GetConfig();
        size_t kvCacheBytes = 2ULL * m_maxSeqLen * m_numKVHeads * m_headDim * sizeof(float);
        size_t weightBytes = static_cast<size_t>(config.hiddenSize) * config.hiddenSize * 4; // Approximate
        stats.peak_memory_mb = static_cast<float>(kvCacheBytes + weightBytes) / (1024.0f * 1024.0f);
    }
    
    return stats;
}

void OptimizedTransformerModel::ResetModelPerfStats() {
    for (auto& layer : m_optimized_layers) {
        layer->ResetPerfStats();
    }
    m_model_stats = ModelPerfStats();
}

// ============================================================================
// Benchmark Implementation
// ============================================================================
TransformerBenchmark::Results TransformerBenchmark::RunBenchmark(
    const OptimizedTransformerModel& model,
    const Config& config
) {
    Results results;
    
    const auto& firstLayer = model.GetLayer(0);
    const auto& cfg = firstLayer.GetConfig();
    const uint32_t hiddenSize = cfg.hiddenSize;
    
    // Warmup
    std::vector<float> input(hiddenSize, 0.5f);
    std::vector<float> output(hiddenSize);
    
    for (uint32_t i = 0; i < config.warmup_iterations; ++i) {
        model.Forward(input.data(), 1, i, output.data());
    }
    
    // Benchmark
    auto start = std::chrono::high_resolution_clock::now();
    
    for (uint32_t i = 0; i < config.benchmark_iterations; ++i) {
        model.Forward(input.data(), 1, i, output.data());
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    float total_ms = duration.count() / 1000.0f;
    results.avg_latency_ms = total_ms / config.benchmark_iterations;
    results.throughput_tokens_per_sec = 1000.0f / results.avg_latency_ms;
    
    // Get detailed stats
    auto modelStats = model.GetModelPerfStats();
    if (modelStats.total_tokens > 0) {
        // Calculate breakdown from layer stats
        uint64_t total_qkv = 0, total_attn = 0, total_mlp = 0, total_all = 0;
        for (size_t i = 0; i < model.GetLayerCount(); ++i) {
            const auto& stats = model.GetLayer(i).GetPerfStats();
            total_qkv += stats.qkv_cycles;
            total_attn += stats.attention_cycles;
            total_mlp += stats.mlp_cycles;
            total_all += stats.total_cycles;
        }
        
        if (total_all > 0) {
            results.qkv_percent = 100.0f * total_qkv / total_all;
            results.attention_percent = 100.0f * total_attn / total_all;
            results.mlp_percent = 100.0f * total_mlp / total_all;
        }
    }
    
    return results;
}

void TransformerBenchmark::PrintResults(const Results& results) {
    std::cout << "========================================\n";
    std::cout << "Transformer Benchmark Results\n";
    std::cout << "========================================\n";
    std::cout << "Average latency: " << results.avg_latency_ms << " ms\n";
    std::cout << "Throughput: " << results.throughput_tokens_per_sec << " tokens/sec\n";
    std::cout << "Memory bandwidth: " << results.memory_bandwidth_gbps << " GB/s\n";
    std::cout << "\nBreakdown:\n";
    std::cout << "  QKV projection: " << results.qkv_percent << "%\n";
    std::cout << "  Attention: " << results.attention_percent << "%\n";
    std::cout << "  MLP: " << results.mlp_percent << "%\n";
    std::cout << "========================================\n";
}

} // namespace Runtime
} // namespace RawrXD
