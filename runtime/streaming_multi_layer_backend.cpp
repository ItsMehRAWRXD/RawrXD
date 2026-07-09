// ============================================================================
// streaming_multi_layer_backend.cpp - Multi-Layer Streaming Inference
// ============================================================================

#include "streaming_multi_layer_backend.hpp"
#include "streaming_gguf_loader.hpp"
#include "streaming_layer_registry.hpp"
#include "telemetry_ids.hpp"
#include <cstring>
#include <cmath>
#include <algorithm>

namespace RawrXD {
namespace Runtime {

// ============================================================================
// KV Cache (simplified implementation)
// ============================================================================
class KVCache {
public:
    void Resize(uint32_t max_seq, uint32_t num_heads, uint32_t head_dim) {
        m_max_seq = max_seq;
        m_num_heads = num_heads;
        m_head_dim = head_dim;
        size_t size = static_cast<size_t>(max_seq) * num_heads * head_dim;
        m_k_cache.resize(size, 0.0f);
        m_v_cache.resize(size, 0.0f);
    }
    
    void Reset() {
        std::fill(m_k_cache.begin(), m_k_cache.end(), 0.0f);
        std::fill(m_v_cache.begin(), m_v_cache.end(), 0.0f);
    }
    
    float* GetK(uint32_t pos, uint32_t head) {
        size_t offset = static_cast<size_t>(pos) * m_num_heads * m_head_dim + head * m_head_dim;
        return m_k_cache.data() + offset;
    }
    
    float* GetV(uint32_t pos, uint32_t head) {
        size_t offset = static_cast<size_t>(pos) * m_num_heads * m_head_dim + head * m_head_dim;
        return m_v_cache.data() + offset;
    }
    
private:
    uint32_t m_max_seq = 0;
    uint32_t m_num_heads = 0;
    uint32_t m_head_dim = 0;
    std::vector<float> m_k_cache;
    std::vector<float> m_v_cache;
};

// ============================================================================
// Constructor / Destructor
// ============================================================================
StreamingMultiLayerBackend::StreamingMultiLayerBackend() = default;
StreamingMultiLayerBackend::~StreamingMultiLayerBackend() = default;

// ============================================================================
// Initialize
// ============================================================================
bool StreamingMultiLayerBackend::Initialize(StreamingGGUFLoader& loader) {
    using namespace Telemetry;
    TELEMETRY_SCOPE(TELEMETRY_BRIDGE_INIT, TELEMETRY_BRIDGE_INIT + 1);
    
    // Initialize layer registry
    if (!m_registry.Initialize(loader)) {
        return false;
    }
    
    // Discover model architecture from metadata
    m_num_layers = m_registry.GetNumLayers();
    m_hidden_size = loader.GetMetadataInt("llama.embedding_length", 4096);
    m_num_heads = loader.GetMetadataInt("llama.attention.head_count", 32);
    m_num_kv_heads = loader.GetMetadataInt("llama.attention.head_count_kv", m_num_heads);
    m_head_dim = m_hidden_size / m_num_heads;
    m_intermediate_size = loader.GetMetadataInt("llama.feed_forward_length", 11008);
    m_vocab_size = loader.GetMetadataInt("llama.vocab_size", 32000);
    m_max_seq_len = loader.GetMetadataInt("llama.context_length", 2048);
    
    // Load model tensors (embeddings, output)
    if (!LoadModelTensors(loader)) {
        return false;
    }
    
    // Initialize KV cache
    m_kv_cache = std::make_unique<KVCache>();
    m_kv_cache->Resize(m_max_seq_len, m_num_kv_heads, m_head_dim);
    
    m_initialized = true;
    return true;
}

// ============================================================================
// Load Model Tensors
// ============================================================================
bool StreamingMultiLayerBackend::LoadModelTensors(StreamingGGUFLoader& loader) {
    // Load token embeddings
    TensorInfo info;
    if (loader.SeekToTensor("token_embd.weight", info)) {
        m_token_embeddings = loader.CreateTensorView(info);
    }
    
    // Load output norm
    if (loader.SeekToTensor("output_norm.weight", info)) {
        m_output_norm = loader.CreateTensorView(info);
    }
    
    // Load output weight
    if (loader.SeekToTensor("output.weight", info)) {
        m_output_weight = loader.CreateTensorView(info);
    }
    
    return m_token_embeddings.IsValid() && m_output_weight.IsValid();
}

// ============================================================================
// Embedding Lookup
// ============================================================================
bool StreamingMultiLayerBackend::EmbeddingLookup(uint32_t token_id, float* out) {
    using namespace Telemetry;
    TELEMETRY_SCOPE(TELEMETRY_TOKEN_EMBED, TELEMETRY_TOKEN_EMBED + 1);
    
    if (!m_token_embeddings.IsValid()) return false;
    
    // Dequantize the embedding row
    size_t dequantized = m_token_embeddings.DequantizeRow(token_id, out, m_hidden_size);
    return dequantized == m_hidden_size;
}

// ============================================================================
// Output Projection
// ============================================================================
bool StreamingMultiLayerBackend::OutputProjection(const float* hidden, float* logits) {
    using namespace Telemetry;
    TELEMETRY_SCOPE(TELEMETRY_LOGITS_PROJECTION, TELEMETRY_LOGITS_PROJECTION + 1);
    
    if (!m_output_norm.IsValid() || !m_output_weight.IsValid()) return false;
    
    // Apply output norm
    std::vector<float> norm_weights(m_hidden_size);
    m_output_norm.DequantizeRow(0, norm_weights.data(), m_hidden_size);
    
    std::vector<float> normed(m_hidden_size);
    for (uint32_t i = 0; i < m_hidden_size; ++i) {
        normed[i] = hidden[i] * norm_weights[i];
    }
    
    // Project to logits
    for (uint32_t v = 0; v < m_vocab_size; ++v) {
        std::vector<float> weight_row(m_hidden_size);
        m_output_weight.DequantizeRow(v, weight_row.data(), m_hidden_size);
        
        float sum = 0.0f;
        for (uint32_t h = 0; h < m_hidden_size; ++h) {
            sum += normed[h] * weight_row[h];
        }
        logits[v] = sum;
    }
    
    return true;
}

// ============================================================================
// Execute Layer - Full Transformer Forward Pass
// ============================================================================
bool StreamingMultiLayerBackend::ExecuteLayer(uint32_t layer_idx, uint32_t position) {
    using namespace Telemetry;
    TELEMETRY_SCOPE(TELEMETRY_LAYER_START + layer_idx, TELEMETRY_LAYER_END + layer_idx);
    
    // Load layer weights
    if (!m_registry.LoadLayer(layer_idx)) {
        return false;
    }
    
    const LayerWeights& weights = m_registry.GetCurrentWeights();
    if (!weights.IsValid()) {
        return false;
    }
    
    // ------------------------------------------------------------------------
    // 1. Pre-Attention RMSNorm
    // ------------------------------------------------------------------------
    RMSNorm(m_hidden, weights.attn_norm, m_normed, m_hidden_size);
    
    // ------------------------------------------------------------------------
    // 2. QKV Projection
    // ------------------------------------------------------------------------
    // m_normed [hidden] -> m_qkv [3 * hidden]
    float* q_out = m_qkv;
    float* k_out = m_qkv + m_hidden_size;
    float* v_out = m_qkv + 2 * m_hidden_size;
    
    ProjectQKV(m_normed, weights, q_out, k_out, v_out);
    
    // ------------------------------------------------------------------------
    // 3. Store K, V in cache
    // ------------------------------------------------------------------------
    for (uint32_t h = 0; h < m_num_heads; ++h) {
        float* k_head = k_out + h * m_head_dim;
        float* v_head = v_out + h * m_head_dim;
        
        std::memcpy(m_kv_cache->GetK(position, h), k_head, m_head_dim * sizeof(float));
        std::memcpy(m_kv_cache->GetV(position, h), v_head, m_head_dim * sizeof(float));
    }
    
    // ------------------------------------------------------------------------
    // 4. Multi-Head Attention
    // ------------------------------------------------------------------------
    AttentionMultiHead(q_out, *m_kv_cache, position, m_attn_out);
    
    // ------------------------------------------------------------------------
    // 5. Output projection + residual
    // ------------------------------------------------------------------------
    // attn_out [hidden] -> output [hidden]
    float attn_proj[8192];
    MatMulRow(weights.attn_output, m_attn_out, attn_proj, m_hidden_size, m_hidden_size);
    
    // Residual: hidden = hidden + attn_proj
    for (uint32_t i = 0; i < m_hidden_size; ++i) {
        m_next_hidden[i] = m_hidden[i] + attn_proj[i];
    }
    
    // ------------------------------------------------------------------------
    // 6. Pre-FFN RMSNorm
    // ------------------------------------------------------------------------
    RMSNorm(m_next_hidden, weights.ffn_norm, m_normed, m_hidden_size);
    
    // ------------------------------------------------------------------------
    // 7. MLP Forward
    // ------------------------------------------------------------------------
    MLPForward(m_normed, weights, m_mlp_out);
    
    // ------------------------------------------------------------------------
    // 8. Residual: next_hidden = next_hidden + mlp_out
    // ------------------------------------------------------------------------
    for (uint32_t i = 0; i < m_hidden_size; ++i) {
        m_next_hidden[i] = m_next_hidden[i] + m_mlp_out[i];
    }
    
    // Copy result to m_hidden for next layer
    std::memcpy(m_hidden, m_next_hidden, m_hidden_size * sizeof(float));
    
    return true;
}

// ============================================================================
// RMS Normalization
// ============================================================================
void StreamingMultiLayerBackend::RMSNorm(const float* input, const TensorView& weight, float* output, uint32_t size) {
    // Compute RMS
    float sum_sq = 0.0f;
    for (uint32_t i = 0; i < size; ++i) {
        sum_sq += input[i] * input[i];
    }
    float rms = std::sqrt(sum_sq / size + 1e-6f);
    float scale = 1.0f / rms;
    
    // Load norm weights
    std::vector<float> norm_weights(size);
    weight.DequantizeRow(0, norm_weights.data(), size);
    
    // Apply: output[i] = input[i] * scale * weight[i]
    for (uint32_t i = 0; i < size; ++i) {
        output[i] = input[i] * scale * norm_weights[i];
    }
}

// ============================================================================
// QKV Projection
// ============================================================================
void StreamingMultiLayerBackend::ProjectQKV(
    const float* input,
    const LayerWeights& weights,
    float* q_out,
    float* k_out,
    float* v_out
) {
    // Q projection: [hidden] x [hidden, hidden] -> [hidden]
    MatMulRow(weights.attn_q, input, q_out, m_hidden_size, m_hidden_size);
    
    // K projection: [hidden] x [num_kv_heads * head_dim, hidden] -> [num_kv_heads * head_dim]
    // Note: For GQA, K/V have fewer heads than Q
    uint32_t kv_hidden = m_num_kv_heads * m_head_dim;
    MatMulRow(weights.attn_k, input, k_out, kv_hidden, m_hidden_size);
    
    // V projection
    MatMulRow(weights.attn_v, input, v_out, kv_hidden, m_hidden_size);
}

// ============================================================================
// Multi-Head Attention
// ============================================================================
void StreamingMultiLayerBackend::AttentionMultiHead(
    const float* query,
    const KVCache& cache,
    uint32_t position,
    float* output
) {
    // For each head
    for (uint32_t h = 0; h < m_num_heads; ++h) {
        const float* q_head = query + h * m_head_dim;
        
        // Compute attention scores with all past positions
        float scores[8192];  // Max sequence length
        float max_score = -1e30f;
        
        for (uint32_t pos = 0; pos <= position; ++pos) {
            const float* k_head = cache.GetK(pos, h % m_num_kv_heads);  // GQA: repeat K heads
            
            // Dot product q · k
            float dot = 0.0f;
            for (uint32_t d = 0; d < m_head_dim; ++d) {
                dot += q_head[d] * k_head[d];
            }
            
            // Scale
            scores[pos] = dot / std::sqrt(static_cast<float>(m_head_dim));
            if (scores[pos] > max_score) max_score = scores[pos];
        }
        
        // Softmax
        float sum_exp = 0.0f;
        for (uint32_t pos = 0; pos <= position; ++pos) {
            scores[pos] = std::exp(scores[pos] - max_score);
            sum_exp += scores[pos];
        }
        for (uint32_t pos = 0; pos <= position; ++pos) {
            scores[pos] /= sum_exp;
        }
        
        // Weighted sum of values
        float* out_head = output + h * m_head_dim;
        std::fill(out_head, out_head + m_head_dim, 0.0f);
        
        for (uint32_t pos = 0; pos <= position; ++pos) {
            const float* v_head = cache.GetV(pos, h % m_num_kv_heads);
            float weight = scores[pos];
            
            for (uint32_t d = 0; d < m_head_dim; ++d) {
                out_head[d] += weight * v_head[d];
            }
        }
    }
}

// ============================================================================
// MLP Forward
// ============================================================================
void StreamingMultiLayerBackend::MLPForward(const float* input, const LayerWeights& weights, float* output) {
    // SwiGLU: gate = SiLU(x @ W_gate) * (x @ W_up)
    // Then: output = gate @ W_down
    
    // Compute gate and up projections
    float gate_buf[32768];  // Max intermediate size
    float up_buf[32768];
    
    MatMulRow(weights.ffn_gate, input, gate_buf, m_intermediate_size, m_hidden_size);
    MatMulRow(weights.ffn_up, input, up_buf, m_intermediate_size, m_hidden_size);
    
    // SiLU activation on gate
    for (uint32_t i = 0; i < m_intermediate_size; ++i) {
        gate_buf[i] = SiLU(gate_buf[i]);
    }
    
    // Element-wise multiply
    for (uint32_t i = 0; i < m_intermediate_size; ++i) {
        gate_buf[i] *= up_buf[i];
    }
    
    // Down projection
    MatMulRow(weights.ffn_down, gate_buf, output, m_hidden_size, m_intermediate_size);
}

// ============================================================================
// MatMul with Quantized Weights
// ============================================================================
void StreamingMultiLayerBackend::MatMulRow(
    const TensorView& weight,
    const float* input,
    float* output,
    uint32_t out_dim,
    uint32_t in_dim
) {
    // weight shape: [out_dim, in_dim]
    // input shape: [in_dim]
    // output shape: [out_dim]
    
    for (uint32_t row = 0; row < out_dim; ++row) {
        // Dequantize weight row
        float weight_row[8192];  // Max hidden size
        weight.DequantizeRow(row, weight_row, in_dim);
        
        // Dot product
        float sum = 0.0f;
        for (uint32_t col = 0; col < in_dim; ++col) {
            sum += input[col] * weight_row[col];
        }
        output[row] = sum;
    }
}

// ============================================================================
// Execute Token
// ============================================================================
bool StreamingMultiLayerBackend::ExecuteToken(
    uint32_t token_id,
    uint32_t position_id,
    float* logits_out
) {
    using namespace Telemetry;
    TELEMETRY_SCOPE(TELEMETRY_TRANSFORMER_FORWARD, TELEMETRY_TRANSFORMER_FORWARD + 1);
    
    // 1. Embedding lookup
    if (!EmbeddingLookup(token_id, m_hidden)) {
        return false;
    }
    
    // 2. Execute each layer
    for (uint32_t layer = 0; layer < m_num_layers; ++layer) {
        if (!ExecuteLayer(layer, position_id)) {
            return false;
        }
        
        // Swap hidden buffers
        std::memcpy(m_hidden, m_next_hidden, m_hidden_size * sizeof(float));
    }
    
    // 3. Output projection
    if (!OutputProjection(m_hidden, logits_out)) {
        return false;
    }
    
    return true;
}

// ============================================================================
// Generate
// ============================================================================
bool StreamingMultiLayerBackend::Generate(
    const std::vector<uint32_t>& prompt_tokens,
    std::vector<uint32_t>& output_tokens,
    size_t max_new_tokens,
    float temperature,
    int top_k
) {
    using namespace Telemetry;
    TELEMETRY_SCOPE(TELEMETRY_GENERATION_START, TELEMETRY_GENERATION_END);
    
    Reset();
    
    uint32_t pos = 0;
    
    // Prime KV cache with prompt
    for (auto token : prompt_tokens) {
        if (!ExecuteToken(token, pos, m_logits)) {
            return false;
        }
        ++pos;
    }
    
    // Get last token (or use 0 if empty)
    uint32_t last_token = prompt_tokens.empty() ? 0 : prompt_tokens.back();
    
    // Generate new tokens
    for (size_t i = 0; i < max_new_tokens; ++i) {
        Telemetry::Telemetry_Log(Telemetry::TELEMETRY_GENERATION_TOKEN, i, pos, 0);
        
        // Execute model
        if (!ExecuteToken(last_token, pos, m_logits)) {
            return false;
        }
        
        // Sample next token
        int32_t next = SampleToken(m_logits, temperature, top_k);
        if (next < 0) break;
        
        output_tokens.push_back(static_cast<uint32_t>(next));
        last_token = next;
        ++pos;
        
        // Stop on EOS (typically token 2)
        if (next == 2) break;
    }
    
    return true;
}

// ============================================================================
// Reset
// ============================================================================
void StreamingMultiLayerBackend::Reset() {
    if (m_kv_cache) {
        m_kv_cache->Reset();
    }
    m_registry.UnloadLayer();
}

// ============================================================================
// Sampling
// ============================================================================
int32_t StreamingMultiLayerBackend::SampleToken(const float* logits, float temperature, int top_k) {
    if (temperature <= 0.0f || top_k <= 1) {
        return GreedySample(logits);
    }
    return TopKSample(logits, top_k, temperature);
}

int32_t StreamingMultiLayerBackend::GreedySample(const float* logits) {
    int32_t best_idx = 0;
    float best_logit = logits[0];
    
    for (uint32_t i = 1; i < m_vocab_size; ++i) {
        if (logits[i] > best_logit) {
            best_logit = logits[i];
            best_idx = i;
        }
    }
    
    return best_idx;
}

int32_t StreamingMultiLayerBackend::TopKSample(const float* logits, int k, float temperature) {
    // Simple implementation: find top k, then sample
    struct Candidate {
        int32_t idx;
        float logit;
    };
    
    std::vector<Candidate> candidates;
    candidates.reserve(m_vocab_size);
    
    for (uint32_t i = 0; i < m_vocab_size; ++i) {
        candidates.push_back({static_cast<int32_t>(i), logits[i]});
    }
    
    // Sort by logit descending
    std::partial_sort(candidates.begin(), candidates.begin() + k, candidates.end(),
        [](const Candidate& a, const Candidate& b) { return a.logit > b.logit; });
    
    // Apply temperature and softmax
    std::vector<float> probs(k);
    float sum = 0.0f;
    for (int i = 0; i < k; ++i) {
        probs[i] = std::exp((candidates[i].logit - candidates[0].logit) / temperature);
        sum += probs[i];
    }
    
    // Normalize
    for (int i = 0; i < k; ++i) {
        probs[i] /= sum;
    }
    
    // Sample
    float r = static_cast<float>(rand()) / RAND_MAX;
    float cumsum = 0.0f;
    for (int i = 0; i < k; ++i) {
        cumsum += probs[i];
        if (r <= cumsum) {
            return candidates[i].idx;
        }
    }
    
    return candidates[k - 1].idx;
}

void StreamingMultiLayerBackend::Softmax(float* data, uint32_t size) {
    // Find max for numerical stability
    float max_val = data[0];
    for (uint32_t i = 1; i < size; ++i) {
        if (data[i] > max_val) max_val = data[i];
    }
    
    // Compute exp and sum
    float sum = 0.0f;
    for (uint32_t i = 0; i < size; ++i) {
        data[i] = std::exp(data[i] - max_val);
        sum += data[i];
    }
    
    // Normalize
    float inv_sum = 1.0f / sum;
    for (uint32_t i = 0; i < size; ++i) {
        data[i] *= inv_sum;
    }
}

} // namespace Runtime
} // namespace RawrXD
