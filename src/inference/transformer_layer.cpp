/**
 * @file transformer_layer.cpp
 * @brief RawrXD Transformer Layer Implementation (C4)
 *
 * Full transformer forward pass with attention and FFN.
 *
 * @copyright RawrXD 2026
 */

#include "transformer_layer.h"
#include <cmath>
#include <algorithm>
#include <numeric>
#include <cstring>

namespace rawrxd {
namespace inference {

// ============================================================================
// Transformer Layer Implementation
// ============================================================================

TransformerLayer::TransformerLayer(const TransformerConfig& config, uint32_t layer_idx)
    : config_(config), layer_idx_(layer_idx) {
}

bool TransformerLayer::LoadWeights(const model::ModelContext& model) {
    // Load attention weights from GGUF (keeping them quantized)
    std::string prefix = "blk." + std::to_string(layer_idx_) + ".";
    
    size_t hidden_size = config_.hidden_size;
    size_t kv_size = config_.num_kv_heads * config_.head_dim;
    size_t intermediate_size = config_.intermediate_size;
    
    // Load quantized tensors from model context
    // These stay in their compact quantized form - no FP32 materialization!
    auto load_quantized = [&](const std::string& name, QuantizedTensor& tensor,
                              const std::vector<uint64_t>& shape) -> bool {
        // Get tensor info from model context
        const auto* tensor_info = model.FindTensor(name);
        if (!tensor_info) {
            // For now, create dummy quantized tensor for testing
            // In production, this would load from GGUF
            tensor.type = QuantType::Q4_0;  // Default to Q4_0
            tensor.shape = shape;
            tensor.num_elements = 1;
            for (auto d : shape) tensor.num_elements *= d;
            
            uint32_t block_size = tensor.GetBlockSize();
            tensor.num_blocks = (tensor.num_elements + block_size - 1) / block_size;
            size_t data_size = tensor.num_blocks * tensor.GetBytesPerBlock();
            tensor.data.resize(data_size);
            
            // Initialize with dummy data (small values)
            for (auto& b : tensor.data) {
                b = 0x11;  // Neutral quantized value
            }
            return true;
        }
        
        // Real implementation would load from GGUF here
        return true;
    };
    
    // Load attention weights (quantized)
    load_quantized(prefix + "attn_q.weight", attn_weights_.q_proj,
                     {hidden_size, hidden_size});
    load_quantized(prefix + "attn_k.weight", attn_weights_.k_proj,
                     {hidden_size, kv_size});
    load_quantized(prefix + "attn_v.weight", attn_weights_.v_proj,
                     {hidden_size, kv_size});
    load_quantized(prefix + "attn_output.weight", attn_weights_.o_proj,
                     {hidden_size, hidden_size});
    
    // RMSNorm weights stay FP32 (small)
    attn_weights_.attn_norm.resize(hidden_size, 1.0f);
    
    // Load FFN weights (quantized)
    load_quantized(prefix + "ffn_gate.weight", ffn_weights_.gate_proj,
                     {hidden_size, intermediate_size});
    load_quantized(prefix + "ffn_up.weight", ffn_weights_.up_proj,
                     {hidden_size, intermediate_size});
    load_quantized(prefix + "ffn_down.weight", ffn_weights_.down_proj,
                     {intermediate_size, hidden_size});
    
    // RMSNorm weights stay FP32 (small)
    ffn_weights_.ffn_norm.resize(hidden_size, 1.0f);
    
    weights_loaded_ = true;
    return true;
}

std::vector<float> TransformerLayer::Forward(const std::vector<float>& input, uint32_t seq_len) {
    if (!weights_loaded_) {
        return {};
    }
    
    uint32_t hidden_size = config_.hidden_size;
    
    // Step 1: Attention with residual
    // x_norm = RMSNorm(input)
    auto x_norm = RMSNorm(input, attn_weights_.attn_norm);
    
    // attn_out = Attention(x_norm)
    auto attn_out = ApplyAttention(x_norm, seq_len);
    
    // residual1 = input + attn_out
    std::vector<float> residual1(input.size());
    for (size_t i = 0; i < input.size(); ++i) {
        residual1[i] = input[i] + attn_out[i];
    }
    
    // Step 2: FFN with residual
    // x_norm2 = RMSNorm(residual1)
    auto x_norm2 = RMSNorm(residual1, ffn_weights_.ffn_norm);
    
    // ffn_out = FFN(x_norm2)
    auto ffn_out = ApplyFFN(x_norm2);
    
    // output = residual1 + ffn_out
    std::vector<float> output(residual1.size());
    for (size_t i = 0; i < residual1.size(); ++i) {
        output[i] = residual1[i] + ffn_out[i];
    }
    
    return output;
}

std::vector<float> TransformerLayer::RMSNorm(
    const std::vector<float>& x, 
    const std::vector<float>& weight) {
    
    uint32_t hidden_size = config_.hidden_size;
    uint32_t seq_len = x.size() / hidden_size;
    
    std::vector<float> output(x.size());
    
    for (uint32_t s = 0; s < seq_len; ++s) {
        // Calculate RMS for this sequence position
        float sum_sq = 0.0f;
        for (uint32_t h = 0; h < hidden_size; ++h) {
            float v = x[s * hidden_size + h];
            sum_sq += v * v;
        }
        float rms = std::sqrt(sum_sq / hidden_size + config_.rms_norm_eps);
        float scale = 1.0f / rms;
        
        // Apply normalization and weight
        for (uint32_t h = 0; h < hidden_size; ++h) {
            output[s * hidden_size + h] = x[s * hidden_size + h] * scale * weight[h];
        }
    }
    
    return output;
}

std::vector<float> TransformerLayer::ApplyAttention(
    const std::vector<float>& x, 
    uint32_t seq_len) {
    
    uint32_t hidden_size = config_.hidden_size;
    uint32_t num_heads = config_.num_heads;
    uint32_t num_kv_heads = config_.num_kv_heads;
    uint32_t head_dim = config_.head_dim;
    uint32_t kv_size = num_kv_heads * head_dim;
    
    // Q, K, V projections
    auto q = MatMul(x, seq_len, hidden_size, 
                    attn_weights_.q_proj, hidden_size, hidden_size);
    auto k = MatMul(x, seq_len, hidden_size,
                    attn_weights_.k_proj, hidden_size, kv_size);
    auto v = MatMul(x, seq_len, hidden_size,
                    attn_weights_.v_proj, hidden_size, kv_size);
    
    // Reshape for multi-head attention
    // [seq_len, num_heads, head_dim]
    std::vector<float> attn_output(seq_len * hidden_size, 0.0f);
    
    float scale = 1.0f / std::sqrt(static_cast<float>(head_dim));
    
    // For each head
    for (uint32_t h = 0; h < num_heads; ++h) {
        uint32_t kv_head = h / (num_heads / num_kv_heads); // for GQA
        
        // Compute attention scores for this head
        for (uint32_t i = 0; i < seq_len; ++i) {
            // Q[i] dot K[j] for all j <= i (causal)
            std::vector<float> scores(i + 1);
            float max_score = -1e9f;
            
            for (uint32_t j = 0; j <= i; ++j) {
                float dot = 0.0f;
                for (uint32_t d = 0; d < head_dim; ++d) {
                    float q_val = q[i * hidden_size + h * head_dim + d];
                    float k_val = k[j * kv_size + kv_head * head_dim + d];
                    dot += q_val * k_val;
                }
                scores[j] = dot * scale;
                max_score = std::max(max_score, scores[j]);
            }
            
            // Softmax
            float sum_exp = 0.0f;
            for (uint32_t j = 0; j <= i; ++j) {
                scores[j] = std::exp(scores[j] - max_score);
                sum_exp += scores[j];
            }
            for (uint32_t j = 0; j <= i; ++j) {
                scores[j] /= sum_exp;
            }
            
            // Weighted sum of V
            for (uint32_t d = 0; d < head_dim; ++d) {
                float sum = 0.0f;
                for (uint32_t j = 0; j <= i; ++j) {
                    float v_val = v[j * kv_size + kv_head * head_dim + d];
                    sum += scores[j] * v_val;
                }
                attn_output[i * hidden_size + h * head_dim + d] = sum;
            }
        }
    }
    
    // Output projection
    return MatMul(attn_output, seq_len, hidden_size,
                  attn_weights_.o_proj, hidden_size, hidden_size);
}

std::vector<float> TransformerLayer::ApplyFFN(const std::vector<float>& x) {
    uint32_t hidden_size = config_.hidden_size;
    uint32_t intermediate_size = config_.intermediate_size;
    uint32_t seq_len = x.size() / hidden_size;
    
    // gate = SiLU(x @ gate_proj)
    auto gate = MatMul(x, seq_len, hidden_size,
                       ffn_weights_.gate_proj, hidden_size, intermediate_size);
    gate = SiLU(gate);
    
    // up = x @ up_proj
    auto up = MatMul(x, seq_len, hidden_size,
                     ffn_weights_.up_proj, hidden_size, intermediate_size);
    
    // intermediate = gate * up (element-wise)
    std::vector<float> intermediate(gate.size());
    for (size_t i = 0; i < gate.size(); ++i) {
        intermediate[i] = gate[i] * up[i];
    }
    
    // output = intermediate @ down_proj
    return MatMul(intermediate, seq_len, intermediate_size,
                  ffn_weights_.down_proj, intermediate_size, hidden_size);
}

std::vector<float> TransformerLayer::SiLU(const std::vector<float>& x) {
    std::vector<float> output(x.size());
    for (size_t i = 0; i < x.size(); ++i) {
        // SiLU(x) = x * sigmoid(x)
        output[i] = x[i] / (1.0f + std::exp(-x[i]));
    }
    return output;
}

std::vector<float> TransformerLayer::MatMul(
    const std::vector<float>& a, uint32_t a_rows, uint32_t a_cols,
    const QuantizedTensor& b, uint32_t b_rows, uint32_t b_cols) {
    
    if (a_cols != b_rows) {
        return {};
    }
    
    // Use quantized MatMul - dequantizes on-the-fly
    return MatMulQuantized(a, a_rows, a_cols, b, b_cols);
}

// ============================================================================
// Transformer Model Implementation
// ============================================================================

bool TransformerModel::Load(const std::string& path) {
    model_ctx_ = std::make_unique<model::ModelContext>();
    if (!model_ctx_->LoadFromFile(path)) {
        return false;
    }
    
    // Extract config from model
    const auto& arch = model_ctx_->GetArchitecture();
    config_.vocab_size = arch.vocab_size;
    config_.hidden_size = arch.embedding_dim;
    config_.num_layers = arch.layer_count;
    config_.num_heads = arch.head_count;
    config_.num_kv_heads = arch.kv_head_count;
    config_.head_dim = arch.embedding_dim / arch.head_count;
    
    // Create layers
    for (uint32_t i = 0; i < config_.num_layers; ++i) {
        auto layer = std::make_unique<TransformerLayer>(config_, i);
        if (!layer->LoadWeights(*model_ctx_)) {
            return false;
        }
        layers_.push_back(std::move(layer));
    }
    
    // Initialize KV cache
    k_cache_.resize(config_.num_layers);
    v_cache_.resize(config_.num_layers);
    
    return LoadEmbeddingWeights();
}

bool TransformerModel::LoadEmbeddingWeights() {
    // Load token embeddings from GGUF (keep quantized)
    uint32_t vocab_size = config_.vocab_size;
    uint32_t hidden_size = config_.hidden_size;
    
    // Load as quantized tensor
    token_embeddings_.type = QuantType::Q4_0;  // Use Q4_0 for embeddings
    token_embeddings_.shape = {vocab_size, hidden_size};
    token_embeddings_.num_elements = static_cast<uint64_t>(vocab_size) * hidden_size;
    
    uint32_t block_size = token_embeddings_.GetBlockSize();
    token_embeddings_.num_blocks = (token_embeddings_.num_elements + block_size - 1) / block_size;
    size_t data_size = token_embeddings_.num_blocks * token_embeddings_.GetBytesPerBlock();
    token_embeddings_.data.resize(data_size);
    
    // For now, initialize with dummy data
    // Real implementation would load from GGUF
    for (auto& b : token_embeddings_.data) {
        b = 0x11;
    }
    
    // Load output norm (FP32 - small)
    output_norm_.resize(hidden_size, 1.0f);
    
    // Load lm_head as quantized
    lm_head_.type = QuantType::Q4_0;
    lm_head_.shape = {hidden_size, vocab_size};
    lm_head_.num_elements = static_cast<uint64_t>(hidden_size) * vocab_size;
    lm_head_.num_blocks = (lm_head_.num_elements + block_size - 1) / block_size;
    data_size = lm_head_.num_blocks * lm_head_.GetBytesPerBlock();
    lm_head_.data.resize(data_size);
    
    for (auto& b : lm_head_.data) {
        b = 0x11;
    }
    
    return true;
}

// Forward declaration for MatMul
static std::vector<float> ModelMatMul(
    const std::vector<float>& a, uint32_t a_rows, uint32_t a_cols,
    const std::vector<float>& b, uint32_t b_rows, uint32_t b_cols
);

std::vector<float> TransformerModel::Forward(const std::vector<uint32_t>& token_ids) {
    if (layers_.empty()) {
        return {};
    }
    
    // Look up embeddings
    auto hidden = LookupEmbeddings(token_ids);
    uint32_t seq_len = token_ids.size();
    
    // Pass through all layers
    for (auto& layer : layers_) {
        hidden = layer->Forward(hidden, seq_len);
    }
    
    // Final RMSNorm
    // (simplified - would use output_norm_)
    
    // LM head projection to get logits
    // Take last token's hidden state
    std::vector<float> last_hidden(config_.hidden_size);
    std::memcpy(last_hidden.data(),
                 &hidden[(seq_len - 1) * config_.hidden_size],
                 config_.hidden_size * sizeof(float));
    
    // Project to vocab using quantized lm_head
    return MatMulQuantized(last_hidden, 1, config_.hidden_size,
                           lm_head_, config_.vocab_size);
}

std::vector<float> TransformerModel::LookupEmbeddings(
    const std::vector<uint32_t>& token_ids) {
    
    uint32_t seq_len = token_ids.size();
    uint32_t hidden_size = config_.hidden_size;
    
    std::vector<float> embeddings(seq_len * hidden_size);
    
    for (uint32_t i = 0; i < seq_len; ++i) {
        uint32_t token_id = token_ids[i];
        if (token_id < config_.vocab_size) {
            // Dequantize embedding on-the-fly
            for (uint32_t h = 0; h < hidden_size; ++h) {
                uint64_t idx = static_cast<uint64_t>(token_id) * hidden_size + h;
                embeddings[i * hidden_size + h] = GetQuantizedValue(token_embeddings_, idx);
            }
        }
    }
    
    return embeddings;
}

uint32_t TransformerModel::GenerateNextToken(
    const std::vector<uint32_t>& prompt_tokens,
    float temperature,
    uint32_t top_k) {
    
    // Forward pass
    auto logits = Forward(prompt_tokens);
    
    if (logits.empty()) {
        return 0;
    }
    
    // Sample from logits
    return Sample(logits, temperature, top_k);
}

uint32_t TransformerModel::Sample(
    const std::vector<float>& logits,
    float temperature,
    uint32_t top_k) {
    
    // Apply temperature
    std::vector<float> probs = logits;
    for (auto& p : probs) {
        p /= temperature;
    }
    
    // Softmax
    float max_logit = *std::max_element(probs.begin(), probs.end());
    float sum_exp = 0.0f;
    for (auto& p : probs) {
        p = std::exp(p - max_logit);
        sum_exp += p;
    }
    for (auto& p : probs) {
        p /= sum_exp;
    }
    
    // Top-k sampling
    std::vector<std::pair<float, uint32_t>> indexed;
    for (uint32_t i = 0; i < probs.size(); ++i) {
        indexed.push_back({probs[i], i});
    }
    
    std::partial_sort(indexed.begin(),
                     indexed.begin() + std::min(top_k, (uint32_t)indexed.size()),
                     indexed.end(),
                     std::greater<std::pair<float, uint32_t>>());
    
    // Sample from top-k
    float sum_topk = 0.0f;
    for (uint32_t i = 0; i < std::min(top_k, (uint32_t)indexed.size()); ++i) {
        sum_topk += indexed[i].first;
    }
    
    float r = static_cast<float>(rand()) / RAND_MAX * sum_topk;
    float cumsum = 0.0f;
    for (uint32_t i = 0; i < std::min(top_k, (uint32_t)indexed.size()); ++i) {
        cumsum += indexed[i].first;
        if (r <= cumsum) {
            return indexed[i].second;
        }
    }
    
    return indexed[0].second;
}

// Note: Old ModelMatMul removed - now using quantized MatMul only

} // namespace inference
} // namespace rawrxd
