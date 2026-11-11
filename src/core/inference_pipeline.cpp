// ============================================================================
// RawrXD Inference Pipeline Implementation
// Zero dependencies, pure C++17, Windows/Linux compatible
// ============================================================================

#include "inference_pipeline.hpp"
#include <algorithm>
#include <numeric>
#include <cstring>
#include <cstdio>

// Include sovereign loader for GGUF access
#include "sovereign_gguf_loader.h"

namespace RawrXD {
namespace Inference {

// ============================================================================
// TensorView Implementation
// ============================================================================

uint64_t TensorView::NumElements() const {
    if (n_dims == 0) return 0;
    uint64_t count = 1;
    for (uint32_t i = 0; i < n_dims; ++i) {
        count *= dims[i];
    }
    return count;
}

uint64_t TensorView::Stride(uint32_t dim) const {
    if (dim >= n_dims) return 0;
    uint64_t stride = 1;
    for (uint32_t i = dim + 1; i < n_dims; ++i) {
        stride *= dims[i];
    }
    return stride;
}

// ============================================================================
// KV Cache Implementation
// ============================================================================

bool KVCache::Initialize(uint32_t layers, uint32_t kv_heads, uint32_t h_dim, uint32_t max_len) {
    num_layers = layers;
    num_kv_heads = kv_heads;
    head_dim = h_dim;
    max_seq_len = max_len;
    current_len = 0;
    
    k_cache.resize(layers);
    v_cache.resize(layers);
    
    size_t cache_size = max_len * kv_heads * h_dim;
    
    for (uint32_t i = 0; i < layers; ++i) {
        k_cache[i].resize(cache_size);
        v_cache[i].resize(cache_size);
        std::fill(k_cache[i].begin(), k_cache[i].end(), 0.0f);
        std::fill(v_cache[i].begin(), v_cache[i].end(), 0.0f);
    }
    
    return true;
}

void KVCache::Reset() {
    current_len = 0;
    for (uint32_t i = 0; i < num_layers; ++i) {
        std::fill(k_cache[i].begin(), k_cache[i].end(), 0.0f);
        std::fill(v_cache[i].begin(), v_cache[i].end(), 0.0f);
    }
}

bool KVCache::Resize(uint32_t new_len) {
    if (new_len > max_seq_len) return false;
    current_len = new_len;
    return true;
}

void KVCache::GetIdentities(std::vector<KVCacheIdentity>& identities) const {
    identities.resize(num_layers);
    // Note: KVCacheIdentity is defined in hash_chain.hpp
    // This would compute hashes of each layer's cache
    // For now, stub implementation
    for (uint32_t i = 0; i < num_layers; ++i) {
        // identities[i].Compute(...)
    }
}

// ============================================================================
// Tokenizer Implementation (simplified BPE)
// ============================================================================

bool Tokenizer::Load(const std::string& vocab_path) {
    // Simplified: assume vocab is already loaded or embedded
    // Real implementation would parse tokenizer.json from GGUF
    printf("[Tokenizer] Loading from %s\n", vocab_path.c_str());
    
    // Build basic vocab (placeholder)
    for (uint32_t i = 0; i < 32000; ++i) {
        std::string token = "<token_" + std::to_string(i) + ">";
        vocab_[token] = i;
        reverse_vocab_[i] = token;
    }
    
    // Special tokens
    vocab_["<s>"] = bos_id_;
    reverse_vocab_[bos_id_] = "<s>";
    vocab_["</s>"] = eos_id_;
    reverse_vocab_[eos_id_] = "</s>";
    vocab_["<pad>"] = pad_id_;
    reverse_vocab_[pad_id_] = "<pad>";
    vocab_["<unk>"] = unk_id_;
    reverse_vocab_[unk_id_] = "<unk>";
    
    printf("[Tokenizer] Loaded %zu tokens\n", vocab_.size());
    return true;
}

bool Tokenizer::LoadFromGGUF(const void* gguf_data, size_t size) {
    // Parse tokenizer from GGUF metadata
    // This would extract vocab from GGUF's tokenizer.ggml.tokens
    printf("[Tokenizer] Loading from GGUF (%zu bytes)\n", size);
    return Load("");  // Fallback for now
}

std::vector<uint32_t> Tokenizer::Encode(const std::string& text, bool bos, bool eos) const {
    std::vector<uint32_t> result;
    if (bos) result.push_back(bos_id_);
    
    // Simple word-level tokenization (placeholder)
    // Real BPE would apply merge rules
    std::string word;
    for (char c : text) {
        if (c == ' ') {
            if (!word.empty()) {
                auto it = vocab_.find(word);
                if (it != vocab_.end()) {
                    result.push_back(it->second);
                } else {
                    result.push_back(unk_id_);
                }
                word.clear();
            }
            // Try to find space token, otherwise skip
            auto space_it = vocab_.find(" ");
            if (space_it != vocab_.end()) {
                result.push_back(space_it->second);
            }
        } else {
            word += c;
        }
    }
    
    if (!word.empty()) {
        auto it = vocab_.find(word);
        if (it != vocab_.end()) {
            result.push_back(it->second);
        } else {
            // Byte fallback
            for (char c : word) {
                std::string byte_token(1, c);
                auto bit = vocab_.find(byte_token);
                if (bit != vocab_.end()) {
                    result.push_back(bit->second);
                } else {
                    result.push_back(unk_id_);
                }
            }
        }
    }
    
    if (eos) result.push_back(eos_id_);
    return result;
}

std::string Tokenizer::Decode(const std::vector<uint32_t>& tokens) const {
    std::string result;
    for (uint32_t id : tokens) {
        if (id == bos_id_ || id == eos_id_ || id == pad_id_) continue;
        auto it = reverse_vocab_.find(id);
        if (it != reverse_vocab_.end()) {
            result += it->second;
        }
    }
    return result;
}

std::vector<std::string> Tokenizer::PreTokenize(const std::string& text) const {
    std::vector<std::string> words;
    std::string current;
    for (char c : text) {
        if (c == ' ') {
            if (!current.empty()) {
                words.push_back(current);
                current.clear();
            }
            words.push_back(" ");
        } else {
            current += c;
        }
    }
    if (!current.empty()) {
        words.push_back(current);
    }
    return words;
}

std::vector<uint32_t> Tokenizer::EncodeWord(const std::string& word) const {
    // Simplified BPE - just look up the word
    auto it = vocab_.find(word);
    if (it != vocab_.end()) {
        return {it->second};
    }
    // Byte fallback
    std::vector<uint32_t> result;
    for (char c : word) {
        std::string byte(1, c);
        auto bit = vocab_.find(byte);
        if (bit != vocab_.end()) {
            result.push_back(bit->second);
        } else {
            result.push_back(unk_id_);
        }
    }
    return result;
}

uint64_t Tokenizer::HashToken(const std::string& token) const {
    // FNV-1a hash
    uint64_t hash = 0xcbf29ce484222325ULL;
    for (char c : token) {
        hash ^= static_cast<uint64_t>(c);
        hash *= 0x100000001b3ULL;
    }
    return hash;
}

// ============================================================================
// Quantization Implementation
// ============================================================================

namespace Quant {

void DequantizeQ4_0(const void* src, float* dst, uint32_t n, uint32_t stride) {
    const uint8_t* ptr = static_cast<const uint8_t*>(src);
    uint32_t blocks = n / 32;
    
    for (uint32_t b = 0; b < blocks; ++b) {
        // Q4_0: 2 bytes scale + 16 bytes quantized (32 4-bit values)
        float scale = *reinterpret_cast<const float*>(ptr);
        ptr += 2;  // Actually 2 bytes for scale in Q4_0
        
        for (uint32_t i = 0; i < 16; ++i) {
            uint8_t packed = ptr[i];
            uint8_t low = packed & 0x0F;
            uint8_t high = (packed >> 4) & 0x0F;
            
            // Dequantize: value = (q - 8) * scale
            dst[b * 32 + i * 2] = (static_cast<float>(low) - 8.0f) * scale;
            dst[b * 32 + i * 2 + 1] = (static_cast<float>(high) - 8.0f) * scale;
        }
        ptr += 16;
    }
}

void DequantizeQ8_0(const void* src, float* dst, uint32_t n, uint32_t stride) {
    const uint8_t* ptr = static_cast<const uint8_t*>(src);
    uint32_t blocks = n / 32;
    
    for (uint32_t b = 0; b < blocks; ++b) {
        // Q8_0: 2 bytes scale + 32 bytes quantized
        float scale = *reinterpret_cast<const float*>(ptr);
        ptr += 2;
        
        for (uint32_t i = 0; i < 32; ++i) {
            int8_t q = static_cast<int8_t>(ptr[i]);
            dst[b * 32 + i] = static_cast<float>(q) * scale;
        }
        ptr += 32;
    }
}

void QuantizedMatVecMul(const TensorView& weights, const float* input,
                        float* output, uint32_t out_dim, uint32_t in_dim) {
    // Simple reference implementation
    // Real implementation would use optimized kernels
    
    if (weights.type == 0) {  // F32
        const float* w = static_cast<const float*>(weights.data);
        for (uint32_t i = 0; i < out_dim; ++i) {
            float sum = 0.0f;
            for (uint32_t j = 0; j < in_dim; ++j) {
                sum += w[i * in_dim + j] * input[j];
            }
            output[i] = sum;
        }
    } else if (weights.type == 2) {  // Q4_0
        // Dequantize on the fly
        std::vector<float> dequant(in_dim);
        DequantizeQ4_0(weights.data, dequant.data(), in_dim);
        
        const float* w = dequant.data();
        for (uint32_t i = 0; i < out_dim; ++i) {
            float sum = 0.0f;
            for (uint32_t j = 0; j < in_dim; ++j) {
                sum += w[i * in_dim + j] * input[j];
            }
            output[i] = sum;
        }
    }
}

} // namespace Quant

// ============================================================================
// Operations Implementation
// ============================================================================

namespace Ops {

void RMSNorm(const float* input, float* output, uint32_t n, float eps, const float* weight) {
    // Compute RMS
    float sum_sq = 0.0f;
    for (uint32_t i = 0; i < n; ++i) {
        sum_sq += input[i] * input[i];
    }
    float rms = std::sqrt(sum_sq / n + eps);
    float scale = 1.0f / rms;
    
    // Normalize and apply weight
    for (uint32_t i = 0; i < n; ++i) {
        output[i] = input[i] * scale;
        if (weight) {
            output[i] *= weight[i];
        }
    }
}

void Softmax(float* x, uint32_t n, float temperature) {
    // Find max for numerical stability
    float max_val = x[0];
    for (uint32_t i = 1; i < n; ++i) {
        if (x[i] > max_val) max_val = x[i];
    }
    
    // Compute exp and sum
    float sum = 0.0f;
    for (uint32_t i = 0; i < n; ++i) {
        x[i] = std::exp((x[i] - max_val) / temperature);
        sum += x[i];
    }
    
    // Normalize
    for (uint32_t i = 0; i < n; ++i) {
        x[i] /= sum;
    }
}

void RoPE(float* q, float* k, uint32_t dim, uint32_t head_dim,
          uint32_t pos, float theta) {
    // Apply rotary position embedding
    for (uint32_t i = 0; i < dim; i += 2) {
        uint32_t head_idx = i % head_dim;
        float freq = 1.0f / std::pow(theta, static_cast<float>(head_idx) / head_dim);
        float angle = pos * freq;
        float cos_a = std::cos(angle);
        float sin_a = std::sin(angle);
        
        float q0 = q[i];
        float q1 = q[i + 1];
        q[i] = q0 * cos_a - q1 * sin_a;
        q[i + 1] = q0 * sin_a + q1 * cos_a;
        
        float k0 = k[i];
        float k1 = k[i + 1];
        k[i] = k0 * cos_a - k1 * sin_a;
        k[i + 1] = k0 * sin_a + k1 * cos_a;
    }
}

void MatMul(const float* A, const float* B, float* C,
            uint32_t M, uint32_t N, uint32_t K, bool transpose_B) {
    // C[M, N] = A[M, K] @ B[K, N]
    for (uint32_t i = 0; i < M; ++i) {
        for (uint32_t j = 0; j < N; ++j) {
            float sum = 0.0f;
            for (uint32_t k = 0; k < K; ++k) {
                float b_val = transpose_B ? B[j * K + k] : B[k * N + j];
                sum += A[i * K + k] * b_val;
            }
            C[i * N + j] = sum;
        }
    }
}

void SwiGLU(const float* gate, const float* up, float* output, uint32_t n) {
    for (uint32_t i = 0; i < n; ++i) {
        // SiLU(gate) * up
        float silu = gate[i] * (1.0f / (1.0f + std::exp(-gate[i])));
        output[i] = silu * up[i];
    }
}

float SiLU(float x) {
    return x * (1.0f / (1.0f + std::exp(-x)));
}

void Attention(const float* q, const float* k, const float* v, float* output,
               uint32_t seq_len, uint32_t num_heads, uint32_t num_kv_heads,
               uint32_t head_dim, uint32_t pos) {
    // Simplified attention: output = softmax(Q @ K^T / sqrt(d)) @ V
    uint32_t heads_per_kv = num_heads / num_kv_heads;
    
    for (uint32_t h = 0; h < num_heads; ++h) {
        uint32_t kv_head = h / heads_per_kv;
        
        // Compute attention scores for this head
        std::vector<float> scores(seq_len);
        float scale = 1.0f / std::sqrt(static_cast<float>(head_dim));
        
        for (uint32_t t = 0; t < seq_len; ++t) {
            float dot = 0.0f;
            for (uint32_t d = 0; d < head_dim; ++d) {
                float q_val = q[h * head_dim + d];
                float k_val = k[kv_head * seq_len * head_dim + t * head_dim + d];
                dot += q_val * k_val;
            }
            scores[t] = dot * scale;
        }
        
        // Softmax
        Softmax(scores.data(), seq_len);
        
        // Weighted sum of values
        for (uint32_t d = 0; d < head_dim; ++d) {
            float sum = 0.0f;
            for (uint32_t t = 0; t < seq_len; ++t) {
                float v_val = v[kv_head * seq_len * head_dim + t * head_dim + d];
                sum += scores[t] * v_val;
            }
            output[h * head_dim + d] = sum;
        }
    }
}

} // namespace Ops

// ============================================================================
// Sampler Implementation
// ============================================================================

void Sampler::SetConfig(float temp, float p, uint32_t k) {
    temperature_ = temp;
    top_p_ = p;
    top_k_ = k;
}

void Sampler::SetSeed(uint32_t seed) {
    rng_.seed(seed);
}

Sampler::SampleResult Sampler::Sample(const float* logits, uint32_t vocab_size, uint32_t eos_id) {
    // Copy logits to mutable buffer
    std::vector<float> probs(logits, logits + vocab_size);
    
    // Apply sampling strategies
    ApplyTemperature(probs.data(), vocab_size);
    ApplyTopK(probs.data(), vocab_size, top_k_);
    ApplyTopP(probs.data(), vocab_size, top_p_);
    
    // Convert to probabilities
    Ops::Softmax(probs.data(), vocab_size);
    
    // Sample
    uint32_t token = MultinomialSample(probs.data(), vocab_size);
    
    return {token, probs[token], token == eos_id};
}

Sampler::SampleResult Sampler::SampleGreedy(const float* logits, uint32_t vocab_size) {
    uint32_t best_idx = 0;
    float best_val = logits[0];
    for (uint32_t i = 1; i < vocab_size; ++i) {
        if (logits[i] > best_val) {
            best_val = logits[i];
            best_idx = i;
        }
    }
    return {best_idx, 1.0f, false};
}

void Sampler::ApplyTemperature(float* logits, uint32_t n) {
    for (uint32_t i = 0; i < n; ++i) {
        logits[i] /= temperature_;
    }
}

void Sampler::ApplyTopK(float* logits, uint32_t n, uint32_t k) {
    if (k >= n) return;
    
    // Find k-th largest
    std::vector<float> sorted(logits, logits + n);
    std::nth_element(sorted.begin(), sorted.begin() + k, sorted.end(), std::greater<float>());
    float threshold = sorted[k];
    
    // Zero out below threshold
    for (uint32_t i = 0; i < n; ++i) {
        if (logits[i] < threshold) {
            logits[i] = -std::numeric_limits<float>::infinity();
        }
    }
}

void Sampler::ApplyTopP(float* logits, uint32_t n, float p) {
    // Sort logits
    std::vector<std::pair<float, uint32_t>> sorted;
    sorted.reserve(n);
    for (uint32_t i = 0; i < n; ++i) {
        sorted.push_back({logits[i], i});
    }
    std::sort(sorted.begin(), sorted.end(), std::greater<std::pair<float, uint32_t>>());
    
    // Compute cumulative probabilities
    std::vector<float> probs(n);
    for (uint32_t i = 0; i < n; ++i) {
        probs[i] = std::exp(sorted[i].first);
    }
    float sum = std::accumulate(probs.begin(), probs.end(), 0.0f);
    for (uint32_t i = 0; i < n; ++i) {
        probs[i] /= sum;
    }
    
    // Find cutoff
    float cumsum = 0.0f;
    uint32_t cutoff = n;
    for (uint32_t i = 0; i < n; ++i) {
        cumsum += probs[i];
        if (cumsum > p) {
            cutoff = i + 1;
            break;
        }
    }
    
    // Zero out below cutoff
    std::vector<bool> keep(n, false);
    for (uint32_t i = 0; i < cutoff; ++i) {
        keep[sorted[i].second] = true;
    }
    for (uint32_t i = 0; i < n; ++i) {
        if (!keep[i]) {
            logits[i] = -std::numeric_limits<float>::infinity();
        }
    }
}

uint32_t Sampler::MultinomialSample(const float* probs, uint32_t n) {
    std::uniform_real_distribution<float> dist(0.0f, 1.0f);
    float r = dist(rng_);
    
    float cumsum = 0.0f;
    for (uint32_t i = 0; i < n; ++i) {
        cumsum += probs[i];
        if (r <= cumsum) {
            return i;
        }
    }
    return n - 1;
}

// ============================================================================
// Pipeline Implementation
// ============================================================================

Pipeline::Pipeline() = default;
Pipeline::~Pipeline() {
    FreeBuffers();
}

bool Pipeline::Initialize(const std::string& model_path) {
    printf("[Pipeline] Initializing with model: %s\n", model_path.c_str());
    
    // Load GGUF
    gguf_handle_ = LoadGGUFModel(model_path, &config_);
    if (!gguf_handle_) {
        printf("[Pipeline] Failed to load GGUF model\n");
        return false;
    }
    
    // Initialize tokenizer
    if (!tokenizer_.LoadFromGGUF(gguf_handle_, 0)) {
        printf("[Pipeline] Failed to load tokenizer\n");
        return false;
    }
    
    // Initialize KV cache
    if (!kv_cache_.Initialize(config_.num_layers, config_.num_kv_heads,
                               config_.hidden_size / config_.num_heads,
                               config_.cache_seq_len)) {
        printf("[Pipeline] Failed to initialize KV cache\n");
        return false;
    }
    
    // Allocate buffers
    if (!AllocateBuffers()) {
        printf("[Pipeline] Failed to allocate buffers\n");
        return false;
    }
    
    loaded_ = true;
    printf("[Pipeline] Initialized successfully\n");
    printf("  Vocab size: %u\n", config_.vocab_size);
    printf("  Hidden size: %u\n", config_.hidden_size);
    printf("  Layers: %u\n", config_.num_layers);
    printf("  Heads: %u\n", config_.num_heads);
    
    return true;
}

bool Pipeline::AllocateBuffers() {
    uint32_t hidden = config_.hidden_size;
    uint32_t intermediate = config_.intermediate_size;
    uint32_t heads = config_.num_heads;
    uint32_t head_dim = hidden / heads;
    
    activation_buffer_.resize(hidden);
    residual_buffer_.resize(hidden);
    q_buffer_.resize(hidden);
    k_buffer_.resize(hidden);
    v_buffer_.resize(hidden);
    attn_output_buffer_.resize(hidden);
    ffn_buffer_.resize(intermediate);
    logits_buffer_.resize(config_.vocab_size);
    
    return true;
}

void Pipeline::FreeBuffers() {
    activation_buffer_.clear();
    residual_buffer_.clear();
    q_buffer_.clear();
    k_buffer_.clear();
    v_buffer_.clear();
    attn_output_buffer_.clear();
    ffn_buffer_.clear();
    logits_buffer_.clear();
}

std::string Pipeline::Generate(const std::string& prompt, const InferenceConfig& config) {
    // Encode prompt
    auto prompt_tokens = tokenizer_.Encode(prompt, true, false);
    
    // Generate tokens
    auto output_tokens = GenerateTokens(prompt_tokens, config);
    
    // Decode
    return tokenizer_.Decode(output_tokens);
}

std::vector<uint32_t> Pipeline::GenerateTokens(const std::vector<uint32_t>& prompt_tokens,
                                                const InferenceConfig& config) {
    std::vector<uint32_t> result = prompt_tokens;
    uint32_t pos = static_cast<uint32_t>(prompt_tokens.size());
    
    sampler_.SetConfig(config.temperature, config.top_p, config.top_k);
    
    for (uint32_t i = 0; i < config.max_tokens; ++i) {
        // Forward pass
        auto logits = Forward(result, pos);
        
        // Sample next token
        auto sample = sampler_.Sample(logits.data(), config.vocab_size, tokenizer_.GetEOS());
        
        result.push_back(sample.token_id);
        pos++;
        
        if (sample.is_eos) break;
    }
    
    // Return only generated tokens (not prompt)
    return std::vector<uint32_t>(result.begin() + prompt_tokens.size(), result.end());
}

std::vector<float> Pipeline::Forward(const std::vector<uint32_t>& tokens, uint32_t start_pos) {
    uint32_t seq_len = static_cast<uint32_t>(tokens.size()) - start_pos;
    uint32_t hidden = config_.hidden_size;
    
    // Token embeddings (placeholder - would lookup from weights)
    std::fill(activation_buffer_.begin(), activation_buffer_.end(), 0.0f);
    
    // Transformer layers
    for (uint32_t layer = 0; layer < config_.num_layers; ++layer) {
        // Save residual
        residual_buffer_ = activation_buffer_;
        
        // Attention
        ForwardAttention(layer, activation_buffer_.data(), activation_buffer_.data(), seq_len, start_pos);
        
        // Add residual
        for (uint32_t i = 0; i < hidden; ++i) {
            activation_buffer_[i] += residual_buffer_[i];
        }
        
        // Save residual
        residual_buffer_ = activation_buffer_;
        
        // FFN
        ForwardFFN(layer, activation_buffer_.data(), activation_buffer_.data(), seq_len);
        
        // Add residual
        for (uint32_t i = 0; i < hidden; ++i) {
            activation_buffer_[i] += residual_buffer_[i];
        }
    }
    
    // Final norm
    Ops::RMSNorm(activation_buffer_.data(), activation_buffer_.data(), hidden, config_.rms_norm_eps);
    
    // Output projection (placeholder)
    std::fill(logits_buffer_.begin(), logits_buffer_.end(), 0.0f);
    
    return logits_buffer_;
}

void Pipeline::ForwardAttention(uint32_t layer_idx, const float* input, float* output,
                                uint32_t seq_len, uint32_t pos) {
    uint32_t hidden = config_.hidden_size;
    uint32_t heads = config_.num_heads;
    uint32_t kv_heads = config_.num_kv_heads;
    uint32_t head_dim = hidden / heads;
    
    // QKV projections (placeholder)
    std::fill(q_buffer_.begin(), q_buffer_.end(), 0.0f);
    std::fill(k_buffer_.begin(), k_buffer_.end(), 0.0f);
    std::fill(v_buffer_.begin(), v_buffer_.end(), 0.0f);
    
    // Apply RoPE
    Ops::RoPE(q_buffer_.data(), k_buffer_.data(), hidden, head_dim, pos, config_.rope_theta);
    
    // Store K,V in cache
    for (uint32_t h = 0; h < kv_heads; ++h) {
        for (uint32_t d = 0; d < head_dim; ++d) {
            kv_cache_.k_cache[layer_idx][pos * kv_heads * head_dim + h * head_dim + d] = k_buffer_[h * head_dim + d];
            kv_cache_.v_cache[layer_idx][pos * kv_heads * head_dim + h * head_dim + d] = v_buffer_[h * head_dim + d];
        }
    }
    
    // Attention
    Ops::Attention(q_buffer_.data(), k_buffer_.data(), v_buffer_.data(),
                   attn_output_buffer_.data(), seq_len, heads, kv_heads, head_dim, pos);
    
    // Output projection (placeholder)
    std::copy(attn_output_buffer_.begin(), attn_output_buffer_.end(), output);
}

void Pipeline::ForwardFFN(uint32_t layer_idx, const float* input, float* output, uint32_t seq_len) {
    uint32_t hidden = config_.hidden_size;
    uint32_t intermediate = config_.intermediate_size;
    
    // Gate and up projections (placeholder)
    std::vector<float> gate(intermediate);
    std::vector<float> up(intermediate);
    
    // SwiGLU
    Ops::SwiGLU(gate.data(), up.data(), ffn_buffer_.data(), intermediate);
    
    // Down projection (placeholder)
    std::copy(ffn_buffer_.begin(), ffn_buffer_.begin() + hidden, output);
}

// ============================================================================
// GGUF Loading
// ============================================================================

void* LoadGGUFModel(const std::string& path, InferenceConfig* out_config) {
    // Use sovereign loader
    SovereignLoaderConfig loader_config = {};
    loader_config.use_memory_mapping = 1;
    loader_config.use_zero_copy = 1;
    
    SovereignGGUFModelHandle handle = Sovereign_LoadModel(path.c_str(), &loader_config);
    if (!handle) {
        return nullptr;
    }
    
    // Extract config
    if (out_config) {
        SovereignModelConfig cfg = {};
        if (Sovereign_Model_GetConfig(handle, &cfg) == 0) {
            out_config->vocab_size = cfg.vocab_size;
            out_config->hidden_size = cfg.hidden_size;
            out_config->num_layers = cfg.num_layers;
            out_config->num_heads = cfg.num_heads;
            out_config->num_kv_heads = cfg.num_kv_heads;
            out_config->intermediate_size = cfg.intermediate_size;
            out_config->max_seq_len = cfg.max_position_embeddings;
        }
    }
    
    return handle;
}

void UnloadGGUFModel(void* handle) {
    if (handle) {
        Sovereign_UnloadModel(static_cast<SovereignGGUFModelHandle>(handle));
    }
}

// ============================================================================
// Quick Inference
// ============================================================================

std::string RunInference(const std::string& model_path,
                         const std::string& prompt,
                         const InferenceConfig& config) {
    Pipeline pipeline;
    if (!pipeline.Initialize(model_path)) {
        return "Error: Failed to initialize pipeline";
    }
    return pipeline.Generate(prompt, config);
}

} // namespace Inference
} // namespace RawrXD
