// ============================================================================
// TransformerLayerRuntime - Implementation
// ============================================================================

#include "transformer_layer_runtime.hpp"
#include <cmath>
#include <chrono>
#include <algorithm>
#include <cstring>

// ============================================================================
// KV Cache Implementation
// ============================================================================
namespace transformer {

void KVCacheEntry::Resize(uint32_t max_len, uint32_t num_kv_heads, uint32_t head_dim) {
    max_seq_len = max_len;
    size_t cache_size = max_len * num_kv_heads * head_dim;
    key_cache.resize(cache_size);
    value_cache.resize(cache_size);
    seq_len = 0;
}

void KVCacheEntry::Reset() {
    seq_len = 0;
    std::fill(key_cache.begin(), key_cache.end(), 0.0f);
    std::fill(value_cache.begin(), value_cache.end(), 0.0f);
}

TensorViewF32 KVCacheEntry::GetKeyView(uint32_t pos, uint32_t num_kv_heads, uint32_t head_dim) {
    size_t offset = pos * num_kv_heads * head_dim;
    return TensorViewF32(key_cache.data() + offset, {num_kv_heads, head_dim});
}

TensorViewF32 KVCacheEntry::GetValueView(uint32_t pos, uint32_t num_kv_heads, uint32_t head_dim) {
    size_t offset = pos * num_kv_heads * head_dim;
    return TensorViewF32(value_cache.data() + offset, {num_kv_heads, head_dim});
}

// ============================================================================
// CPU Backend (Fallback)
// ============================================================================
class CPUBackend : public GPUBackend {
public:
    bool Initialize() override { return true; }
    void Cleanup() override {}
    
    bool AllocateBuffer(size_t size, void** device_ptr) override {
        *device_ptr = new char[size];
        return *device_ptr != nullptr;
    }
    
    void FreeBuffer(void* device_ptr) override {
        delete[] static_cast<char*>(device_ptr);
    }
    
    bool CopyHostToDevice(const void* host_ptr, void* device_ptr, size_t size) override {
        std::memcpy(device_ptr, host_ptr, size);
        return true;
    }
    
    bool CopyDeviceToHost(const void* device_ptr, void* host_ptr, size_t size) override {
        std::memcpy(host_ptr, device_ptr, size);
        return true;
    }
    
    void RMSNorm(const void* input, void* output, const void* weights,
                 uint32_t size, float epsilon) override {
        const float* in = static_cast<const float*>(input);
        float* out = static_cast<float*>(output);
        const float* w = static_cast<const float*>(weights);
        
        // Compute RMS
        float sum_sq = 0.0f;
        for (uint32_t i = 0; i < size; i++) {
            sum_sq += in[i] * in[i];
        }
        float rms = std::sqrt(sum_sq / size + epsilon);
        float inv_rms = 1.0f / rms;
        
        // Normalize and scale
        for (uint32_t i = 0; i < size; i++) {
            out[i] = in[i] * inv_rms * w[i];
        }
    }
    
    void MatMul(const void* a, const void* b, void* c,
                uint32_t m, uint32_t k, uint32_t n) override {
        const float* A = static_cast<const float*>(a);
        const float* B = static_cast<const float*>(b);
        float* C = static_cast<float*>(c);
        
        // Simple GEMM: C = A @ B
        // A: [m, k], B: [k, n], C: [m, n]
        for (uint32_t i = 0; i < m; i++) {
            for (uint32_t j = 0; j < n; j++) {
                float sum = 0.0f;
                for (uint32_t l = 0; l < k; l++) {
                    sum += A[i * k + l] * B[l * n + j];
                }
                C[i * n + j] = sum;
            }
        }
    }
    
    void Softmax(const void* input, void* output, uint32_t size) override {
        const float* in = static_cast<const float*>(input);
        float* out = static_cast<float*>(output);
        
        // Find max for numerical stability
        float max_val = in[0];
        for (uint32_t i = 1; i < size; i++) {
            max_val = std::max(max_val, in[i]);
        }
        
        // Compute exp and sum
        float sum_exp = 0.0f;
        for (uint32_t i = 0; i < size; i++) {
            out[i] = std::exp(in[i] - max_val);
            sum_exp += out[i];
        }
        
        // Normalize
        float inv_sum = 1.0f / sum_exp;
        for (uint32_t i = 0; i < size; i++) {
            out[i] *= inv_sum;
        }
    }
    
    void FlashAttention(const void* q, const void* k, const void* v,
                        void* output, uint32_t seq_len, uint32_t head_dim) override {
        // Simplified attention: softmax(Q @ K^T / sqrt(d)) @ V
        const float* Q = static_cast<const float*>(q);
        const float* K = static_cast<const float*>(k);
        const float* V = static_cast<const float*>(v);
        float* O = static_cast<float*>(output);
        
        float scale = 1.0f / std::sqrt(static_cast<float>(head_dim));
        
        // Q @ K^T
        std::vector<float> scores(seq_len);
        for (uint32_t i = 0; i < seq_len; i++) {
            float sum = 0.0f;
            for (uint32_t j = 0; j < head_dim; j++) {
                sum += Q[j] * K[i * head_dim + j];
            }
            scores[i] = sum * scale;
        }
        
        // Softmax
        float max_val = scores[0];
        for (uint32_t i = 1; i < seq_len; i++) {
            max_val = std::max(max_val, scores[i]);
        }
        float sum_exp = 0.0f;
        for (uint32_t i = 0; i < seq_len; i++) {
            scores[i] = std::exp(scores[i] - max_val);
            sum_exp += scores[i];
        }
        for (uint32_t i = 0; i < seq_len; i++) {
            scores[i] /= sum_exp;
        }
        
        // @ V
        for (uint32_t j = 0; j < head_dim; j++) {
            float sum = 0.0f;
            for (uint32_t i = 0; i < seq_len; i++) {
                sum += scores[i] * V[i * head_dim + j];
            }
            O[j] = sum;
        }
    }
    
    void Synchronize() override {}
};

// ============================================================================
// TransformerLayerRuntime Implementation
// ============================================================================
TransformerLayerRuntime::TransformerLayerRuntime() = default;
TransformerLayerRuntime::~TransformerLayerRuntime() = default;

bool TransformerLayerRuntime::Initialize(const TransformerConfig& config, 
                                         const LayerWeights& weights) {
    config_ = config;
    weights_ = weights;
    
    // Allocate working buffers
    q_buffer_.resize(config.num_heads * config.head_dim);
    k_buffer_.resize(config.num_kv_heads * config.head_dim);
    v_buffer_.resize(config.num_kv_heads * config.head_dim);
    attn_scores_.resize(config.num_heads * config.max_seq_len);
    attn_output_.resize(config.num_heads * config.head_dim);
    ffn_gate_.resize(config.intermediate_size);
    ffn_up_.resize(config.intermediate_size);
    ffn_down_.resize(config.hidden_size);
    
    // Default to CPU backend if not set
    if (!backend_) {
        backend_ = std::make_unique<CPUBackend>();
        if (!backend_->Initialize()) {
            return false;
        }
    }
    
    return true;
}

void TransformerLayerRuntime::Cleanup() {
    if (backend_) {
        backend_->Cleanup();
        backend_.reset();
    }
}

void TransformerLayerRuntime::SetBackend(std::unique_ptr<GPUBackend> backend) {
    backend_ = std::move(backend);
}

void TransformerLayerRuntime::Forward(const TensorViewF32& input, 
                                        TensorViewF32& output,
                                        KVCacheEntry& kv_cache, 
                                        uint32_t seq_pos) {
    auto start = std::chrono::high_resolution_clock::now();
    
    // Step 1: Input RMS Norm
    RMSNorm(input, TensorViewF32(weights_.input_layernorm.data(), {config_.hidden_size}),
            output, 1e-6f);
    
    // Step 2: QKV Projection
    QKVProjection(output);
    
    // Step 3: Flash Attention
    FlashAttention(output, kv_cache, seq_pos);
    
    // Step 4: Output projection and residual
    // output = output + residual
    for (uint32_t i = 0; i < config_.hidden_size; i++) {
        output.data[i] = output.data[i] + input.data[i];
    }
    
    // Step 5: Post-attention RMS Norm
    TensorViewF32 residual(output);
    RMSNorm(output, TensorViewF32(weights_.post_attn_layernorm.data(), {config_.hidden_size}),
            output, 1e-6f);
    
    // Step 6: MLP
    MLP(output, output);
    
    // Step 7: Residual connection
    for (uint32_t i = 0; i < config_.hidden_size; i++) {
        output.data[i] = output.data[i] + residual.data[i];
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    last_metrics_.time_ms = std::chrono::duration<double, std::milli>(end - start).count();
}

void TransformerLayerRuntime::RMSNorm(const TensorViewF32& input, 
                                      const TensorViewF32& weights,
                                      TensorViewF32& output, 
                                      float epsilon) {
    backend_->RMSNorm(input.data, output.data, weights.data, 
                      input.shape[0], epsilon);
}

void TransformerLayerRuntime::QKVProjection(const TensorViewF32& input) {
    // Q projection: [hidden_size] @ [hidden_size, num_heads * head_dim]
    backend_->MatMul(input.data, weights_.q_proj.data(), q_buffer_.data(),
                     1, config_.hidden_size, config_.num_heads * config_.head_dim);
    
    // K projection: [hidden_size] @ [hidden_size, num_kv_heads * head_dim]
    backend_->MatMul(input.data, weights_.k_proj.data(), k_buffer_.data(),
                     1, config_.hidden_size, config_.num_kv_heads * config_.head_dim);
    
    // V projection: [hidden_size] @ [hidden_size, num_kv_heads * head_dim]
    backend_->MatMul(input.data, weights_.v_proj.data(), v_buffer_.data(),
                     1, config_.hidden_size, config_.num_kv_heads * config_.head_dim);
}

void TransformerLayerRuntime::FlashAttention(TensorViewF32& output,
                                              KVCacheEntry& kv_cache,
                                              uint32_t seq_pos) {
    // Store K and V in cache
    auto key_view = kv_cache.GetKeyView(seq_pos, config_.num_kv_heads, config_.head_dim);
    auto value_view = kv_cache.GetValueView(seq_pos, config_.num_kv_heads, config_.head_dim);
    
    memcpy(key_view.data, k_buffer_.data(), k_buffer_.size() * sizeof(float));
    memcpy(value_view.data, v_buffer_.data(), v_buffer_.size() * sizeof(float));
    
    // Update sequence length
    kv_cache.seq_len = std::max(kv_cache.seq_len, seq_pos + 1);
    
    // Compute attention for each head
    for (uint32_t h = 0; h < config_.num_heads; h++) {
        // Get Q for this head
        float* q_head = q_buffer_.data() + h * config_.head_dim;
        
        // Get K, V for this head (with GQA)
        // uint32_t kv_head = h / (config_.num_heads / config_.num_kv_heads);
        
        // Compute attention
        // Simplified: just use the current position for now
        backend_->FlashAttention(q_head, kv_cache.key_cache.data(), kv_cache.value_cache.data(),
                                attn_output_.data() + h * config_.head_dim,
                                kv_cache.seq_len, config_.head_dim);
    }
    
    // Output projection: [num_heads * head_dim] @ [num_heads * head_dim, hidden_size]
    backend_->MatMul(attn_output_.data(), weights_.o_proj.data(), output.data,
                     1, config_.num_heads * config_.head_dim, config_.hidden_size);
}

void TransformerLayerRuntime::MLP(const TensorViewF32& input, TensorViewF32& output) {
    // Gate projection
    backend_->MatMul(input.data, weights_.gate_proj.data(), ffn_gate_.data(),
                     1, config_.hidden_size, config_.intermediate_size);
    
    // Up projection
    backend_->MatMul(input.data, weights_.up_proj.data(), ffn_up_.data(),
                     1, config_.hidden_size, config_.intermediate_size);
    
    // SiLU activation: gate * sigmoid(gate)
    TensorViewF32 gate_view(ffn_gate_.data(), {config_.intermediate_size});
    SiLU(gate_view, gate_view);
    
    // Element-wise multiply: gate * up
    for (uint32_t i = 0; i < config_.intermediate_size; i++) {
        ffn_gate_[i] *= ffn_up_[i];
    }
    
    // Down projection
    backend_->MatMul(ffn_gate_.data(), weights_.down_proj.data(), output.data,
                     1, config_.intermediate_size, config_.hidden_size);
}

void TransformerLayerRuntime::SiLU(const TensorViewF32& input, TensorViewF32& output) {
    // SiLU(x) = x * sigmoid(x)
    for (size_t i = 0; i < input.shape[0]; i++) {
        float x = input.data[i];
        float sigmoid = 1.0f / (1.0f + std::exp(-x));
        output.data[i] = x * sigmoid;
    }
}

// ============================================================================
// TransformerRuntime Implementation
// ============================================================================
TransformerRuntime::TransformerRuntime() = default;
TransformerRuntime::~TransformerRuntime() = default;

bool TransformerRuntime::Initialize(const TransformerConfig& config,
                                     const std::vector<LayerWeights>& layer_weights) {
    config_ = config;
    
    // Initialize layers
    layers_.reserve(config.num_layers);
    for (uint32_t i = 0; i < config.num_layers; i++) {
        auto layer = std::make_unique<TransformerLayerRuntime>();
        if (!layer->Initialize(config, layer_weights[i])) {
            return false;
        }
        layers_.push_back(std::move(layer));
    }
    
    // Initialize KV caches
    kv_caches_.resize(config.num_layers);
    for (auto& cache : kv_caches_) {
        cache.Resize(config.max_seq_len, config.num_kv_heads, config.head_dim);
    }
    
    return true;
}

void TransformerRuntime::Cleanup() {
    for (auto& layer : layers_) {
        layer->Cleanup();
    }
    layers_.clear();
}

std::vector<uint32_t> TransformerRuntime::Generate(const std::vector<uint32_t>& prompt,
                                                    uint32_t max_new_tokens,
                                                    float temperature,
                                                    float top_p) {
    std::vector<uint32_t> tokens = prompt;
    std::vector<float> hidden(config_.hidden_size);
    std::vector<float> logits(config_.vocab_size);
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    for (uint32_t i = 0; i < max_new_tokens; i++) {
        // Get last token
        uint32_t last_token = tokens.back();
        
        // Embedding lookup
        for (uint32_t j = 0; j < config_.hidden_size; j++) {
            hidden[j] = token_embedding_[last_token * config_.hidden_size + j];
        }
        
        // Forward through all layers
        TensorViewF32 input(hidden.data(), {config_.hidden_size});
        TensorViewF32 output(hidden.data(), {config_.hidden_size});
        
        for (uint32_t layer_idx = 0; layer_idx < config_.num_layers; layer_idx++) {
            layers_[layer_idx]->Forward(input, output, kv_caches_[layer_idx], tokens.size() - 1);
            input = output;
        }
        
        // Output norm
        for (uint32_t j = 0; j < config_.hidden_size; j++) {
            hidden[j] = hidden[j] * output_norm_[j];
        }
        
        // LM head
        for (uint32_t v = 0; v < config_.vocab_size; v++) {
            float sum = 0.0f;
            for (uint32_t j = 0; j < config_.hidden_size; j++) {
                sum += hidden[j] * lm_head_[j * config_.vocab_size + v];
            }
            logits[v] = sum;
        }
        
        // Sample next token
        uint32_t next_token = SampleToken(logits, temperature, top_p);
        tokens.push_back(next_token);
        total_tokens_++;
        
        // Check for EOS
        if (next_token == 2) break; // EOS token
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    double elapsed_sec = std::chrono::duration<double>(end_time - start_time).count();
    
    if (elapsed_sec > 0) {
        tokens_per_second_ = max_new_tokens / elapsed_sec;
        time_per_token_ms_ = (elapsed_sec * 1000.0) / max_new_tokens;
    }
    
    return tokens;
}

uint32_t TransformerRuntime::SampleToken(const std::vector<float>& logits,
                                         float temperature, 
                                         float top_p) {
    // Temperature scaling
    std::vector<float> probs = logits;
    Softmax(probs, temperature);
    
    // Top-p (nucleus) sampling
    // Sort probabilities
    std::vector<std::pair<float, uint32_t>> indexed_probs;
    for (uint32_t i = 0; i < probs.size(); i++) {
        indexed_probs.push_back({probs[i], i});
    }
    std::sort(indexed_probs.begin(), indexed_probs.end(), 
              std::greater<std::pair<float, uint32_t>>());
    
    // Find cutoff
    float cumsum = 0.0f;
    uint32_t cutoff = probs.size();
    for (uint32_t i = 0; i < indexed_probs.size(); i++) {
        cumsum += indexed_probs[i].first;
        if (cumsum > top_p) {
            cutoff = i + 1;
            break;
        }
    }
    
    // Sample from top-p
    float r = static_cast<float>(rand()) / RAND_MAX;
    float sum = 0.0f;
    for (uint32_t i = 0; i < cutoff; i++) {
        sum += indexed_probs[i].first;
        if (r <= sum) {
            return indexed_probs[i].second;
        }
    }
    
    return indexed_probs[cutoff - 1].second;
}

void TransformerRuntime::Softmax(std::vector<float>& logits, float temperature) {
    // Apply temperature
    for (auto& logit : logits) {
        logit /= temperature;
    }
    
    // Find max
    float max_val = logits[0];
    for (const auto& logit : logits) {
        max_val = std::max(max_val, logit);
    }
    
    // Compute exp and sum
    float sum_exp = 0.0f;
    for (auto& logit : logits) {
        logit = std::exp(logit - max_val);
        sum_exp += logit;
    }
    
    // Normalize
    float inv_sum = 1.0f / sum_exp;
    for (auto& logit : logits) {
        logit *= inv_sum;
    }
}

// ============================================================================
// Factory Functions
// ============================================================================
std::unique_ptr<GPUBackend> CreateCPUBackend() {
    return std::make_unique<CPUBackend>();
}

std::vector<LayerWeights> LoadWeightsFromGGUF(const std::string& path,
                                              const TransformerConfig& config) {
    // TODO: Implement GGUF loading
    // For now, return empty weights
    return std::vector<LayerWeights>(config.num_layers);
}

} // namespace transformer
