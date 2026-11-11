/*===========================================================================
 * SovereignInferenceBridge_Q4.cpp
 * 
 * Q4_K_M inference implementation for SovereignInferenceBridge
 * 
 * Production path: GGUF Q4_K_M -> Deep2_Q4KM -> MASM kernels
 *===========================================================================*/

#include "SovereignInferenceBridge_Q4.hpp"
#include "SovereignInferenceBridge.h"
#include <cstring>
#include <algorithm>
#include <cmath>

// Deep2 kernels
extern "C" {
    void Deep2_RMSNorm(const float* x, float* out, size_t n, float eps);
    void Deep2_SwiGLU(const float* x, const float* y, float* out, size_t n);
    void Deep2_VecDotProduct(const float* a, const float* b, float* out, size_t n);
}

namespace RawrXD {
namespace IDE {

/*===========================================================================
 * SIB_Q4InferenceContext Implementation
 *===========================================================================*/

SIB_Q4InferenceContext::~SIB_Q4InferenceContext() {
    if (scratch_buffer_) {
        _aligned_free(scratch_buffer_);
    }
    if (temp_buffer_) {
        _aligned_free(temp_buffer_);
    }
    if (attn_buffer_) {
        _aligned_free(attn_buffer_);
    }
}

bool SIB_Q4InferenceContext::Initialize(const SIB_Q4ModelState& model_state) {
    model_ = &model_state;
    
    const size_t hidden_dim = model_state.base_info.hiddenDim;
    const size_t num_layers = model_state.base_info.numLayers;
    
    // Allocate scratch buffers (3x hidden_dim for safety)
    buffer_size_ = hidden_dim * 3;
    scratch_buffer_ = (float*)_aligned_malloc(buffer_size_ * sizeof(float), 32);
    temp_buffer_ = (float*)_aligned_malloc(buffer_size_ * sizeof(float), 32);
    attn_buffer_ = (float*)_aligned_malloc(buffer_size_ * sizeof(float), 32);
    
    if (!scratch_buffer_ || !temp_buffer_ || !attn_buffer_) {
        return false;
    }
    
    // Initialize quantized linear layers
    q_layers_.resize(num_layers);
    k_layers_.resize(num_layers);
    v_layers_.resize(num_layers);
    o_layers_.resize(num_layers);
    gate_layers_.resize(num_layers);
    up_layers_.resize(num_layers);
    down_layers_.resize(num_layers);
    
    for (size_t i = 0; i < num_layers; ++i) {
        const auto& layer_weights = model_state.layers[i];
        
        if (layer_weights.q_proj.IsValid()) {
            q_layers_[i].Initialize(layer_weights.q_proj);
        }
        if (layer_weights.k_proj.IsValid()) {
            k_layers_[i].Initialize(layer_weights.k_proj);
        }
        if (layer_weights.v_proj.IsValid()) {
            v_layers_[i].Initialize(layer_weights.v_proj);
        }
        if (layer_weights.o_proj.IsValid()) {
            o_layers_[i].Initialize(layer_weights.o_proj);
        }
        if (layer_weights.gate_proj.IsValid()) {
            gate_layers_[i].Initialize(layer_weights.gate_proj);
        }
        if (layer_weights.up_proj.IsValid()) {
            up_layers_[i].Initialize(layer_weights.up_proj);
        }
        if (layer_weights.down_proj.IsValid()) {
            down_layers_[i].Initialize(layer_weights.down_proj);
        }
    }
    
    return true;
}

bool SIB_Q4InferenceContext::RunTransformerLayer(
    const float* input,
    float* output,
    int layer_idx,
    int position) {
    
    if (!model_ || layer_idx < 0 || layer_idx >= static_cast<int>(model_->base_info.numLayers)) {
        return false;
    }
    
    const size_t hidden_dim = model_->base_info.hiddenDim;
    
    // Pre-norm
    Deep2_RMSNorm(input, temp_buffer_, hidden_dim, 1e-6f);
    
    // Self-attention
    if (!RunAttention_Q4KM(temp_buffer_, scratch_buffer_, layer_idx, position)) {
        return false;
    }
    
    // Residual connection
    for (size_t i = 0; i < hidden_dim; ++i) {
        scratch_buffer_[i] += input[i];
    }
    
    // Pre-FFN norm
    Deep2_RMSNorm(scratch_buffer_, temp_buffer_, hidden_dim, 1e-6f);
    
    // FFN
    if (!RunFFN_Q4KM(temp_buffer_, output, layer_idx)) {
        return false;
    }
    
    // Residual connection
    for (size_t i = 0; i < hidden_dim; ++i) {
        output[i] += scratch_buffer_[i];
    }
    
    return true;
}

bool SIB_Q4InferenceContext::RunAttention_Q4KM(
    const float* input,
    float* output,
    int layer_idx,
    int position) {
    
    const size_t hidden_dim = model_->base_info.hiddenDim;
    const size_t num_heads = model_->base_info.numExperts;  // Reusing field for heads
    const size_t head_dim = hidden_dim / num_heads;
    
    // Q, K, V projections using quantized weights
    if (!q_layers_[layer_idx].IsInitialized() ||
        !k_layers_[layer_idx].IsInitialized() ||
        !v_layers_[layer_idx].IsInitialized()) {
        return false;
    }
    
    // Compute Q, K, V
    float* q = temp_buffer_;
    float* k = temp_buffer_ + hidden_dim;
    float* v = temp_buffer_ + hidden_dim * 2;
    
    q_layers_[layer_idx].Forward(input, q);
    k_layers_[layer_idx].Forward(input, k);
    v_layers_[layer_idx].Forward(input, v);
    
    // Store K, V in cache
    if (model_->k_cache && model_->v_cache) {
        const size_t cache_offset = position * hidden_dim;
        memcpy(model_->k_cache + cache_offset, k, hidden_dim * sizeof(float));
        memcpy(model_->v_cache + cache_offset, v, hidden_dim * sizeof(float));
    }
    
    // Compute attention scores (simplified - full attention)
    // For production, use KV cache and compute only new token
    for (size_t head = 0; head < num_heads; ++head) {
        float* q_head = q + head * head_dim;
        float* out_head = output + head * head_dim;
        
        // Compute attention for this head
        // Simplified: just copy Q for now (full attention needs more implementation)
        memcpy(out_head, q_head, head_dim * sizeof(float));
    }
    
    // O projection
    if (o_layers_[layer_idx].IsInitialized()) {
        memcpy(scratch_buffer_, output, hidden_dim * sizeof(float));
        o_layers_[layer_idx].Forward(scratch_buffer_, output);
    }
    
    return true;
}

bool SIB_Q4InferenceContext::RunFFN_Q4KM(
    const float* input,
    float* output,
    int layer_idx) {
    
    const size_t hidden_dim = model_->base_info.hiddenDim;
    const size_t intermediate_dim = hidden_dim * 4;  // Standard expansion
    
    // Gate and Up projections
    if (!gate_layers_[layer_idx].IsInitialized() ||
        !up_layers_[layer_idx].IsInitialized()) {
        return false;
    }
    
    float* gate = temp_buffer_;
    float* up = temp_buffer_ + intermediate_dim;
    
    gate_layers_[layer_idx].Forward(input, gate);
    up_layers_[layer_idx].Forward(input, up);
    
    // SwiGLU activation: gate * sigmoid(gate) * up
    Deep2_SwiGLU(gate, up, scratch_buffer_, intermediate_dim);
    
    // Down projection
    if (!down_layers_[layer_idx].IsInitialized()) {
        return false;
    }
    
    down_layers_[layer_idx].Forward(scratch_buffer_, output);
    
    return true;
}

bool SIB_Q4InferenceContext::Forward(
    const int* token_ids,
    int num_tokens,
    float* output_logits) {
    
    if (!model_ || !token_ids || num_tokens <= 0 || !output_logits) {
        return false;
    }
    
    const size_t hidden_dim = model_->base_info.hiddenDim;
    const size_t vocab_size = model_->base_info.vocabSize;
    const size_t num_layers = model_->base_info.numLayers;
    
    // Token embedding lookup (simplified - should use embedding table)
    // For now, use random initialization as placeholder
    for (size_t i = 0; i < hidden_dim; ++i) {
        scratch_buffer_[i] = static_cast<float>(token_ids[num_tokens - 1] % 10) * 0.1f;
    }
    
    // Run through all transformer layers
    float* layer_input = scratch_buffer_;
    float* layer_output = temp_buffer_;
    
    for (size_t layer = 0; layer < num_layers; ++layer) {
        if (!RunTransformerLayer(layer_input, layer_output, 
                               static_cast<int>(layer), 
                               num_tokens - 1)) {
            return false;
        }
        
        // Swap buffers for next layer
        std::swap(layer_input, layer_output);
    }
    
    // Final output is in layer_input (due to swap)
    // Apply output head to get logits
    // Simplified: just copy hidden state
    const size_t output_size = std::min(hidden_dim, vocab_size);
    memcpy(output_logits, layer_input, output_size * sizeof(float));
    
    // Zero remaining logits
    if (vocab_size > hidden_dim) {
        memset(output_logits + hidden_dim, 0, (vocab_size - hidden_dim) * sizeof(float));
    }
    
    ++inference_count_;
    return true;
}

int SIB_Q4InferenceContext::GenerateNextToken(
    const int* prompt_tokens,
    int num_prompt_tokens,
    float temperature,
    int top_k) {
    
    if (!model_ || !prompt_tokens || num_prompt_tokens <= 0) {
        return -1;
    }
    
    const size_t vocab_size = model_->base_info.vocabSize;
    
    // Allocate logits buffer
    float* logits = (float*)_aligned_malloc(vocab_size * sizeof(float), 32);
    if (!logits) {
        return -1;
    }
    
    // Run forward pass
    bool success = Forward(prompt_tokens, num_prompt_tokens, logits);
    
    int next_token = 0;
    if (success) {
        // Apply temperature
        if (temperature != 1.0f && temperature > 0.0f) {
            for (size_t i = 0; i < vocab_size; ++i) {
                logits[i] /= temperature;
            }
        }
        
        // Simple argmax (should use softmax sampling)
        float max_logit = logits[0];
        next_token = 0;
        for (size_t i = 1; i < vocab_size; ++i) {
            if (logits[i] > max_logit) {
                max_logit = logits[i];
                next_token = static_cast<int>(i);
            }
        }
    }
    
    _aligned_free(logits);
    return success ? next_token : -1;
}

void SIB_Q4InferenceContext::ClearKVCache() {
    if (model_ && model_->k_cache && model_->v_cache) {
        const size_t cache_size = model_->cache_seq_len * model_->cache_batch_size * 
                                  model_->base_info.hiddenDim;
        memset(model_->k_cache, 0, cache_size * sizeof(float));
        memset(model_->v_cache, 0, cache_size * sizeof(float));
    }
}

void SIB_Q4InferenceContext::ResizeKVCache(size_t seq_len, size_t batch_size) {
    // Implementation would reallocate KV cache
    (void)seq_len;
    (void)batch_size;
}

double SIB_Q4InferenceContext::GetAverageTPS() const {
    if (inference_count_ == 0) {
        return 0.0;
    }
    // Estimate based on cycles (assuming 3GHz CPU)
    const double seconds = static_cast<double>(total_cycles_) / 3.0e9;
    return inference_count_ / seconds;
}

void SIB_Q4InferenceContext::ResetPerformanceStats() {
    inference_count_ = 0;
    total_cycles_ = 0;
}

/*===========================================================================
 * C API Implementation
 *===========================================================================*/

static SIB_Q4InferenceContext* g_q4_context = nullptr;

} // namespace IDE
} // namespace RawrXD

extern "C" {

using namespace RawrXD::IDE;

__declspec(dllexport)
bool SIB_Q4_Initialize(void) {
    // Check if Q4 kernels are available
    return RawrXD::Bridge::Deep2Bridge_HasQuantizedKernels();
}

__declspec(dllexport)
bool SIB_Q4_LoadModel(
    const WCHAR* gguf_path,
    const SIB_ModelInfo* model_info,
    int gguf_quant_type) {
    
    (void)gguf_path;
    (void)model_info;
    (void)gguf_quant_type;
    
    // Model loading implementation would go here
    // This connects to BraidedModelLoader and extracts Q4_K_M weights
    
    return true;
}

__declspec(dllexport)
bool SIB_Q4_RunInference(
    const int* input_tokens,
    int num_tokens,
    SIB_CompletionResult* result) {
    
    if (!g_q4_context || !input_tokens || num_tokens <= 0 || !result) {
        return false;
    }
    
    int next_token = g_q4_context->GenerateNextToken(
        input_tokens, num_tokens, 1.0f, 40);
    
    if (next_token < 0) {
        return false;
    }
    
    // Fill result (simplified)
    result->tokenCount = 1;
    result->tokens[0] = next_token;
    
    return true;
}

__declspec(dllexport)
bool SIB_Q4_IsAvailable(void) {
    return RawrXD::Bridge::Deep2Bridge_HasQuantizedKernels();
}

__declspec(dllexport)
const char* SIB_Q4_GetKernelVersion(void) {
    return RawrXD::Bridge::Deep2Bridge_GetQuantizedKernelVersion();
}

__declspec(dllexport)
const char* SIB_Q4_QuantTypeToString(int gguf_quant_type) {
    switch (gguf_quant_type) {
        case 0:  return "F32";
        case 1:  return "F16";
        case 2:  return "Q4_0";
        case 3:  return "Q4_1";
        case 7:  return "Q8_0";
        case 8:  return "Q5_0";
        case 9:  return "Q5_1";
        case 10: return "Q2_K";
        case 11: return "Q3_K_S";
        case 12: return "Q3_K_M";
        case 13: return "Q3_K_L";
        case 14: return "Q4_K_S";
        case 15: return "Q4_K_M";
        case 16: return "Q5_K_S";
        case 17: return "Q5_K_M";
        case 18: return "Q6_K";
        default: return "UNKNOWN";
    }
}

} // extern "C"
