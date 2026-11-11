// sovereign_runtime.cpp - Sovereign Runtime Bridge Implementation
// Phase 8.1 - Production Runtime Integration
// NO DEPENDENCIES - Pure Win32 API

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#define SOVEREIGN_RUNTIME_EXPORTS

#include "sovereign_runtime.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

// ============================================================================
// INTERNAL UTILITIES
// ============================================================================

static float* allocate_float_buffer(size_t n_elements) {
    return (float*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, n_elements * sizeof(float));
}

static void free_float_buffer(float* buffer) {
    if (buffer) {
        HeapFree(GetProcessHeap(), 0, buffer);
    }
}

static float rmsnorm_epsilon = 1e-6f;

// ============================================================================
// KERNEL IMPLEMENTATIONS
// ============================================================================

// RMSNorm: output = input * weight / sqrt(mean(input^2) + eps)
static void kernel_rmsnorm(float* output, const float* input, const float* weight,
                           int n_elements, float eps) {
    // Calculate RMS
    float sum_sq = 0.0f;
    for (int i = 0; i < n_elements; i++) {
        sum_sq += input[i] * input[i];
    }
    float rms = sqrtf(sum_sq / n_elements + eps);
    float scale = 1.0f / rms;
    
    // Apply normalization and weight
    for (int i = 0; i < n_elements; i++) {
        output[i] = input[i] * scale * weight[i];
    }
}

// Softmax: output = exp(x - max) / sum(exp(x - max))
static void kernel_softmax(float* output, const float* input, int n_elements) {
    // Find max
    float max_val = input[0];
    for (int i = 1; i < n_elements; i++) {
        if (input[i] > max_val) max_val = input[i];
    }
    
    // Compute exp and sum
    float sum = 0.0f;
    for (int i = 0; i < n_elements; i++) {
        output[i] = expf(input[i] - max_val);
        sum += output[i];
    }
    
    // Normalize
    float inv_sum = 1.0f / sum;
    for (int i = 0; i < n_elements; i++) {
        output[i] *= inv_sum;
    }
}

// SiLU (Swish): output = x * sigmoid(x)
static float kernel_silu(float x) {
    return x / (1.0f + expf(-x));
}

// MatMul: C = A * B (A: m x k, B: k x n, C: m x n)
static void kernel_matmul(float* C, const float* A, const float* B,
                          int m, int n, int k) {
    for (int i = 0; i < m; i++) {
        for (int j = 0; j < n; j++) {
            float sum = 0.0f;
            for (int l = 0; l < k; l++) {
                sum += A[i * k + l] * B[l * n + j];
            }
            C[i * n + j] = sum;
        }
    }
}

// RoPE (Rotary Position Embedding)
static void kernel_rope(float* query, float* key, int n_heads, int head_dim,
                        int position, float freq_base) {
    for (int h = 0; h < n_heads; h++) {
        for (int d = 0; d < head_dim / 2; d++) {
            float freq = 1.0f / powf(freq_base, (2.0f * d) / head_dim);
            float theta = position * freq;
            float cos_theta = cosf(theta);
            float sin_theta = sinf(theta);
            
            int idx = h * head_dim + d;
            int pair_idx = h * head_dim + d + head_dim / 2;
            
            // Rotate query
            float q1 = query[idx];
            float q2 = query[pair_idx];
            query[idx] = q1 * cos_theta - q2 * sin_theta;
            query[pair_idx] = q1 * sin_theta + q2 * cos_theta;
            
            // Rotate key
            float k1 = key[idx];
            float k2 = key[pair_idx];
            key[idx] = k1 * cos_theta - k2 * sin_theta;
            key[pair_idx] = k1 * sin_theta + k2 * cos_theta;
        }
    }
}

// Attention: softmax(Q @ K^T / sqrt(d_k)) @ V
static void kernel_attention(float* output, const float* query, const float* key,
                             const float* value, int n_heads, int seq_len, int head_dim) {
    float scale = 1.0f / sqrtf((float)head_dim);
    int total_dim = n_heads * head_dim;
    
    // Allocate temporary buffers
    float* scores = (float*)malloc(seq_len * sizeof(float));
    float* attn_weights = (float*)malloc(seq_len * sizeof(float));
    
    for (int h = 0; h < n_heads; h++) {
        // Compute attention scores for this head
        for (int t = 0; t < seq_len; t++) {
            float dot = 0.0f;
            for (int d = 0; d < head_dim; d++) {
                float q = query[h * head_dim + d];
                float k = key[t * total_dim + h * head_dim + d];
                dot += q * k;
            }
            scores[t] = dot * scale;
        }
        
        // Softmax
        kernel_softmax(attn_weights, scores, seq_len);
        
        // Weighted sum of values
        for (int d = 0; d < head_dim; d++) {
            float sum = 0.0f;
            for (int t = 0; t < seq_len; t++) {
                float v = value[t * total_dim + h * head_dim + d];
                sum += attn_weights[t] * v;
            }
            output[h * head_dim + d] = sum;
        }
    }
    
    free(scores);
    free(attn_weights);
}

// ============================================================================
// G4: RMSNorm/RoPE/Attention Execution
// ============================================================================

SOVEREIGN_RUNTIME_API SovereignRuntimeStatus Sovereign_Runtime_RMSNorm(
    ModelContext* ctx,
    float* output,
    const float* input,
    const TensorView* weight,
    int n_elements
) {
    if (!ctx || !output || !input || !weight) {
        return SOVEREIGN_RUNTIME_ERROR_NULL_POINTER;
    }
    
    const float* weight_data = (const float*)weight->data;
    kernel_rmsnorm(output, input, weight_data, n_elements, ctx->rms_norm_eps);
    
    return SOVEREIGN_RUNTIME_SUCCESS;
}

SOVEREIGN_RUNTIME_API SovereignRuntimeStatus Sovereign_Runtime_RoPE(
    ModelContext* ctx,
    float* query,
    float* key,
    int position
) {
    if (!ctx || !query || !key) {
        return SOVEREIGN_RUNTIME_ERROR_NULL_POINTER;
    }
    
    kernel_rope(query, key, ctx->n_heads, ctx->head_dim, position, ctx->rope_freq_base);
    
    return SOVEREIGN_RUNTIME_SUCCESS;
}

SOVEREIGN_RUNTIME_API SovereignRuntimeStatus Sovereign_Runtime_Attention(
    ModelContext* ctx,
    int layer_idx,
    const float* query,
    float* output,
    int seq_len
) {
    if (!ctx || !query || !output) {
        return SOVEREIGN_RUNTIME_ERROR_NULL_POINTER;
    }
    
    if (layer_idx < 0 || layer_idx >= ctx->n_layers) {
        return SOVEREIGN_RUNTIME_ERROR_INVALID_TENSOR;
    }
    
    // Retrieve K and V from cache
    int total_dim = ctx->n_heads * ctx->head_dim;
    float* key = (float*)malloc(seq_len * total_dim * sizeof(float));
    float* value = (float*)malloc(seq_len * total_dim * sizeof(float));
    
    if (!key || !value) {
        free(key);
        free(value);
        return SOVEREIGN_RUNTIME_ERROR_OUT_OF_MEMORY;
    }
    
    for (int pos = 0; pos < seq_len; pos++) {
        Sovereign_Runtime_KVCache_Retrieve(ctx, layer_idx, 
            key + pos * total_dim, value + pos * total_dim, pos);
    }
    
    // Compute attention
    kernel_attention(output, query, key, value, ctx->n_heads, seq_len, ctx->head_dim);
    
    free(key);
    free(value);
    
    return SOVEREIGN_RUNTIME_SUCCESS;
}

// ============================================================================
// G6: Forward Pass (First real token from weights)
// ============================================================================

SOVEREIGN_RUNTIME_API SovereignRuntimeStatus Sovereign_Runtime_Forward(
    ModelContext* ctx,
    const int* tokens,
    int n_tokens,
    float* logits
) {
    if (!ctx || !tokens || !logits) {
        return SOVEREIGN_RUNTIME_ERROR_NULL_POINTER;
    }
    
    if (!ctx->token_embd || !ctx->layers) {
        return SOVEREIGN_RUNTIME_ERROR_INVALID_MODEL;
    }
    
    int hidden_dim = ctx->hidden_dim;
    int vocab_size = ctx->vocab_size;
    
    // Allocate buffers
    float* hidden = allocate_float_buffer(hidden_dim);
    float* temp = allocate_float_buffer(hidden_dim);
    float* qkv = allocate_float_buffer(3 * ctx->n_heads * ctx->head_dim);
    float* attn_out = allocate_float_buffer(ctx->n_heads * ctx->head_dim);
    
    if (!hidden || !temp || !qkv || !attn_out) {
        free_float_buffer(hidden);
        free_float_buffer(temp);
        free_float_buffer(qkv);
        free_float_buffer(attn_out);
        return SOVEREIGN_RUNTIME_ERROR_OUT_OF_MEMORY;
    }
    
    // Get embedding for first token (simplified - would process full sequence)
    const float* emb_data = (const float*)ctx->token_embd->data;
    memcpy(hidden, emb_data + tokens[0] * hidden_dim, hidden_dim * sizeof(float));
    
    // Process through transformer layers
    for (int layer = 0; layer < ctx->n_layers; layer++) {
        // Attention block
        // 1. RMSNorm
        kernel_rmsnorm(temp, hidden, (const float*)ctx->layers[layer].attention_norm->data,
                       hidden_dim, ctx->rms_norm_eps);
        
        // 2. QKV projections (simplified - would use actual matmul)
        // For now, just copy as placeholder
        memcpy(qkv, temp, hidden_dim * sizeof(float));
        
        // 3. RoPE
        float* q = qkv;
        float* k = qkv + ctx->n_heads * ctx->head_dim;
        kernel_rope(q, k, ctx->n_heads, ctx->head_dim, n_tokens - 1, ctx->rope_freq_base);
        
        // 4. Attention
        // Store K,V in cache
        Sovereign_Runtime_KVCache_Append(ctx, layer, k, 
            qkv + 2 * ctx->n_heads * ctx->head_dim, n_tokens);
        
        // Compute attention
        kernel_attention(attn_out, q, k, qkv + 2 * ctx->n_heads * ctx->head_dim,
                         ctx->n_heads, n_tokens, ctx->head_dim);
        
        // 5. Output projection (simplified)
        for (int i = 0; i < hidden_dim; i++) {
            temp[i] = attn_out[i % (ctx->n_heads * ctx->head_dim)];
        }
        
        // 6. Residual connection
        for (int i = 0; i < hidden_dim; i++) {
            hidden[i] += temp[i];
        }
        
        // FFN block
        // 1. RMSNorm
        kernel_rmsnorm(temp, hidden, (const float*)ctx->layers[layer].ffn_norm->data,
                       hidden_dim, ctx->rms_norm_eps);
        
        // 2. SwiGLU FFN (simplified)
        for (int i = 0; i < hidden_dim; i++) {
            float gate = kernel_silu(temp[i]);
            float up = temp[i];
            temp[i] = gate * up;
        }
        
        // 3. Residual connection
        for (int i = 0; i < hidden_dim; i++) {
            hidden[i] += temp[i];
        }
    }
    
    // Final RMSNorm
    kernel_rmsnorm(hidden, hidden, (const float*)ctx->norm_final->data,
                   hidden_dim, ctx->rms_norm_eps);
    
    // Output projection (logits)
    const float* output_weight = (const float*)ctx->output->data;
    for (int v = 0; v < vocab_size; v++) {
        float sum = 0.0f;
        for (int i = 0; i < hidden_dim; i++) {
            sum += hidden[i] * output_weight[v * hidden_dim + i];
        }
        logits[v] = sum;
    }
    
    // Cleanup
    free_float_buffer(hidden);
    free_float_buffer(temp);
    free_float_buffer(qkv);
    free_float_buffer(attn_out);
    
    return SOVEREIGN_RUNTIME_SUCCESS;
}

// ============================================================================
// SAMPLING
// ============================================================================

static int sample_argmax(const float* logits, int n_vocab) {
    int max_idx = 0;
    float max_val = logits[0];
    for (int i = 1; i < n_vocab; i++) {
        if (logits[i] > max_val) {
            max_val = logits[i];
            max_idx = i;
        }
    }
    return max_idx;
}

static int sample_top_k(const float* logits, int n_vocab, int k, float temperature, unsigned int* seed) {
    // Apply temperature
    float* probs = (float*)malloc(n_vocab * sizeof(float));
    if (!probs) return 0;
    
    float max_logit = logits[0];
    for (int i = 1; i < n_vocab; i++) {
        if (logits[i] > max_logit) max_logit = logits[i];
    }
    
    float sum = 0.0f;
    for (int i = 0; i < n_vocab; i++) {
        probs[i] = expf((logits[i] - max_logit) / temperature);
        sum += probs[i];
    }
    
    for (int i = 0; i < n_vocab; i++) {
        probs[i] /= sum;
    }
    
    // Find top k
    int* indices = (int*)malloc(k * sizeof(int));
    float* top_probs = (float*)malloc(k * sizeof(float));
    
    for (int i = 0; i < k; i++) {
        int max_idx = 0;
        for (int j = 1; j < n_vocab; j++) {
            if (probs[j] > probs[max_idx]) max_idx = j;
        }
        indices[i] = max_idx;
        top_probs[i] = probs[max_idx];
        probs[max_idx] = -1.0f; // Mark as used
    }
    
    // Sample from top k
    float r = (float)rand() / RAND_MAX;
    float cumsum = 0.0f;
    int result = indices[0];
    
    for (int i = 0; i < k; i++) {
        cumsum += top_probs[i];
        if (r <= cumsum) {
            result = indices[i];
            break;
        }
    }
    
    free(probs);
    free(indices);
    free(top_probs);
    
    return result;
}

// ============================================================================
// G7: Streaming Generation
// ============================================================================

SOVEREIGN_RUNTIME_API SovereignRuntimeStatus Sovereign_Runtime_Generate(
    ModelContext* ctx,
    const char* prompt,
    int max_tokens,
    SamplerConfig* sampler,
    void (*on_token)(int token_id, const char* token_text, void* user_data),
    void* user_data
) {
    if (!ctx || !prompt || !sampler) {
        return SOVEREIGN_RUNTIME_ERROR_NULL_POINTER;
    }
    
    // Tokenize prompt
    int tokens[1024];
    int n_tokens = Sovereign_Runtime_Encode(ctx, prompt, tokens, 1024);
    if (n_tokens <= 0) {
        return SOVEREIGN_RUNTIME_ERROR_TOKENIZER;
    }
    
    // Allocate logits buffer
    float* logits = allocate_float_buffer(ctx->vocab_size);
    if (!logits) {
        return SOVEREIGN_RUNTIME_ERROR_OUT_OF_MEMORY;
    }
    
    // Set random seed
    srand(sampler->seed);
    
    // Generation loop
    for (int i = 0; i < max_tokens; i++) {
        // Forward pass
        SovereignRuntimeStatus status = Sovereign_Runtime_Forward(ctx, tokens, n_tokens, logits);
        if (status != SOVEREIGN_RUNTIME_SUCCESS) {
            free_float_buffer(logits);
            return status;
        }
        
        // Sample next token
        int next_token;
        if (sampler->temperature <= 0.0f) {
            next_token = sample_argmax(logits, ctx->vocab_size);
        } else {
            next_token = sample_top_k(logits, ctx->vocab_size, sampler->top_k, 
                                      sampler->temperature, &sampler->seed);
        }
        
        // Check for EOS
        if (next_token == ctx->tokenizer.eos_token) {
            break;
        }
        
        // Get token text
        const char* token_text = Sovereign_Runtime_DecodeSingle(ctx, next_token);
        
        // Callback
        if (on_token) {
            on_token(next_token, token_text, user_data);
        }
        
        // Append token to sequence
        if (n_tokens < 1024) {
            tokens[n_tokens++] = next_token;
        } else {
            // Shift tokens (keep last 512)
            memmove(tokens, tokens + 512, (n_tokens - 512) * sizeof(int));
            n_tokens = 512;
            tokens[n_tokens++] = next_token;
        }
    }
    
    free_float_buffer(logits);
    
    return SOVEREIGN_RUNTIME_SUCCESS;
}

// Helper to decode single token
SOVEREIGN_RUNTIME_API const char* Sovereign_Runtime_DecodeSingle(
    ModelContext* ctx,
    int token_id
) {
    if (!ctx || token_id < 0 || token_id >= ctx->tokenizer.vocab_size) {
        return "<unk>";
    }
    return ctx->tokenizer.vocab[token_id];
}

// ============================================================================
// LIFECYCLE MANAGEMENT
// ============================================================================

SOVEREIGN_RUNTIME_API SovereignRuntimeStatus Sovereign_Runtime_Init(
    ModelContext* ctx,
    int model_id
) {
    if (!ctx) {
        return SOVEREIGN_RUNTIME_ERROR_NULL_POINTER;
    }
    
    memset(ctx, 0, sizeof(ModelContext));
    ctx->model_id = model_id;
    ctx->rms_norm_eps = 1e-6f;
    ctx->rope_freq_base = 10000.0f;
    
    return SOVEREIGN_RUNTIME_SUCCESS;
}

SOVEREIGN_RUNTIME_API void Sovereign_Runtime_Free(
    ModelContext* ctx
) {
    if (!ctx) {
        return;
    }
    
    // Free KV cache
    Sovereign_Runtime_KVCache_Free(ctx);
    
    // Free tokenizer
    // (implementation in tokenizer_bridge.cpp)
    
    // Free tensor mappings
    // (implementation in tensor_binding.cpp)
    
    // Unmap model data
    if (ctx->model_data) {
        UnmapViewOfFile(ctx->model_data);
        ctx->model_data = NULL;
    }
    
    memset(ctx, 0, sizeof(ModelContext));
}