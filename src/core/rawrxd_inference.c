//=============================================================================
// rawrxd_inference.c
// Zero-Dependency Inference Implementation
//=============================================================================

#include "rawrxd_inference.h"
#include "rawrxd_core.h"

#include <math.h>
#include <string.h>

//=============================================================================
// KV Cache Implementation
//=============================================================================

rawrxd_kv_cache* rawrxd_kv_cache_create(const rawrxd_model_config* config) {
    if (!config) return NULL;
    
    rawrxd_kv_cache* cache = rawrxd_alloc(sizeof(rawrxd_kv_cache));
    if (!cache) return NULL;
    
    memset(cache, 0, sizeof(*cache));
    
    cache->n_layers = config->num_layers;
    cache->n_heads = config->num_kv_heads > 0 ? config->num_kv_heads : config->num_heads;
    cache->head_dim = config->head_dim;
    cache->max_seq_len = config->max_seq_len;
    cache->current_len = 0;
    
    // Calculate cache size: [layers][2][heads][seq][dim]
    // 2 for K and V
    u64 cache_elements = (u64)cache->n_layers * 2 * cache->n_heads * 
                          cache->max_seq_len * cache->head_dim;
    cache->cache_size = cache_elements * sizeof(f16);
    
    cache->k_cache = rawrxd_alloc(cache->cache_size / 2);
    cache->v_cache = rawrxd_alloc(cache->cache_size / 2);
    
    if (!cache->k_cache || !cache->v_cache) {
        rawrxd_free(cache->k_cache, cache->cache_size / 2);
        rawrxd_free(cache->v_cache, cache->cache_size / 2);
        rawrxd_free(cache, sizeof(rawrxd_kv_cache));
        return NULL;
    }
    
    memset(cache->k_cache, 0, cache->cache_size / 2);
    memset(cache->v_cache, 0, cache->cache_size / 2);
    
    return cache;
}

void rawrxd_kv_cache_clear(rawrxd_kv_cache* cache) {
    if (!cache) return;
    cache->current_len = 0;
    if (cache->k_cache) memset(cache->k_cache, 0, cache->cache_size / 2);
    if (cache->v_cache) memset(cache->v_cache, 0, cache->cache_size / 2);
}

void rawrxd_kv_cache_resize(rawrxd_kv_cache* cache, u32 new_len) {
    if (!cache) return;
    cache->current_len = new_len < cache->max_seq_len ? new_len : cache->max_seq_len;
}

void rawrxd_kv_cache_destroy(rawrxd_kv_cache* cache) {
    if (!cache) return;
    if (cache->k_cache) rawrxd_free(cache->k_cache, cache->cache_size / 2);
    if (cache->v_cache) rawrxd_free(cache->v_cache, cache->cache_size / 2);
    rawrxd_free(cache, sizeof(rawrxd_kv_cache));
}

void rawrxd_kv_cache_store(rawrxd_kv_cache* cache, u32 layer, u32 head, 
                           u32 pos, const f16* key, const f16* value) {
    if (!cache || layer >= cache->n_layers || head >= cache->n_heads || 
        pos >= cache->max_seq_len) return;
    
    u64 head_offset = ((u64)layer * cache->n_heads + head) * cache->max_seq_len * cache->head_dim;
    u64 pos_offset = (u64)pos * cache->head_dim;
    
    f16* k_dest = cache->k_cache + head_offset + pos_offset;
    f16* v_dest = cache->v_cache + head_offset + pos_offset;
    
    memcpy(k_dest, key, cache->head_dim * sizeof(f16));
    memcpy(v_dest, value, cache->head_dim * sizeof(f16));
}

void rawrxd_kv_cache_fetch(const rawrxd_kv_cache* cache, u32 layer, u32 head,
                           u32 pos, f16* key_out, f16* value_out) {
    if (!cache || layer >= cache->n_layers || head >= cache->n_heads ||
        pos >= cache->max_seq_len) return;
    
    u64 head_offset = ((u64)layer * cache->n_heads + head) * cache->max_seq_len * cache->head_dim;
    u64 pos_offset = (u64)pos * cache->head_dim;
    
    const f16* k_src = cache->k_cache + head_offset + pos_offset;
    const f16* v_src = cache->v_cache + head_offset + pos_offset;
    
    memcpy(key_out, k_src, cache->head_dim * sizeof(f16));
    memcpy(value_out, v_src, cache->head_dim * sizeof(f16));
}

//=============================================================================
// Quantization - Q4_0
//=============================================================================

typedef struct { f32 d; u8 qs[18]; } block_q4_0;

void rawrxd_dequantize_q4_0(const void* src, f32* dst, u64 n) {
    const block_q4_0* blocks = (const block_q4_0*)src;
    u64 nb = n / 32;
    
    for (u64 i = 0; i < nb; i++) {
        f32 d = blocks[i].d;
        for (int j = 0; j < 16; j++) {
            u8 q = blocks[i].qs[j];
            dst[i * 32 + j] = d * ((q & 0x0F) - 8);
            dst[i * 32 + j + 16] = d * ((q >> 4) - 8);
        }
    }
}

void rawrxd_quantize_q4_0(const f32* src, void* dst, u64 n) {
    block_q4_0* blocks = (block_q4_0*)dst;
    u64 nb = n / 32;
    
    for (u64 i = 0; i < nb; i++) {
        // Find min/max
        f32 min = src[i * 32], max = src[i * 32];
        for (int j = 1; j < 32; j++) {
            f32 v = src[i * 32 + j];
            if (v < min) min = v;
            if (v > max) max = v;
        }
        
        // Calculate scale
        f32 d = (max - min) / 15.0f;
        if (d == 0) d = 1.0f;
        blocks[i].d = d;
        
        // Quantize
        for (int j = 0; j < 16; j++) {
            int v0 = (int)roundf((src[i * 32 + j] - min) / d);
            int v1 = (int)roundf((src[i * 32 + j + 16] - min) / d);
            v0 = v0 < 0 ? 0 : (v0 > 15 ? 15 : v0);
            v1 = v1 < 0 ? 0 : (v1 > 15 ? 15 : v1);
            blocks[i].qs[j] = (u8)(v0 | (v1 << 4));
        }
    }
}

void rawrxd_q4_0_mat_vec(const void* mat, const f32* vec, f32* out, 
                         u64 nrows, u64 ncols) {
    const block_q4_0* blocks = (const block_q4_0*)mat;
    u64 nb_per_row = ncols / 32;
    
    for (u64 row = 0; row < nrows; row++) {
        f32 sum = 0.0f;
        const block_q4_0* row_blocks = blocks + row * nb_per_row;
        
        for (u64 nb = 0; nb < nb_per_row; nb++) {
            f32 d = row_blocks[nb].d;
            for (int j = 0; j < 16; j++) {
                u8 q = row_blocks[nb].qs[j];
                f32 v0 = d * ((q & 0x0F) - 8);
                f32 v1 = d * ((q >> 4) - 8);
                sum += v0 * vec[nb * 32 + j];
                sum += v1 * vec[nb * 32 + j + 16];
            }
        }
        out[row] = sum;
    }
}

//=============================================================================
// Quantization - Q8_0
//=============================================================================

typedef struct { f32 d; i8 qs[32]; } block_q8_0;

void rawrxd_dequantize_q8_0(const void* src, f32* dst, u64 n) {
    const block_q8_0* blocks = (const block_q8_0*)src;
    u64 nb = n / 32;
    
    for (u64 i = 0; i < nb; i++) {
        f32 d = blocks[i].d;
        for (int j = 0; j < 32; j++) {
            dst[i * 32 + j] = d * blocks[i].qs[j];
        }
    }
}

void rawrxd_quantize_q8_0(const f32* src, void* dst, u64 n) {
    block_q8_0* blocks = (block_q8_0*)dst;
    u64 nb = n / 32;
    
    for (u64 i = 0; i < nb; i++) {
        // Find max abs
        f32 max_abs = 0.0f;
        for (int j = 0; j < 32; j++) {
            f32 abs_v = fabsf(src[i * 32 + j]);
            if (abs_v > max_abs) max_abs = abs_v;
        }
        
        f32 d = max_abs / 127.0f;
        if (d == 0) d = 1.0f;
        blocks[i].d = d;
        
        for (int j = 0; j < 32; j++) {
            int v = (int)roundf(src[i * 32 + j] / d);
            v = v < -128 ? -128 : (v > 127 ? 127 : v);
            blocks[i].qs[j] = (i8)v;
        }
    }
}

void rawrxd_q8_0_mat_vec(const void* mat, const f32* vec, f32* out,
                         u64 nrows, u64 ncols) {
    const block_q8_0* blocks = (const block_q8_0*)mat;
    u64 nb_per_row = ncols / 32;
    
    for (u64 row = 0; row < nrows; row++) {
        f32 sum = 0.0f;
        const block_q8_0* row_blocks = blocks + row * nb_per_row;
        
        for (u64 nb = 0; nb < nb_per_row; nb++) {
            f32 d = row_blocks[nb].d;
            i32 acc = 0;
            for (int j = 0; j < 32; j++) {
                acc += row_blocks[nb].qs[j] * (i32)(vec[nb * 32 + j] * 127.0f);
            }
            sum += d * acc / 127.0f;
        }
        out[row] = sum;
    }
}

//=============================================================================
// Normalization
//=============================================================================

void rawrxd_rms_norm(f32* output, const f32* input, u32 size, f32 eps) {
    f32 sum = 0.0f;
    for (u32 i = 0; i < size; i++) {
        sum += input[i] * input[i];
    }
    f32 scale = 1.0f / sqrtf(sum / size + eps);
    for (u32 i = 0; i < size; i++) {
        output[i] = input[i] * scale;
    }
}

void rawrxd_layer_norm(f32* output, const f32* input, u32 size, f32 eps) {
    f32 mean = 0.0f;
    for (u32 i = 0; i < size; i++) {
        mean += input[i];
    }
    mean /= size;
    
    f32 var = 0.0f;
    for (u32 i = 0; i < size; i++) {
        f32 diff = input[i] - mean;
        var += diff * diff;
    }
    var /= size;
    
    f32 scale = 1.0f / sqrtf(var + eps);
    for (u32 i = 0; i < size; i++) {
        output[i] = (input[i] - mean) * scale;
    }
}

void rawrxd_softmax(f32* x, u32 size) {
    f32 max_val = x[0];
    for (u32 i = 1; i < size; i++) {
        if (x[i] > max_val) max_val = x[i];
    }
    
    f32 sum = 0.0f;
    for (u32 i = 0; i < size; i++) {
        x[i] = expf(x[i] - max_val);
        sum += x[i];
    }
    
    for (u32 i = 0; i < size; i++) {
        x[i] /= sum;
    }
}

void rawrxd_softmax_inplace(f32* x, u32 size) {
    rawrxd_softmax(x, size);
}

//=============================================================================
// Activations
//=============================================================================

void rawrxd_silu(f32* x, u32 n) {
    for (u32 i = 0; i < n; i++) {
        x[i] = x[i] / (1.0f + expf(-x[i]));
    }
}

void rawrxd_gelu(f32* x, u32 n) {
    const f32 sqrt_2_over_pi = 0.7978845608f;
    for (u32 i = 0; i < n; i++) {
        f32 v = x[i];
        x[i] = 0.5f * v * (1.0f + tanhf(sqrt_2_over_pi * (v + 0.044715f * v * v * v)));
    }
}

void rawrxd_relu(f32* x, u32 n) {
    for (u32 i = 0; i < n; i++) {
        if (x[i] < 0) x[i] = 0;
    }
}

void rawrxd_swiglu(f32* output, const f32* gate, const f32* up, u32 n) {
    for (u32 i = 0; i < n; i++) {
        f32 g = gate[i];
        f32 sigmoid = 1.0f / (1.0f + expf(-g));
        output[i] = sigmoid * g * up[i];
    }
}

//=============================================================================
// RoPE (Rotary Position Embedding)
//=============================================================================

void rawrxd_rope_inplace(f32* q, f32* k, u32 n_heads, u32 head_dim, 
                         u32 pos, f32 theta) {
    for (u32 h = 0; h < n_heads; h++) {
        for (u32 i = 0; i < head_dim; i += 2) {
            f32 freq = 1.0f / powf(theta, (f32)i / head_dim);
            f32 angle = pos * freq;
            f32 cos_a = cosf(angle);
            f32 sin_a = sinf(angle);
            
            // Rotate Q
            f32 q0 = q[h * head_dim + i];
            f32 q1 = q[h * head_dim + i + 1];
            q[h * head_dim + i] = q0 * cos_a - q1 * sin_a;
            q[h * head_dim + i + 1] = q0 * sin_a + q1 * cos_a;
            
            // Rotate K
            f32 k0 = k[h * head_dim + i];
            f32 k1 = k[h * head_dim + i + 1];
            k[h * head_dim + i] = k0 * cos_a - k1 * sin_a;
            k[h * head_dim + i + 1] = k0 * sin_a + k1 * cos_a;
        }
    }
}

//=============================================================================
// Attention
//=============================================================================

void rawrxd_self_attention(f32* output, const f32* query, const f32* key_cache,
                           const f32* value_cache, u32 seq_len, u32 n_heads,
                           u32 head_dim, f32 scale) {
    u32 head_size = head_dim;
    
    for (u32 h = 0; h < n_heads; h++) {
        const f32* q = query + h * head_size;
        
        // Compute attention scores for each position
        for (u32 pos = 0; pos < seq_len; pos++) {
            const f32* k = key_cache + ((u64)h * seq_len + pos) * head_size;
            
            // Q @ K^T
            f32 score = 0.0f;
            for (u32 d = 0; d < head_dim; d++) {
                score += q[d] * k[d];
            }
            score *= scale;
            
            // Store score (simplified - would use softmax in practice)
            // For now, just accumulate weighted values
            const f32* v = value_cache + ((u64)h * seq_len + pos) * head_size;
            for (u32 d = 0; d < head_dim; d++) {
                output[h * head_size + d] += score * v[d];
            }
        }
    }
}

//=============================================================================
// Context Management
//=============================================================================

rawrxd_context* rawrxd_context_create(rawrxd_model* model) {
    if (!model) return NULL;
    
    rawrxd_context* ctx = rawrxd_alloc(sizeof(rawrxd_context));
    if (!ctx) return NULL;
    
    memset(ctx, 0, sizeof(*ctx));
    ctx->model = model;
    ctx->vocab_size = model->config.vocab_size;
    
    // Allocate working buffers
    u32 hidden_size = model->config.hidden_size;
    u32 intermediate_size = model->config.intermediate_size;
    
    ctx->logits = rawrxd_alloc(ctx->vocab_size * sizeof(f32));
    ctx->attn_scores = rawrxd_alloc(model->config.max_seq_len * sizeof(f32));
    ctx->attn_probs = rawrxd_alloc(model->config.max_seq_len * sizeof(f32));
    ctx->qkv_buffer = rawrxd_alloc(hidden_size * 3 * sizeof(f16));
    ctx->mlp_buffer = rawrxd_alloc(intermediate_size * sizeof(f32));
    ctx->norm_buffer = rawrxd_alloc(hidden_size * sizeof(f32));
    ctx->layer_input = rawrxd_alloc(hidden_size * sizeof(f32));
    ctx->layer_output = rawrxd_alloc(hidden_size * sizeof(f32));
    
    if (!ctx->logits || !ctx->attn_scores || !ctx->attn_probs ||
        !ctx->qkv_buffer || !ctx->mlp_buffer || !ctx->norm_buffer ||
        !ctx->layer_input || !ctx->layer_output) {
        rawrxd_context_destroy(ctx);
        return NULL;
    }
    
    // Initialize RNG
    rawrxd_rng_init(&ctx->rng, (u64)rawrxd_time_ns());
    
    // Default sampling params
    ctx->temperature = 0.8f;
    ctx->top_p = 0.9f;
    ctx->top_k = 40;
    ctx->repetition_penalty = 1.0f;
    
    return ctx;
}

void rawrxd_context_destroy(rawrxd_context* ctx) {
    if (!ctx) return;
    
    rawrxd_free(ctx->logits, ctx->vocab_size * sizeof(f32));
    rawrxd_free(ctx->attn_scores, ctx->model->config.max_seq_len * sizeof(f32));
    rawrxd_free(ctx->attn_probs, ctx->model->config.max_seq_len * sizeof(f32));
    rawrxd_free(ctx->qkv_buffer, ctx->model->config.hidden_size * 3 * sizeof(f16));
    rawrxd_free(ctx->mlp_buffer, ctx->model->config.intermediate_size * sizeof(f32));
    rawrxd_free(ctx->norm_buffer, ctx->model->config.hidden_size * sizeof(f32));
    rawrxd_free(ctx->layer_input, ctx->model->config.hidden_size * sizeof(f32));
    rawrxd_free(ctx->layer_output, ctx->model->config.hidden_size * sizeof(f32));
    
    if (ctx->input_tokens) {
        rawrxd_free(ctx->input_tokens, ctx->num_input_tokens * sizeof(u32));
    }
    
    rawrxd_free(ctx, sizeof(rawrxd_context));
}

void rawrxd_context_reset(rawrxd_context* ctx) {
    if (!ctx) return;
    ctx->current_pos = 0;
    ctx->total_len = 0;
    ctx->forward_count = 0;
    ctx->total_forward_time = 0;
    if (ctx->model && ctx->model->kv_cache) {
        rawrxd_kv_cache_clear(ctx->model->kv_cache);
    }
}

//=============================================================================
// Token Sampling
//=============================================================================

u32 rawrxd_sample_token(rawrxd_context* ctx, const f32* logits, u32 vocab_size) {
    if (!ctx || !logits) return 0;
    
    // Apply temperature
    f32 temp = ctx->temperature;
    if (temp != 1.0f && temp > 0) {
        for (u32 i = 0; i < vocab_size; i++) {
            ctx->logits[i] = logits[i] / temp;
        }
    } else {
        memcpy(ctx->logits, logits, vocab_size * sizeof(f32));
    }
    
    // Top-k filtering
    if (ctx->top_k > 0 && ctx->top_k < vocab_size) {
        // Simple selection - find top k
        // (Full implementation would use quickselect)
    }
    
    // Softmax
    rawrxd_softmax_inplace(ctx->logits, vocab_size);
    
    // Sample
    f32 r = rawrxd_rng_f32(&ctx->rng);
    f32 cumsum = 0.0f;
    for (u32 i = 0; i < vocab_size; i++) {
        cumsum += ctx->logits[i];
        if (r <= cumsum) {
            return i;
        }
    }
    
    return vocab_size - 1;
}

//=============================================================================
// Performance Stats
//=============================================================================

void rawrxd_get_perf_stats(const rawrxd_context* ctx, rawrxd_perf_stats* stats) {
    if (!ctx || !stats) return;
    
    memset(stats, 0, sizeof(*stats));
    stats->tokens_generated = ctx->forward_count;
    stats->total_time_sec = ctx->total_forward_time;
    
    if (ctx->forward_count > 0) {
        stats->tokens_per_sec = ctx->forward_count / ctx->total_forward_time;
        stats->ms_per_token = (ctx->total_forward_time / ctx->forward_count) * 1000.0;
    }
}

void rawrxd_reset_perf_stats(rawrxd_context* ctx) {
    if (!ctx) return;
    ctx->forward_count = 0;
    ctx->total_forward_time = 0;
}
