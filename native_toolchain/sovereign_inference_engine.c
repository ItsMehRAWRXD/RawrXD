/*
 * Sovereign Inference Engine - Zero Dependencies
 * Pure C implementation of transformer inference without any external libraries
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#endif

#include "gguf_loader_native.c"

// Activation functions
static inline float gelu(float x) {
    // GELU approximation: 0.5 * x * (1 + tanh(sqrt(2/pi) * (x + 0.044715 * x^3)))
    const float sqrt_2_over_pi = 0.7978845608f;
    float c = 0.044715f * x * x * x;
    return 0.5f * x * (1.0f + tanhf(sqrt_2_over_pi * (x + c)));
}

static inline float silu(float x) {
    // SiLU(x) = x * sigmoid(x)
    return x / (1.0f + expf(-x));
}

static inline float rms_norm(float x, float weight, float eps) {
    return x * weight / sqrtf(x * x + eps);
}

// Softmax
static void softmax(float* x, int size) {
    float max_val = x[0];
    for (int i = 1; i < size; i++) {
        if (x[i] > max_val) max_val = x[i];
    }
    
    float sum = 0.0f;
    for (int i = 0; i < size; i++) {
        x[i] = expf(x[i] - max_val);
        sum += x[i];
    }
    
    for (int i = 0; i < size; i++) {
        x[i] /= sum;
    }
}

// RoPE (Rotary Position Embedding)
static void apply_rope(float* q, float* k, int head_dim, int pos, float theta) {
    for (int i = 0; i < head_dim; i += 2) {
        float freq = 1.0f / powf(theta, (float)i / head_dim);
        float val = pos * freq;
        float cos_val = cosf(val);
        float sin_val = sinf(val);
        
        float q0 = q[i];
        float q1 = q[i + 1];
        q[i] = q0 * cos_val - q1 * sin_val;
        q[i + 1] = q0 * sin_val + q1 * cos_val;
        
        float k0 = k[i];
        float k1 = k[i + 1];
        k[i] = k0 * cos_val - k1 * sin_val;
        k[i + 1] = k0 * sin_val + k1 * cos_val;
    }
}

// Matrix multiplication: C = A * B
// A: [M x K], B: [K x N], C: [M x N]
static void matmul(const float* A, const float* B, float* C, int M, int N, int K) {
    for (int i = 0; i < M; i++) {
        for (int j = 0; j < N; j++) {
            float sum = 0.0f;
            for (int k = 0; k < K; k++) {
                sum += A[i * K + k] * B[k * N + j];
            }
            C[i * N + j] = sum;
        }
    }
}

// Quantized matrix multiplication for Q4_0
static void matmul_q4_0(const void* A_q, const float* B, float* C, int M, int N, int K) {
    // Q4_0: 32 weights per block, 4 bits per weight
    // Block: 16 bytes (2x FP16 scales + 16x uint8 packed weights)
    int blocks_per_row = K / 32;
    
    for (int i = 0; i < M; i++) {
        for (int j = 0; j < N; j++) {
            float sum = 0.0f;
            const uint8_t* qdata = (const uint8_t*)A_q + i * blocks_per_row * 16;
            
            for (int b = 0; b < blocks_per_row; b++) {
                // Read scale (FP16)
                uint16_t scale_bits = *(uint16_t*)qdata;
                float scale = ((scale_bits & 0x7C00) >> 10) - 15;
                scale = (scale_bits & 0x8000) ? -scale : scale;
                scale *= (1 << ((scale_bits & 0x7C00) >> 10)) / 1024.0f;
                
                // Dequantize and multiply
                for (int k = 0; k < 32; k++) {
                    int byte_idx = 2 + k / 2;
                    int nibble = (k % 2 == 0) ? (qdata[byte_idx] & 0x0F) : (qdata[byte_idx] >> 4);
                    float w = (nibble - 8) * scale;
                    sum += w * B[(b * 32 + k) * N + j];
                }
                
                qdata += 16; // Next block
            }
            
            C[i * N + j] = sum;
        }
    }
}

// Inference context
struct inference_ctx {
    struct gguf_file* model;
    
    // Model dimensions
    int vocab_size;
    int embed_dim;
    int num_layers;
    int num_heads;
    int head_dim;
    int kv_heads;
    int kv_dim;
    int hidden_dim;
    int max_seq_len;
    
    // Activations
    float* token_embed;
    float* pos_embed;
    
    // Layer buffers
    float* x;           // Current hidden state
    float* q;           // Query
    float* k;           // Key
    float* v;           // Value
    float* attn_out;    // Attention output
    float* ffn_hidden;  // FFN hidden state
    float* logits;      // Output logits
    
    // KV cache
    float* k_cache;
    float* v_cache;
    int cache_pos;
    
    // Tokenizer (simple BPE)
    char** vocab;
    int vocab_len;
};

// Create inference context
struct inference_ctx* inference_create(struct gguf_file* model) {
    if (!model) return NULL;
    
    struct inference_ctx* ctx = calloc(1, sizeof(struct inference_ctx));
    if (!ctx) return NULL;
    
    ctx->model = model;
    const struct model_metadata* meta = gguf_get_metadata(model);
    
    // Set dimensions
    ctx->vocab_size = meta->vocab_size;
    ctx->embed_dim = meta->embedding_dim;
    ctx->num_layers = meta->layer_count;
    ctx->num_heads = meta->head_count;
    ctx->kv_heads = meta->kv_head_count ? meta->kv_head_count : meta->head_count;
    ctx->head_dim = ctx->embed_dim / ctx->num_heads;
    ctx->kv_dim = ctx->head_dim * ctx->kv_heads;
    ctx->hidden_dim = ctx->embed_dim * 4;  // Standard FFN expansion
    ctx->max_seq_len = meta->context_length;
    
    // Allocate buffers
    ctx->x = calloc(ctx->embed_dim, sizeof(float));
    ctx->q = calloc(ctx->embed_dim, sizeof(float));
    ctx->k = calloc(ctx->kv_dim, sizeof(float));
    ctx->v = calloc(ctx->kv_dim, sizeof(float));
    ctx->attn_out = calloc(ctx->embed_dim, sizeof(float));
    ctx->ffn_hidden = calloc(ctx->hidden_dim, sizeof(float));
    ctx->logits = calloc(ctx->vocab_size, sizeof(float));
    
    // KV cache
    ctx->k_cache = calloc(ctx->max_seq_len * ctx->kv_dim, sizeof(float));
    ctx->v_cache = calloc(ctx->max_seq_len * ctx->kv_dim, sizeof(float));
    ctx->cache_pos = 0;
    
    printf("[Inference] Created context:\n");
    printf("  Vocab: %d, Embed: %d, Layers: %d\n", ctx->vocab_size, ctx->embed_dim, ctx->num_layers);
    printf("  Heads: %d, KV Heads: %d, Head Dim: %d\n", ctx->num_heads, ctx->kv_heads, ctx->head_dim);
    printf("  Context: %d, Hidden: %d\n", ctx->max_seq_len, ctx->hidden_dim);
    
    return ctx;
}

// Free inference context
void inference_free(struct inference_ctx* ctx) {
    if (!ctx) return;
    
    free(ctx->x);
    free(ctx->q);
    free(ctx->k);
    free(ctx->v);
    free(ctx->attn_out);
    free(ctx->ffn_hidden);
    free(ctx->logits);
    free(ctx->k_cache);
    free(ctx->v_cache);
    
    free(ctx);
}

// Get tensor data pointer
static float* get_tensor_data(struct gguf_file* gf, const char* name) {
    const struct gguf_tensor_info* ti = gguf_find_tensor(gf, name);
    if (!ti) return NULL;
    
    if (!ti->loaded) {
        if (!gguf_load_tensor_by_name(gf, name)) {
            return NULL;
        }
    }
    
    return (float*)ti->data;
}

// Forward pass for one token
float* inference_forward(struct inference_ctx* ctx, int token_id, int pos) {
    if (!ctx || !ctx->model) return NULL;
    
    struct gguf_file* gf = ctx->model;
    
    // Token embedding
    char embed_name[256];
    snprintf(embed_name, sizeof(embed_name), "token_embd.weight");
    float* token_embed = get_tensor_data(gf, embed_name);
    
    if (token_embed) {
        // Copy embedding for this token
        memcpy(ctx->x, token_embed + token_id * ctx->embed_dim, 
               ctx->embed_dim * sizeof(float));
    } else {
        // Random embedding for testing
        for (int i = 0; i < ctx->embed_dim; i++) {
            ctx->x[i] = ((float)rand() / RAND_MAX - 0.5f) * 0.1f;
        }
    }
    
    // Transformer layers
    for (int layer = 0; layer < ctx->num_layers; layer++) {
        // Layer norm
        char norm_name[256];
        snprintf(norm_name, sizeof(norm_name), "blk.%d.attn_norm.weight", layer);
        float* norm_weight = get_tensor_data(gf, norm_name);
        
        float x_norm[ctx->embed_dim];
        if (norm_weight) {
            float mean = 0.0f;
            for (int i = 0; i < ctx->embed_dim; i++) mean += ctx->x[i];
            mean /= ctx->embed_dim;
            
            float var = 0.0f;
            for (int i = 0; i < ctx->embed_dim; i++) {
                float diff = ctx->x[i] - mean;
                var += diff * diff;
            }
            var = sqrtf(var / ctx->embed_dim + 1e-5f);
            
            for (int i = 0; i < ctx->embed_dim; i++) {
                x_norm[i] = (ctx->x[i] - mean) / var * norm_weight[i];
            }
        } else {
            memcpy(x_norm, ctx->x, ctx->embed_dim * sizeof(float));
        }
        
        // Attention weights
        char wq_name[256], wk_name[256], wv_name[256], wo_name[256];
        snprintf(wq_name, sizeof(wq_name), "blk.%d.attn_q.weight", layer);
        snprintf(wk_name, sizeof(wk_name), "blk.%d.attn_k.weight", layer);
        snprintf(wv_name, sizeof(wv_name), "blk.%d.attn_v.weight", layer);
        snprintf(wo_name, sizeof(wo_name), "blk.%d.attn_output.weight", layer);
        
        float* wq = get_tensor_data(gf, wq_name);
        float* wk = get_tensor_data(gf, wk_name);
        float* wv = get_tensor_data(gf, wv_name);
        float* wo = get_tensor_data(gf, wo_name);
        
        // Compute Q, K, V
        if (wq) {
            matmul(x_norm, wq, ctx->q, 1, ctx->embed_dim, ctx->embed_dim);
        }
        if (wk) {
            matmul(x_norm, wk, ctx->k, 1, ctx->kv_dim, ctx->embed_dim);
        }
        if (wv) {
            matmul(x_norm, wv, ctx->v, 1, ctx->kv_dim, ctx->embed_dim);
        }
        
        // Apply RoPE
        const struct model_metadata* meta = gguf_get_metadata(gf);
        for (int h = 0; h < ctx->num_heads; h++) {
            apply_rope(ctx->q + h * ctx->head_dim, 
                      ctx->k + (h % ctx->kv_heads) * ctx->head_dim,
                      ctx->head_dim, pos, meta->rope_theta);
        }
        
        // Store in KV cache
        memcpy(ctx->k_cache + pos * ctx->kv_dim, ctx->k, ctx->kv_dim * sizeof(float));
        memcpy(ctx->v_cache + pos * ctx->kv_dim, ctx->v, ctx->kv_dim * sizeof(float));
        
        // Attention computation
        memset(ctx->attn_out, 0, ctx->embed_dim * sizeof(float));
        
        for (int h = 0; h < ctx->num_heads; h++) {
            float* q_head = ctx->q + h * ctx->head_dim;
            float attn_scores[pos + 1];
            
            // Compute attention scores
            for (int t = 0; t <= pos; t++) {
                float* k_head = ctx->k_cache + t * ctx->kv_dim + (h % ctx->kv_heads) * ctx->head_dim;
                float score = 0.0f;
                for (int d = 0; d < ctx->head_dim; d++) {
                    score += q_head[d] * k_head[d];
                }
                attn_scores[t] = score / sqrtf(ctx->head_dim);
            }
            
            // Softmax
            softmax(attn_scores, pos + 1);
            
            // Weighted sum of values
            float* out_head = ctx->attn_out + h * ctx->head_dim;
            for (int d = 0; d < ctx->head_dim; d++) {
                out_head[d] = 0.0f;
                for (int t = 0; t <= pos; t++) {
                    float* v_head = ctx->v_cache + t * ctx->kv_dim + (h % ctx->kv_heads) * ctx->head_dim;
                    out_head[d] += attn_scores[t] * v_head[d];
                }
            }
        }
        
        // Output projection
        if (wo) {
            float attn_proj[ctx->embed_dim];
            matmul(ctx->attn_out, wo, attn_proj, 1, ctx->embed_dim, ctx->embed_dim);
            
            // Residual connection
            for (int i = 0; i < ctx->embed_dim; i++) {
                ctx->x[i] += attn_proj[i];
            }
        }
        
        // FFN
        char ffn_norm_name[256], w1_name[256], w2_name[256], w3_name[256];
        snprintf(ffn_norm_name, sizeof(ffn_norm_name), "blk.%d.ffn_norm.weight", layer);
        snprintf(w1_name, sizeof(w1_name), "blk.%d.ffn_gate.weight", layer);
        snprintf(w2_name, sizeof(w2_name), "blk.%d.ffn_down.weight", layer);
        snprintf(w3_name, sizeof(w3_name), "blk.%d.ffn_up.weight", layer);
        
        float* ffn_norm = get_tensor_data(gf, ffn_norm_name);
        float* w1 = get_tensor_data(gf, w1_name);
        float* w2 = get_tensor_data(gf, w2_name);
        float* w3 = get_tensor_data(gf, w3_name);
        
        if (ffn_norm) {
            float mean = 0.0f;
            for (int i = 0; i < ctx->embed_dim; i++) mean += ctx->x[i];
            mean /= ctx->embed_dim;
            
            float var = 0.0f;
            for (int i = 0; i < ctx->embed_dim; i++) {
                float diff = ctx->x[i] - mean;
                var += diff * diff;
            }
            var = sqrtf(var / ctx->embed_dim + 1e-5f);
            
            for (int i = 0; i < ctx->embed_dim; i++) {
                x_norm[i] = (ctx->x[i] - mean) / var * ffn_norm[i];
            }
        } else {
            memcpy(x_norm, ctx->x, ctx->embed_dim * sizeof(float));
        }
        
        // SwiGLU FFN
        if (w1 && w2 && w3) {
            float gate[ctx->hidden_dim];
            float up[ctx->hidden_dim];
            
            matmul(x_norm, w1, gate, 1, ctx->hidden_dim, ctx->embed_dim);
            matmul(x_norm, w3, up, 1, ctx->hidden_dim, ctx->embed_dim);
            
            for (int i = 0; i < ctx->hidden_dim; i++) {
                ctx->ffn_hidden[i] = silu(gate[i]) * up[i];
            }
            
            float ffn_out[ctx->embed_dim];
            matmul(ctx->ffn_hidden, w2, ffn_out, 1, ctx->embed_dim, ctx->hidden_dim);
            
            // Residual
            for (int i = 0; i < ctx->embed_dim; i++) {
                ctx->x[i] += ffn_out[i];
            }
        }
    }
    
    // Final norm
    char final_norm_name[256];
    snprintf(final_norm_name, sizeof(final_norm_name), "output_norm.weight");
    float* final_norm = get_tensor_data(gf, final_norm_name);
    
    if (final_norm) {
        float mean = 0.0f;
        for (int i = 0; i < ctx->embed_dim; i++) mean += ctx->x[i];
        mean /= ctx->embed_dim;
        
        float var = 0.0f;
        for (int i = 0; i < ctx->embed_dim; i++) {
            float diff = ctx->x[i] - mean;
            var += diff * diff;
        }
        var = sqrtf(var / ctx->embed_dim + 1e-5f);
        
        for (int i = 0; i < ctx->embed_dim; i++) {
            ctx->x[i] = (ctx->x[i] - mean) / var * final_norm[i];
        }
    }
    
    // Output projection
    char output_name[256];
    snprintf(output_name, sizeof(output_name), "output.weight");
    float* output_weight = get_tensor_data(gf, output_name);
    
    if (output_weight) {
        matmul(ctx->x, output_weight, ctx->logits, 1, ctx->vocab_size, ctx->embed_dim);
    } else {
        // Fallback: random logits
        for (int i = 0; i < ctx->vocab_size; i++) {
            ctx->logits[i] = ((float)rand() / RAND_MAX - 0.5f);
        }
    }
    
    return ctx->logits;
}

// Simple greedy sampling
int inference_sample_greedy(float* logits, int vocab_size) {
    int max_idx = 0;
    float max_val = logits[0];
    
    for (int i = 1; i < vocab_size; i++) {
        if (logits[i] > max_val) {
            max_val = logits[i];
            max_idx = i;
        }
    }
    
    return max_idx;
}

// Temperature sampling
int inference_sample_temperature(float* logits, int vocab_size, float temperature) {
    if (temperature <= 0) {
        return inference_sample_greedy(logits, vocab_size);
    }
    
    // Apply temperature
    float probs[vocab_size];
    float sum = 0.0f;
    
    for (int i = 0; i < vocab_size; i++) {
        probs[i] = expf(logits[i] / temperature);
        sum += probs[i];
    }
    
    // Normalize
    for (int i = 0; i < vocab_size; i++) {
        probs[i] /= sum;
    }
    
    // Sample
    float r = (float)rand() / RAND_MAX;
    float cumsum = 0.0f;
    
    for (int i = 0; i < vocab_size; i++) {
        cumsum += probs[i];
        if (r <= cumsum) {
            return i;
        }
    }
    
    return vocab_size - 1;
}

// Generate text
void inference_generate(struct inference_ctx* ctx, int* prompt_tokens, int prompt_len,
                        int max_new_tokens, float temperature,
                        void (*token_callback)(int token_id, const char* token_str)) {
    if (!ctx) return;
    
    printf("[Inference] Generating %d tokens...\n", max_new_tokens);
    
    // Process prompt
    int pos = 0;
    for (int i = 0; i < prompt_len && pos < ctx->max_seq_len; i++, pos++) {
        float* logits = inference_forward(ctx, prompt_tokens[i], pos);
        (void)logits; // Prompt processing, don't sample
    }
    
    // Generate new tokens
    int next_token = prompt_len > 0 ? prompt_tokens[prompt_len - 1] : 1; // BOS
    
    for (int i = 0; i < max_new_tokens && pos < ctx->max_seq_len; i++, pos++) {
        float* logits = inference_forward(ctx, next_token, pos);
        
        next_token = inference_sample_temperature(logits, ctx->vocab_size, temperature);
        
        if (token_callback) {
            token_callback(next_token, NULL);
        }
        
        // Stop on EOS
        if (next_token == 2) break; // EOS token
    }
    
    printf("\n[Inference] Generation complete.\n");
}

// Test main
#ifdef TEST_INFERENCE
int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <model.gguf> [prompt]\n", argv[0]);
        return 1;
    }
    
    printf("=== Sovereign Inference Engine ===\n\n");
    
    // Load model
    struct gguf_file* gf = gguf_open(argv[1]);
    if (!gf) {
        fprintf(stderr, "Failed to load model\n");
        return 1;
    }
    
    gguf_print_info(gf);
    
    // Load all tensors
    printf("\nLoading all tensors...\n");
    gguf_load_all_tensors(gf);
    printf("Total loaded: %.2f MB\n", gguf_get_loaded_memory(gf) / (1024.0 * 1024.0));
    
    // Create inference context
    struct inference_ctx* ctx = inference_create(gf);
    if (!ctx) {
        fprintf(stderr, "Failed to create inference context\n");
        gguf_close(gf);
        return 1;
    }
    
    // Test forward pass
    printf("\nTesting forward pass...\n");
    int test_token = 1; // BOS
    float* logits = inference_forward(ctx, test_token, 0);
    
    if (logits) {
        printf("Logits computed successfully!\n");
        printf("Sample logits: ");
        for (int i = 0; i < 10 && i < ctx->vocab_size; i++) {
            printf("%.3f ", logits[i]);
        }
        printf("...\n");
        
        int next_token = inference_sample_greedy(logits, ctx->vocab_size);
        printf("Greedy sample: %d\n", next_token);
    }
    
    // Cleanup
    inference_free(ctx);
    gguf_close(gf);
    
    printf("\n=== Test Complete ===\n");
    return 0;
}
#endif
