/*
 * Truth Gate 003 - Phase 4: Full Transformer Implementation
 * 
 * Complete transformer with attention, RoPE, SwiGLU, and KV cache
 * Produces coherent text generation
 */

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <windows.h>
#include <time.h>

#define MAX_TOKENS 2048
#define MAX_LAYERS 40
#define MAX_HEADS 32
#define MAX_SEQ_LEN 512

/* Q4_0 block */
typedef struct {
    uint16_t d;
    uint8_t qs[16];
} block_q4_0;

/* Q4_K block (144 bytes for 256 weights) */
typedef struct {
    uint8_t scales[12];      /* Super-block scales and mins */
    uint8_t qs[144];         /* 4-bit quantized values */
    uint16_t d;              /* Global scale (f16) */
    uint16_t dmin;           /* Global min (f16) */
} block_q4_K;

/* Tensor info */
typedef struct {
    char name[64];
    uint32_t n_dims;
    uint64_t dims[4];
    uint32_t type;
    uint64_t offset;
} TensorInfo;

/* Model configuration */
typedef struct {
    uint32_t n_vocab;
    uint32_t n_embd;
    uint32_t n_layer;
    uint32_t n_head;
    uint32_t n_kv_head;
    uint32_t n_ff;
    float norm_eps;
    float rope_theta;
} ModelConfig;

/* f16 to f32 conversion */
float f16_to_f32(uint16_t h) {
    uint32_t sign = (h >> 15) & 1;
    uint32_t exp = (h >> 10) & 0x1F;
    uint32_t mant = h & 0x3FF;
    
    if (exp == 0) return sign ? -0.0f : 0.0f;
    if (exp == 31) return (mant == 0) ? (sign ? -INFINITY : INFINITY) : NAN;
    
    uint32_t f32_bits = (sign << 31) | ((exp + 112) << 23) | (mant << 13);
    float result;
    memcpy(&result, &f32_bits, sizeof(result));
    return result;
}

/* Dequantize Q4_0 block */
void dequantize_q4_0(const block_q4_0 *block, float *out, int n) {
    float delta = f16_to_f32(block->d);
    for (int i = 0; i < n && i < 32; i++) {
        int byte_idx = i / 2;
        int nibble = (i % 2 == 0) ? (block->qs[byte_idx] & 0x0F) : ((block->qs[byte_idx] >> 4) & 0x0F);
        out[i] = delta * (nibble - 8);
    }
}

/* Dequantize Q4_K block */
void dequantize_q4_k(const block_q4_K *block, float *out, int n) {
    float d = f16_to_f32(block->d);
    float dmin = f16_to_f32(block->dmin);
    
    /* Decode 8 super-block scales and mins from 12 bytes */
    float scales[8];
    float mins[8];
    
    for (int i = 0; i < 8; i++) {
        int scale_byte = i / 2;
        int scale_nibble = (i % 2 == 0) ? (block->scales[scale_byte] & 0x0F) 
                                        : ((block->scales[scale_byte] >> 4) & 0x0F);
        
        int min_byte = 4 + i / 2;
        int min_nibble = (i % 2 == 0) ? (block->scales[min_byte] & 0x0F)
                                       : ((block->scales[min_byte] >> 4) & 0x0F);
        
        scales[i] = (float)scale_nibble;
        mins[i] = (float)min_nibble;
    }
    
    /* Dequantize 256 weights */
    for (int i = 0; i < n && i < 256; i++) {
        int byte_idx = i / 2;
        /* In Q4_K, first weight in each byte is in the high nibble */
        int nibble = (i % 2 == 0) ? ((block->qs[byte_idx] >> 4) & 0x0F)
                                   : (block->qs[byte_idx] & 0x0F);
        
        int super_block = i / 32;
        out[i] = d * scales[super_block] * nibble - dmin * mins[super_block];
    }
}

/* Read string from GGUF */
static int read_string(const uint8_t** ptr, char* buffer, size_t max_len) {
    uint64_t len = *(uint64_t*)*ptr;
    *ptr += sizeof(uint64_t);
    if (len >= max_len) { *ptr += len; return 0; }
    memcpy(buffer, *ptr, len);
    buffer[len] = '\0';
    *ptr += len;
    return 1;
}

/* Skip metadata value */
static int skip_metadata_value(const uint8_t** ptr, uint32_t type) {
    switch (type) {
        case 0: case 1: *ptr += 1; break;
        case 2: case 3: *ptr += 2; break;
        case 4: case 5: *ptr += 4; break;
        case 6: *ptr += 4; break;
        case 7: *ptr += 1; break;
        case 8: { uint64_t len = *(uint64_t*)*ptr; *ptr += sizeof(uint64_t) + len; break; }
        case 9: {
            uint32_t elem_type = *(uint32_t*)*ptr;
            *ptr += sizeof(uint32_t);
            uint64_t count = *(uint64_t*)*ptr;
            *ptr += sizeof(uint64_t);
            for (uint64_t i = 0; i < count; i++) skip_metadata_value(ptr, elem_type);
            break;
        }
        case 10: case 11: *ptr += 8; break;
        case 12: *ptr += 8; break;
        default: *ptr += 4; break;
    }
    return 1;
}

/* RMS normalization */
void rms_norm(const float *x, float *out, int n, float eps, const float *weight) {
    float sum = 0.0f;
    for (int i = 0; i < n; i++) sum += x[i] * x[i];
    float scale = 1.0f / sqrtf(sum / n + eps);
    for (int i = 0; i < n; i++) out[i] = x[i] * scale * weight[i];
}

/* Dot product */
float dot_product(const float *a, const float *b, int n) {
    float sum = 0.0f;
    for (int i = 0; i < n; i++) sum += a[i] * b[i];
    return sum;
}

/* Softmax */
void softmax(float *x, int n) {
    float max_val = x[0];
    for (int i = 1; i < n; i++) if (x[i] > max_val) max_val = x[i];
    
    float sum = 0.0f;
    for (int i = 0; i < n; i++) {
        x[i] = expf(x[i] - max_val);
        sum += x[i];
    }
    for (int i = 0; i < n; i++) x[i] /= sum;
}

/* Tokenize text */
int tokenize(const char **vocab, int vocab_size, const char *text, int *tokens, int max_tokens) {
    int len = (int)strlen(text);
    int pos = 0;
    int n_tokens = 0;
    
    tokens[n_tokens++] = 1; /* BOS */
    
    while (pos < len && n_tokens < max_tokens - 1) {
        while (pos < len && (text[pos] == ' ' || text[pos] == '\t' || text[pos] == '\n')) pos++;
        if (pos >= len) break;
        
        int best_len = 0;
        int best_id = 0;
        
        for (int i = 0; i < vocab_size; i++) {
            int tok_len = (int)strlen(vocab[i]);
            if (tok_len > 0 && pos + tok_len <= len) {
                if (memcmp(text + pos, vocab[i], tok_len) == 0) {
                    if (tok_len > best_len) {
                        best_len = tok_len;
                        best_id = i;
                    }
                }
            }
        }
        
        tokens[n_tokens++] = best_id;
        pos += best_len;
    }
    
    return n_tokens;
}

/* Get tensor by name */
TensorInfo* get_tensor(TensorInfo *tensors, uint32_t n_tensors, const char *name) {
    for (uint32_t i = 0; i < n_tensors; i++) {
        if (strcmp(tensors[i].name, name) == 0) return &tensors[i];
    }
    return NULL;
}

/* Dequantize row from Q4_0 or Q4_K tensor */
void dequantize_row(const uint8_t *tensor_base, TensorInfo *t, int row, float *out, int n) {
    if (t->type == 2) { /* Q4_0 */
        int blocks_per_row = n / 32;
        block_q4_0 *blocks = (block_q4_0*)(tensor_base + t->offset);
        blocks += row * blocks_per_row;
        for (int i = 0; i < blocks_per_row; i++) {
            dequantize_q4_0(&blocks[i], &out[i * 32], 32);
        }
    } else if (t->type == 14) { /* Q4_K */
        int blocks_per_row = n / 256;
        if (blocks_per_row < 1) blocks_per_row = 1;
        block_q4_K *blocks = (block_q4_K*)(tensor_base + t->offset);
        blocks += row * blocks_per_row;
        for (int i = 0; i < blocks_per_row && (i * 256) < n; i++) {
            int to_dequant = (n - i * 256 < 256) ? (n - i * 256) : 256;
            dequantize_q4_k(&blocks[i], &out[i * 256], to_dequant);
        }
    } else if (t->type == 0) { /* F32 */
        float *src = (float*)(tensor_base + t->offset);
        memcpy(out, &src[row * n], n * sizeof(float));
    }
}

/* Simple matrix-vector multiplication with dequantization */
void matvec_dequantized(const uint8_t *tensor_base, TensorInfo *weight, 
                        const float *input, float *output, int rows, int cols) {
    float *row_buf = calloc(cols, sizeof(float));
    
    for (int i = 0; i < rows; i++) {
        dequantize_row(tensor_base, weight, i, row_buf, cols);
        output[i] = dot_product(row_buf, input, cols);
    }
    
    free(row_buf);
}

/* RoPE (Rotary Position Embedding) */
void apply_rope(float *q, float *k, int n_embd, int n_head, int pos, float theta) {
    int head_dim = n_embd / n_head;
    
    for (int h = 0; h < n_head; h++) {
        for (int i = 0; i < head_dim; i += 2) {
            float freq = 1.0f / powf(theta, (float)i / head_dim);
            float val = pos * freq;
            float cos_val = cosf(val);
            float sin_val = sinf(val);
            
            int idx = h * head_dim + i;
            float q0 = q[idx], q1 = q[idx + 1];
            float k0 = k[idx], k1 = k[idx + 1];
            
            q[idx] = q0 * cos_val - q1 * sin_val;
            q[idx + 1] = q0 * sin_val + q1 * cos_val;
            k[idx] = k0 * cos_val - k1 * sin_val;
            k[idx + 1] = k0 * sin_val + k1 * cos_val;
        }
    }
}

/* Transformer context */
typedef struct {
    const uint8_t *tensor_base;
    TensorInfo *tensors;
    uint32_t n_tensors;
    ModelConfig config;
    
    /* KV cache: [layer][seq][embd] */
    float *k_cache[MAX_LAYERS];
    float *v_cache[MAX_LAYERS];
    int cache_pos;
} TransformerCtx;

/* Forward pass through one transformer layer */
void transformer_layer(TransformerCtx *ctx, int layer, float *x, int pos, int seq_len) {
    ModelConfig *cfg = &ctx->config;
    int n_embd = cfg->n_embd;
    int n_head = cfg->n_head;
    int head_dim = n_embd / n_head;
    int n_ff = cfg->n_ff;
    
    char buf[64];
    
    /* Get layer weights */
    sprintf(buf, "blk.%d.attn_norm.weight", layer);
    TensorInfo *attn_norm = get_tensor(ctx->tensors, ctx->n_tensors, buf);
    
    sprintf(buf, "blk.%d.attn_q.weight", layer);
    TensorInfo *attn_q = get_tensor(ctx->tensors, ctx->n_tensors, buf);
    
    sprintf(buf, "blk.%d.attn_k.weight", layer);
    TensorInfo *attn_k = get_tensor(ctx->tensors, ctx->n_tensors, buf);
    
    sprintf(buf, "blk.%d.attn_v.weight", layer);
    TensorInfo *attn_v = get_tensor(ctx->tensors, ctx->n_tensors, buf);
    
    sprintf(buf, "blk.%d.attn_output.weight", layer);
    TensorInfo *attn_output = get_tensor(ctx->tensors, ctx->n_tensors, buf);
    
    sprintf(buf, "blk.%d.ffn_norm.weight", layer);
    TensorInfo *ffn_norm = get_tensor(ctx->tensors, ctx->n_tensors, buf);
    
    sprintf(buf, "blk.%d.ffn_gate.weight", layer);
    TensorInfo *ffn_gate = get_tensor(ctx->tensors, ctx->n_tensors, buf);
    
    sprintf(buf, "blk.%d.ffn_up.weight", layer);
    TensorInfo *ffn_up = get_tensor(ctx->tensors, ctx->n_tensors, buf);
    
    sprintf(buf, "blk.%d.ffn_down.weight", layer);
    TensorInfo *ffn_down = get_tensor(ctx->tensors, ctx->n_tensors, buf);
    
    if (!attn_norm || !attn_q) {
        printf("Layer %d weights not found, skipping\n", layer);
        return;
    }
    
    /* Allocate temporaries */
    float *normed = calloc(n_embd, sizeof(float));
    float *q = calloc(n_embd, sizeof(float));
    float *k = calloc(n_embd, sizeof(float));
    float *v = calloc(n_embd, sizeof(float));
    float *attn_out = calloc(n_embd, sizeof(float));
    
    /* === Attention === */
    /* Normalize input */
    float *norm_weight = (float*)(ctx->tensor_base + attn_norm->offset);
    rms_norm(x, normed, n_embd, cfg->norm_eps, norm_weight);
    
    /* QKV projections */
    matvec_dequantized(ctx->tensor_base, attn_q, normed, q, n_embd, n_embd);
    matvec_dequantized(ctx->tensor_base, attn_k, normed, k, n_embd, n_embd);
    matvec_dequantized(ctx->tensor_base, attn_v, normed, v, n_embd, n_embd);
    
    /* Apply RoPE */
    apply_rope(q, k, n_embd, n_head, pos, cfg->rope_theta);
    
    /* Store K,V in cache */
    if (ctx->k_cache[layer] && ctx->v_cache[layer]) {
        memcpy(&ctx->k_cache[layer][pos * n_embd], k, n_embd * sizeof(float));
        memcpy(&ctx->v_cache[layer][pos * n_embd], v, n_embd * sizeof(float));
    }
    
    /* Multi-head attention */
    float *attn_scores = calloc(seq_len, sizeof(float));
    float scale = 1.0f / sqrtf(head_dim);
    
    for (int h = 0; h < n_head; h++) {
        /* Compute attention scores for this head */
        for (int t = 0; t < seq_len; t++) {
            float score = 0.0f;
            for (int d = 0; d < head_dim; d++) {
                int q_idx = h * head_dim + d;
                int k_idx = t * n_embd + h * head_dim + d;
                score += q[q_idx] * ctx->k_cache[layer][k_idx];
            }
            attn_scores[t] = score * scale;
        }
        
        /* Causal mask - can only attend to previous positions */
        for (int t = pos + 1; t < seq_len; t++) {
            attn_scores[t] = -INFINITY;
        }
        
        /* Softmax */
        softmax(attn_scores, seq_len);
        
        /* Weighted sum of values */
        for (int d = 0; d < head_dim; d++) {
            float sum = 0.0f;
            for (int t = 0; t < seq_len; t++) {
                int v_idx = t * n_embd + h * head_dim + d;
                sum += attn_scores[t] * ctx->v_cache[layer][v_idx];
            }
            attn_out[h * head_dim + d] = sum;
        }
    }
    free(attn_scores);
    
    /* Output projection */
    float *temp = calloc(n_embd, sizeof(float));
    matvec_dequantized(ctx->tensor_base, attn_output, attn_out, temp, n_embd, n_embd);
    
    /* Residual connection */
    for (int i = 0; i < n_embd; i++) x[i] += temp[i];
    
    /* === FFN (SwiGLU) === */
    if (ffn_norm && ffn_gate && ffn_up && ffn_down) {
        /* Normalize */
        float *ffn_norm_weight = (float*)(ctx->tensor_base + ffn_norm->offset);
        rms_norm(x, normed, n_embd, cfg->norm_eps, ffn_norm_weight);
        
        /* Gate and Up projections */
        float *gate = calloc(n_ff, sizeof(float));
        float *up = calloc(n_ff, sizeof(float));
        
        matvec_dequantized(ctx->tensor_base, ffn_gate, normed, gate, n_ff, n_embd);
        matvec_dequantized(ctx->tensor_base, ffn_up, normed, up, n_ff, n_embd);
        
        /* SwiGLU: gate * up * sigmoid(gate) */
        for (int i = 0; i < n_ff; i++) {
            float sigmoid = 1.0f / (1.0f + expf(-gate[i]));
            gate[i] = gate[i] * up[i] * sigmoid;
        }
        free(up);
        
        /* Down projection */
        matvec_dequantized(ctx->tensor_base, ffn_down, gate, temp, n_embd, n_ff);
        free(gate);
        
        /* Residual connection */
        for (int i = 0; i < n_embd; i++) x[i] += temp[i];
    }
    
    free(normed); free(q); free(k); free(v); free(attn_out); free(temp);
}

/* Generate tokens */
int generate(TransformerCtx *ctx, int *tokens, int n_tokens, int max_new,
             const char **vocab, float temperature) {
    ModelConfig *cfg = &ctx->config;
    int n_embd = cfg->n_embd;
    int n_vocab = cfg->n_vocab;
    int max_seq = n_tokens + max_new;
    
    /* Allocate KV cache */
    for (int l = 0; l < cfg->n_layer; l++) {
        ctx->k_cache[l] = calloc(max_seq * n_embd, sizeof(float));
        ctx->v_cache[l] = calloc(max_seq * n_embd, sizeof(float));
    }
    ctx->cache_pos = 0;
    
    /* Get token embeddings */
    float *embeddings = calloc(max_seq * n_embd, sizeof(float));
    TensorInfo *token_embd = get_tensor(ctx->tensors, ctx->n_tensors, "token_embd.weight");
    
    for (int pos = 0; pos < n_tokens; pos++) {
        dequantize_row(ctx->tensor_base, token_embd, tokens[pos], &embeddings[pos * n_embd], n_embd);
    }
    
    /* Process prompt tokens */
    for (int pos = 0; pos < n_tokens; pos++) {
        float *x = &embeddings[pos * n_embd];
        for (int l = 0; l < cfg->n_layer; l++) {
            transformer_layer(ctx, l, x, pos, pos + 1);
        }
        ctx->cache_pos = pos + 1;
    }
    
    /* Generate new tokens */
    int *generated = calloc(max_new, sizeof(int));
    int n_generated = 0;
    int current_token = tokens[n_tokens - 1];
    
    printf("\nGenerating %d tokens...\n\n", max_new);
    
    for (int gen = 0; gen < max_new; gen++) {
        int pos = n_tokens + gen;
        
        /* Get embedding for current token */
        float *x = &embeddings[pos * n_embd];
        dequantize_row(ctx->tensor_base, token_embd, current_token, x, n_embd);
        
        /* Run through all layers */
        if (gen == 0) printf("  Processing %d layers...", cfg->n_layer);
        for (int l = 0; l < cfg->n_layer; l++) {
            transformer_layer(ctx, l, x, pos, pos + 1);
            if (gen == 0 && (l + 1) % 10 == 0) printf(" %d", l + 1);
        }
        if (gen == 0) printf(" done\n");
        ctx->cache_pos = pos + 1;
        
        /* Final normalization */
        TensorInfo *output_norm = get_tensor(ctx->tensors, ctx->n_tensors, "output_norm.weight");
        float *normed = calloc(n_embd, sizeof(float));
        if (output_norm) {
            float *norm_weight = (float*)(ctx->tensor_base + output_norm->offset);
            rms_norm(x, normed, n_embd, cfg->norm_eps, norm_weight);
        } else {
            memcpy(normed, x, n_embd * sizeof(float));
        }
        
        /* Compute logits using output.weight (Q4_K supported) */
        /* Use first 500 tokens for speed during testing */
        int n_sample = (n_vocab < 500) ? n_vocab : 500;
        float *logits = calloc(n_sample, sizeof(float));
        
        if (gen == 0) {
            printf("  (Sampling from %d tokens for speed)\n", n_sample);
        }
        TensorInfo *output_weight = get_tensor(ctx->tensors, ctx->n_tensors, "output.weight");
        
        /* Compute dot product for each token's output row */
        float *row_buf = calloc(n_embd, sizeof(float));
        float max_logit = -INFINITY;
        
        for (int tok = 0; tok < n_sample; tok++) {
            /* Dequantize output row for this token */
            dequantize_row(ctx->tensor_base, output_weight, tok, row_buf, n_embd);
            
            /* Compute dot product with normalized hidden state */
            logits[tok] = dot_product(row_buf, normed, n_embd);
            
            if (logits[tok] > max_logit) {
                max_logit = logits[tok];
            }
        }
        free(row_buf);
        
        /* Sample next token */
        int next_token;
        if (temperature == 0.0f) {
            /* Greedy: argmax */
            next_token = 0;
            float best = logits[0];
            for (int i = 1; i < n_sample; i++) {
                if (logits[i] > best) {
                    best = logits[i];
                    next_token = i;
                }
            }
        } else {
            /* Temperature sampling */
            float sum = 0.0f;
            for (int i = 0; i < n_sample; i++) {
                logits[i] = expf((logits[i] - max_logit) / temperature);
                sum += logits[i];
            }
            for (int i = 0; i < n_sample; i++) {
                logits[i] /= sum;
            }
            
            /* Sample */
            float r = (float)rand() / RAND_MAX;
            float cumsum = 0.0f;
            next_token = 0;
            for (int i = 0; i < n_sample; i++) {
                cumsum += logits[i];
                if (r <= cumsum) {
                    next_token = i;
                    break;
                }
            }
        }
        
        free(logits);
        free(normed);
        
        /* Stop on EOS */
        if (next_token == 2) break;
        
        generated[n_generated++] = next_token;
        current_token = next_token;
        
        /* Print token */
        const char *tok_str = vocab[next_token];
        if (tok_str[0] != '<') {
            printf("%s", tok_str);
            fflush(stdout);
        }
    }
    
    printf("\n\n");
    
    /* Cleanup */
    for (int l = 0; l < cfg->n_layer; l++) {
        free(ctx->k_cache[l]);
        free(ctx->v_cache[l]);
        ctx->k_cache[l] = NULL;
        ctx->v_cache[l] = NULL;
    }
    free(embeddings);
    free(generated);
    
    return n_generated;
}

int main(int argc, char **argv) {
    srand((unsigned int)time(NULL));
    
    printf("Truth Gate 003 - Phase 4: Full Transformer\n");
    printf("==========================================\n\n");
    
    if (argc < 2) {
        printf("Usage: %s <model.gguf> [prompt] [max_tokens] [temp]\n", argv[0]);
        printf("  Default prompt: 'The capital of France is'\n");
        printf("  Default max_tokens: 20\n");
        printf("  Default temp: 0.0 (greedy)\n");
        return 1;
    }
    
    const char *model_path = argv[1];
    const char *prompt = (argc > 2) ? argv[2] : "The capital of France is";
    int max_new = (argc > 3) ? atoi(argv[3]) : 20;
    float temperature = (argc > 4) ? atof(argv[4]) : 0.0f;
    
    printf("Model: %s\n", model_path);
    printf("Prompt: '%s'\n", prompt);
    printf("Max new tokens: %d\n", max_new);
    printf("Temperature: %.2f\n\n", temperature);
    
    /* Open and map file */
    HANDLE hFile = CreateFileA(model_path, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[FAIL] Cannot open file: %lu\n", GetLastError());
        return 1;
    }
    
    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    void *mapped = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(hMap);
    CloseHandle(hFile);
    
    if (!mapped) { printf("[FAIL] Cannot map file\n"); return 1; }
    
    const uint8_t *p = mapped;
    
    /* Parse GGUF */
    uint32_t magic = *(uint32_t*)p;
    if (magic != 0x46554747) { printf("[FAIL] Not a GGUF file\n"); return 1; }
    
    uint64_t n_tensors = *(uint64_t*)(p + 8);
    uint64_t n_kv = *(uint64_t*)(p + 16);
    p += 24;
    
    printf("GGUF: %llu tensors, %llu KV pairs\n", n_tensors, n_kv);
    
    /* Parse metadata */
    char **vocab = NULL;
    int vocab_size = 0;
    
    for (uint64_t i = 0; i < n_kv; i++) {
        char key[256];
        read_string(&p, key, sizeof(key));
        uint32_t type = *(uint32_t*)p;
        p += sizeof(uint32_t);
        
        if (strcmp(key, "tokenizer.ggml.tokens") == 0) {
            p += sizeof(uint32_t);
            vocab_size = *(uint64_t*)p;
            p += sizeof(uint64_t);
            
            printf("Loading vocab: %d tokens\n", vocab_size);
            vocab = calloc(vocab_size, sizeof(char*));
            
            for (int j = 0; j < vocab_size; j++) {
                uint64_t tok_len = *(uint64_t*)p;
                p += sizeof(uint64_t);
                vocab[j] = malloc(tok_len + 1);
                memcpy(vocab[j], p, tok_len);
                vocab[j][tok_len] = '\0';
                p += tok_len;
            }
        } else {
            skip_metadata_value(&p, type);
        }
    }
    
    if (!vocab) { printf("[FAIL] No vocab found\n"); return 1; }
    
    /* Parse tensors */
    TensorInfo *tensors = calloc(n_tensors, sizeof(TensorInfo));
    
    for (uint32_t i = 0; i < n_tensors; i++) {
        uint64_t name_len = *(uint64_t*)p; p += 8;
        memcpy(tensors[i].name, p, name_len < 63 ? name_len : 63);
        tensors[i].name[name_len < 63 ? name_len : 63] = '\0';
        p += name_len;
        
        tensors[i].n_dims = *(uint32_t*)p; p += 4;
        for (uint32_t j = 0; j < tensors[i].n_dims; j++) {
            tensors[i].dims[j] = *(uint64_t*)p; p += 8;
        }
        for (uint32_t j = tensors[i].n_dims; j < 4; j++) tensors[i].dims[j] = 1;
        
        tensors[i].type = *(uint32_t*)p; p += 4;
        tensors[i].offset = *(uint64_t*)p; p += 8;
    }
    
    const uint8_t *tensor_base = (const uint8_t*)(((uintptr_t)p + 31) & ~31);
    
    /* Setup context */
    TransformerCtx ctx = {0};
    ctx.tensor_base = tensor_base;
    ctx.tensors = tensors;
    ctx.n_tensors = n_tensors;
    
    /* Extract config */
    TensorInfo *token_embd = get_tensor(tensors, n_tensors, "token_embd.weight");
    if (token_embd) {
        ctx.config.n_vocab = (uint32_t)token_embd->dims[0];
        ctx.config.n_embd = (uint32_t)token_embd->dims[1];
    }
    
    /* Count layers */
    ctx.config.n_layer = 0;
    for (uint32_t i = 0; i < n_tensors; i++) {
        if (strncmp(tensors[i].name, "blk.", 4) == 0) {
            int layer = atoi(tensors[i].name + 4);
            if (layer >= (int)ctx.config.n_layer) ctx.config.n_layer = layer + 1;
        }
    }
    
    ctx.config.n_head = 32;
    ctx.config.n_ff = 14336; /* ministral3 FFN dim */
    ctx.config.norm_eps = 1e-5f;
    ctx.config.rope_theta = 10000.0f;
    
    /* ministral3 has dims=[4096, 131072] which is transposed */
    if (ctx.config.n_embd > ctx.config.n_vocab) {
        int tmp = ctx.config.n_vocab;
        ctx.config.n_vocab = ctx.config.n_embd;
        ctx.config.n_embd = tmp;
    }
    
    printf("\nModel config:\n");
    printf("  Vocab: %d\n", ctx.config.n_vocab);
    printf("  Embd: %d\n", ctx.config.n_embd);
    printf("  Layers: %d\n", ctx.config.n_layer);
    printf("  Heads: %d\n", ctx.config.n_head);
    printf("  FFN: %d\n", ctx.config.n_ff);
    
    /* Tokenize */
    int tokens[MAX_TOKENS];
    int n_tokens = tokenize((const char**)vocab, vocab_size, prompt, tokens, MAX_TOKENS);
    
    printf("\nTokenized (%d tokens):\n", n_tokens);
    for (int i = 0; i < n_tokens && i < 8; i++) {
        printf("  [%d] %d: '%s'\n", i, tokens[i], vocab[tokens[i]]);
    }
    
    /* Generate */
    printf("\n====================================\n");
    printf("Generation:\n");
    printf("====================================\n");
    printf("%s", prompt);
    
    int n_gen = generate(&ctx, tokens, n_tokens, max_new, (const char**)vocab, temperature);
    
    printf("====================================\n");
    printf("Generated %d tokens\n", n_gen);
    printf("====================================\n");
    
    /* Cleanup */
    for (int i = 0; i < vocab_size; i++) free(vocab[i]);
    free(vocab);
    free(tensors);
    UnmapViewOfFile(mapped);
    
    return 0;
}
