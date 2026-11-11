/*
 * Truth Gate 003 - Layer 0 Validation Test
 * 
 * Tests just the first transformer layer to validate:
 * - Embedding lookup
 * - RMSNorm
 * - QKV projections
 * - RoPE
 * - Attention
 * - Output
 */

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <windows.h>

#define MAX_TOKENS 512
#define MAX_LAYERS 40

/* Q4_0 block */
typedef struct {
    uint16_t d;
    uint8_t qs[16];
} block_q4_0;

/* Q4_K block */
typedef struct {
    uint8_t scales[12];
    uint8_t qs[144];
    uint16_t d;
    uint16_t dmin;
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

void dequantize_q4_0(const block_q4_0 *block, float *out, int n) {
    float delta = f16_to_f32(block->d);
    for (int i = 0; i < n && i < 32; i++) {
        int byte_idx = i / 2;
        int nibble = (i % 2 == 0) ? (block->qs[byte_idx] & 0x0F) : ((block->qs[byte_idx] >> 4) & 0x0F);
        out[i] = delta * (nibble - 8);
    }
}

void dequantize_q4_k(const block_q4_K *block, float *out, int n) {
    float d = f16_to_f32(block->d);
    float dmin = f16_to_f32(block->dmin);
    
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
    
    for (int i = 0; i < n && i < 256; i++) {
        int byte_idx = i / 2;
        int nibble = (i % 2 == 0) ? (block->qs[byte_idx] & 0x0F)
                                   : ((block->qs[byte_idx] >> 4) & 0x0F);
        int super_block = i / 32;
        out[i] = d * scales[super_block] * nibble - dmin * mins[super_block];
    }
}

static int read_string(const uint8_t** ptr, char* buffer, size_t max_len) {
    uint64_t len = *(uint64_t*)*ptr;
    *ptr += sizeof(uint64_t);
    if (len >= max_len) { *ptr += len; return 0; }
    memcpy(buffer, *ptr, len);
    buffer[len] = '\0';
    *ptr += len;
    return 1;
}

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

void rms_norm(const float *x, float *out, int n, float eps, const float *weight) {
    float sum_sq = 0.0f;
    for (int i = 0; i < n; i++) sum_sq += x[i] * x[i];
    float rms = sqrtf(sum_sq / n + eps);
    float scale = 1.0f / rms;
    for (int i = 0; i < n; i++) out[i] = x[i] * scale * weight[i];
}

float dot_product(const float *a, const float *b, int n) {
    float sum = 0.0f;
    for (int i = 0; i < n; i++) sum += a[i] * b[i];
    return sum;
}

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

TensorInfo* get_tensor(TensorInfo *tensors, uint32_t n_tensors, const char *name) {
    for (uint32_t i = 0; i < n_tensors; i++) {
        if (strcmp(tensors[i].name, name) == 0) return &tensors[i];
    }
    return NULL;
}

void dequantize_row(const uint8_t *tensor_base, TensorInfo *t, int row, float *out, int n) {
    if (t->type == 2) {
        int blocks_per_row = n / 32;
        block_q4_0 *blocks = (block_q4_0*)(tensor_base + t->offset);
        blocks += row * blocks_per_row;
        for (int i = 0; i < blocks_per_row; i++) {
            dequantize_q4_0(&blocks[i], &out[i * 32], 32);
        }
    } else if (t->type == 14) {
        int blocks_per_row = n / 256;
        if (blocks_per_row < 1) blocks_per_row = 1;
        block_q4_K *blocks = (block_q4_K*)(tensor_base + t->offset);
        blocks += row * blocks_per_row;
        for (int i = 0; i < blocks_per_row && (i * 256) < n; i++) {
            int to_dequant = (n - i * 256 < 256) ? (n - i * 256) : 256;
            dequantize_q4_k(&blocks[i], &out[i * 256], to_dequant);
        }
    } else if (t->type == 0) {
        float *src = (float*)(tensor_base + t->offset);
        memcpy(out, &src[row * n], n * sizeof(float));
    }
}

void matvec_dequantized(const uint8_t *tensor_base, TensorInfo *weight, 
                        const float *input, float *output, int rows, int cols) {
    float *row_buf = calloc(cols, sizeof(float));
    for (int i = 0; i < rows; i++) {
        dequantize_row(tensor_base, weight, i, row_buf, cols);
        output[i] = dot_product(row_buf, input, cols);
    }
    free(row_buf);
}

void apply_rope(float *q, float *k, int n_embd, int n_head, int pos, float theta) {
    int head_dim = n_embd / n_head;
    for (int h = 0; h < n_head; h++) {
        for (int i = 0; i < head_dim; i += 2) {
            float inv_freq = powf(theta, -2.0f * i / head_dim);
            float val = pos * inv_freq;
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

int main(int argc, char **argv) {
    printf("Truth Gate 003 - Layer 0 Validation Test\n");
    printf("=========================================\n\n");
    
    if (argc < 2) {
        printf("Usage: %s <model.gguf>\n", argv[0]);
        return 1;
    }
    
    const char *model_path = argv[1];
    
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
    ModelConfig config = {0};
    
    for (uint64_t i = 0; i < n_kv; i++) {
        char key[256];
        if (!read_string(&p, key, sizeof(key))) continue;
        uint32_t type = *(uint32_t*)p; p += 4;
        
        if (strcmp(key, "tokenizer.ggml.tokens") == 0 && type == 9) {
            uint32_t elem_type = *(uint32_t*)p; p += 4;
            uint64_t count = *(uint64_t*)p; p += 8;
            vocab = calloc(count, sizeof(char*));
            vocab_size = (int)count;
            for (uint64_t j = 0; j < count; j++) {
                char tok[256];
                if (read_string(&p, tok, sizeof(tok))) {
                    vocab[j] = strdup(tok);
                }
            }
        }
        else if (strcmp(key, "llama.vocab_size") == 0 && type == 4) {
            config.n_vocab = *(uint32_t*)p; p += 4;
        }
        else if (strcmp(key, "llama.embedding_length") == 0 && type == 4) {
            config.n_embd = *(uint32_t*)p; p += 4;
        }
        else if (strcmp(key, "llama.block_count") == 0 && type == 4) {
            config.n_layer = *(uint32_t*)p; p += 4;
        }
        else if (strcmp(key, "llama.attention.head_count") == 0 && type == 4) {
            config.n_head = *(uint32_t*)p; p += 4;
        }
        else if (strcmp(key, "llama.attention.head_count_kv") == 0 && type == 4) {
            config.n_kv_head = *(uint32_t*)p; p += 4;
        }
        else if (strcmp(key, "llama.feed_forward_length") == 0 && type == 4) {
            config.n_ff = *(uint32_t*)p; p += 4;
        }
        else if (strcmp(key, "llama.attention.layer_norm_rms_epsilon") == 0 && type == 6) {
            config.norm_eps = *(float*)p; p += 4;
        }
        else if (strcmp(key, "llama.rope.freq_base") == 0 && type == 6) {
            config.rope_theta = *(float*)p; p += 4;
        }
        else {
            skip_metadata_value(&p, type);
        }
    }
    
    if (config.n_vocab == 0) config.n_vocab = 32000;
    if (config.n_embd == 0) config.n_embd = 4096;
    if (config.n_layer == 0) config.n_layer = 32;
    if (config.n_head == 0) config.n_head = 32;
    if (config.n_kv_head == 0) config.n_kv_head = config.n_head;
    if (config.n_ff == 0) config.n_ff = 14336;
    if (config.norm_eps == 0.0f) config.norm_eps = 1e-5f;
    if (config.rope_theta == 0.0f) config.rope_theta = 10000.0f;
    
    printf("\nModel config:\n");
    printf("  Vocab: %d\n", config.n_vocab);
    printf("  Embd: %d\n", config.n_embd);
    printf("  Layers: %d\n", config.n_layer);
    printf("  Heads: %d\n", config.n_head);
    printf("  KV Heads: %d\n", config.n_kv_head);
    printf("  FFN: %d\n", config.n_ff);
    printf("  Norm eps: %.2e\n", config.norm_eps);
    printf("  RoPE theta: %.2f\n\n", config.rope_theta);
    
    /* Parse tensors - CORRECT GGUF format:
     * - name (string)
     * - n_dimensions (uint32)
     * - dimensions (uint64[n_dimensions])
     * - type (uint32)
     * - offset (uint64)
     */
    printf("Parsing %llu tensors...\n", n_tensors);
    TensorInfo *tensors = calloc(n_tensors, sizeof(TensorInfo));
    for (uint64_t i = 0; i < n_tensors; i++) {
        /* Read name */
        uint64_t name_len = *(uint64_t*)p; p += 8;
        if (name_len >= sizeof(tensors[i].name)) name_len = sizeof(tensors[i].name) - 1;
        memcpy(tensors[i].name, p, name_len);
        tensors[i].name[name_len] = '\0';
        p += name_len;
        
        /* Read dimensions */
        uint32_t n_dims = *(uint32_t*)p; p += 4;
        tensors[i].n_dims = n_dims;
        for (uint32_t j = 0; j < n_dims && j < 4; j++) {
            tensors[i].dims[j] = *(uint64_t*)p; p += 8;
        }
        for (uint32_t j = n_dims; j < 4; j++) {
            tensors[i].dims[j] = 1;
        }
        
        /* Read type and offset */
        tensors[i].type = *(uint32_t*)p; p += 4;
        tensors[i].offset = *(uint64_t*)p; p += 8;
        
        if (i < 5 || strstr(tensors[i].name, "blk.0.attn")) {
            printf("  Tensor %llu: '%s' type=%u dims=[%llu, %llu, %llu, %llu] offset=%llu\n",
                   i, tensors[i].name, tensors[i].type,
                   tensors[i].dims[0], tensors[i].dims[1],
                   tensors[i].dims[2], tensors[i].dims[3],
                   tensors[i].offset);
        }
    }
    
    printf("Tensors parsed.\n");
    /* Tensor data starts after tensor info, aligned to 32 bytes */
    const uint8_t *tensor_base = (const uint8_t*)(((uintptr_t)p + 31) & ~31);
    printf("Tensor base offset: %zu\n", (size_t)(tensor_base - (const uint8_t*)mapped));
    
    /* Get layer 0 tensors */
    printf("Looking for tensors...\n");
    TensorInfo *token_embd = get_tensor(tensors, n_tensors, "token_embd.weight");
    printf("  token_embd: %p\n", (void*)token_embd);
    
    TensorInfo *attn_norm = get_tensor(tensors, n_tensors, "blk.0.attn_norm.weight");
    printf("  attn_norm: %p\n", (void*)attn_norm);
    
    TensorInfo *attn_q = get_tensor(tensors, n_tensors, "blk.0.attn_q.weight");
    printf("  attn_q: %p\n", (void*)attn_q);
    
    TensorInfo *attn_k = get_tensor(tensors, n_tensors, "blk.0.attn_k.weight");
    printf("  attn_k: %p\n", (void*)attn_k);
    
    TensorInfo *attn_v = get_tensor(tensors, n_tensors, "blk.0.attn_v.weight");
    printf("  attn_v: %p\n", (void*)attn_v);
    
    TensorInfo *attn_output = get_tensor(tensors, n_tensors, "blk.0.attn_output.weight");
    printf("  attn_output: %p\n", (void*)attn_output);
    
    printf("\nLayer 0 tensors found:\n");
    printf("  token_embd: %s\n", token_embd ? "YES" : "NO");
    printf("  attn_norm: %s\n", attn_norm ? "YES" : "NO");
    printf("  attn_q: %s\n", attn_q ? "YES" : "NO");
    printf("  attn_k: %s\n", attn_k ? "YES" : "NO");
    printf("  attn_v: %s\n", attn_v ? "YES" : "NO");
    printf("  attn_output: %s\n\n", attn_output ? "YES" : "NO");
    
    if (!token_embd || !attn_q) {
        printf("[FAIL] Required tensors not found\n");
        return 1;
    }
    
    /* Test with token 1 (BOS) */
    int test_token = 1;
    printf("Testing with token %d ('%s')\n\n", test_token, vocab[test_token]);
    
    int n_embd = config.n_embd;
    int n_head = config.n_head;
    int n_kv_head = config.n_kv_head;
    int head_dim = n_embd / n_head;
    
    /* Allocate buffers */
    float *embedding = calloc(n_embd, sizeof(float));
    float *normed = calloc(n_embd, sizeof(float));
    float *q = calloc(n_embd, sizeof(float));
    float *k = calloc(n_kv_head * head_dim, sizeof(float));
    float *v = calloc(n_kv_head * head_dim, sizeof(float));
    float *attn_out = calloc(n_embd, sizeof(float));
    float *temp = calloc(n_embd, sizeof(float));
    
    /* Step 1: Embedding lookup */
    printf("Step 1: Embedding lookup\n");
    dequantize_row(tensor_base, token_embd, test_token, embedding, n_embd);
    
    float emb_mean = 0.0f, emb_var = 0.0f;
    for (int i = 0; i < n_embd; i++) {
        emb_mean += embedding[i];
        emb_var += embedding[i] * embedding[i];
    }
    emb_mean /= n_embd;
    emb_var = emb_var / n_embd - emb_mean * emb_mean;
    printf("  Embedding mean: %.6f, std: %.6f\n", emb_mean, sqrtf(emb_var));
    printf("  First 5 values: %.6f %.6f %.6f %.6f %.6f\n",
           embedding[0], embedding[1], embedding[2], embedding[3], embedding[4]);
    
    /* Step 2: RMSNorm */
    printf("\nStep 2: RMSNorm\n");
    float *norm_weight = (float*)(tensor_base + attn_norm->offset);
    rms_norm(embedding, normed, n_embd, config.norm_eps, norm_weight);
    
    float norm_mean = 0.0f, norm_var = 0.0f;
    for (int i = 0; i < n_embd; i++) {
        norm_mean += normed[i];
        norm_var += normed[i] * normed[i];
    }
    norm_mean /= n_embd;
    norm_var = norm_var / n_embd - norm_mean * norm_mean;
    printf("  After RMSNorm mean: %.6f, std: %.6f\n", norm_mean, sqrtf(norm_var));
    printf("  First 5 values: %.6f %.6f %.6f %.6f %.6f\n",
           normed[0], normed[1], normed[2], normed[3], normed[4]);
    
    /* Step 3: QKV projections */
    printf("\nStep 3: QKV Projections\n");
    matvec_dequantized(tensor_base, attn_q, normed, q, n_embd, n_embd);
    matvec_dequantized(tensor_base, attn_k, normed, k, n_kv_head * head_dim, n_embd);
    matvec_dequantized(tensor_base, attn_v, normed, v, n_kv_head * head_dim, n_embd);
    
    float q_mean = 0.0f, k_mean = 0.0f, v_mean = 0.0f;
    for (int i = 0; i < n_embd; i++) q_mean += q[i];
    for (int i = 0; i < n_kv_head * head_dim; i++) k_mean += k[i];
    for (int i = 0; i < n_kv_head * head_dim; i++) v_mean += v[i];
    printf("  Q mean: %.6f\n", q_mean / n_embd);
    printf("  K mean: %.6f\n", k_mean / (n_kv_head * head_dim));
    printf("  V mean: %.6f\n", v_mean / (n_kv_head * head_dim));
    
    /* Step 4: RoPE */
    printf("\nStep 4: RoPE (position 0)\n");
    apply_rope(q, k, n_embd, n_head, 0, config.rope_theta);
    
    printf("  After RoPE Q first 5: %.6f %.6f %.6f %.6f %.6f\n",
           q[0], q[1], q[2], q[3], q[4]);
    printf("  After RoPE K first 5: %.6f %.6f %.6f %.6f %.6f\n",
           k[0], k[1], k[2], k[3], k[4]);
    
    /* Step 5: Attention (simplified - single position) */
    printf("\nStep 5: Attention Output\n");
    /* For position 0, attention is just V (no previous tokens) */
    /* Repeat V for GQA */
    int heads_per_kv = n_head / n_kv_head;
    for (int h = 0; h < n_head; h++) {
        int kv_h = h / heads_per_kv;
        for (int d = 0; d < head_dim; d++) {
            attn_out[h * head_dim + d] = v[kv_h * head_dim + d];
        }
    }
    
    float attn_mean = 0.0f;
    for (int i = 0; i < n_embd; i++) attn_mean += attn_out[i];
    printf("  Attention output mean: %.6f\n", attn_mean / n_embd);
    
    /* Step 6: Output projection */
    printf("\nStep 6: Output Projection\n");
    matvec_dequantized(tensor_base, attn_output, attn_out, temp, n_embd, n_embd);
    
    /* Residual connection */
    for (int i = 0; i < n_embd; i++) temp[i] += embedding[i];
    
    float out_mean = 0.0f, out_var = 0.0f;
    for (int i = 0; i < n_embd; i++) {
        out_mean += temp[i];
        out_var += temp[i] * temp[i];
    }
    out_mean /= n_embd;
    out_var = out_var / n_embd - out_mean * out_mean;
    printf("  After residual mean: %.6f, std: %.6f\n", out_mean, sqrtf(out_var));
    printf("  First 5 values: %.6f %.6f %.6f %.6f %.6f\n",
           temp[0], temp[1], temp[2], temp[3], temp[4]);
    
    printf("\n=== Layer 0 Test Complete ===\n");
    
    /* Cleanup */
    free(embedding); free(normed); free(q); free(k); free(v); free(attn_out); free(temp);
    for (int i = 0; i < vocab_size; i++) free(vocab[i]);
    free(vocab);
    free(tensors);
    UnmapViewOfFile(mapped);
    
    return 0;
}
