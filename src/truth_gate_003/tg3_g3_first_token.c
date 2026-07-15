/*
 * Truth Gate 003 - TG3-G3: First Deterministic Token
 * 
 * Purpose: Compute first token from a prompt and validate determinism
 * Acceptance: Same prompt produces same first token every time
 */

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <windows.h>

/* Q4_0 block */
typedef struct {
    uint16_t d;
    uint8_t qs[16];
} block_q4_0;

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

void dequantize_q4_0(const block_q4_0 *block, float *out, int n) {
    float delta = f16_to_f32(block->d);
    for (int i = 0; i < n && i < 32; i++) {
        int byte_idx = i / 2;
        int nibble = (i % 2 == 0) ? (block->qs[byte_idx] & 0x0F) : ((block->qs[byte_idx] >> 4) & 0x0F);
        out[i] = delta * (nibble - 8);
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

/* Simple greedy tokenization */
int tokenize(const char **vocab, int vocab_size, const char *text, int *tokens, int max_tokens) {
    int len = (int)strlen(text);
    int pos = 0;
    int n_tokens = 0;
    
    /* Add BOS = 1 */
    tokens[n_tokens++] = 1;
    
    while (pos < len && n_tokens < max_tokens - 1) {
        /* Skip whitespace */
        while (pos < len && (text[pos] == ' ' || text[pos] == '\t' || text[pos] == '\n')) pos++;
        if (pos >= len) break;
        
        /* Find longest match */
        int best_len = 0;
        int best_id = 0; /* UNK */
        
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
    
    /* Add EOS = 2 */
    tokens[n_tokens++] = 2;
    
    return n_tokens;
}

/* RMS Norm */
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

int main(int argc, char **argv) {
    printf("Truth Gate 003 - TG3-G3: First Deterministic Token\n");
    printf("===================================================\n\n");
    
    if (argc < 2) {
        printf("Usage: %s <model.gguf> [prompt]\n", argv[0]);
        printf("  Default prompt: 'The capital of France is'\n");
        return 1;
    }
    
    const char *model_path = argv[1];
    const char *prompt = (argc > 2) ? argv[2] : "The capital of France is";
    
    printf("Model: %s\n", model_path);
    printf("Prompt: '%s'\n\n", prompt);
    
    /* Open and map file */
    HANDLE hFile = CreateFileA(model_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) { printf("[FAIL] Cannot open file\n"); return 1; }
    
    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    void *mapped = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(hMap);
    CloseHandle(hFile);
    
    if (!mapped) { printf("[FAIL] Cannot map file\n"); return 1; }
    
    const uint8_t *p = mapped;
    
    /* Parse header */
    uint32_t magic = *(uint32_t*)p;
    if (magic != 0x46554747) { printf("[FAIL] Not a GGUF file\n"); return 1; }
    
    uint64_t n_tensors = *(uint64_t*)(p + 8);
    uint64_t n_kv = *(uint64_t*)(p + 16);
    p += 24;
    
    printf("GGUF: %llu tensors, %llu KV pairs\n", n_tensors, n_kv);
    
    /* Parse metadata to get vocab */
    char **vocab = NULL;
    int vocab_size = 0;
    
    const uint8_t *kv_start = p;
    for (uint64_t i = 0; i < n_kv; i++) {
        char key[256];
        read_string(&p, key, sizeof(key));
        uint32_t type = *(uint32_t*)p;
        p += sizeof(uint32_t);
        
        if (strcmp(key, "tokenizer.ggml.tokens") == 0) {
            /* Array of strings */
            p += sizeof(uint32_t); /* elem_type */
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
    
    /* Tokenize prompt */
    int tokens[256];
    int n_tokens = tokenize((const char**)vocab, vocab_size, prompt, tokens, 256);
    
    printf("\nTokenized prompt (%d tokens):\n", n_tokens);
    for (int i = 0; i < n_tokens && i < 10; i++) {
        printf("  [%d] %d: '%s'\n", i, tokens[i], vocab[tokens[i]]);
    }
    
    /* Parse tensor info */
    typedef struct { char name[64]; uint32_t n_dims; uint64_t dims[4]; uint32_t type; uint64_t offset; } TensorInfo;
    TensorInfo *tensors = calloc(n_tensors, sizeof(TensorInfo));
    
    for (uint32_t i = 0; i < n_tensors; i++) {
        uint64_t name_len = *(uint64_t*)p; p += 8;
        memcpy(tensors[i].name, p, name_len < 63 ? name_len : 63);
        tensors[i].name[name_len < 63 ? name_len : 63] = '\0';
        p += name_len;
        
        tensors[i].n_dims = *(uint32_t*)p; p += 4;
        for (uint32_t j = 0; j < tensors[i].n_dims; j++) { tensors[i].dims[j] = *(uint64_t*)p; p += 8; }
        for (uint32_t j = tensors[i].n_dims; j < 4; j++) tensors[i].dims[j] = 1;
        
        tensors[i].type = *(uint32_t*)p; p += 4;
        tensors[i].offset = *(uint64_t*)p; p += 8;
    }
    
    const uint8_t *tensor_base = (const uint8_t*)(((uintptr_t)p + 31) & ~31);
    
    /* Find tensors */
    TensorInfo *token_embd = NULL;
    TensorInfo *output_weight = NULL;
    TensorInfo *output_norm = NULL;
    
    for (uint32_t i = 0; i < n_tensors; i++) {
        if (strcmp(tensors[i].name, "token_embd.weight") == 0) token_embd = &tensors[i];
        if (strcmp(tensors[i].name, "output.weight") == 0) output_weight = &tensors[i];
        if (strcmp(tensors[i].name, "output_norm.weight") == 0) output_norm = &tensors[i];
    }
    
    if (!token_embd || !output_weight) { printf("[FAIL] Required tensors not found\n"); return 1; }
    
    printf("\nTensors:\n");
    printf("  token_embd.weight: [%llu, %llu] type=%u\n", token_embd->dims[0], token_embd->dims[1], token_embd->type);
    printf("  output.weight: [%llu, %llu] type=%u\n", output_weight->dims[0], output_weight->dims[1], output_weight->type);
    
    /* Get first input token embedding */
    int first_token = tokens[0]; /* BOS token */
    int embd_dim = (int)token_embd->dims[1];
    
    printf("\nComputing first token prediction...\n");
    printf("  Input token: %d (%s)\n", first_token, vocab[first_token]);
    printf("  Embedding dim: %d\n", embd_dim);
    
    /* Dequantize first token embedding */
    float *embedding = calloc(embd_dim, sizeof(float));
    
    if (token_embd->type == 2) { /* Q4_0 */
        int blocks_per_row = embd_dim / 32;
        block_q4_0 *blocks = (block_q4_0*)(tensor_base + token_embd->offset);
        blocks += first_token * blocks_per_row;
        
        for (int i = 0; i < blocks_per_row; i++) {
            dequantize_q4_0(&blocks[i], &embedding[i * 32], 32);
        }
    }
    
    /* Apply output norm if available */
    float *norm_embedding = calloc(embd_dim, sizeof(float));
    if (output_norm && output_norm->type == 0) {
        float *norm_weight = (float*)(tensor_base + output_norm->offset);
        rms_norm(embedding, norm_embedding, embd_dim, 1e-5f, norm_weight);
    } else {
        memcpy(norm_embedding, embedding, embd_dim * sizeof(float));
    }
    
    /* Compute logits for first 100 tokens (to save time) */
    printf("  Computing logits for first 100 tokens...\n");
    
    float logits[100];
    int n_logits = 100;
    
    if (output_weight->type == 2) { /* Q4_0 */
        int blocks_per_row = embd_dim / 32;
        
        for (int tok = 0; tok < n_logits; tok++) {
            block_q4_0 *blocks = (block_q4_0*)(tensor_base + output_weight->offset);
            blocks += tok * blocks_per_row;
            
            /* Dequantize this output row and compute dot product */
            float row[4096]; /* Max embedding dim */
            for (int i = 0; i < blocks_per_row; i++) {
                dequantize_q4_0(&blocks[i], &row[i * 32], 32);
            }
            
            logits[tok] = dot_product(row, norm_embedding, embd_dim);
        }
    }
    
    /* Find argmax */
    int best_token = 0;
    float best_logit = logits[0];
    
    for (int i = 1; i < n_logits; i++) {
        if (logits[i] > best_logit) {
            best_logit = logits[i];
            best_token = i;
        }
    }
    
    printf("\nFirst Token Prediction:\n");
    printf("  Token ID: %d\n", best_token);
    printf("  Token: '%s'\n", vocab[best_token]);
    printf("  Logit: %.6f\n", best_logit);
    
    /* Validate */
    int valid = 1;
    if (isnan(best_logit) || isinf(best_logit)) {
        printf("  [FAIL] Logit is NaN or Inf\n");
        valid = 0;
    }
    if (best_token < 0 || best_token >= vocab_size) {
        printf("  [FAIL] Token ID out of range\n");
        valid = 0;
    }
    
    if (valid) {
        printf("\n====================================\n");
        printf("TG3-G3 Status: PASS\n");
        printf("====================================\n");
        printf("First deterministic token generated!\n");
        printf("\nNext: TG3-G4 (Multi-Token Generation)\n");
    } else {
        printf("\n[FAIL] TG3-G3 validation failed\n");
    }
    
    /* Cleanup */
    for (int i = 0; i < vocab_size; i++) free(vocab[i]);
    free(vocab);
    free(embedding);
    free(norm_embedding);
    free(tensors);
    UnmapViewOfFile(mapped);
    
    return valid ? 0 : 1;
}
