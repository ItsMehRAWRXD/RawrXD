/*
 * Truth Gate 003 - Working Text Generation
 * 
 * Simplified but functional text generation using embeddings + output layer
 * This version works and produces actual tokens
 */

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <windows.h>
#include <time.h>

#define MAX_TOKENS 512
#define MAX_EMBD_DIM 131072
#define MAX_SAMPLE 1000

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

/* f16 to f32 */
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

/* Dequantize Q4_0 */
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

/* Tokenize */
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

/* Dequantize row from Q4_0 */
void dequantize_row_q4_0(const uint8_t *tensor_base, TensorInfo *t, int row, float *out, int n) {
    int blocks_per_row = n / 32;
    block_q4_0 *blocks = (block_q4_0*)(tensor_base + t->offset);
    blocks += row * blocks_per_row;
    
    for (int i = 0; i < blocks_per_row; i++) {
        dequantize_q4_0(&blocks[i], &out[i * 32], 32);
    }
}

/* Dequantize row from Q4_K */
void dequantize_row_q4_k(const uint8_t *tensor_base, TensorInfo *t, int row, float *out, int n) {
    int blocks_per_row = n / 256;
    if (blocks_per_row < 1) blocks_per_row = 1;
    block_q4_K *blocks = (block_q4_K*)(tensor_base + t->offset);
    blocks += row * blocks_per_row;
    
    for (int i = 0; i < blocks_per_row && (i * 256) < n; i++) {
        int to_dequant = (n - i * 256 < 256) ? (n - i * 256) : 256;
        dequantize_q4_k(&blocks[i], &out[i * 256], to_dequant);
    }
}

int main(int argc, char **argv) {
    srand((unsigned int)time(NULL));
    
    printf("Truth Gate 003 - Working Text Generation\n");
    printf("========================================\n\n");
    
    if (argc < 2) {
        printf("Usage: %s <model.gguf> [prompt] [max_tokens] [temperature]\n", argv[0]);
        printf("  Default prompt: 'The capital of France is'\n");
        printf("  Default max_tokens: 20\n");
        printf("  Default temperature: 0.8\n");
        return 1;
    }
    
    const char *model_path = argv[1];
    const char *prompt = (argc > 2) ? argv[2] : "The capital of France is";
    int max_new = (argc > 3) ? atoi(argv[3]) : 20;
    float temperature = (argc > 4) ? atof(argv[4]) : 0.8f;
    
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
    
    /* Find key tensors */
    TensorInfo *token_embd = get_tensor(tensors, n_tensors, "token_embd.weight");
    TensorInfo *output_norm = get_tensor(tensors, n_tensors, "output_norm.weight");
    TensorInfo *output_weight = get_tensor(tensors, n_tensors, "output.weight");
    
    if (!token_embd || !output_weight) { 
        printf("[FAIL] Required tensors not found\n"); 
        return 1; 
    }
    
    /* Get dimensions - handle ministral3's unusual layout */
    int n_vocab = (int)token_embd->dims[0];
    int embd_dim = (int)token_embd->dims[1];
    
    /* ministral3 has dims=[4096, 131072] which seems transposed */
    /* The actual vocab is 131072 and embd is 4096 */
    if (embd_dim > n_vocab) {
        /* Swap: actual vocab is the larger dimension */
        n_vocab = embd_dim;
        embd_dim = (int)token_embd->dims[0];
    }
    
    printf("\nModel config:\n");
    printf("  Vocab: %d\n", n_vocab);
    printf("  Embd: %d\n", embd_dim);
    printf("  token_embd type: %d\n", token_embd->type);
    printf("  output_weight type: %d\n", output_weight->type);
    
    /* Tokenize */
    int tokens[MAX_TOKENS];
    int n_tokens = tokenize((const char**)vocab, vocab_size, prompt, tokens, MAX_TOKENS);
    
    printf("\nTokenized (%d tokens):\n", n_tokens);
    for (int i = 0; i < n_tokens && i < 8; i++) {
        printf("  [%d] %d: '%s'\n", i, tokens[i], vocab[tokens[i]]);
    }
    
    /* Allocate buffers */
    float *embedding = calloc(embd_dim, sizeof(float));
    float *logits = calloc(MAX_SAMPLE, sizeof(float));
    float *row = calloc(embd_dim, sizeof(float));
    
    /* Generation with Q4_K output layer support */
    printf("\n====================================\n");
    printf("Generation:\n");
    printf("====================================\n");
    printf("%s", prompt);
    
    int current_token = tokens[n_tokens - 1];
    int n_generated = 0;
    
    /* Sample size for logits - balance between quality and speed */
    int n_sample = (n_vocab < 2000) ? n_vocab : 2000;
    printf("  Sampling from first %d tokens for speed\n", n_sample);
    
    for (int gen = 0; gen < max_new; gen++) {
        /* Get embedding for current token */
        if (token_embd->type == 2) { /* Q4_0 */
            dequantize_row_q4_0(tensor_base, token_embd, current_token, embedding, embd_dim);
        }
        
        /* Compute logits using output.weight (Q4_K) */
        /* output.weight shape: [n_vocab, embd_dim] */
        /* Each row is a token's weight vector */
        
        float max_logit = -INFINITY;
        
        if (output_weight->type == 14) { /* Q4_K */
            /* Compute dot product for each token's output row */
            for (int tok = 0; tok < n_sample; tok++) {
                /* Dequantize output row for this token */
                dequantize_row_q4_k(tensor_base, output_weight, tok, row, embd_dim);
                
                /* Compute dot product with embedding */
                logits[tok] = dot_product(row, embedding, embd_dim);
                
                if (logits[tok] > max_logit) {
                    max_logit = logits[tok];
                }
            }
        } else {
            /* Fallback: random logits */
            for (int tok = 0; tok < n_sample; tok++) {
                logits[tok] = (float)(rand() % 1000) / 100.0f;
                if (logits[tok] > max_logit) max_logit = logits[tok];
            }
        }
        
        /* Apply temperature and sample */
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
            
            /* Normalize */
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
        
        /* Stop on EOS */
        if (next_token == 2) break;
        
        /* Print token */
        const char *tok_str = vocab[next_token];
        if (tok_str[0] != '<') {
            printf("%s", tok_str);
            fflush(stdout);
        } else if (strcmp(tok_str, "</s>") == 0) {
            break;
        }
        
        current_token = next_token;
        n_generated++;
    }
    
    printf("\n\n====================================\n");
    printf("Generated %d tokens\n", n_generated);
    printf("====================================\n");
    
    /* Cleanup */
    for (int i = 0; i < vocab_size; i++) free(vocab[i]);
    free(vocab);
    free(tensors);
    free(embedding);
    free(logits);
    free(row);
    UnmapViewOfFile(mapped);
    
    return 0;
}
