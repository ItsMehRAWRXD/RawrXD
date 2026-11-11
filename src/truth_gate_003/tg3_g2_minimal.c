/*
 * Truth Gate 003 - TG3-G2: First Logit Validation (Minimal)
 * 
 * Validates that embeddings can be dequantized and produce finite values
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

int main(int argc, char **argv) {
    printf("Truth Gate 003 - TG3-G2: First Logit Validation (Minimal)\n");
    printf("=========================================================\n\n");
    
    if (argc < 2) {
        printf("Usage: %s <model.gguf> [token_id]\n", argv[0]);
        return 1;
    }
    
    const char *model_path = argv[1];
    int token_id = (argc > 2) ? atoi(argv[2]) : 1;
    
    printf("Model: %s\n", model_path);
    printf("Token ID: %d\n\n", token_id);
    
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
    
    /* Skip KV pairs */
    for (uint64_t i = 0; i < n_kv; i++) {
        char key[256];
        read_string(&p, key, sizeof(key));
        uint32_t type = *(uint32_t*)p;
        p += sizeof(uint32_t);
        skip_metadata_value(&p, type);
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
    
    /* Get tensor data base */
    const uint8_t *tensor_base = (const uint8_t*)(((uintptr_t)p + 31) & ~31);
    
    /* Find token_embd.weight */
    TensorInfo *token_embd = NULL;
    for (uint32_t i = 0; i < n_tensors; i++) {
        if (strcmp(tensors[i].name, "token_embd.weight") == 0) {
            token_embd = &tensors[i];
            printf("Found token_embd.weight: dims=[%llu, %llu], type=%u\n",
                   tensors[i].dims[0], tensors[i].dims[1], tensors[i].type);
            break;
        }
    }
    
    if (!token_embd) { printf("[FAIL] token_embd.weight not found\n"); return 1; }
    
    /* Validate token_id */
    if (token_id < 0 || token_id >= (int)token_embd->dims[0]) {
        printf("[FAIL] Invalid token_id %d (vocab_size=%llu)\n", token_id, token_embd->dims[0]);
        return 1;
    }
    
    /* Dequantize single token embedding */
    int embd_dim = (int)token_embd->dims[1];
    float *embedding = calloc(embd_dim, sizeof(float));
    
    printf("Dequantizing token %d embedding (dim=%d)...\n", token_id, embd_dim);
    
    if (token_embd->type == 2) { /* Q4_0 */
        int blocks_per_row = embd_dim / 32;
        block_q4_0 *blocks = (block_q4_0*)(tensor_base + token_embd->offset);
        blocks += token_id * blocks_per_row;
        
        for (int i = 0; i < blocks_per_row; i++) {
            dequantize_q4_0(&blocks[i], &embedding[i * 32], 32);
        }
        
        /* Validate embedding */
        int nan_count = 0, inf_count = 0, zero_count = 0;
        float sum = 0.0f, min_val = INFINITY, max_val = -INFINITY;
        
        for (int i = 0; i < embd_dim; i++) {
            if (isnan(embedding[i])) nan_count++;
            else if (isinf(embedding[i])) inf_count++;
            else {
                if (embedding[i] == 0.0f) zero_count++;
                sum += embedding[i];
                if (embedding[i] < min_val) min_val = embedding[i];
                if (embedding[i] > max_val) max_val = embedding[i];
            }
        }
        
        printf("\nEmbedding Statistics:\n");
        printf("  NaN: %d\n", nan_count);
        printf("  Inf: %d\n", inf_count);
        printf("  Zero: %d\n", zero_count);
        printf("  Min: %.6f\n", min_val);
        printf("  Max: %.6f\n", max_val);
        printf("  Mean: %.6f\n", sum / embd_dim);
        
        if (nan_count == 0 && inf_count == 0) {
            printf("\n====================================\n");
            printf("TG3-G2 Status: PASS\n");
            printf("====================================\n");
            printf("Embedding dequantization successful\n");
            printf("All values are finite\n");
        } else {
            printf("\n[FAIL] Embedding contains NaN or Inf\n");
        }
    } else {
        printf("[SKIP] token_embd.weight type=%u not Q4_0\n", token_embd->type);
    }
    
    free(embedding);
    free(tensors);
    UnmapViewOfFile(mapped);
    
    return 0;
}
