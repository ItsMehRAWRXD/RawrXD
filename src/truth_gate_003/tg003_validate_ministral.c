/*
 * Truth Gate 003 - Phase 1: Real Tensor Validation (Ministral3)
 * 
 * Validates Q4_0 dequantization on real model weights.
 * Uses working Phase 1 GGUF parser.
 */

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <string.h>
#include <windows.h>

/* GGML Types */
typedef enum {
    GGML_TYPE_F32  = 0,
    GGML_TYPE_F16  = 1,
    GGML_TYPE_Q4_0 = 2,
    GGML_TYPE_Q4_1 = 3,
    GGML_TYPE_Q5_0 = 6,
    GGML_TYPE_Q5_1 = 7,
    GGML_TYPE_Q8_0 = 8,
    GGML_TYPE_Q8_1 = 9,
    GGML_TYPE_Q2_K = 10,
    GGML_TYPE_Q3_K = 11,
    GGML_TYPE_Q4_K = 12,
    GGML_TYPE_Q5_K = 13,
    GGML_TYPE_Q6_K = 14,
    GGML_TYPE_Q8_K = 15,
} ggml_type_t;

/* GGUF Header */
typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint32_t version;
    uint64_t tensor_count;
    uint64_t metadata_kv_count;
} gguf_header_t;

/* Tensor Info */
typedef struct {
    char name[256];
    uint32_t n_dims;
    uint64_t dimensions[4];
    uint32_t type;
    uint64_t offset;
    uint64_t size;
} tensor_info_t;

/* GGUF Context */
typedef struct {
    HANDLE file_handle;
    HANDLE map_handle;
    void* base_addr;
    size_t file_size;
    gguf_header_t header;
    tensor_info_t* tensors;
    uint64_t data_offset;
} gguf_context_t;

/* Q4_0 block structure */
typedef struct {
    uint16_t delta;
    uint8_t quants[16];
} block_q4_0;

/* ============== GGUF PARSING (from Phase 1) ============== */

/* Forward declarations */
void gguf_close(gguf_context_t* ctx);

static uint32_t read_u32_le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t read_u64_le(const uint8_t *p) {
    uint32_t lo = read_u32_le(p);
    uint32_t hi = read_u32_le(p + 4);
    return (uint64_t)lo | ((uint64_t)hi << 32);
}

static float f16_to_f32(uint16_t h) {
    uint32_t sign = (h >> 15) & 1;
    uint32_t exp = (h >> 10) & 0x1F;
    uint32_t mant = h & 0x3FF;
    
    if (exp == 0) {
        if (mant == 0) return sign ? -0.0f : 0.0f;
        float val = mant / 1024.0f;
        return sign ? -val * powf(2, -14) : val * powf(2, -14);
    }
    if (exp == 31) {
        if (mant == 0) return sign ? -INFINITY : INFINITY;
        return NAN;
    }
    float val = 1.0f + mant / 1024.0f;
    int e = (int)exp - 15;
    return sign ? -val * powf(2, e) : val * powf(2, e);
}

static int read_string(const uint8_t** ptr, char* buffer, size_t max_len) {
    uint64_t len = read_u64_le(*ptr);
    *ptr += sizeof(uint64_t);
    
    printf("[DEBUG] read_string: len=%llu, max_len=%zu\n", (unsigned long long)len, max_len);
    
    if (len >= max_len) {
        printf("[DEBUG] String too long, skipping\n");
        *ptr += len;
        buffer[0] = '\0';
        return 0;
    }
    
    memcpy(buffer, *ptr, len);
    buffer[len] = '\0';
    *ptr += len;
    printf("[DEBUG] read_string: got '%s'\n", buffer);
    return 1;
}

static int skip_metadata_value(const uint8_t** ptr, uint32_t type) {
    switch (type) {
        case 0: case 1:  *ptr += 1; break;
        case 2: case 3:  *ptr += 2; break;
        case 4: case 5: case 6:  *ptr += 4; break;
        case 10: case 11: case 12: *ptr += 8; break;
        case 7:  *ptr += 1; break;
        case 8: {
            uint64_t len = *(uint64_t*)*ptr;
            *ptr += sizeof(uint64_t) + len;
            break;
        }
        case 9: {
            uint32_t elem_type = *(uint32_t*)*ptr;
            *ptr += sizeof(uint32_t);
            uint64_t count = *(uint64_t*)*ptr;
            *ptr += sizeof(uint64_t);
            for (uint64_t i = 0; i < count; i++) {
                if (!skip_metadata_value(ptr, elem_type)) return 0;
            }
            break;
        }
        default:
            return 0;
    }
    return 1;
}

int gguf_open(const char* path, gguf_context_t* ctx) {
    memset(ctx, 0, sizeof(gguf_context_t));
    
    ctx->file_handle = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (ctx->file_handle == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        printf("[DEBUG] CreateFileA failed for: %s\n", path);
        printf("[DEBUG] Error code: %lu\n", err);
        return -1;
    }
    printf("[DEBUG] CreateFileA succeeded\n");
    
    LARGE_INTEGER size;
    if (!GetFileSizeEx(ctx->file_handle, &size)) {
        DWORD err = GetLastError();
        printf("[DEBUG] GetFileSizeEx failed (error %lu)\n", err);
        CloseHandle(ctx->file_handle);
        return -1;
    }
    ctx->file_size = (size_t)size.QuadPart;
    printf("[DEBUG] File size: %zu bytes\n", ctx->file_size);
    
    ctx->map_handle = CreateFileMappingA(ctx->file_handle, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!ctx->map_handle) {
        DWORD err = GetLastError();
        printf("[DEBUG] CreateFileMappingA failed (error %lu)\n", err);
        CloseHandle(ctx->file_handle);
        return -1;
    }
    printf("[DEBUG] CreateFileMappingA succeeded\n");
    
    ctx->base_addr = MapViewOfFile(ctx->map_handle, FILE_MAP_READ, 0, 0, 0);
    if (!ctx->base_addr) {
        DWORD err = GetLastError();
        printf("[DEBUG] MapViewOfFile failed (error %lu)\n", err);
        CloseHandle(ctx->map_handle);
        CloseHandle(ctx->file_handle);
        return -1;
    }
    printf("[DEBUG] MapViewOfFile succeeded\n");
    
    memcpy(&ctx->header, ctx->base_addr, sizeof(gguf_header_t));
    
    printf("[DEBUG] Magic: 0x%08X (expected 0x46554747)\n", ctx->header.magic);
    printf("[DEBUG] Version: %u\n", ctx->header.version);
    printf("[DEBUG] Tensors: %llu\n", (unsigned long long)ctx->header.tensor_count);
    printf("[DEBUG] Metadata: %llu\n", (unsigned long long)ctx->header.metadata_kv_count);
    
    if (ctx->header.magic != 0x46554747) {
        fprintf(stderr, "Error: Invalid GGUF magic\n");
        gguf_close(ctx);
        return -1;
    }
    
    ctx->tensors = calloc(ctx->header.tensor_count, sizeof(tensor_info_t));
    if (!ctx->tensors) {
        printf("[DEBUG] calloc failed for tensors\n");
        gguf_close(ctx);
        return -1;
    }
    printf("[DEBUG] Allocated %llu tensors\n", (unsigned long long)ctx->header.tensor_count);
    
    /* Parse tensors */
    const uint8_t* ptr = (uint8_t*)ctx->base_addr + sizeof(gguf_header_t);
    
    /* Skip metadata */
    printf("[DEBUG] Skipping %llu KV pairs...\n", (unsigned long long)ctx->header.metadata_kv_count);
    printf("[DEBUG] Starting at offset %zu\n", (size_t)(ptr - (uint8_t*)ctx->base_addr));
    for (uint64_t i = 0; i < ctx->header.metadata_kv_count; i++) {
        char key[256];
        printf("[DEBUG] Reading KV %llu at offset %zu\n", (unsigned long long)i, (size_t)(ptr - (uint8_t*)ctx->base_addr));
        if (!read_string(&ptr, key, sizeof(key))) {
            printf("[DEBUG] Failed to read KV key %llu\n", (unsigned long long)i);
            gguf_close(ctx);
            return -1;
        }
        printf("[DEBUG] KV key %llu: %s\n", (unsigned long long)i, key);
        uint32_t type = read_u32_le(ptr);
        ptr += sizeof(uint32_t);
        printf("[DEBUG] KV type %llu: %u\n", (unsigned long long)i, type);
        if (!skip_metadata_value(&ptr, type)) {
            printf("[DEBUG] Failed to skip KV value %llu (type %u)\n", (unsigned long long)i, type);
            gguf_close(ctx);
            return -1;
        }
    }
    printf("[DEBUG] KV pairs skipped OK\n");
    
    /* Read tensor info */
    for (uint64_t i = 0; i < ctx->header.tensor_count; i++) {
        if (!read_string(&ptr, ctx->tensors[i].name, sizeof(ctx->tensors[i].name))) {
            gguf_close(ctx);
            return -1;
        }
        
        ctx->tensors[i].n_dims = *(uint32_t*)ptr;
        ptr += sizeof(uint32_t);
        
        for (uint32_t j = 0; j < ctx->tensors[i].n_dims; j++) {
            ctx->tensors[i].dimensions[j] = *(uint64_t*)ptr;
            ptr += sizeof(uint64_t);
        }
        
        ctx->tensors[i].type = *(uint32_t*)ptr;
        ptr += sizeof(uint32_t);
        
        ctx->tensors[i].offset = *(uint64_t*)ptr;
        ptr += sizeof(uint64_t);
        
        /* Calculate size */
        uint64_t num_elements = 1;
        for (uint32_t j = 0; j < ctx->tensors[i].n_dims; j++) {
            num_elements *= ctx->tensors[i].dimensions[j];
        }
        
        switch (ctx->tensors[i].type) {
            case GGML_TYPE_F32:  ctx->tensors[i].size = num_elements * 4; break;
            case GGML_TYPE_F16:  ctx->tensors[i].size = num_elements * 2; break;
            case GGML_TYPE_Q4_0: ctx->tensors[i].size = (num_elements / 32) * 18; break;
            case GGML_TYPE_Q4_1: ctx->tensors[i].size = (num_elements / 32) * 20; break;
            case GGML_TYPE_Q6_K: ctx->tensors[i].size = (num_elements / 256) * 210; break;
            default:
                fprintf(stderr, "Warning: Unknown type %d for tensor %s\n",
                        ctx->tensors[i].type, ctx->tensors[i].name);
                ctx->tensors[i].size = 0;
        }
    }
    
    ctx->data_offset = (uint64_t)(ptr - (uint8_t*)ctx->base_addr);
    ctx->data_offset = (ctx->data_offset + 31) & ~31;
    
    return 0;
}

void gguf_close(gguf_context_t* ctx) {
    if (ctx->tensors) {
        free(ctx->tensors);
        ctx->tensors = NULL;
    }
    if (ctx->base_addr) {
        UnmapViewOfFile(ctx->base_addr);
    }
    if (ctx->map_handle) {
        CloseHandle(ctx->map_handle);
    }
    if (ctx->file_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(ctx->file_handle);
    }
}

tensor_info_t* gguf_get_tensor(gguf_context_t* ctx, const char* name) {
    for (uint64_t i = 0; i < ctx->header.tensor_count; i++) {
        if (strcmp(ctx->tensors[i].name, name) == 0) {
            return &ctx->tensors[i];
        }
    }
    return NULL;
}

void* gguf_get_tensor_data(gguf_context_t* ctx, tensor_info_t* tensor) {
    return (uint8_t*)ctx->base_addr + ctx->data_offset + tensor->offset;
}

/* ============== Q4_0 DEQUANTIZATION ============== */

void dequantize_q4_0(const block_q4_0 *blocks, int n_blocks, float *out) {
    for (int b = 0; b < n_blocks; b++) {
        float delta = f16_to_f32(blocks[b].delta);
        for (int i = 0; i < 16; i++) {
            uint8_t q = blocks[b].quants[i];
            int x0 = (q & 0x0F) - 8;
            int x1 = (q >> 4) - 8;
            out[b * 32 + i * 2] = x0 * delta;
            out[b * 32 + i * 2 + 1] = x1 * delta;
        }
    }
}

/* ============== VALIDATION ============== */

void validate_tensor(gguf_context_t *ctx, const char *tensor_name) {
    printf("\nValidating tensor: %s\n", tensor_name);
    printf("----------------------------------------\n");
    
    tensor_info_t *tensor = gguf_get_tensor(ctx, tensor_name);
    if (!tensor) {
        printf("[FAIL] Tensor not found\n");
        return;
    }
    
    printf("  Type: %d\n", tensor->type);
    printf("  Dims: %u", tensor->n_dims);
    for (uint32_t d = 0; d < tensor->n_dims; d++) {
        printf(" x %llu", (unsigned long long)tensor->dimensions[d]);
    }
    printf("\n");
    printf("  Size: %llu bytes\n", (unsigned long long)tensor->size);
    printf("  Offset: 0x%llX\n", (unsigned long long)tensor->offset);
    
    if (tensor->type != GGML_TYPE_Q4_0) {
        printf("  [SKIP] Only Q4_0 supported for validation\n");
        return;
    }
    
    /* Get raw data */
    block_q4_0 *blocks = (block_q4_0*)gguf_get_tensor_data(ctx, tensor);
    size_t n_blocks = tensor->size / sizeof(block_q4_0);
    size_t n_elements = n_blocks * 32;
    
    printf("\n  Dequantizing %zu blocks (%zu elements)...\n", n_blocks, n_elements);
    
    /* Dequantize */
    float *dequantized = malloc(n_elements * sizeof(float));
    if (!dequantized) {
        printf("  [FAIL] Memory allocation failed\n");
        return;
    }
    
    dequantize_q4_0(blocks, (int)n_blocks, dequantized);
    
    /* Analyze */
    float min_val = dequantized[0], max_val = dequantized[0];
    float sum = 0.0f, sum_sq = 0.0f;
    int nan_count = 0, inf_count = 0;
    
    for (size_t i = 0; i < n_elements; i++) {
        if (isnan(dequantized[i])) nan_count++;
        if (isinf(dequantized[i])) inf_count++;
        if (dequantized[i] < min_val) min_val = dequantized[i];
        if (dequantized[i] > max_val) max_val = dequantized[i];
        sum += dequantized[i];
        sum_sq += dequantized[i] * dequantized[i];
    }
    
    float mean = sum / n_elements;
    float variance = (sum_sq / n_elements) - (mean * mean);
    float std_dev = sqrtf(variance);
    
    printf("\n  Statistics:\n");
    printf("    Elements:  %zu\n", n_elements);
    printf("    NaN:       %d\n", nan_count);
    printf("    Inf:       %d\n", inf_count);
    printf("    Min:       %.6f\n", min_val);
    printf("    Max:       %.6f\n", max_val);
    printf("    Mean:      %.6f\n", mean);
    printf("    Std Dev:   %.6f\n", std_dev);
    
    /* Sample values */
    printf("\n  Sample values (first 10):\n");
    for (size_t i = 0; i < 10 && i < n_elements; i++) {
        printf("    [%6zu] = %10.6f\n", i, dequantized[i]);
    }
    
    /* Validation checks */
    printf("\n  Validation:\n");
    int pass = 1;
    
    if (nan_count > 0) {
        printf("    [FAIL] NaN values detected\n");
        pass = 0;
    } else {
        printf("    [PASS] No NaN values\n");
    }
    
    if (inf_count > 0) {
        printf("    [FAIL] Inf values detected\n");
        pass = 0;
    } else {
        printf("    [PASS] No Inf values\n");
    }
    
    if (max_val > 100.0f || min_val < -100.0f) {
        printf("    [WARN] Values outside typical range [-100, 100]\n");
    } else {
        printf("    [PASS] Values in reasonable range\n");
    }
    
    if (std_dev > 0.0f) {
        printf("    [PASS] Non-zero variance\n");
    } else {
        printf("    [WARN] Zero variance\n");
    }
    
    printf("\n  %s\n", pass ? "[PASS] Tensor validation successful" : "[FAIL] Validation failed");
    
    free(dequantized);
}

/* ============== MAIN ============== */

int main(int argc, char **argv) {
    printf("Truth Gate 003 - Phase 1: Real Tensor Validation\n");
    printf("=================================================\n\n");
    
    const char *model_path = (argc > 1) ? argv[1] : "d:/ministral3_q4_0.gguf";
    
    printf("Model: %s\n\n", model_path);
    fflush(stdout);
    
    gguf_context_t ctx;
    int result = gguf_open(model_path, &ctx);
    printf("[DEBUG] gguf_open returned: %d\n", result);
    fflush(stdout);
    
    if (result != 0) {
        printf("[FAIL] Could not open model\n");
        return 1;
    }
    
    printf("[OK] GGUF loaded\n");
    printf("  Version: %u\n", ctx.header.version);
    printf("  Tensors: %llu\n", (unsigned long long)ctx.header.tensor_count);
    printf("  Metadata: %llu pairs\n", (unsigned long long)ctx.header.metadata_kv_count);
    printf("  Data offset: 0x%llX\n", (unsigned long long)ctx.data_offset);
    
    /* Validate token_embd.weight */
    validate_tensor(&ctx, "token_embd.weight");
    
    /* Validate a few more Q4_0 tensors */
    validate_tensor(&ctx, "v.blk.0.attn_q.weight");
    validate_tensor(&ctx, "v.blk.0.attn_k.weight");
    validate_tensor(&ctx, "v.blk.0.attn_v.weight");
    
    printf("\n=================================================\n");
    printf("Phase 1 validation complete\n");
    printf("Next: Compare against llama.cpp reference output\n");
    
    gguf_close(&ctx);
    return 0;
}
