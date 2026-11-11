/*
 * Truth Gate 003 - Phase 1: Real Tensor Validation
 * 
 * Extracts Q4_0 tensors from real GGUF model and validates
 * dequantization produces sane outputs.
 */

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <string.h>

/* GGUF v3 structures */
#pragma pack(push, 1)
typedef struct {
    uint32_t magic;
    uint32_t version;
    uint64_t n_tensors;
    uint64_t n_kv;
} gguf_header_t;

typedef struct {
    uint64_t offset;
    uint64_t size;
    uint32_t type;
    uint64_t n_dims;
    uint64_t dims[4];
} tensor_info_t;
#pragma pack(pop)

/* Q4_0 block structure */
typedef struct {
    uint16_t delta;
    uint8_t quants[16];
} block_q4_0;

/* File handle */
typedef struct {
    FILE *fp;
    uint64_t data_offset;
    uint64_t n_tensors;
    tensor_info_t *tensors;
    char **tensor_names;
} gguf_file_t;

/* ============== GGUF PARSING (from TG002) ============== */

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

static int read_str(FILE *fp, char *out, size_t max_len) {
    uint8_t len_buf[8];
    if (fread(len_buf, 1, 8, fp) != 8) return -1;
    uint64_t len = read_u64_le(len_buf);
    if (len >= max_len) {
        fseek(fp, (long)len, SEEK_CUR);
        return -1;
    }
    if (fread(out, 1, (size_t)len, fp) != len) return -1;
    out[len] = '\0';
    return 0;
}

static int skip_kv_value(FILE *fp, uint32_t type) {
    switch (type) {
        case 0: case 1: fseek(fp, 1, SEEK_CUR); break;
        case 2: case 3: fseek(fp, 2, SEEK_CUR); break;
        case 4: case 5: case 6: fseek(fp, 4, SEEK_CUR); break;
        case 7: fseek(fp, 1, SEEK_CUR); break;
        case 8: {
            uint8_t len_buf[8];
            fread(len_buf, 1, 8, fp);
            uint64_t len = read_u64_le(len_buf);
            fseek(fp, (long)len, SEEK_CUR);
            break;
        }
        case 9: {
            uint8_t arr_type_buf[4], count_buf[8];
            fread(arr_type_buf, 1, 4, fp);
            fread(count_buf, 1, 8, fp);
            uint32_t arr_type = read_u32_le(arr_type_buf);
            uint64_t count = read_u64_le(count_buf);
            for (uint64_t i = 0; i < count; i++) {
                if (skip_kv_value(fp, arr_type) < 0) return -1;
            }
            break;
        }
        case 10: case 11: case 12: fseek(fp, 8, SEEK_CUR); break;
        default: fseek(fp, 4, SEEK_CUR); break;
    }
    return 0;
}

gguf_file_t* gguf_open(const char *path) {
    printf("[DEBUG] Entering gguf_open\n");
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        printf("[DEBUG] fopen failed for: %s\n", path);
        perror("[DEBUG] Error");
        return NULL;
    }
    printf("[DEBUG] fopen succeeded\n");
    
    gguf_file_t *gf = calloc(1, sizeof(gguf_file_t));
    if (!gf) {
        printf("[DEBUG] calloc failed\n");
        fclose(fp);
        return NULL;
    }
    gf->fp = fp;
    
    uint8_t hdr[24];
    if (fread(hdr, 1, 24, fp) != 24) {
        printf("[DEBUG] fread header failed\n");
        goto fail;
    }
    printf("[DEBUG] Header read OK\n");
    
    uint32_t magic = read_u32_le(hdr);
    printf("[DEBUG] Magic: 0x%08X (expected 0x46554747)\n", magic);
    if (magic != 0x46554747) {
        printf("[DEBUG] Magic mismatch\n");
        goto fail;
    }
    
    gf->n_tensors = read_u64_le(hdr + 8);
    uint64_t n_kv = read_u64_le(hdr + 16);
    printf("[DEBUG] Tensors: %llu, KV: %llu\n", (unsigned long long)gf->n_tensors, (unsigned long long)n_kv);
    
    /* Skip KV pairs */
    for (uint64_t i = 0; i < n_kv; i++) {
        char key[256];
        if (read_str(fp, key, sizeof(key)) < 0) {
            printf("[DEBUG] Failed to read KV key %llu\n", (unsigned long long)i);
            goto fail;
        }
        uint8_t type_buf[4];
        if (fread(type_buf, 1, 4, fp) != 4) {
            printf("[DEBUG] Failed to read KV type %llu\n", (unsigned long long)i);
            goto fail;
        }
        uint32_t type = read_u32_le(type_buf);
        if (skip_kv_value(fp, type) < 0) {
            printf("[DEBUG] Failed to skip KV value %llu (type %u)\n", (unsigned long long)i, type);
            goto fail;
        }
    }
    printf("[DEBUG] KV pairs skipped OK\n");
    
    /* Read tensor info */
    printf("[DEBUG] Allocating for %llu tensors\n", (unsigned long long)gf->n_tensors);
    gf->tensors = calloc(gf->n_tensors, sizeof(tensor_info_t));
    gf->tensor_names = calloc(gf->n_tensors, sizeof(char*));
    if (!gf->tensors || !gf->tensor_names) {
        printf("[DEBUG] Failed to allocate tensor arrays\n");
        goto fail;
    }
    
    for (uint64_t i = 0; i < gf->n_tensors; i++) {
        char name[256];
        printf("[DEBUG] Reading tensor %llu at pos %lld\n", (unsigned long long)i, _ftelli64(fp));
        if (read_str(fp, name, sizeof(name)) < 0) {
            printf("[DEBUG] Failed to read tensor name %llu\n", (unsigned long long)i);
            goto fail;
        }
        printf("[DEBUG] Tensor %llu name: %s\n", (unsigned long long)i, name);
        gf->tensor_names[i] = strdup(name);
        
        /* GGUF format: n_dims (uint32), dims[], type (uint32), offset (uint64) */
        uint8_t ndims_buf[4];
        fread(ndims_buf, 1, 4, fp);
        gf->tensors[i].n_dims = read_u32_le(ndims_buf);
        
        if (gf->tensors[i].n_dims > 4) gf->tensors[i].n_dims = 4;
        for (uint64_t d = 0; d < gf->tensors[i].n_dims; d++) {
            uint8_t dim_buf[8];
            fread(dim_buf, 1, 8, fp);
            gf->tensors[i].dims[d] = read_u64_le(dim_buf);
        }
        
        uint8_t type_buf[4];
        fread(type_buf, 1, 4, fp);
        gf->tensors[i].type = read_u32_le(type_buf);
        
        uint8_t offset_buf[8];
        fread(offset_buf, 1, 8, fp);
        /* offset stored but we calculate our own */
        
        /* Alignment to 32 bytes after each tensor info (GGUF v3 spec) */
        long long tpos = _ftelli64(fp);
        long long tpad = (32 - (tpos % 32)) % 32;
        if (tpad > 0) _fseeki64(fp, (long)tpad, SEEK_CUR);
    }
    
    /* Data offset - align to 32 bytes */
    long long data_pos = _ftelli64(fp);
    long long data_pad = (32 - (data_pos % 32)) % 32;
    gf->data_offset = data_pos + data_pad;
    
    /* Calculate tensor offsets */
    uint64_t offset = 0;
    for (uint64_t i = 0; i < gf->n_tensors; i++) {
        gf->tensors[i].offset = gf->data_offset + offset;
        
        uint64_t n_elements = 1;
        for (uint64_t d = 0; d < gf->tensors[i].n_dims; d++) {
            n_elements *= gf->tensors[i].dims[d];
        }
        
        size_t block_size = 32, type_size = 18; /* Q4_0 */
        if (gf->tensors[i].type == 0) { block_size = 1; type_size = 4; } /* F32 */
        else if (gf->tensors[i].type == 1) { block_size = 1; type_size = 2; } /* F16 */
        
        uint64_t n_blocks = (n_elements + block_size - 1) / block_size;
        gf->tensors[i].size = n_blocks * type_size;
        offset += gf->tensors[i].size;
        offset = (offset + 63) & ~63;
    }
    
    return gf;
    
fail:
    fclose(fp);
    free(gf);
    return NULL;
}

void gguf_close(gguf_file_t *gf) {
    if (!gf) return;
    if (gf->fp) fclose(gf->fp);
    if (gf->tensor_names) {
        for (uint64_t i = 0; i < gf->n_tensors; i++) free(gf->tensor_names[i]);
        free(gf->tensor_names);
    }
    free(gf->tensors);
    free(gf);
}

int gguf_find_tensor(gguf_file_t *gf, const char *name) {
    for (uint64_t i = 0; i < gf->n_tensors; i++) {
        if (strcmp(gf->tensor_names[i], name) == 0) return (int)i;
    }
    return -1;
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

void validate_real_tensor(const char *model_path, const char *tensor_name) {
    printf("Truth Gate 003 - Phase 1: Real Tensor Validation\n");
    printf("=================================================\n\n");
    
    printf("Model: %s\n", model_path);
    printf("Tensor: %s\n\n", tensor_name);
    
    /* Open GGUF */
    printf("[DEBUG] Calling gguf_open with: %s\n", model_path);
    gguf_file_t *gf = gguf_open(model_path);
    if (!gf) {
        printf("[FAIL] Could not open model\n");
        return;
    }
    
    printf("[OK] GGUF loaded\n");
    printf("  Total tensors: %llu\n", (unsigned long long)gf->n_tensors);
    
    /* Find tensor */
    int idx = gguf_find_tensor(gf, tensor_name);
    if (idx < 0) {
        printf("\n[FAIL] Tensor not found: %s\n", tensor_name);
        printf("\nAvailable tensors (first 20):\n");
        for (uint64_t i = 0; i < gf->n_tensors && i < 20; i++) {
            const char *type_str = "?";
            switch (gf->tensors[i].type) {
                case 0: type_str = "F32"; break;
                case 1: type_str = "F16"; break;
                case 2: type_str = "Q4_0"; break;
                case 3: type_str = "Q4_1"; break;
                case 12: type_str = "Q4_K"; break;
            }
            printf("  [%3llu] %-50s %s\n", i, gf->tensor_names[i], type_str);
        }
        gguf_close(gf);
        return;
    }
    
    printf("\n[OK] Found tensor: %s\n", tensor_name);
    printf("  Type: %d\n", gf->tensors[idx].type);
    printf("  Dims: %llu", (unsigned long long)gf->tensors[idx].n_dims);
    for (uint64_t d = 0; d < gf->tensors[idx].n_dims; d++) {
        printf(" x %llu", (unsigned long long)gf->tensors[idx].dims[d]);
    }
    printf("\n");
    printf("  Size: %llu bytes\n", (unsigned long long)gf->tensors[idx].size);
    
    /* Only validate Q4_0 tensors */
    if (gf->tensors[idx].type != 2) {
        printf("\n[SKIP] Only Q4_0 tensors supported for validation\n");
        gguf_close(gf);
        return;
    }
    
    /* Read and dequantize */
    size_t n_blocks = gf->tensors[idx].size / sizeof(block_q4_0);
    size_t n_elements = n_blocks * 32;
    
    printf("\n[LOAD] Reading %zu Q4_0 blocks (%zu elements)...\n", n_blocks, n_elements);
    
    block_q4_0 *blocks = malloc(gf->tensors[idx].size);
    float *dequantized = malloc(n_elements * sizeof(float));
    
    if (!blocks || !dequantized) {
        printf("[FAIL] Memory allocation failed\n");
        free(blocks);
        free(dequantized);
        gguf_close(gf);
        return;
    }
    
    fseek(gf->fp, (long)gf->tensors[idx].offset, SEEK_SET);
    if (fread(blocks, 1, gf->tensors[idx].size, gf->fp) != gf->tensors[idx].size) {
        printf("[FAIL] Failed to read tensor data\n");
        free(blocks);
        free(dequantized);
        gguf_close(gf);
        return;
    }
    
    /* Dequantize */
    dequantize_q4_0(blocks, (int)n_blocks, dequantized);
    
    /* Analyze dequantized values */
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
    
    printf("\n[ANALYSIS] Dequantized values:\n");
    printf("  Count:     %zu\n", n_elements);
    printf("  NaN:       %d\n", nan_count);
    printf("  Inf:       %d\n", inf_count);
    printf("  Min:       %.6f\n", min_val);
    printf("  Max:       %.6f\n", max_val);
    printf("  Mean:      %.6f\n", mean);
    printf("  Std Dev:   %.6f\n", std_dev);
    
    /* Sample values */
    printf("\n  Sample values (first 10):\n");
    for (size_t i = 0; i < 10 && i < n_elements; i++) {
        printf("    [%6zu] = %10.6f\n", i, dequantized[i]);
    }
    
    /* Validation checks */
    printf("\n[VALIDATION]\n");
    int pass = 1;
    
    if (nan_count > 0) {
        printf("  [FAIL] NaN values detected\n");
        pass = 0;
    } else {
        printf("  [PASS] No NaN values\n");
    }
    
    if (inf_count > 0) {
        printf("  [FAIL] Inf values detected\n");
        pass = 0;
    } else {
        printf("  [PASS] No Inf values\n");
    }
    
    /* Check if values are in reasonable range for neural network weights */
    if (max_val > 100.0f || min_val < -100.0f) {
        printf("  [WARN] Values outside typical NN weight range [-100, 100]\n");
    } else {
        printf("  [PASS] Values in reasonable range\n");
    }
    
    if (std_dev > 0.0f) {
        printf("  [PASS] Non-zero variance (weights have magnitude)\n");
    } else {
        printf("  [WARN] Zero variance (all weights identical)\n");
    }
    
    printf("\n=================================================\n");
    if (pass) {
        printf("[PASS] Real tensor validation successful\n");
        printf("\nNext: Compare against llama.cpp reference output\n");
    } else {
        printf("[FAIL] Validation failed\n");
    }
    
    free(blocks);
    free(dequantized);
    gguf_close(gf);
}

int main(int argc, char **argv) {
    const char *model = (argc > 1) ? argv[1] : "d:/ministral3_q4_0.gguf";
    const char *tensor = (argc > 2) ? argv[2] : "token_embd.weight";
    
    printf("[DEBUG] Opening model: %s\n", model);
    validate_real_tensor(model, tensor);
    return 0;
}
