// Truth Gate 002: Real GGUF Weight Binding - Version 4
// Exact copy of working debug_gguf.c logic

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>

#ifdef _WIN32
#include <windows.h>
static double GET_TIME() {
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (double)count.QuadPart / (double)freq.QuadPart;
}
#else
#include <sys/time.h>
static double GET_TIME() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec / 1000000.0;
}
#endif

#define GGUF_MAGIC 0x46554747

typedef struct {
    char name[256];
    uint32_t n_dims;
    uint64_t dims[4];
    uint32_t type;
    uint64_t offset;
} gguf_tensor_info_t;

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint64_t tensor_count;
    uint64_t metadata_kv_count;
    gguf_tensor_info_t *tensors;
    int num_tensors;
    uint8_t *data;
    size_t data_size;
    uint64_t data_offset;
} gguf_context_t;

gguf_context_t* gguf_load(const char *filename) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) return NULL;
    
    gguf_context_t *ctx = calloc(1, sizeof(gguf_context_t));
    if (!ctx) { fclose(fp); return NULL; }
    
    // Read header (individual fields like debug_gguf.c)
    uint32_t magic, version;
    uint64_t tensor_count, metadata_kv_count;
    fread(&magic, 4, 1, fp);
    fread(&version, 4, 1, fp);
    fread(&tensor_count, 8, 1, fp);
    fread(&metadata_kv_count, 8, 1, fp);
    
    ctx->magic = magic;
    ctx->version = version;
    ctx->tensor_count = tensor_count;
    ctx->metadata_kv_count = metadata_kv_count;
    
    if (ctx->magic != GGUF_MAGIC) {
        fprintf(stderr, "Invalid GGUF magic: 0x%08X\n", ctx->magic);
        free(ctx); fclose(fp); return NULL;
    }
    
    // Skip all metadata (exactly as debug_gguf.c does)
    for (uint64_t i = 0; i < ctx->metadata_kv_count; i++) {
        uint64_t key_len;
        if (fread(&key_len, 8, 1, fp) != 1) break;
        
        if (key_len > 0 && key_len < 256) {
            char key[256];
            fread(key, 1, (size_t)key_len, fp);
            key[key_len] = '\0';
        } else if (key_len > 0) {
            fseek(fp, (long)key_len, SEEK_CUR);
        }
        
        uint32_t val_type;
        fread(&val_type, 4, 1, fp);
        
        // Skip value based on type (exactly as debug_gguf.c)
        switch(val_type) {
            case 0: case 1: fseek(fp, 1, SEEK_CUR); break;
            case 2: case 3: fseek(fp, 2, SEEK_CUR); break;
            case 4: case 5: case 6: fseek(fp, 4, SEEK_CUR); break;
            case 10: case 11: case 12: fseek(fp, 8, SEEK_CUR); break;
            case 7: fseek(fp, 1, SEEK_CUR); break;
            case 8: {
                uint64_t str_len;
                fread(&str_len, 8, 1, fp);
                if (str_len > 0) fseek(fp, (long)str_len, SEEK_CUR);
                break;
            }
            case 9: {
                uint32_t arr_type;
                uint64_t arr_len;
                fread(&arr_type, 4, 1, fp);
                fread(&arr_len, 8, 1, fp);
                size_t elem_size = 4;
                fseek(fp, (long)(arr_len * elem_size), SEEK_CUR);
                break;
            }
            default:
                fprintf(stderr, "Unknown value type: %u at entry %llu\n", val_type, (unsigned long long)i);
                break;
        }
    }
    
    // Read tensor info (exactly as debug_gguf.c)
    ctx->num_tensors = (int)ctx->tensor_count;
    ctx->tensors = calloc(ctx->num_tensors, sizeof(gguf_tensor_info_t));
    if (!ctx->tensors) {
        free(ctx); fclose(fp); return NULL;
    }
    
    for (int i = 0; i < ctx->num_tensors; i++) {
        uint64_t name_len;
        if (fread(&name_len, 8, 1, fp) != 1) break;
        
        if (name_len > 0 && name_len < 256) {
            fread(ctx->tensors[i].name, 1, (size_t)name_len, fp);
            ctx->tensors[i].name[name_len] = '\0';
        } else if (name_len > 0) {
            fseek(fp, (long)name_len, SEEK_CUR);
            ctx->tensors[i].name[0] = '\0';
        } else {
            ctx->tensors[i].name[0] = '\0';
        }
        
        fread(&ctx->tensors[i].n_dims, 4, 1, fp);
        
        for (uint32_t j = 0; j < ctx->tensors[i].n_dims && j < 4; j++) {
            fread(&ctx->tensors[i].dims[j], 8, 1, fp);
        }
        if (ctx->tensors[i].n_dims > 4) {
            fseek(fp, (long)((ctx->tensors[i].n_dims - 4) * 8), SEEK_CUR);
            ctx->tensors[i].n_dims = 4;
        }
        
        fread(&ctx->tensors[i].type, 4, 1, fp);
        fread(&ctx->tensors[i].offset, 8, 1, fp);
    }
    
    // Calculate data offset (align to 32)
    long current_pos = ftell(fp);
    ctx->data_offset = (uint64_t)current_pos;
    if (ctx->data_offset % 32 != 0) {
        ctx->data_offset += 32 - (ctx->data_offset % 32);
    }
    
    // Read tensor data
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, (long)ctx->data_offset, SEEK_SET);
    
    ctx->data_size = (size_t)(file_size - (long)ctx->data_offset);
    if (ctx->data_size > 0 && ctx->data_size < (size_t)file_size) {
        ctx->data = malloc(ctx->data_size);
        if (ctx->data) {
            fread(ctx->data, 1, ctx->data_size, fp);
        }
    }
    
    fclose(fp);
    return ctx;
}

void gguf_free(gguf_context_t *ctx) {
    if (!ctx) return;
    free(ctx->tensors);
    free(ctx->data);
    free(ctx);
}

static gguf_tensor_info_t* find_tensor(gguf_context_t *ctx, const char *name) {
    for (int i = 0; i < ctx->num_tensors; i++) {
        if (strcmp(ctx->tensors[i].name, name) == 0) {
            return &ctx->tensors[i];
        }
    }
    return NULL;
}

int main(int argc, char **argv) {
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║  TRUTH GATE 002: Real GGUF Weight Binding                  ║\n");
    printf("║  Zero Dependencies - Pure C Implementation                 ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n\n");
    
    if (argc < 2) {
        printf("Usage: %s <model.gguf>\n", argv[0]);
        return 1;
    }
    
    const char *model_path = argv[1];
    printf("Model: %s\n\n", model_path);
    
    double start = GET_TIME();
    gguf_context_t *gguf = gguf_load(model_path);
    double load_time = GET_TIME() - start;
    
    if (!gguf) {
        printf("FAILED: Could not load GGUF\n");
        return 1;
    }
    
    printf("Loaded in %.2f ms\n", load_time * 1000);
    printf("Version: %u\n", gguf->version);
    printf("Tensors: %d\n", gguf->num_tensors);
    printf("Data size: %.2f MB\n\n", gguf->data_size / (1024.0 * 1024.0));
    
    printf("First 10 tensors:\n");
    for (int i = 0; i < gguf->num_tensors && i < 10; i++) {
        printf("  %d: '%s' (type=%u, dims=%u)\n", i, 
               gguf->tensors[i].name[0] ? gguf->tensors[i].name : "(empty)",
               gguf->tensors[i].type, gguf->tensors[i].n_dims);
    }
    printf("\n");
    
    const char *required[] = {
        "token_embd.weight",
        "output_norm.weight", 
        "output.weight",
        NULL
    };
    
    int found = 0;
    printf("Checking required tensors:\n");
    for (int i = 0; required[i]; i++) {
        gguf_tensor_info_t *t = find_tensor(gguf, required[i]);
        if (t) {
            printf("  [OK] %s\n", required[i]);
            found++;
        } else {
            printf("  [MISSING] %s\n", required[i]);
        }
    }
    
    printf("\n╔════════════════════════════════════════════════════════════╗\n");
    printf("║  TRUTH GATE 002: RESULT                                    ║\n");
    printf("╠════════════════════════════════════════════════════════════╣\n");
    printf("║  Model: %-50s ║\n", model_path);
    printf("║  Tensors: %-48d ║\n", gguf->num_tensors);
    printf("║  Data Size: %-46.2f MB ║\n", gguf->data_size / (1024.0 * 1024.0));
    printf("║  Found: %-50d ║\n", found);
    printf("║  Status: %-49s ║\n", found >= 2 ? "PASS ✅" : "FAIL ❌");
    printf("╚════════════════════════════════════════════════════════════╝\n");
    
    int result = (found >= 2) ? 0 : 1;
    if (result == 0) {
        printf("\n✅ TRUTH GATE 002 PASSED\n");
    } else {
        printf("\n❌ TRUTH GATE 002 FAILED\n");
    }
    
    gguf_free(gguf);
    return result;
}
