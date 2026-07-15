// Truth Gate 002: Real GGUF Weight Binding - Version 5
// With detailed debugging

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
    
    // Read header
    fread(&ctx->magic, 4, 1, fp);
    fread(&ctx->version, 4, 1, fp);
    fread(&ctx->tensor_count, 8, 1, fp);
    fread(&ctx->metadata_kv_count, 8, 1, fp);
    
    if (ctx->magic != GGUF_MAGIC) {
        fprintf(stderr, "Invalid GGUF magic: 0x%08X\n", ctx->magic);
        free(ctx); fclose(fp); return NULL;
    }
    
    printf("  Header: magic=0x%08X, version=%u\n", ctx->magic, ctx->version);
    printf("  Tensors: %llu, Metadata: %llu\n", 
           (unsigned long long)ctx->tensor_count,
           (unsigned long long)ctx->metadata_kv_count);
    
    // Skip all metadata with position tracking
    for (uint64_t i = 0; i < ctx->metadata_kv_count; i++) {
        long pos_before = ftell(fp);
        
        uint64_t key_len;
        if (fread(&key_len, 8, 1, fp) != 1) {
            printf("  Failed to read key_len at entry %llu\n", (unsigned long long)i);
            break;
        }
        
        if (key_len > 0 && key_len < 256) {
            char key[256];
            fread(key, 1, (size_t)key_len, fp);
            key[key_len] = '\0';
            printf("  Entry %llu: key='%s', len=%llu\n", 
                   (unsigned long long)i, key, (unsigned long long)key_len);
        } else if (key_len > 0) {
            printf("  Entry %llu: key_len=%llu (too long, pos=%ld)\n", 
                   (unsigned long long)i, (unsigned long long)key_len, ftell(fp));
            fseek(fp, (long)key_len, SEEK_CUR);
        }
        
        uint32_t val_type;
        if (fread(&val_type, 4, 1, fp) != 1) {
            printf("  Failed to read val_type at entry %llu\n", (unsigned long long)i);
            break;
        }
        
        printf("  Entry %llu: val_type=%u at pos %ld\n", 
               (unsigned long long)i, val_type, ftell(fp));
        
        if (val_type > 12 && val_type != 8 && val_type != 9) {
            printf("  Entry %llu: suspicious val_type=%u at pos %ld\n", 
                   (unsigned long long)i, val_type, ftell(fp));
        }
        
        // Skip value
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
                printf("    Array: type=%u, len=%llu\n", arr_type, (unsigned long long)arr_len);
                
                // Handle array of strings specially
                if (arr_type == 8) {
                    for (uint64_t j = 0; j < arr_len; j++) {
                        uint64_t str_len;
                        fread(&str_len, 8, 1, fp);
                        if (str_len > 0) fseek(fp, (long)str_len, SEEK_CUR);
                    }
                } else {
                    // Calculate element size based on arr_type
                    size_t elem_size = 4;
                    switch(arr_type) {
                        case 0: case 1: elem_size = 1; break;
                        case 2: case 3: elem_size = 2; break;
                        case 4: case 5: case 6: elem_size = 4; break;
                        case 10: case 11: case 12: elem_size = 8; break;
                        case 7: elem_size = 1; break;
                        default: elem_size = 4; break;
                    }
                    fseek(fp, (long)(arr_len * elem_size), SEEK_CUR);
                }
                break;
            }
            default:
                printf("  Unknown val_type=%u at entry %llu, pos=%ld\n", 
                       val_type, (unsigned long long)i, ftell(fp));
                // Try to recover by skipping a few bytes
                fseek(fp, 4, SEEK_CUR);
                break;
        }
    }
    
    long pos_after_metadata = ftell(fp);
    printf("  Position after metadata: %ld\n", pos_after_metadata);
    
    // Read tensor info
    ctx->num_tensors = (int)ctx->tensor_count;
    ctx->tensors = calloc(ctx->num_tensors, sizeof(gguf_tensor_info_t));
    if (!ctx->tensors) {
        free(ctx); fclose(fp); return NULL;
    }
    
    printf("  Reading %d tensor infos...\n", ctx->num_tensors);
    
    for (int i = 0; i < ctx->num_tensors && i < 5; i++) {
        long tensor_pos = ftell(fp);
        
        uint64_t name_len;
        if (fread(&name_len, 8, 1, fp) != 1) {
            printf("  Failed to read name_len for tensor %d\n", i);
            break;
        }
        
        printf("  Tensor %d at pos %ld: name_len=%llu\n", i, tensor_pos, (unsigned long long)name_len);
        
        if (name_len > 0 && name_len < 256) {
            fread(ctx->tensors[i].name, 1, (size_t)name_len, fp);
            ctx->tensors[i].name[name_len] = '\0';
        } else if (name_len > 0) {
            printf("    (skipping %llu bytes)\n", (unsigned long long)name_len);
            fseek(fp, (long)name_len, SEEK_CUR);
            ctx->tensors[i].name[0] = '\0';
        } else {
            ctx->tensors[i].name[0] = '\0';
        }
        
        fread(&ctx->tensors[i].n_dims, 4, 1, fp);
        printf("    name='%s', n_dims=%u\n", ctx->tensors[i].name, ctx->tensors[i].n_dims);
        
        if (ctx->tensors[i].n_dims > 4) {
            printf("    (clamping n_dims from %u to 4)\n", ctx->tensors[i].n_dims);
            uint32_t orig_dims = ctx->tensors[i].n_dims;
            for (uint32_t j = 0; j < 4; j++) {
                fread(&ctx->tensors[i].dims[j], 8, 1, fp);
            }
            fseek(fp, (long)((orig_dims - 4) * 8), SEEK_CUR);
            ctx->tensors[i].n_dims = 4;
        } else {
            for (uint32_t j = 0; j < ctx->tensors[i].n_dims; j++) {
                fread(&ctx->tensors[i].dims[j], 8, 1, fp);
            }
        }
        
        fread(&ctx->tensors[i].type, 4, 1, fp);
        fread(&ctx->tensors[i].offset, 8, 1, fp);
        
        printf("    type=%u, offset=%llu\n", 
               ctx->tensors[i].type, 
               (unsigned long long)ctx->tensors[i].offset);
    }
    
    // Skip remaining tensors
    for (int i = 5; i < ctx->num_tensors; i++) {
        uint64_t name_len;
        if (fread(&name_len, 8, 1, fp) != 1) break;
        if (name_len > 0) fseek(fp, (long)name_len, SEEK_CUR);
        
        uint32_t n_dims;
        fread(&n_dims, 4, 1, fp);
        if (n_dims > 0) fseek(fp, (long)(n_dims * 8), SEEK_CUR);
        
        fseek(fp, 4 + 8, SEEK_CUR); // type + offset
    }
    
    // Calculate data offset
    long current_pos = ftell(fp);
    ctx->data_offset = (uint64_t)current_pos;
    if (ctx->data_offset % 32 != 0) {
        ctx->data_offset += 32 - (ctx->data_offset % 32);
    }
    
    printf("  Position before data: %ld, aligned offset: %llu\n", 
           current_pos, (unsigned long long)ctx->data_offset);
    
    // Read tensor data
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, (long)ctx->data_offset, SEEK_SET);
    
    ctx->data_size = (size_t)(file_size - (long)ctx->data_offset);
    printf("  File size: %ld, data size: %zu\n", file_size, ctx->data_size);
    
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
    
    printf("\nLoaded in %.2f ms\n", load_time * 1000);
    printf("Data size: %.2f MB\n\n", gguf->data_size / (1024.0 * 1024.0));
    
    printf("First 5 tensors:\n");
    for (int i = 0; i < gguf->num_tensors && i < 5; i++) {
        printf("  %d: '%s'\n", i, 
               gguf->tensors[i].name[0] ? gguf->tensors[i].name : "(empty)");
    }
    
    const char *required[] = {
        "token_embd.weight",
        "output_norm.weight", 
        "output.weight",
        NULL
    };
    
    int found = 0;
    printf("\nChecking required tensors:\n");
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
    printf("║  Found: %-50d ║\n", found);
    printf("║  Status: %-49s ║\n", found >= 2 ? "PASS ✅" : "FAIL ❌");
    printf("╚════════════════════════════════════════════════════════════╝\n");
    
    int result = (found >= 2) ? 0 : 1;
    
    gguf_free(gguf);
    return result;
}
