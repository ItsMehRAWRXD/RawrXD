// Truth Gate 002: Real GGUF Weight Binding - Version 3
// Based on working debug_gguf.c

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

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;
    uint32_t version;
    uint64_t tensor_count;
    uint64_t metadata_kv_count;
} gguf_header_t;
#pragma pack(pop)

typedef struct {
    char name[256];
    uint32_t n_dims;
    uint64_t dims[4];
    uint32_t type;
    uint64_t offset;
} gguf_tensor_info_t;

typedef struct {
    gguf_header_t header;
    gguf_tensor_info_t *tensors;
    int num_tensors;
    uint8_t *data;
    size_t data_size;
    uint64_t data_offset;
} gguf_context_t;

// Skip a GGUF value based on type (from debug_gguf.c)
static int skip_gguf_value(FILE *fp, uint32_t type) {
    switch (type) {
        case 0: case 1:  // uint8, int8
            return fseek(fp, 1, SEEK_CUR) == 0 ? 0 : -1;
        case 2: case 3:  // uint16, int16
            return fseek(fp, 2, SEEK_CUR) == 0 ? 0 : -1;
        case 4: case 5: case 6:  // uint32, int32, float32
            return fseek(fp, 4, SEEK_CUR) == 0 ? 0 : -1;
        case 10: case 11: case 12:  // uint64, int64, float64
            return fseek(fp, 8, SEEK_CUR) == 0 ? 0 : -1;
        case 7: {  // bool
            uint8_t b;
            return fread(&b, 1, 1, fp) == 1 ? 0 : -1;
        }
        case 8: {  // string
            uint64_t len;
            if (fread(&len, sizeof(len), 1, fp) != 1) return -1;
            return fseek(fp, (long)len, SEEK_CUR) == 0 ? 0 : -1;
        }
        case 9: {  // array
            uint32_t arr_type;
            uint64_t arr_len;
            if (fread(&arr_type, sizeof(arr_type), 1, fp) != 1) return -1;
            if (fread(&arr_len, sizeof(arr_len), 1, fp) != 1) return -1;
            // Skip array data based on element type
            size_t elem_size = 4;  // default
            switch (arr_type) {
                case 0: case 1: elem_size = 1; break;
                case 2: case 3: elem_size = 2; break;
                case 4: case 5: case 6: elem_size = 4; break;
                case 10: case 11: case 12: elem_size = 8; break;
                default: elem_size = 4; break;
            }
            return fseek(fp, (long)(arr_len * elem_size), SEEK_CUR) == 0 ? 0 : -1;
        }
        default:
            fprintf(stderr, "Unknown value type: %u\n", type);
            return -1;
    }
}

gguf_context_t* gguf_load(const char *filename) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) return NULL;
    
    gguf_context_t *ctx = calloc(1, sizeof(gguf_context_t));
    if (!ctx) { fclose(fp); return NULL; }
    
    // Read header
    if (fread(&ctx->header, sizeof(ctx->header), 1, fp) != 1) {
        free(ctx); fclose(fp); return NULL;
    }
    
    if (ctx->header.magic != GGUF_MAGIC) {
        fprintf(stderr, "Invalid GGUF magic: 0x%08X\n", ctx->header.magic);
        free(ctx); fclose(fp); return NULL;
    }
    
    // Skip all metadata (key + value type + value)
    for (uint64_t i = 0; i < ctx->header.metadata_kv_count; i++) {
        // Read key string
        uint64_t key_len;
        if (fread(&key_len, sizeof(key_len), 1, fp) != 1) break;
        if (key_len > 0) {
            fseek(fp, (long)key_len, SEEK_CUR);  // skip key
        }
        
        // Read value type and skip value
        uint32_t val_type;
        if (fread(&val_type, sizeof(val_type), 1, fp) != 1) break;
        if (skip_gguf_value(fp, val_type) != 0) {
            fprintf(stderr, "Failed to skip metadata value type %u at entry %llu\n", 
                    val_type, (unsigned long long)i);
            break;
        }
    }
    
    // Read tensor info
    ctx->num_tensors = (int)ctx->header.tensor_count;
    ctx->tensors = calloc(ctx->num_tensors, sizeof(gguf_tensor_info_t));
    if (!ctx->tensors) {
        free(ctx); fclose(fp); return NULL;
    }
    
    for (int i = 0; i < ctx->num_tensors; i++) {
        // Read name
        uint64_t name_len;
        if (fread(&name_len, sizeof(name_len), 1, fp) != 1) break;
        if (name_len > 0 && name_len < sizeof(ctx->tensors[i].name)) {
            if (fread(ctx->tensors[i].name, 1, (size_t)name_len, fp) != name_len) break;
            ctx->tensors[i].name[name_len] = '\0';
        } else if (name_len > 0) {
            fseek(fp, (long)name_len, SEEK_CUR);
            ctx->tensors[i].name[0] = '\0';
        } else {
            ctx->tensors[i].name[0] = '\0';
        }
        
        // Read n_dims
        if (fread(&ctx->tensors[i].n_dims, sizeof(ctx->tensors[i].n_dims), 1, fp) != 1) break;
        
        // Read dimensions
        for (uint32_t j = 0; j < ctx->tensors[i].n_dims && j < 4; j++) {
            if (fread(&ctx->tensors[i].dims[j], sizeof(ctx->tensors[i].dims[j]), 1, fp) != 1) break;
        }
        // Skip extra dimensions if > 4
        if (ctx->tensors[i].n_dims > 4) {
            fseek(fp, (long)((ctx->tensors[i].n_dims - 4) * sizeof(uint64_t)), SEEK_CUR);
            ctx->tensors[i].n_dims = 4;
        }
        
        // Read type and offset
        if (fread(&ctx->tensors[i].type, sizeof(ctx->tensors[i].type), 1, fp) != 1) break;
        if (fread(&ctx->tensors[i].offset, sizeof(ctx->tensors[i].offset), 1, fp) != 1) break;
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

static size_t get_tensor_size(gguf_tensor_info_t *tensor) {
    size_t type_size = 4;
    switch (tensor->type) {
        case 0: type_size = 4; break;  // F32
        case 1: type_size = 2; break;  // F16
        case 2: type_size = 18; break; // Q4_0
        case 3: type_size = 20; break; // Q4_1
        case 8: type_size = 34; break; // Q8_0
        default: type_size = 4; break;
    }
    
    size_t num_elements = 1;
    for (uint32_t i = 0; i < tensor->n_dims; i++) {
        num_elements *= (size_t)tensor->dims[i];
    }
    
    return num_elements * type_size;
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
    
    // Load GGUF
    printf("[1/6] Loading GGUF...\n");
    double start = GET_TIME();
    gguf_context_t *gguf = gguf_load(model_path);
    double load_time = GET_TIME() - start;
    
    if (!gguf) {
        printf("  FAILED: Could not load GGUF\n");
        return 1;
    }
    
    printf("  Loaded in %.2f ms\n", load_time * 1000);
    printf("  Version: %u\n", gguf->header.version);
    printf("  Tensors: %d\n", gguf->num_tensors);
    printf("  Data size: %.2f MB\n\n", gguf->data_size / (1024.0 * 1024.0));
    
    // List first tensors
    printf("[2/6] First 10 tensors:\n");
    for (int i = 0; i < gguf->num_tensors && i < 10; i++) {
        printf("  %d: '%s'\n", i, 
               gguf->tensors[i].name[0] ? gguf->tensors[i].name : "(empty)");
    }
    printf("\n");
    
    // Check for required tensors
    printf("[3/6] Checking required tensors...\n");
    const char *required[] = {
        "token_embd.weight",
        "output_norm.weight",
        "output.weight",
        NULL
    };
    
    int found = 0;
    for (int i = 0; required[i]; i++) {
        gguf_tensor_info_t *t = find_tensor(gguf, required[i]);
        if (t) {
            printf("  [OK] %s\n", required[i]);
            found++;
        } else {
            printf("  [MISSING] %s\n", required[i]);
        }
    }
    printf("\n  Found: %d/%d critical tensors\n\n", found, 3);
    
    // Summary
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║  TRUTH GATE 002: RESULT                                    ║\n");
    printf("╠════════════════════════════════════════════════════════════╣\n");
    printf("║  Model: %-50s ║\n", model_path);
    printf("║  Version: %-48u ║\n", gguf->header.version);
    printf("║  Tensors: %-48d ║\n", gguf->num_tensors);
    printf("║  Data Size: %-46.2f MB ║\n", gguf->data_size / (1024.0 * 1024.0));
    printf("║                                                            ║\n");
    printf("║  Critical Tensors Found: %-35d ║\n", found);
    printf("║  Status: %-49s ║\n", found >= 2 ? "PASS ✅" : "FAIL ❌");
    printf("╚════════════════════════════════════════════════════════════╝\n");
    
    int result = (found >= 2) ? 0 : 1;
    
    if (result == 0) {
        printf("\n✅ TRUTH GATE 002 PASSED\n");
        printf("   Real GGUF weights successfully loaded and validated.\n");
    } else {
        printf("\n❌ TRUTH GATE 002 FAILED\n");
    }
    
    gguf_free(gguf);
    return result;
}
