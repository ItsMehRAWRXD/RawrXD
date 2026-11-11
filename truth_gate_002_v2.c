// Truth Gate 002: Real GGUF Weight Binding - Version 2
// Simplified, robust GGUF parser

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
#define GGUF_VERSION 3

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

// Read a GGUF string (length-prefixed)
static int read_gguf_string(FILE *fp, char *buf, size_t max_len) {
    uint64_t len;
    if (fread(&len, sizeof(len), 1, fp) != 1) return -1;
    if (len >= max_len) {
        // Skip the string
        fseek(fp, (long)len, SEEK_CUR);
        buf[0] = '\0';
        return 0;
    }
    if (fread(buf, 1, (size_t)len, fp) != len) return -1;
    buf[len] = '\0';
    return 0;
}

// Skip a GGUF value based on type
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
            // For simplicity, assume 4-byte elements
            return fseek(fp, (long)(arr_len * 4), SEEK_CUR) == 0 ? 0 : -1;
        }
        default:
            return -1;
    }
}

// Skip metadata value (reads type then skips value)
static int skip_metadata_value(FILE *fp) {
    uint32_t type;
    if (fread(&type, sizeof(type), 1, fp) != 1) return -1;
    return skip_gguf_value(fp, type);
}

gguf_context_t* gguf_load(const char *filename) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        fprintf(stderr, "Cannot open file: %s\n", filename);
        return NULL;
    }
    
    gguf_context_t *ctx = calloc(1, sizeof(gguf_context_t));
    if (!ctx) {
        fclose(fp);
        return NULL;
    }
    
    // Read header
    if (fread(&ctx->header, sizeof(ctx->header), 1, fp) != 1) {
        fprintf(stderr, "Failed to read header\n");
        free(ctx);
        fclose(fp);
        return NULL;
    }
    
    if (ctx->header.magic != GGUF_MAGIC) {
        fprintf(stderr, "Invalid GGUF magic: 0x%08X\n", ctx->header.magic);
        free(ctx);
        fclose(fp);
        return NULL;
    }
    
    printf("  Header: magic=0x%08X, version=%u, tensors=%llu, metadata=%llu\n",
           ctx->header.magic, ctx->header.version,
           (unsigned long long)ctx->header.tensor_count,
           (unsigned long long)ctx->header.metadata_kv_count);
    
    // Skip all metadata
    for (uint64_t i = 0; i < ctx->header.metadata_kv_count; i++) {
        char key[256];
        if (read_gguf_string(fp, key, sizeof(key)) != 0) {
            fprintf(stderr, "Failed to read metadata key %llu\n", (unsigned long long)i);
            break;
        }
        if (skip_metadata_value(fp) != 0) {
            fprintf(stderr, "Failed to skip metadata value %llu\n", (unsigned long long)i);
            break;
        }
    }
    
    // Read tensor info
    ctx->num_tensors = (int)ctx->header.tensor_count;
    ctx->tensors = calloc(ctx->num_tensors, sizeof(gguf_tensor_info_t));
    if (!ctx->tensors) {
        fprintf(stderr, "Failed to allocate tensor array\n");
        free(ctx);
        fclose(fp);
        return NULL;
    }
    
    printf("  Reading %d tensor infos...\n", ctx->num_tensors);
    
    for (int i = 0; i < ctx->num_tensors; i++) {
        // Read tensor name
        if (read_gguf_string(fp, ctx->tensors[i].name, sizeof(ctx->tensors[i].name)) != 0) {
            fprintf(stderr, "Failed to read tensor %d name\n", i);
            break;
        }
        
        // Read number of dimensions
        if (fread(&ctx->tensors[i].n_dims, sizeof(ctx->tensors[i].n_dims), 1, fp) != 1) {
            fprintf(stderr, "Failed to read tensor %d n_dims\n", i);
            break;
        }
        if (ctx->tensors[i].n_dims > 4) {
            fprintf(stderr, "Warning: tensor %d has %u dims, clamping\n", i, ctx->tensors[i].n_dims);
            ctx->tensors[i].n_dims = 4;
        }
        
        // Read dimensions
        for (uint32_t j = 0; j < ctx->tensors[i].n_dims; j++) {
            if (fread(&ctx->tensors[i].dims[j], sizeof(ctx->tensors[i].dims[j]), 1, fp) != 1) {
                fprintf(stderr, "Failed to read tensor %d dim %u\n", i, j);
                break;
            }
        }
        
        // Read type
        if (fread(&ctx->tensors[i].type, sizeof(ctx->tensors[i].type), 1, fp) != 1) {
            fprintf(stderr, "Failed to read tensor %d type\n", i);
            break;
        }
        
        // Read offset
        if (fread(&ctx->tensors[i].offset, sizeof(ctx->tensors[i].offset), 1, fp) != 1) {
            fprintf(stderr, "Failed to read tensor %d offset\n", i);
            break;
        }
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
            size_t read = fread(ctx->data, 1, ctx->data_size, fp);
            printf("  Read %zu bytes of tensor data\n", read);
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
    printf("  Tensors: %d\n", gguf->num_tensors);
    printf("  Data size: %.2f MB\n\n", gguf->data_size / (1024.0 * 1024.0));
    
    // List first tensors
    printf("[2/6] First 10 tensors:\n");
    for (int i = 0; i < gguf->num_tensors && i < 10; i++) {
        printf("  %d: '%s' (type=%u, dims=%u)\n", i, 
               gguf->tensors[i].name[0] ? gguf->tensors[i].name : "(empty)",
               gguf->tensors[i].type, gguf->tensors[i].n_dims);
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
    printf("║  Tensors: %-48d ║\n", gguf->num_tensors);
    printf("║  Data Size: %-46.2f MB ║\n", gguf->data_size / (1024.0 * 1024.0));
    printf("║                                                            ║\n");
    printf("║  Critical Tensors Found: %-35d ║\n", found);
    printf("║  Status: %-49s ║\n", found >= 2 ? "PASS" : "FAIL");
    printf("╚════════════════════════════════════════════════════════════╝\n");
    
    gguf_free(gguf);
    return (found >= 2) ? 0 : 1;
}
