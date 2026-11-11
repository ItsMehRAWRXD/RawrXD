// Minimal GGUF Loader - Zero Dependencies
// Parses GGUF files without any external libraries
// Only uses standard C library

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

// GGUF Magic number
#define GGUF_MAGIC 0x46554747  // "GGUF" in little-endian

// GGUF Version
#define GGUF_VERSION 3

// Tensor types
enum ggml_type {
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
    GGML_TYPE_IQ2_XXS = 16,
    GGML_TYPE_IQ2_XS  = 17,
    GGML_TYPE_IQ3_XXS = 18,
    GGML_TYPE_IQ1_S   = 19,
    GGML_TYPE_IQ4_NL  = 20,
    GGML_TYPE_IQ3_S   = 21,
    GGML_TYPE_IQ2_S   = 22,
    GGML_TYPE_IQ4_XS  = 23,
    GGML_TYPE_I8  = 24,
    GGML_TYPE_I16 = 25,
    GGML_TYPE_I32 = 26,
    GGML_TYPE_I64 = 27,
    GGML_TYPE_F64 = 28,
    GGML_TYPE_IQ1_M = 29,
    GGML_TYPE_BF16 = 30,
    GGML_TYPE_COUNT,
};

// Metadata value types
enum gguf_metadata_value_type {
    GGUF_METADATA_VALUE_TYPE_UINT8   = 0,
    GGUF_METADATA_VALUE_TYPE_INT8    = 1,
    GGUF_METADATA_VALUE_TYPE_UINT16  = 2,
    GGUF_METADATA_VALUE_TYPE_INT16   = 3,
    GGUF_METADATA_VALUE_TYPE_UINT32  = 4,
    GGUF_METADATA_VALUE_TYPE_INT32   = 5,
    GGUF_METADATA_VALUE_TYPE_FLOAT32 = 6,
    GGUF_METADATA_VALUE_TYPE_BOOL    = 7,
    GGUF_METADATA_VALUE_TYPE_STRING  = 8,
    GGUF_METADATA_VALUE_TYPE_ARRAY   = 9,
    GGUF_METADATA_VALUE_TYPE_UINT64  = 10,
    GGUF_METADATA_VALUE_TYPE_INT64   = 11,
    GGUF_METADATA_VALUE_TYPE_FLOAT64 = 12,
    GGUF_METADATA_VALUE_TYPE_COUNT,
};

// GGUF Header
#pragma pack(push, 1)
typedef struct {
    uint32_t magic;
    uint32_t version;
    uint64_t tensor_count;
    uint64_t metadata_kv_count;
} gguf_header_t;
#pragma pack(pop)

// Tensor info
typedef struct {
    char name[256];
    uint32_t n_dims;
    uint64_t dims[4];
    uint32_t type;
    uint64_t offset;
} gguf_tensor_info_t;

// Metadata value
typedef struct {
    uint32_t type;
    union {
        uint8_t  uint8_val;
        int8_t   int8_val;
        uint16_t uint16_val;
        int16_t  int16_val;
        uint32_t uint32_val;
        int32_t  int32_val;
        float    float32_val;
        uint64_t uint64_val;
        int64_t  int64_val;
        double   float64_val;
        bool     bool_val;
        struct {
            uint64_t len;
            char *data;
        } string_val;
        struct {
            uint32_t type;
            uint64_t len;
            void *data;
        } array_val;
    } value;
} gguf_metadata_value_t;

// Metadata KV
typedef struct {
    char key[256];
    gguf_metadata_value_t value;
} gguf_metadata_kv_t;

// GGUF Context
typedef struct {
    gguf_header_t header;
    gguf_tensor_info_t *tensors;
    gguf_metadata_kv_t *metadata;
    uint64_t data_offset;
    uint8_t *data;
    size_t data_size;
} gguf_context_t;

// Read a string from file
static bool read_string(FILE *fp, char *buf, size_t max_len) {
    uint64_t len;
    if (fread(&len, sizeof(len), 1, fp) != 1) return false;
    if (len >= max_len) {
        // Skip the string if too long
        fseek(fp, (long)len, SEEK_CUR);
        buf[0] = '\0';
        return true;
    }
    if (fread(buf, 1, (size_t)len, fp) != len) return false;
    buf[len] = '\0';
    return true;
}

// Read metadata value
static bool read_metadata_value(FILE *fp, gguf_metadata_value_t *val) {
    if (fread(&val->type, sizeof(val->type), 1, fp) != 1) return false;
    
    switch (val->type) {
        case GGUF_METADATA_VALUE_TYPE_UINT8:
            return fread(&val->value.uint8_val, sizeof(val->value.uint8_val), 1, fp) == 1;
        case GGUF_METADATA_VALUE_TYPE_INT8:
            return fread(&val->value.int8_val, sizeof(val->value.int8_val), 1, fp) == 1;
        case GGUF_METADATA_VALUE_TYPE_UINT16:
            return fread(&val->value.uint16_val, sizeof(val->value.uint16_val), 1, fp) == 1;
        case GGUF_METADATA_VALUE_TYPE_INT16:
            return fread(&val->value.int16_val, sizeof(val->value.int16_val), 1, fp) == 1;
        case GGUF_METADATA_VALUE_TYPE_UINT32:
            return fread(&val->value.uint32_val, sizeof(val->value.uint32_val), 1, fp) == 1;
        case GGUF_METADATA_VALUE_TYPE_INT32:
            return fread(&val->value.int32_val, sizeof(val->value.int32_val), 1, fp) == 1;
        case GGUF_METADATA_VALUE_TYPE_FLOAT32:
            return fread(&val->value.float32_val, sizeof(val->value.float32_val), 1, fp) == 1;
        case GGUF_METADATA_VALUE_TYPE_UINT64:
            return fread(&val->value.uint64_val, sizeof(val->value.uint64_val), 1, fp) == 1;
        case GGUF_METADATA_VALUE_TYPE_INT64:
            return fread(&val->value.int64_val, sizeof(val->value.int64_val), 1, fp) == 1;
        case GGUF_METADATA_VALUE_TYPE_FLOAT64:
            return fread(&val->value.float64_val, sizeof(val->value.float64_val), 1, fp) == 1;
        case GGUF_METADATA_VALUE_TYPE_BOOL:
            return fread(&val->value.bool_val, sizeof(val->value.bool_val), 1, fp) == 1;
        case GGUF_METADATA_VALUE_TYPE_STRING: {
            uint64_t len;
            if (fread(&len, sizeof(len), 1, fp) != 1) return false;
            val->value.string_val.len = len;
            val->value.string_val.data = malloc((size_t)len + 1);
            if (!val->value.string_val.data) return false;
            if (fread(val->value.string_val.data, 1, (size_t)len, fp) != len) {
                free(val->value.string_val.data);
                return false;
            }
            val->value.string_val.data[len] = '\0';
            return true;
        }
        case GGUF_METADATA_VALUE_TYPE_ARRAY: {
            uint32_t arr_type;
            uint64_t arr_len;
            if (fread(&arr_type, sizeof(arr_type), 1, fp) != 1) return false;
            if (fread(&arr_len, sizeof(arr_len), 1, fp) != 1) return false;
            val->value.array_val.type = arr_type;
            val->value.array_val.len = arr_len;
            // Skip array data for now
            size_t elem_size = 0;
            switch (arr_type) {
                case GGUF_METADATA_VALUE_TYPE_UINT8:  elem_size = 1; break;
                case GGUF_METADATA_VALUE_TYPE_INT8:   elem_size = 1; break;
                case GGUF_METADATA_VALUE_TYPE_UINT16: elem_size = 2; break;
                case GGUF_METADATA_VALUE_TYPE_INT16:  elem_size = 2; break;
                case GGUF_METADATA_VALUE_TYPE_UINT32: elem_size = 4; break;
                case GGUF_METADATA_VALUE_TYPE_INT32:  elem_size = 4; break;
                case GGUF_METADATA_VALUE_TYPE_FLOAT32: elem_size = 4; break;
                case GGUF_METADATA_VALUE_TYPE_UINT64: elem_size = 8; break;
                case GGUF_METADATA_VALUE_TYPE_INT64:  elem_size = 8; break;
                case GGUF_METADATA_VALUE_TYPE_FLOAT64: elem_size = 8; break;
                case GGUF_METADATA_VALUE_TYPE_BOOL:   elem_size = 1; break;
                default: elem_size = 1; break;
            }
            fseek(fp, (long)(arr_len * elem_size), SEEK_CUR);
            val->value.array_val.data = NULL;
            return true;
        }
        default:
            return false;
    }
}

// Load GGUF file
gguf_context_t* gguf_load(const char *filename) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        fprintf(stderr, "Failed to open: %s\n", filename);
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
    
    // Verify magic
    if (ctx->header.magic != GGUF_MAGIC) {
        fprintf(stderr, "Invalid GGUF magic: 0x%08X (expected 0x%08X)\n", 
                ctx->header.magic, GGUF_MAGIC);
        free(ctx);
        fclose(fp);
        return NULL;
    }
    
    printf("GGUF Version: %u\n", ctx->header.version);
    printf("Tensor count: %llu\n", (unsigned long long)ctx->header.tensor_count);
    printf("Metadata KV count: %llu\n", (unsigned long long)ctx->header.metadata_kv_count);
    
    // Read metadata
    if (ctx->header.metadata_kv_count > 0) {
        ctx->metadata = calloc(ctx->header.metadata_kv_count, sizeof(gguf_metadata_kv_t));
        if (!ctx->metadata) {
            free(ctx);
            fclose(fp);
            return NULL;
        }
        
        for (uint64_t i = 0; i < ctx->header.metadata_kv_count; i++) {
            if (!read_string(fp, ctx->metadata[i].key, sizeof(ctx->metadata[i].key))) {
                fprintf(stderr, "Failed to read metadata key %llu\n", (unsigned long long)i);
                break;
            }
            if (!read_metadata_value(fp, &ctx->metadata[i].value)) {
                fprintf(stderr, "Failed to read metadata value %llu\n", (unsigned long long)i);
                break;
            }
        }
    }
    
    // Read tensor info
    if (ctx->header.tensor_count > 0) {
        ctx->tensors = calloc(ctx->header.tensor_count, sizeof(gguf_tensor_info_t));
        if (!ctx->tensors) {
            free(ctx->metadata);
            free(ctx);
            fclose(fp);
            return NULL;
        }
        
        for (uint64_t i = 0; i < ctx->header.tensor_count; i++) {
            if (!read_string(fp, ctx->tensors[i].name, sizeof(ctx->tensors[i].name))) {
                fprintf(stderr, "Failed to read tensor name %llu\n", (unsigned long long)i);
                break;
            }
            if (fread(&ctx->tensors[i].n_dims, sizeof(ctx->tensors[i].n_dims), 1, fp) != 1) {
                fprintf(stderr, "Failed to read tensor dims %llu\n", (unsigned long long)i);
                break;
            }
            for (uint32_t j = 0; j < ctx->tensors[i].n_dims; j++) {
                if (fread(&ctx->tensors[i].dims[j], sizeof(ctx->tensors[i].dims[j]), 1, fp) != 1) {
                    fprintf(stderr, "Failed to read tensor dim %u\n", j);
                    break;
                }
            }
            if (fread(&ctx->tensors[i].type, sizeof(ctx->tensors[i].type), 1, fp) != 1) {
                fprintf(stderr, "Failed to read tensor type %llu\n", (unsigned long long)i);
                break;
            }
            if (fread(&ctx->tensors[i].offset, sizeof(ctx->tensors[i].offset), 1, fp) != 1) {
                fprintf(stderr, "Failed to read tensor offset %llu\n", (unsigned long long)i);
                break;
            }
        }
    }
    
    // Calculate data offset (must be aligned to 32)
    ctx->data_offset = ftell(fp);
    if (ctx->data_offset % 32 != 0) {
        ctx->data_offset += 32 - (ctx->data_offset % 32);
    }
    
    // Get file size
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, (long)ctx->data_offset, SEEK_SET);
    
    ctx->data_size = file_size - ctx->data_offset;
    ctx->data = malloc(ctx->data_size);
    if (ctx->data) {
        fread(ctx->data, 1, ctx->data_size, fp);
    }
    
    fclose(fp);
    return ctx;
}

// Free GGUF context
void gguf_free(gguf_context_t *ctx) {
    if (!ctx) return;
    
    if (ctx->metadata) {
        for (uint64_t i = 0; i < ctx->header.metadata_kv_count; i++) {
            if (ctx->metadata[i].value.type == GGUF_METADATA_VALUE_TYPE_STRING) {
                free(ctx->metadata[i].value.value.string_val.data);
            }
        }
        free(ctx->metadata);
    }
    
    free(ctx->tensors);
    free(ctx->data);
    free(ctx);
}

// Print metadata
void gguf_print_metadata(gguf_context_t *ctx) {
    if (!ctx || !ctx->metadata) return;
    
    printf("\n=== Metadata ===\n");
    for (uint64_t i = 0; i < ctx->header.metadata_kv_count; i++) {
        printf("%s: ", ctx->metadata[i].key);
        switch (ctx->metadata[i].value.type) {
            case GGUF_METADATA_VALUE_TYPE_UINT8:
                printf("%u (uint8)\n", ctx->metadata[i].value.value.uint8_val);
                break;
            case GGUF_METADATA_VALUE_TYPE_INT8:
                printf("%d (int8)\n", ctx->metadata[i].value.value.int8_val);
                break;
            case GGUF_METADATA_VALUE_TYPE_UINT32:
                printf("%u (uint32)\n", ctx->metadata[i].value.value.uint32_val);
                break;
            case GGUF_METADATA_VALUE_TYPE_INT32:
                printf("%d (int32)\n", ctx->metadata[i].value.value.int32_val);
                break;
            case GGUF_METADATA_VALUE_TYPE_FLOAT32:
                printf("%f (float32)\n", ctx->metadata[i].value.value.float32_val);
                break;
            case GGUF_METADATA_VALUE_TYPE_STRING:
                printf("\"%s\" (string)\n", ctx->metadata[i].value.value.string_val.data);
                break;
            case GGUF_METADATA_VALUE_TYPE_BOOL:
                printf("%s (bool)\n", ctx->metadata[i].value.value.bool_val ? "true" : "false");
                break;
            default:
                printf("(type %u)\n", ctx->metadata[i].value.type);
                break;
        }
    }
}

// Print tensor info
void gguf_print_tensors(gguf_context_t *ctx) {
    if (!ctx || !ctx->tensors) return;
    
    printf("\n=== Tensors ===\n");
    for (uint64_t i = 0; i < ctx->header.tensor_count; i++) {
        printf("%s: ", ctx->tensors[i].name);
        printf("type=%u, dims=[", ctx->tensors[i].type);
        for (uint32_t j = 0; j < ctx->tensors[i].n_dims; j++) {
            printf("%llu", (unsigned long long)ctx->tensors[i].dims[j]);
            if (j < ctx->tensors[i].n_dims - 1) printf(", ");
        }
        printf("], offset=%llu\n", (unsigned long long)ctx->tensors[i].offset);
    }
}

// Get tensor data
void* gguf_get_tensor_data(gguf_context_t *ctx, uint64_t tensor_idx) {
    if (!ctx || !ctx->data || tensor_idx >= ctx->header.tensor_count) return NULL;
    return ctx->data + ctx->tensors[tensor_idx].offset;
}

// Get tensor size
size_t gguf_get_tensor_size(gguf_context_t *ctx, uint64_t tensor_idx) {
    if (!ctx || tensor_idx >= ctx->header.tensor_count) return 0;
    
    size_t type_size = 0;
    switch (ctx->tensors[tensor_idx].type) {
        case GGML_TYPE_F32:  type_size = 4; break;
        case GGML_TYPE_F16:  type_size = 2; break;
        case GGML_TYPE_Q4_0: type_size = 18; break; // 4-bit quantized
        case GGML_TYPE_Q4_1: type_size = 20; break;
        case GGML_TYPE_Q8_0: type_size = 34; break;
        default: type_size = 4; break;
    }
    
    size_t num_elements = 1;
    for (uint32_t i = 0; i < ctx->tensors[tensor_idx].n_dims; i++) {
        num_elements *= (size_t)ctx->tensors[tensor_idx].dims[i];
    }
    
    return num_elements * type_size;
}

// Main
int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <model.gguf>\n", argv[0]);
        printf("Minimal GGUF loader - zero dependencies\n");
        return 1;
    }
    
    printf("Loading: %s\n", argv[1]);
    
    gguf_context_t *ctx = gguf_load(argv[1]);
    if (!ctx) {
        fprintf(stderr, "Failed to load GGUF file\n");
        return 1;
    }
    
    gguf_print_metadata(ctx);
    gguf_print_tensors(ctx);
    
    printf("\n=== Summary ===\n");
    printf("Data offset: %llu\n", (unsigned long long)ctx->data_offset);
    printf("Data size: %zu bytes\n", ctx->data_size);
    
    gguf_free(ctx);
    printf("\nDone.\n");
    return 0;
}
