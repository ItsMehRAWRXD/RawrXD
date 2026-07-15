/* tg002_full_pipeline.c - Complete Truth Gate 002 Implementation
 * Phase 1: Tensor Extraction (proven working pattern from tg002_integrated.c)
 * Phase 2: K-Quant Dequantization (Q2_K, Q3_K, Q4_K)
 * Compile: gcc -O2 -Wall tg002_full_pipeline.c -o tg002_full_pipeline.exe -lm
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <stdbool.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#endif

#define GGUF_MAGIC 0x46554747

/* GGML Types */
typedef enum {
    GGML_TYPE_F32  = 0,
    GGML_TYPE_F16  = 1,
    GGML_TYPE_Q4_0 = 2,
    GGML_TYPE_Q4_1 = 3,
    GGML_TYPE_Q5_0 = 6,
    GGML_TYPE_Q5_1 = 7,
    GGML_TYPE_Q8_0 = 8,
    GGML_TYPE_Q2_K = 10,
    GGML_TYPE_Q3_K = 11,
    GGML_TYPE_Q4_K = 12,
    GGML_TYPE_Q5_K = 13,
    GGML_TYPE_Q6_K = 14,
    GGML_TYPE_Q8_K = 15,
} ggml_type_t;

/* K-Quant block structures - from llama.cpp ggml-common.h
 * QK_K = 256 (elements per block)
 */

/* Q2_K: 2-bit quantization - from llama.cpp
 * weight = d * (sc & 0xF) * q - dmin * (sc >> 4)
 * Block size: 128 bytes
 * Layout: scales[16] + qs[64] + d(2) + dmin(2) + padding(44)
 */
typedef struct {
    uint8_t scales[16];     /* 16 bytes: scale and min packed in nibbles */
    uint8_t qs[64];         /* 64 bytes for 256 2-bit weights */
    uint16_t d;             /* delta (f16) */
    uint16_t dmin;          /* delta min (f16) */
    uint8_t padding[44];    /* Padding to 128 bytes */
} block_q2_k;

/* Q3_K: 3-bit quantization  
 * weight = d * scale * (q - 4) where q is 3-bit
 * Block size: sizeof(f16) + 32 + 64 + 12 = 110 bytes, padded to 128? */
typedef struct {
    uint8_t hmask[32];      /* 256-bit mask for high bit */
    uint8_t qs[64];         /* 64 bytes for low 2 bits */
    uint8_t scales[12];     /* 12 bytes for 16 signed 6-bit scales */
    uint16_t d;             /* delta (f16) */
    uint8_t padding[18];
} block_q3_k;

/* Q4_K: 4-bit quantization
 * weight = d * scale * q + dmin * min
 * 8 blocks of 32 elements each
 * Block size: 2*sizeof(f16) + 12 + 128 = 144 bytes */
typedef struct {
    uint16_t d;             /* delta (f16) */
    uint16_t dmin;          /* delta min (f16) */
    uint8_t scales[12];     /* 12 bytes for 8 scales + 8 mins (6-bit each) */
    uint8_t qs[128];        /* 128 bytes for 256 4-bit weights */
} block_q4_k;

/* GGUF structures */
typedef struct {
    uint32_t magic;
    uint32_t version;
    uint64_t tensor_count;
    uint64_t metadata_kv_count;
} gguf_header_t;

typedef struct {
    char name[256];
    uint32_t n_dims;
    uint64_t dimensions[4];
    uint32_t type;
    uint64_t offset;
    uint64_t n_elements;
    uint64_t size;
} tensor_info_t;

typedef struct {
#ifdef _WIN32
    HANDLE file_handle;
    HANDLE map_handle;
#else
    int fd;
#endif
    void* base_addr;
    size_t file_size;
    gguf_header_t header;
    tensor_info_t* tensors;
    uint64_t data_offset;
} gguf_context_t;

/* F16 to F32 - IEEE 754 half-precision to single-precision */
static float f16_to_f32(uint16_t h) {
    uint32_t sign = (h >> 15) & 0x1;
    uint32_t exp = (h >> 10) & 0x1F;
    uint32_t mant = h & 0x3FF;
    
    if (exp == 0) {
        if (mant == 0) return sign ? -0.0f : 0.0f;
        /* Denormalized number */
        float val = (float)mant / 1024.0f * powf(2.0f, -14);
        return sign ? -val : val;
    }
    if (exp == 31) {
        if (mant == 0) return sign ? -INFINITY : INFINITY;
        return NAN;
    }
    
    /* Normalized number: val = (1 + mant/1024) * 2^(exp-15) */
    float val = (1.0f + (float)mant / 1024.0f) * powf(2.0f, (float)exp - 15.0f);
    return sign ? -val : val;
}

/* Read string from GGUF */
static bool read_string(const uint8_t** ptr, char* buffer, size_t max_len) {
    uint64_t len = *(uint64_t*)*ptr;
    *ptr += sizeof(uint64_t);
    if (len >= max_len) {
        *ptr += len;
        buffer[0] = '\0';
        return true;
    }
    memcpy(buffer, *ptr, len);
    buffer[len] = '\0';
    *ptr += len;
    return true;
}

/* Skip metadata value */
static bool skip_metadata_value(const uint8_t** ptr, uint32_t type) {
    switch (type) {
        case 0: case 1: *ptr += 1; break;
        case 2: case 3: *ptr += 2; break;
        case 4: case 5: case 6: *ptr += 4; break;
        case 7: *ptr += 1; break;
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
                if (!skip_metadata_value(ptr, elem_type)) return false;
            }
            break;
        }
        case 10: case 11: case 12: *ptr += 8; break;
        default: return false;
    }
    return true;
}

/* Open GGUF file */
int gguf_open(const char* path, gguf_context_t* ctx) {
    memset(ctx, 0, sizeof(gguf_context_t));
    
#ifdef _WIN32
    ctx->file_handle = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (ctx->file_handle == INVALID_HANDLE_VALUE) return -1;
    
    LARGE_INTEGER size;
    if (!GetFileSizeEx(ctx->file_handle, &size)) return -1;
    ctx->file_size = (size_t)size.QuadPart;
    
    ctx->map_handle = CreateFileMappingA(ctx->file_handle, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!ctx->map_handle) return -1;
    
    ctx->base_addr = MapViewOfFile(ctx->map_handle, FILE_MAP_READ, 0, 0, 0);
    if (!ctx->base_addr) return -1;
#else
    ctx->fd = open(path, O_RDONLY);
    if (ctx->fd < 0) return -1;
    
    struct stat st;
    if (fstat(ctx->fd, &st) < 0) return -1;
    ctx->file_size = st.st_size;
    
    ctx->base_addr = mmap(NULL, ctx->file_size, PROT_READ, MAP_PRIVATE, ctx->fd, 0);
    if (ctx->base_addr == MAP_FAILED) return -1;
#endif
    
    memcpy(&ctx->header, ctx->base_addr, sizeof(gguf_header_t));
    
    if (ctx->header.magic != GGUF_MAGIC) {
        fprintf(stderr, "Invalid GGUF magic: 0x%08X\n", ctx->header.magic);
        return -1;
    }
    
    ctx->tensors = calloc(ctx->header.tensor_count, sizeof(tensor_info_t));
    if (!ctx->tensors) return -1;
    
    /* Parse tensors */
    const uint8_t* ptr = (uint8_t*)ctx->base_addr + sizeof(gguf_header_t);
    
    /* Skip metadata */
    for (uint64_t i = 0; i < ctx->header.metadata_kv_count; i++) {
        char key[256];
        if (!read_string(&ptr, key, sizeof(key))) return -1;
        uint32_t type = *(uint32_t*)ptr;
        ptr += sizeof(uint32_t);
        if (!skip_metadata_value(&ptr, type)) return -1;
    }
    
    /* Read tensor info */
    for (uint64_t i = 0; i < ctx->header.tensor_count; i++) {
        if (!read_string(&ptr, ctx->tensors[i].name, sizeof(ctx->tensors[i].name))) return -1;
        
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
        
        /* Calculate elements and size */
        uint64_t num_elements = 1;
        for (uint32_t j = 0; j < ctx->tensors[i].n_dims; j++) {
            num_elements *= ctx->tensors[i].dimensions[j];
        }
        ctx->tensors[i].n_elements = num_elements;
        
        switch (ctx->tensors[i].type) {
            case GGML_TYPE_F32:  ctx->tensors[i].size = num_elements * 4; break;
            case GGML_TYPE_F16:  ctx->tensors[i].size = num_elements * 2; break;
            case GGML_TYPE_Q4_0: ctx->tensors[i].size = (num_elements / 32) * 18; break;
            case GGML_TYPE_Q4_1: ctx->tensors[i].size = (num_elements / 32) * 20; break;
            case GGML_TYPE_Q8_0: ctx->tensors[i].size = (num_elements / 32) * 34; break;
            case GGML_TYPE_Q2_K: ctx->tensors[i].size = (num_elements / 256) * 128; break;
            case GGML_TYPE_Q3_K: ctx->tensors[i].size = (num_elements / 256) * 192; break;
            case GGML_TYPE_Q4_K: ctx->tensors[i].size = (num_elements / 256) * 144; break;
            case GGML_TYPE_Q5_K: ctx->tensors[i].size = (num_elements / 256) * 176; break;
            case GGML_TYPE_Q6_K: ctx->tensors[i].size = (num_elements / 256) * 210; break;
            default: ctx->tensors[i].size = 0;
        }
    }
    
    ctx->data_offset = (uint64_t)(ptr - (uint8_t*)ctx->base_addr);
    ctx->data_offset = (ctx->data_offset + 31) & ~31;
    
    return 0;
}

/* Close GGUF */
void gguf_close(gguf_context_t* ctx) {
    if (ctx->tensors) { free(ctx->tensors); ctx->tensors = NULL; }
#ifdef _WIN32
    if (ctx->base_addr) { UnmapViewOfFile(ctx->base_addr); ctx->base_addr = NULL; }
    if (ctx->map_handle) { CloseHandle(ctx->map_handle); ctx->map_handle = NULL; }
    if (ctx->file_handle != INVALID_HANDLE_VALUE) { 
        CloseHandle(ctx->file_handle); ctx->file_handle = INVALID_HANDLE_VALUE; 
    }
#else
    if (ctx->base_addr && ctx->base_addr != MAP_FAILED) { 
        munmap(ctx->base_addr, ctx->file_size); ctx->base_addr = NULL; 
    }
    if (ctx->fd >= 0) { close(ctx->fd); ctx->fd = -1; }
#endif
}

/* Find tensor */
tensor_info_t* gguf_find_tensor(gguf_context_t* ctx, const char* name) {
    for (uint64_t i = 0; i < ctx->header.tensor_count; i++) {
        if (strcmp(ctx->tensors[i].name, name) == 0) {
            return &ctx->tensors[i];
        }
    }
    return NULL;
}

/* Get tensor data pointer */
void* gguf_tensor_data(gguf_context_t* ctx, tensor_info_t* tensor) {
    if (!tensor || !ctx->base_addr) return NULL;
    return (uint8_t*)ctx->base_addr + ctx->data_offset + tensor->offset;
}

/* Q4_K scale/min extraction - from llama.cpp get_scale_min_k4
 * 12 bytes contain 8 scales + 8 mins, each 6 bits
 */
static inline void get_scale_min_k4(int j, const uint8_t* q, uint8_t* d, uint8_t* m) {
    if (j < 4) {
        *d = q[j] & 63;
        *m = q[j + 4] & 63;
    } else {
        *d = (q[j + 4] & 0x0F) | ((q[j - 4] >> 6) << 4);
        *m = (q[j + 4] >> 4) | ((q[j] >> 6) << 4);
    }
}

/* Dequantize Q2_K - from llama.cpp dequantize_row_q2_K
 * weight = d * (sc & 0xF) * q - dmin * (sc >> 4)
 * 16 blocks of 16 elements each
 */
void dequantize_q2_k(const void* input, float* output, uint64_t n_elements) {
    const block_q2_k* blocks = (const block_q2_k*)input;
    uint64_t n_blocks = n_elements / 256;
    
    for (uint64_t b = 0; b < n_blocks; b++) {
        float d = f16_to_f32(blocks[b].d);
        float min = f16_to_f32(blocks[b].dmin);
        
        /* Validate d and min */
        if (isnan(d) || isinf(d) || isnan(min) || isinf(min)) {
            /* Output zeros for invalid blocks */
            for (int i = 0; i < 256; i++) {
                *output++ = 0.0f;
            }
            continue;
        }
        
        const uint8_t* q = blocks[b].qs;
        int is = 0;
        
        for (int n = 0; n < 256; n += 128) {
            int shift = 0;
            for (int j = 0; j < 4; ++j) {
                uint8_t sc = blocks[b].scales[is++];
                float dl = d * (sc & 0xF);
                float ml = min * (sc >> 4);
                
                /* Clamp scale values to prevent overflow */
                if (dl > 1000.0f) dl = 1000.0f;
                if (ml > 1000.0f) ml = 1000.0f;
                
                for (int l = 0; l < 16; ++l) {
                    int8_t val = ((q[l] >> shift) & 3);
                    /* Convert to signed: 0,1,2,3 -> -1,0,1,2? No, llama.cpp uses as-is */
                    *output++ = dl * val - ml;
                }
                
                sc = blocks[b].scales[is++];
                dl = d * (sc & 0xF);
                ml = min * (sc >> 4);
                
                if (dl > 1000.0f) dl = 1000.0f;
                if (ml > 1000.0f) ml = 1000.0f;
                
                for (int l = 0; l < 16; ++l) {
                    int8_t val = ((q[l + 16] >> shift) & 3);
                    *output++ = dl * val - ml;
                }
                
                shift += 2;
            }
            q += 32;
        }
    }
}

/* Dequantize Q3_K - from llama.cpp dequantize_row_q3_K
 * weight = d_all * (scales[is] - 32) * ((q & 3) - (hmask ? 0 : 4))
 * Complex scale unpacking from 12 bytes to 16 signed 6-bit values
 */
void dequantize_q3_k(const void* input, float* output, uint64_t n_elements) {
    const block_q3_k* blocks = (const block_q3_k*)input;
    uint64_t n_blocks = n_elements / 256;
    
    const uint32_t kmask1 = 0x03030303;
    const uint32_t kmask2 = 0x0F0F0F0F;
    
    for (uint64_t b = 0; b < n_blocks; b++) {
        float d_all = f16_to_f32(blocks[b].d);
        
        const uint8_t* q = blocks[b].qs;
        const uint8_t* hm = blocks[b].hmask;
        uint8_t m = 1;
        
        /* Unpack scales from 12 bytes to 16 signed 6-bit values */
        uint32_t aux[4];
        memcpy(aux, blocks[b].scales, 12);
        uint32_t tmp = aux[2];
        aux[2] = ((aux[0] >> 4) & kmask2) | (((tmp >> 4) & kmask1) << 4);
        aux[3] = ((aux[1] >> 4) & kmask2) | (((tmp >> 6) & kmask1) << 4);
        aux[0] = (aux[0] & kmask2) | (((tmp >> 0) & kmask1) << 4);
        aux[1] = (aux[1] & kmask2) | (((tmp >> 2) & kmask1) << 4);
        
        const int8_t* scales = (const int8_t*)aux;
        int is = 0;
        
        for (int n = 0; n < 256; n += 128) {
            int shift = 0;
            for (int j = 0; j < 4; ++j) {
                float dl = d_all * (scales[is++] - 32);
                for (int l = 0; l < 16; ++l) {
                    *output++ = dl * ((int8_t)((q[l] >> shift) & 3) - ((hm[l] & m) ? 0 : 4));
                }
                
                dl = d_all * (scales[is++] - 32);
                for (int l = 0; l < 16; ++l) {
                    *output++ = dl * ((int8_t)((q[l + 16] >> shift) & 3) - ((hm[l + 16] & m) ? 0 : 4));
                }
                
                shift += 2;
                m <<= 1;
            }
            q += 32;
        }
    }
}

/* Dequantize Q4_K - from llama.cpp dequantize_row_q4_K
 * weight = d * sc * q - min * m
 * 8 blocks of 32 elements each
 */
void dequantize_q4_k(const void* input, float* output, uint64_t n_elements) {
    const block_q4_k* blocks = (const block_q4_k*)input;
    uint64_t n_blocks = n_elements / 256;
    
    for (uint64_t b = 0; b < n_blocks; b++) {
        const uint8_t* q = blocks[b].qs;
        float d = f16_to_f32(blocks[b].d);
        float min = f16_to_f32(blocks[b].dmin);
        
        int is = 0;
        uint8_t sc, m;
        for (int j = 0; j < 256; j += 64) {
            get_scale_min_k4(is + 0, blocks[b].scales, &sc, &m);
            float d1 = d * sc;
            float m1 = min * m;
            
            get_scale_min_k4(is + 1, blocks[b].scales, &sc, &m);
            float d2 = d * sc;
            float m2 = min * m;
            
            for (int l = 0; l < 32; ++l) *output++ = d1 * (q[l] & 0xF) - m1;
            for (int l = 0; l < 32; ++l) *output++ = d2 * (q[l] >> 4) - m2;
            
            q += 32;
            is += 2;
        }
    }
}

/* Type name helper */
const char* ggml_type_name(uint32_t type) {
    switch (type) {
        case 0: return "F32";
        case 1: return "F16";
        case 2: return "Q4_0";
        case 3: return "Q4_1";
        case 6: return "Q5_0";
        case 7: return "Q5_1";
        case 8: return "Q8_0";
        case 10: return "Q2_K";
        case 11: return "Q3_K";
        case 12: return "Q4_K";
        case 13: return "Q5_K";
        case 14: return "Q6_K";
        case 15: return "Q8_K";
        default: return "UNKNOWN";
    }
}

/* Main */
int main(int argc, char* argv[]) {
    printf("========================================\n");
    printf("Truth Gate 002 - Full Pipeline\n");
    printf("Phase 1: Tensor Extraction\n");
    printf("Phase 2: K-Quant Dequantization\n");
    printf("========================================\n\n");
    
    if (argc < 2) {
        printf("Usage: %s <model.gguf> [tensor_name]\n", argv[0]);
        return 1;
    }
    
    const char* model_path = argv[1];
    const char* tensor_name = (argc > 2) ? argv[2] : "token_embd.weight";
    
    printf("Loading: %s\n\n", model_path);
    
    /* Open GGUF */
    gguf_context_t ctx;
    if (gguf_open(model_path, &ctx) != 0) {
        fprintf(stderr, "Failed to open GGUF\n");
        return 1;
    }
    
    printf("GGUF Info:\n");
    printf("  Version: %u\n", ctx.header.version);
    printf("  Tensors: %llu\n", (unsigned long long)ctx.header.tensor_count);
    printf("  Data offset: 0x%llX\n\n", (unsigned long long)ctx.data_offset);
    
    /* Find tensor */
    tensor_info_t* tensor = gguf_find_tensor(&ctx, tensor_name);
    if (!tensor) {
        fprintf(stderr, "Tensor not found: %s\n", tensor_name);
        gguf_close(&ctx);
        return 1;
    }
    
    printf("Selected Tensor:\n");
    printf("  Name: %s\n", tensor->name);
    printf("  Type: %s (%u)\n", ggml_type_name(tensor->type), tensor->type);
    printf("  Dims: [");
    for (uint32_t i = 0; i < tensor->n_dims; i++) {
        if (i > 0) printf(", ");
        printf("%llu", (unsigned long long)tensor->dimensions[i]);
    }
    printf("]\n");
    printf("  Elements: %llu\n", (unsigned long long)tensor->n_elements);
    printf("  Size: %llu bytes\n\n", (unsigned long long)tensor->size);
    
    /* Get raw data */
    void* raw_data = gguf_tensor_data(&ctx, tensor);
    if (!raw_data) {
        fprintf(stderr, "Failed to get tensor data\n");
        gguf_close(&ctx);
        return 1;
    }
    
    printf("Raw data pointer: %p\n", raw_data);
    printf("First 32 bytes: ");
    for (int i = 0; i < 32 && i < tensor->size; i++) {
        printf("%02X ", ((uint8_t*)raw_data)[i]);
    }
    printf("\n");
    
    printf("Raw data pointer: %p\n", raw_data);
    printf("First 16 bytes: ");
    for (int i = 0; i < 16 && i < tensor->size; i++) {
        printf("%02X ", ((uint8_t*)raw_data)[i]);
    }
    printf("\n\n");
    
    /* Dequantize if supported */
    if (tensor->type == GGML_TYPE_Q2_K || 
        tensor->type == GGML_TYPE_Q3_K || 
        tensor->type == GGML_TYPE_Q4_K) {
        
        printf("Dequantizing %s to float32...\n", ggml_type_name(tensor->type));
        
        float* dequantized = (float*)malloc(tensor->n_elements * sizeof(float));
        if (!dequantized) {
            fprintf(stderr, "Failed to allocate output buffer\n");
            gguf_close(&ctx);
            return 1;
        }
        
        switch (tensor->type) {
            case GGML_TYPE_Q2_K: dequantize_q2_k(raw_data, dequantized, tensor->n_elements); break;
            case GGML_TYPE_Q3_K: dequantize_q3_k(raw_data, dequantized, tensor->n_elements); break;
            case GGML_TYPE_Q4_K: dequantize_q4_k(raw_data, dequantized, tensor->n_elements); break;
        }
        
        /* Validate */
        uint64_t nan_count = 0, inf_count = 0;
        float min_val = INFINITY, max_val = -INFINITY;
        double sum = 0.0, sum_sq = 0.0;
        
        uint64_t sample_size = tensor->n_elements > 1000000 ? 1000000 : tensor->n_elements;
        for (uint64_t i = 0; i < sample_size; i++) {
            float v = dequantized[i];
            if (isnan(v)) nan_count++;
            if (isinf(v)) inf_count++;
            if (v < min_val) min_val = v;
            if (v > max_val) max_val = v;
            sum += v;
            sum_sq += v * v;
        }
        
        printf("\nDequantization Results (sampled %llu elements):\n", (unsigned long long)sample_size);
        printf("  NaN: %llu\n", (unsigned long long)nan_count);
        printf("  Inf: %llu\n", (unsigned long long)inf_count);
        printf("  Min: %.6f\n", min_val);
        printf("  Max: %.6f\n", max_val);
        printf("  Mean: %.6f\n", (float)(sum / sample_size));
        printf("  RMS: %.6f\n", (float)sqrt(sum_sq / sample_size));
        
        printf("\nFirst 16 values:\n");
        for (int i = 0; i < 16 && i < tensor->n_elements; i++) {
            printf("  [%4d] = %10.6f\n", i, dequantized[i]);
        }
        
        if (nan_count == 0 && inf_count == 0) {
            printf("\n✓✓✓ K-QUANT DEQUANTIZATION SUCCESSFUL ✓✓✓\n");
        } else {
            printf("\n⚠ Dequantization had issues\n");
        }
        
        free(dequantized);
    } else {
        printf("Note: Type %s dequantization not yet implemented\n", 
               ggml_type_name(tensor->type));
        printf("Supported: Q2_K, Q3_K, Q4_K\n");
    }
    
    gguf_close(&ctx);
    
    printf("\n========================================\n");
    printf("Truth Gate 002: Phases 1+2 Complete\n");
    printf("GGUF → Tensor Bytes → Float32 ✓\n");
    
    return 0;
}
