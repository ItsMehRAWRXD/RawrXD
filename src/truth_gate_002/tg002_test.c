/* tg002_test.c - Test embedding extraction */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <windows.h>
#include <math.h>

#define GGUF_MAGIC 0x46554747
#define VOCAB_SIZE 51200
#define EMBED_DIM 2560
#define QK_K 256

typedef struct {
    uint8_t scales[16];
    uint8_t qs[64];
    uint16_t d;
    uint16_t dmin;
    uint8_t padding[44];
} block_q2_k;

typedef struct {
    char name[256];
    uint32_t n_dims;
    uint64_t dims[4];
    uint32_t type;
    uint64_t offset;
    uint64_t n_elements;
} tensor_info_t;

typedef struct {
    HANDLE file_handle;
    HANDLE map_handle;
    uint8_t* data;
    size_t file_size;
    uint32_t version;
    uint64_t tensor_count;
    tensor_info_t* tensors;
    uint64_t data_offset;
} gguf_context_t;

static float f16_to_f32(uint16_t h) {
    uint32_t sign = (h >> 15) & 0x1;
    uint32_t exp = (h >> 10) & 0x1F;
    uint32_t mant = h & 0x3FF;
    
    if (exp == 0) {
        if (mant == 0) return sign ? -0.0f : 0.0f;
        float val = (float)mant / 1024.0f * powf(2.0f, -14);
        return sign ? -val : val;
    }
    if (exp == 31) {
        if (mant == 0) return sign ? -INFINITY : INFINITY;
        return NAN;
    }
    
    float val = (1.0f + (float)mant / 1024.0f) * powf(2.0f, (float)exp - 15.0f);
    return sign ? -val : val;
}

static uint64_t get_u64(uint8_t* p) {
    return (uint64_t)p[0] | ((uint64_t)p[1] << 8) | 
           ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

static uint32_t get_u32(uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | 
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

int gguf_open(const char* path, gguf_context_t* ctx) {
    memset(ctx, 0, sizeof(gguf_context_t));
    
    ctx->file_handle = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (ctx->file_handle == INVALID_HANDLE_VALUE) return -1;
    
    LARGE_INTEGER size;
    GetFileSizeEx(ctx->file_handle, &size);
    ctx->file_size = (size_t)size.QuadPart;
    
    ctx->map_handle = CreateFileMappingA(ctx->file_handle, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!ctx->map_handle) return -1;
    
    ctx->data = (uint8_t*)MapViewOfFile(ctx->map_handle, FILE_MAP_READ, 0, 0, 0);
    if (!ctx->data) return -1;
    
    uint32_t magic = get_u32(ctx->data);
    if (magic != GGUF_MAGIC) return -1;
    
    ctx->version = get_u32(ctx->data + 4);
    ctx->tensor_count = get_u64(ctx->data + 8);
    
    ctx->tensors = calloc(ctx->tensor_count, sizeof(tensor_info_t));
    if (!ctx->tensors) return -1;
    
    size_t pos = 0x200;
    while (pos < ctx->file_size - 100) {
        if (memcmp(ctx->data + pos, "token_embd.weight", 17) == 0) {
            pos -= 8;
            break;
        }
        pos++;
    }
    
    if (pos >= ctx->file_size - 100) return -1;
    
    for (uint64_t i = 0; i < ctx->tensor_count && pos < ctx->file_size - 100; i++) {
        uint64_t name_len = get_u64(ctx->data + pos);
        pos += 8;
        
        if (name_len == 0 || name_len > 255) break;
        
        memcpy(ctx->tensors[i].name, ctx->data + pos, name_len);
        ctx->tensors[i].name[name_len] = '\0';
        pos += name_len;
        
        ctx->tensors[i].n_dims = get_u32(ctx->data + pos);
        pos += 4;
        
        if (ctx->tensors[i].n_dims > 4) break;
        
        ctx->tensors[i].n_elements = 1;
        for (uint32_t j = 0; j < ctx->tensors[i].n_dims; j++) {
            ctx->tensors[i].dims[j] = get_u64(ctx->data + pos);
            pos += 8;
            ctx->tensors[i].n_elements *= ctx->tensors[i].dims[j];
        }
        
        ctx->tensors[i].type = get_u32(ctx->data + pos);
        pos += 4;
        ctx->tensors[i].offset = get_u64(ctx->data + pos);
        pos += 8;
    }
    
    ctx->data_offset = (pos + 31) & ~31;
    return 0;
}

void gguf_close(gguf_context_t* ctx) {
    if (ctx->tensors) { free(ctx->tensors); ctx->tensors = NULL; }
    if (ctx->data) { UnmapViewOfFile(ctx->data); ctx->data = NULL; }
    if (ctx->map_handle) { CloseHandle(ctx->map_handle); ctx->map_handle = NULL; }
    if (ctx->file_handle != INVALID_HANDLE_VALUE) { 
        CloseHandle(ctx->file_handle); ctx->file_handle = INVALID_HANDLE_VALUE; 
    }
}

tensor_info_t* gguf_find_tensor(gguf_context_t* ctx, const char* name) {
    for (uint64_t i = 0; i < ctx->tensor_count; i++) {
        if (strcmp(ctx->tensors[i].name, name) == 0) {
            return &ctx->tensors[i];
        }
    }
    return NULL;
}

void* gguf_tensor_data(gguf_context_t* ctx, tensor_info_t* tensor) {
    if (!tensor || !ctx->data) return NULL;
    return ctx->data + ctx->data_offset + tensor->offset;
}

void dequantize_q2_k_block(const block_q2_k* block, float* output) {
    float d = f16_to_f32(block->d);
    float min = f16_to_f32(block->dmin);
    
    if (isnan(d) || isinf(d) || isnan(min) || isinf(min)) {
        memset(output, 0, 256 * sizeof(float));
        return;
    }
    
    const uint8_t* q = block->qs;
    int is = 0;
    
    for (int n = 0; n < 256; n += 128) {
        int shift = 0;
        for (int j = 0; j < 4; ++j) {
            uint8_t sc = block->scales[is++];
            float dl = d * (sc & 0xF);
            float ml = min * (sc >> 4);
            
            for (int l = 0; l < 16; ++l) {
                *output++ = dl * ((q[l] >> shift) & 3) - ml;
            }
            
            sc = block->scales[is++];
            dl = d * (sc & 0xF);
            ml = min * (sc >> 4);
            
            for (int l = 0; l < 16; ++l) {
                *output++ = dl * ((q[l + 16] >> shift) & 3) - ml;
            }
            shift += 2;
        }
        q += 32;
    }
}

void get_token_embedding(gguf_context_t* ctx, tensor_info_t* tensor, 
                         int token_id, float* embedding) {
    if (!tensor || tensor->type != 10) return;
    
    void* raw = gguf_tensor_data(ctx, tensor);
    if (!raw) return;
    
    uint64_t start_block = ((uint64_t)token_id * EMBED_DIM) / 256;
    uint64_t offset_in_block = ((uint64_t)token_id * EMBED_DIM) % 256;
    
    const block_q2_k* blocks = (const block_q2_k*)raw;
    float block_output[256];
    
    int elems_to_read = EMBED_DIM;
    int out_pos = 0;
    
    while (elems_to_read > 0) {
        dequantize_q2_k_block(&blocks[start_block], block_output);
        
        int elems_from_block = 256 - (int)offset_in_block;
        if (elems_from_block > elems_to_read) elems_from_block = elems_to_read;
        
        memcpy(embedding + out_pos, block_output + offset_in_block, 
               elems_from_block * sizeof(float));
        
        out_pos += elems_from_block;
        elems_to_read -= elems_from_block;
        offset_in_block = 0;
        start_block++;
    }
}

int main(int argc, char* argv[]) {
    printf("Truth Gate 002 - Test\n\n");
    
    if (argc < 2) {
        printf("Usage: %s <model.gguf>\n", argv[0]);
        return 1;
    }
    
    gguf_context_t ctx;
    if (gguf_open(argv[1], &ctx) != 0) {
        fprintf(stderr, "Failed to load model\n");
        return 1;
    }
    
    printf("GGUF v%u, %llu tensors loaded\n\n", 
           ctx.version, (unsigned long long)ctx.tensor_count);
    
    tensor_info_t* tok_emb = gguf_find_tensor(&ctx, "token_embd.weight");
    if (!tok_emb) {
        printf("token_embd.weight not found\n");
        gguf_close(&ctx);
        return 1;
    }
    
    printf("token_embd: %llu elements, type %u\n",
           (unsigned long long)tok_emb->n_elements, tok_emb->type);
    
    /* Test embedding extraction */
    float embedding[EMBED_DIM];
    printf("\nExtracting embedding for token 0...\n");
    get_token_embedding(&ctx, tok_emb, 0, embedding);
    
    printf("First 10 values: ");
    for (int i = 0; i < 10 && i < EMBED_DIM; i++) {
        printf("%.4f ", embedding[i]);
    }
    printf("\n");
    
    printf("Last 10 values: ");
    for (int i = EMBED_DIM - 10; i < EMBED_DIM; i++) {
        printf("%.4f ", embedding[i]);
    }
    printf("\n");
    
    /* Test token 1 */
    printf("\nExtracting embedding for token 1...\n");
    get_token_embedding(&ctx, tok_emb, 1, embedding);
    
    printf("First 10 values: ");
    for (int i = 0; i < 10 && i < EMBED_DIM; i++) {
        printf("%.4f ", embedding[i]);
    }
    printf("\n");
    
    gguf_close(&ctx);
    printf("\nDone!\n");
    return 0;
}
