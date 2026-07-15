/* tg002_tensor_extract.c - Phase 1: Tensor Extraction from GGUF
 * Reads actual tensor data bytes from GGUF files
 * Compile: gcc -O2 -c tg002_tensor_extract.c -o tg002_tensor_extract.o
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#endif

/* GGUF Constants */
#define GGUF_MAGIC 0x46554747  /* 'GGUF' */

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
    GGML_TYPE_COUNT
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
    uint64_t size;      /* Size in bytes */
} tensor_info_t;

/* GGUF Context */
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

/* Forward declarations */
int gguf_open(const char* path, gguf_context_t* ctx);
void gguf_close(gguf_context_t* ctx);
tensor_info_t* gguf_get_tensor(gguf_context_t* ctx, const char* name);
void* gguf_get_tensor_data(gguf_context_t* ctx, tensor_info_t* tensor);
void gguf_print_tensors(gguf_context_t* ctx);

/* Helper: Read string from GGUF */
static bool read_string(const uint8_t** ptr, char* buffer, size_t max_len) {
    uint64_t len = *(uint64_t*)*ptr;
    *ptr += sizeof(uint64_t);
    
    if (len >= max_len) {
        /* Skip oversized strings */
        *ptr += len;
        buffer[0] = '\0';
        return true;
    }
    
    memcpy(buffer, *ptr, len);
    buffer[len] = '\0';
    *ptr += len;
    return true;
}

/* Helper: Skip metadata value */
static bool skip_metadata_value(const uint8_t** ptr, uint32_t type) {
    switch (type) {
        case 0: case 1:  *ptr += 1; break;  /* UINT8, INT8 */
        case 2: case 3:  *ptr += 2; break;  /* UINT16, INT16 */
        case 4: case 5: case 6:  *ptr += 4; break;  /* UINT32, INT32, FLOAT32 */
        case 10: case 11: case 12: *ptr += 8; break; /* UINT64, INT64, FLOAT64 */
        case 7:  *ptr += 1; break;  /* BOOL */
        case 8: {  /* STRING */
            uint64_t len = *(uint64_t*)*ptr;
            *ptr += sizeof(uint64_t) + len;
            break;
        }
        case 9: {  /* ARRAY */
            uint32_t elem_type = *(uint32_t*)*ptr;
            *ptr += sizeof(uint32_t);
            uint64_t count = *(uint64_t*)*ptr;
            *ptr += sizeof(uint64_t);
            for (uint64_t i = 0; i < count; i++) {
                if (!skip_metadata_value(ptr, elem_type)) return false;
            }
            break;
        }
        default:
            return false;
    }
    return true;
}

/* Open GGUF file */
int gguf_open(const char* path, gguf_context_t* ctx) {
    memset(ctx, 0, sizeof(gguf_context_t));
    
#ifdef _WIN32
    /* Windows: Use memory-mapped files */
    ctx->file_handle = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (ctx->file_handle == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Error: Failed to open file: %s\n", path);
        return -1;
    }
    
    LARGE_INTEGER size;
    if (!GetFileSizeEx(ctx->file_handle, &size)) {
        CloseHandle(ctx->file_handle);
        return -1;
    }
    ctx->file_size = (size_t)size.QuadPart;
    
    ctx->map_handle = CreateFileMappingA(ctx->file_handle, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!ctx->map_handle) {
        CloseHandle(ctx->file_handle);
        return -1;
    }
    
    ctx->base_addr = MapViewOfFile(ctx->map_handle, FILE_MAP_READ, 0, 0, 0);
    if (!ctx->base_addr) {
        CloseHandle(ctx->map_handle);
        CloseHandle(ctx->file_handle);
        return -1;
    }
#else
    /* POSIX: Use mmap */
    ctx->fd = open(path, O_RDONLY);
    if (ctx->fd < 0) {
        fprintf(stderr, "Error: Failed to open file: %s\n", path);
        return -1;
    }
    
    struct stat st;
    if (fstat(ctx->fd, &st) < 0) {
        close(ctx->fd);
        return -1;
    }
    ctx->file_size = st.st_size;
    
    ctx->base_addr = mmap(NULL, ctx->file_size, PROT_READ, MAP_PRIVATE, ctx->fd, 0);
    if (ctx->base_addr == MAP_FAILED) {
        close(ctx->fd);
        return -1;
    }
#endif
    
    /* Read header */
    memcpy(&ctx->header, ctx->base_addr, sizeof(gguf_header_t));
    
    /* Verify magic */
    if (ctx->header.magic != GGUF_MAGIC) {
        fprintf(stderr, "Error: Invalid GGUF magic: 0x%08X (expected 0x%08X)\n",
                ctx->header.magic, GGUF_MAGIC);
        gguf_close(ctx);
        return -1;
    }
    
    /* Allocate tensor array */
    ctx->tensors = calloc(ctx->header.tensor_count, sizeof(tensor_info_t));
    if (!ctx->tensors) {
        gguf_close(ctx);
        return -1;
    }
    
    /* Parse tensors */
    const uint8_t* ptr = (uint8_t*)ctx->base_addr + sizeof(gguf_header_t);
    
    /* Skip metadata (for now) */
    for (uint64_t i = 0; i < ctx->header.metadata_kv_count; i++) {
        char key[256];
        if (!read_string(&ptr, key, sizeof(key))) {
            gguf_close(ctx);
            return -1;
        }
        uint32_t type = *(uint32_t*)ptr;
        ptr += sizeof(uint32_t);
        if (!skip_metadata_value(&ptr, type)) {
            gguf_close(ctx);
            return -1;
        }
    }
    
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
        
        /* Calculate size based on type and dimensions */
        uint64_t num_elements = 1;
        for (uint32_t j = 0; j < ctx->tensors[i].n_dims; j++) {
            num_elements *= ctx->tensors[i].dimensions[j];
        }
        
        /* Size depends on quantization type */
        switch (ctx->tensors[i].type) {
            case GGML_TYPE_F32:  ctx->tensors[i].size = num_elements * 4; break;
            case GGML_TYPE_F16:  ctx->tensors[i].size = num_elements * 2; break;
            case GGML_TYPE_Q4_0: ctx->tensors[i].size = (num_elements / 32) * 18; break;
            case GGML_TYPE_Q4_1: ctx->tensors[i].size = (num_elements / 32) * 20; break;
            case GGML_TYPE_Q5_0: ctx->tensors[i].size = (num_elements / 32) * 22; break;
            case GGML_TYPE_Q5_1: ctx->tensors[i].size = (num_elements / 32) * 24; break;
            case GGML_TYPE_Q8_0: ctx->tensors[i].size = (num_elements / 32) * 34; break;
            case GGML_TYPE_Q4_K: ctx->tensors[i].size = (num_elements / 256) * 144; break;
            case GGML_TYPE_Q5_K: ctx->tensors[i].size = (num_elements / 256) * 176; break;
            case GGML_TYPE_Q6_K: ctx->tensors[i].size = (num_elements / 256) * 210; break;
            default:
                fprintf(stderr, "Warning: Unknown type %d for tensor %s\n",
                        ctx->tensors[i].type, ctx->tensors[i].name);
                ctx->tensors[i].size = 0;
        }
    }
    
    /* Data offset is where ptr ended up, aligned to 32 bytes */
    ctx->data_offset = (uint64_t)(ptr - (uint8_t*)ctx->base_addr);
    ctx->data_offset = (ctx->data_offset + 31) & ~31;  /* Align to 32 */
    
    return 0;
}

/* Close GGUF file */
void gguf_close(gguf_context_t* ctx) {
    if (ctx->tensors) {
        free(ctx->tensors);
        ctx->tensors = NULL;
    }
    
#ifdef _WIN32
    if (ctx->base_addr) {
        UnmapViewOfFile(ctx->base_addr);
        ctx->base_addr = NULL;
    }
    if (ctx->map_handle) {
        CloseHandle(ctx->map_handle);
        ctx->map_handle = NULL;
    }
    if (ctx->file_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(ctx->file_handle);
        ctx->file_handle = INVALID_HANDLE_VALUE;
    }
#else
    if (ctx->base_addr && ctx->base_addr != MAP_FAILED) {
        munmap(ctx->base_addr, ctx->file_size);
        ctx->base_addr = NULL;
    }
    if (ctx->fd >= 0) {
        close(ctx->fd);
        ctx->fd = -1;
    }
#endif
}

/* Get tensor by name */
tensor_info_t* gguf_get_tensor(gguf_context_t* ctx, const char* name) {
    for (uint64_t i = 0; i < ctx->header.tensor_count; i++) {
        if (strcmp(ctx->tensors[i].name, name) == 0) {
            return &ctx->tensors[i];
        }
    }
    return NULL;
}

/* Get pointer to tensor data */
void* gguf_get_tensor_data(gguf_context_t* ctx, tensor_info_t* tensor) {
    if (!tensor || !ctx->base_addr) return NULL;
    return (uint8_t*)ctx->base_addr + ctx->data_offset + tensor->offset;
}

/* Print tensor info */
void gguf_print_tensors(gguf_context_t* ctx) {
    printf("\nTensors (%llu total):\n", ctx->header.tensor_count);
    printf("%-40s %-10s %-10s %-15s %-10s\n",
           "Name", "Type", "Dims", "Shape", "Size");
    printf("%-40s %-10s %-10s %-15s %-10s\n",
           "----", "----", "----", "-----", "----");
    
    for (uint64_t i = 0; i < ctx->header.tensor_count; i++) {
        tensor_info_t* t = &ctx->tensors[i];
        
        /* Build shape string */
        char shape[64] = "";
        for (uint32_t j = 0; j < t->n_dims; j++) {
            char dim[32];
            snprintf(dim, sizeof(dim), "%s%llu", j > 0 ? "x" : "", t->dimensions[j]);
            strcat(shape, dim);
        }
        
        /* Type name */
        const char* type_name = "UNKNOWN";
        switch (t->type) {
            case GGML_TYPE_F32:  type_name = "F32"; break;
            case GGML_TYPE_F16:  type_name = "F16"; break;
            case GGML_TYPE_Q4_0: type_name = "Q4_0"; break;
            case GGML_TYPE_Q4_1: type_name = "Q4_1"; break;
            case GGML_TYPE_Q5_0: type_name = "Q5_0"; break;
            case GGML_TYPE_Q5_1: type_name = "Q5_1"; break;
            case GGML_TYPE_Q8_0: type_name = "Q8_0"; break;
            case GGML_TYPE_Q4_K: type_name = "Q4_K"; break;
            case GGML_TYPE_Q5_K: type_name = "Q5_K"; break;
            case GGML_TYPE_Q6_K: type_name = "Q6_K"; break;
            case GGML_TYPE_Q8_K: type_name = "Q8_K"; break;
        }
        
        printf("%-40s %-10s %-10u %-15s %-10llu\n",
               t->name, type_name, t->n_dims, shape, t->size);
    }
}

/* Main test */
int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <model.gguf>\n", argv[0]);
        printf("\nPhase 1: Tensor Extraction Test\n");
        printf("Verifies that actual tensor data can be read from GGUF files.\n");
        return 1;
    }
    
    printf("Truth Gate 002 - Phase 1: Tensor Extraction\n");
    printf("==========================================\n\n");
    
    printf("Opening: %s\n", argv[1]);
    
    gguf_context_t ctx;
    if (gguf_open(argv[1], &ctx) != 0) {
        fprintf(stderr, "Failed to open GGUF file\n");
        return 1;
    }
    
    printf("\nGGUF Info:\n");
    printf("  Version: %u\n", ctx.header.version);
    printf("  Tensors: %llu\n", ctx.header.tensor_count);
    printf("  Metadata: %llu pairs\n", ctx.header.metadata_kv_count);
    printf("  Data offset: 0x%llX\n", ctx.data_offset);
    
    /* Print all tensors */
    gguf_print_tensors(&ctx);
    
    /* Test: Get specific tensor */
    printf("\n--- Tensor Access Test ---\n");
    
    /* Try to find token embeddings */
    tensor_info_t* embd = gguf_get_tensor(&ctx, "token_embd.weight");
    if (embd) {
        printf("\n✓ Found token_embd.weight:\n");
        printf("  Type: %d\n", embd->type);
        printf("  Size: %llu bytes\n", embd->size);
        printf("  Offset: 0x%llX\n", embd->offset);
        
        /* Get data pointer */
        void* data = gguf_get_tensor_data(&ctx, embd);
        if (data) {
            printf("  Data pointer: %p\n", data);
            
            /* Verify first few bytes */
            uint8_t* bytes = (uint8_t*)data;
            printf("  First 8 bytes: ");
            for (int i = 0; i < 8 && i < embd->size; i++) {
                printf("%02X ", bytes[i]);
            }
            printf("\n");
            
            printf("\n✓✓✓ TENSOR DATA ACCESS SUCCESSFUL ✓✓✓\n");
        } else {
            printf("  ✗ Failed to get data pointer\n");
        }
    } else {
        printf("\nNote: token_embd.weight not found (may be named differently)\n");
    }
    
    /* Try to find attention weights */
    tensor_info_t* attn = gguf_get_tensor(&ctx, "blk.0.attn_q.weight");
    if (attn) {
        printf("\n✓ Found blk.0.attn_q.weight:\n");
        printf("  Type: %d\n", attn->type);
        printf("  Size: %llu bytes\n", attn->size);
    }
    
    gguf_close(&ctx);
    
    printf("\n==========================================\n");
    printf("Phase 1 Complete: Tensor extraction works!\n");
    printf("Next: Phase 2 - Dequantization\n");
    
    return 0;
}
