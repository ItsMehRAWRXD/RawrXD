/*
 * Native GGUF Loader - Zero Dependencies
 * Pure C implementation for loading GGUF models without any external libraries
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#define PATH_SEP '\\'
#else
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#define PATH_SEP '/'
#endif

// GGUF Magic number
#define GGUF_MAGIC 0x46554747  // "GGUF" in little-endian
#define GGUF_VERSION 3

// GGML types
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
    GGML_TYPE_IQ4_NL = 16,
    GGML_TYPE_IQ4_XS = 17,
    GGML_TYPE_COUNT
};

// GGUF metadata types
enum gguf_metadata_type {
    GGUF_METADATA_TYPE_UINT8   = 0,
    GGUF_METADATA_TYPE_INT8     = 1,
    GGUF_METADATA_TYPE_UINT16   = 2,
    GGUF_METADATA_TYPE_INT16    = 3,
    GGUF_METADATA_TYPE_UINT32   = 4,
    GGUF_METADATA_TYPE_INT32    = 5,
    GGUF_METADATA_TYPE_FLOAT32  = 6,
    GGUF_METADATA_TYPE_BOOL     = 7,
    GGUF_METADATA_TYPE_STRING   = 8,
    GGUF_METADATA_TYPE_ARRAY    = 9,
    GGUF_METADATA_TYPE_UINT64   = 10,
    GGUF_METADATA_TYPE_INT64    = 11,
    GGUF_METADATA_TYPE_FLOAT64  = 12,
    GGUF_METADATA_TYPE_COUNT
};

// Tensor information
struct gguf_tensor_info {
    char name[256];
    uint32_t n_dims;
    uint64_t dims[4];
    enum ggml_type type;
    uint64_t offset;
    size_t size;
    void* data;
    int loaded;
};

// Model architecture types
enum model_arch {
    ARCH_UNKNOWN = 0,
    ARCH_LLAMA   = 1,
    ARCH_QWEN2   = 2,
    ARCH_PHI3    = 3,
    ARCH_GEMMA   = 4,
    ARCH_MISTRAL = 5
};

// Model metadata
struct model_metadata {
    enum model_arch arch;
    uint32_t vocab_size;
    uint32_t context_length;
    uint32_t embedding_dim;
    uint32_t layer_count;
    uint32_t head_count;
    uint32_t kv_head_count;
    uint32_t feed_forward_length;
    float rope_theta;
    float rope_scale;
    int use_gqa;
    int use_rope;
};

// GGUF file handle
struct gguf_file {
    FILE* fp;
    void* mmap_addr;
    size_t file_size;
    uint64_t tensor_count;
    uint64_t metadata_kv_count;
    uint64_t tensor_data_offset;
    struct gguf_tensor_info* tensors;
    struct model_metadata metadata;
    char** vocab;
    uint32_t vocab_size;
};

// Type size lookup
static size_t get_type_size(enum ggml_type type) {
    switch (type) {
        case GGML_TYPE_F32:  return 4;
        case GGML_TYPE_F16:  return 2;
        case GGML_TYPE_Q4_0: return 18;  // 32 elements per block
        case GGML_TYPE_Q4_1: return 20;
        case GGML_TYPE_Q5_0: return 22;
        case GGML_TYPE_Q5_1: return 24;
        case GGML_TYPE_Q8_0: return 34;
        case GGML_TYPE_Q8_1: return 36;
        case GGML_TYPE_Q2_K: return 96;  // 256 elements
        case GGML_TYPE_Q3_K: return 110;
        case GGML_TYPE_Q4_K: return 144;
        case GGML_TYPE_Q5_K: return 176;
        case GGML_TYPE_Q6_K: return 210;
        case GGML_TYPE_Q8_K: return 292;
        case GGML_TYPE_IQ4_NL: return 18;
        case GGML_TYPE_IQ4_XS: return 22;
        default: return 1;
    }
}

// Calculate tensor size
static size_t calculate_tensor_size(const struct gguf_tensor_info* info) {
    uint64_t num_elements = 1;
    for (uint32_t i = 0; i < info->n_dims; i++) {
        num_elements *= info->dims[i];
    }
    
    size_t type_size = get_type_size(info->type);
    
    // Quantized types have block-based sizing
    switch (info->type) {
        case GGML_TYPE_Q4_0:
        case GGML_TYPE_Q4_1:
        case GGML_TYPE_Q5_0:
        case GGML_TYPE_Q5_1:
        case GGML_TYPE_Q8_0:
        case GGML_TYPE_Q8_1:
        case GGML_TYPE_IQ4_NL:
        case GGML_TYPE_IQ4_XS:
            return (num_elements / 32) * type_size + (num_elements % 32 ? type_size : 0);
        case GGML_TYPE_Q2_K:
        case GGML_TYPE_Q3_K:
        case GGML_TYPE_Q4_K:
        case GGML_TYPE_Q5_K:
        case GGML_TYPE_Q6_K:
        case GGML_TYPE_Q8_K:
            return (num_elements / 256) * type_size + (num_elements % 256 ? type_size : 0);
        default:
            return num_elements * type_size;
    }
}

// Read little-endian values
static int read_u8(FILE* fp, uint8_t* val) {
    return fread(val, 1, 1, fp) == 1;
}

static int read_u32(FILE* fp, uint32_t* val) {
    uint8_t buf[4];
    if (fread(buf, 1, 4, fp) != 4) return 0;
    *val = (uint32_t)buf[0] | ((uint32_t)buf[1] << 8) |
           ((uint32_t)buf[2] << 16) | ((uint32_t)buf[3] << 24);
    return 1;
}

static int read_u64(FILE* fp, uint64_t* val) {
    uint8_t buf[8];
    if (fread(buf, 1, 8, fp) != 8) return 0;
    *val = (uint64_t)buf[0] | ((uint64_t)buf[1] << 8) |
           ((uint64_t)buf[2] << 16) | ((uint64_t)buf[3] << 24) |
           ((uint64_t)buf[4] << 32) | ((uint64_t)buf[5] << 40) |
           ((uint64_t)buf[6] << 48) | ((uint64_t)buf[7] << 56);
    return 1;
}

static int read_f32(FILE* fp, float* val) {
    uint32_t u32;
    if (!read_u32(fp, &u32)) return 0;
    memcpy(val, &u32, sizeof(float));
    return 1;
}

// Read string
static int read_string(FILE* fp, char* buf, size_t max_len) {
    uint64_t len;
    if (!read_u64(fp, &len)) return 0;
    if (len >= max_len) {
        // Skip if too long
        fseek(fp, (long)len, SEEK_CUR);
        buf[0] = '\0';
        return 1;
    }
    if (fread(buf, 1, (size_t)len, fp) != len) return 0;
    buf[len] = '\0';
    return 1;
}

// Parse metadata value
static int parse_metadata_value(FILE* fp, enum gguf_metadata_type type, void** out_val, size_t* out_size) {
    switch (type) {
        case GGUF_METADATA_TYPE_UINT8: {
            uint8_t* val = malloc(sizeof(uint8_t));
            if (!read_u8(fp, val)) { free(val); return 0; }
            *out_val = val;
            *out_size = sizeof(uint8_t);
            return 1;
        }
        case GGUF_METADATA_TYPE_INT32: {
            int32_t* val = malloc(sizeof(int32_t));
            uint32_t u32;
            if (!read_u32(fp, &u32)) { free(val); return 0; }
            *val = (int32_t)u32;
            *out_val = val;
            *out_size = sizeof(int32_t);
            return 1;
        }
        case GGUF_METADATA_TYPE_UINT32: {
            uint32_t* val = malloc(sizeof(uint32_t));
            if (!read_u32(fp, val)) { free(val); return 0; }
            *out_val = val;
            *out_size = sizeof(uint32_t);
            return 1;
        }
        case GGUF_METADATA_TYPE_FLOAT32: {
            float* val = malloc(sizeof(float));
            if (!read_f32(fp, val)) { free(val); return 0; }
            *out_val = val;
            *out_size = sizeof(float);
            return 1;
        }
        case GGUF_METADATA_TYPE_STRING: {
            uint64_t len;
            if (!read_u64(fp, &len)) return 0;
            char* str = malloc((size_t)len + 1);
            if (fread(str, 1, (size_t)len, fp) != len) { free(str); return 0; }
            str[len] = '\0';
            *out_val = str;
            *out_size = (size_t)len + 1;
            return 1;
        }
        case GGUF_METADATA_TYPE_ARRAY: {
            // Skip array data for now
            uint32_t elem_type;
            if (!read_u32(fp, &elem_type)) return 0;
            uint64_t count;
            if (!read_u64(fp, &count)) return 0;
            // Skip elements
            for (uint64_t i = 0; i < count; i++) {
                if (!parse_metadata_value(fp, elem_type, out_val, out_size)) return 0;
                free(*out_val);
            }
            *out_val = NULL;
            *out_size = 0;
            return 1;
        }
        default: {
            // Skip unknown types
            return 0;
        }
    }
}

// Detect architecture from tensor names
static enum model_arch detect_arch_from_tensors(struct gguf_file* gf) {
    int has_qwen = 0, has_phi = 0, has_gemma = 0, has_llama = 0;
    
    for (uint64_t i = 0; i < gf->tensor_count; i++) {
        const char* name = gf->tensors[i].name;
        if (strstr(name, "qwen")) has_qwen = 1;
        if (strstr(name, "phi")) has_phi = 1;
        if (strstr(name, "gemma")) has_gemma = 1;
        if (strstr(name, "llama") || strstr(name, "blk.")) has_llama = 1;
    }
    
    if (has_qwen) return ARCH_QWEN2;
    if (has_phi) return ARCH_PHI3;
    if (has_gemma) return ARCH_GEMMA;
    if (has_llama) return ARCH_LLAMA;
    return ARCH_UNKNOWN;
}

// Open GGUF file
struct gguf_file* gguf_open(const char* filepath) {
    struct gguf_file* gf = calloc(1, sizeof(struct gguf_file));
    if (!gf) return NULL;
    
    gf->fp = fopen(filepath, "rb");
    if (!gf->fp) {
        free(gf);
        return NULL;
    }
    
    // Get file size
    fseek(gf->fp, 0, SEEK_END);
    gf->file_size = ftell(gf->fp);
    fseek(gf->fp, 0, SEEK_SET);
    
    // Read header
    uint32_t magic;
    if (!read_u32(gf->fp, &magic) || magic != GGUF_MAGIC) {
        fprintf(stderr, "Invalid GGUF magic: 0x%08X\n", magic);
        fclose(gf->fp);
        free(gf);
        return NULL;
    }
    
    uint32_t version;
    if (!read_u32(gf->fp, &version)) {
        fclose(gf->fp);
        free(gf);
        return NULL;
    }
    
    if (!read_u64(gf->fp, &gf->tensor_count)) {
        fclose(gf->fp);
        free(gf);
        return NULL;
    }
    
    if (!read_u64(gf->fp, &gf->metadata_kv_count)) {
        fclose(gf->fp);
        free(gf);
        return NULL;
    }
    
    // Parse metadata
    for (uint64_t i = 0; i < gf->metadata_kv_count; i++) {
        char key[256];
        if (!read_string(gf->fp, key, sizeof(key))) continue;
        
        uint32_t type_val;
        if (!read_u32(gf->fp, &type_val)) continue;
        
        void* val = NULL;
        size_t val_size = 0;
        parse_metadata_value(gf->fp, type_val, &val, &val_size);
        
        // Extract important metadata
        if (strcmp(key, "general.architecture") == 0 && val) {
            const char* arch_str = (const char*)val;
            if (strstr(arch_str, "qwen")) gf->metadata.arch = ARCH_QWEN2;
            else if (strstr(arch_str, "phi")) gf->metadata.arch = ARCH_PHI3;
            else if (strstr(arch_str, "gemma")) gf->metadata.arch = ARCH_GEMMA;
            else if (strstr(arch_str, "llama")) gf->metadata.arch = ARCH_LLAMA;
            else if (strstr(arch_str, "mistral")) gf->metadata.arch = ARCH_MISTRAL;
        }
        else if (strcmp(key, "llama.vocab_size") == 0 || strcmp(key, "qwen2.vocab_size") == 0) {
            if (val) gf->metadata.vocab_size = *(uint32_t*)val;
        }
        else if (strcmp(key, "llama.context_length") == 0 || strcmp(key, "qwen2.context_length") == 0) {
            if (val) gf->metadata.context_length = *(uint32_t*)val;
        }
        else if (strcmp(key, "llama.embedding_length") == 0 || strcmp(key, "qwen2.embedding_length") == 0) {
            if (val) gf->metadata.embedding_dim = *(uint32_t*)val;
        }
        else if (strcmp(key, "llama.block_count") == 0 || strcmp(key, "qwen2.block_count") == 0) {
            if (val) gf->metadata.layer_count = *(uint32_t*)val;
        }
        else if (strcmp(key, "llama.attention.head_count") == 0) {
            if (val) gf->metadata.head_count = *(uint32_t*)val;
        }
        else if (strcmp(key, "llama.attention.head_count_kv") == 0) {
            if (val) gf->metadata.kv_head_count = *(uint32_t*)val;
            gf->metadata.use_gqa = 1;
        }
        else if (strcmp(key, "llama.rope.freq_base") == 0) {
            if (val) gf->metadata.rope_theta = *(float*)val;
            gf->metadata.use_rope = 1;
        }
        
        free(val);
    }
    
    // Allocate tensor array
    gf->tensors = calloc(gf->tensor_count, sizeof(struct gguf_tensor_info));
    if (!gf->tensors) {
        fclose(gf->fp);
        free(gf);
        return NULL;
    }
    
    // Parse tensor info
    for (uint64_t i = 0; i < gf->tensor_count; i++) {
        struct gguf_tensor_info* ti = &gf->tensors[i];
        
        // Read tensor name
        uint64_t name_len;
        if (!read_u64(gf->fp, &name_len) || name_len >= sizeof(ti->name)) {
            fclose(gf->fp);
            free(gf->tensors);
            free(gf);
            return NULL;
        }
        if (fread(ti->name, 1, (size_t)name_len, gf->fp) != name_len) {
            fclose(gf->fp);
            free(gf->tensors);
            free(gf);
            return NULL;
        }
        ti->name[name_len] = '\0';
        
        // Read dimensions
        if (!read_u32(gf->fp, &ti->n_dims)) {
            fclose(gf->fp);
            free(gf->tensors);
            free(gf);
            return NULL;
        }
        
        for (uint32_t j = 0; j < ti->n_dims; j++) {
            if (!read_u64(gf->fp, &ti->dims[j])) {
                fclose(gf->fp);
                free(gf->tensors);
                free(gf);
                return NULL;
            }
        }
        
        // Read type
        uint32_t type_val;
        if (!read_u32(gf->fp, &type_val)) {
            fclose(gf->fp);
            free(gf->tensors);
            free(gf);
            return NULL;
        }
        ti->type = (enum ggml_type)type_val;
        
        // Read offset
        if (!read_u64(gf->fp, &ti->offset)) {
            fclose(gf->fp);
            free(gf->tensors);
            free(gf);
            return NULL;
        }
        
        // Calculate size
        ti->size = calculate_tensor_size(ti);
        ti->data = NULL;
        ti->loaded = 0;
    }
    
    // Calculate tensor data offset (aligned to 32 bytes)
    gf->tensor_data_offset = (uint64_t)ftell(gf->fp);
    gf->tensor_data_offset = (gf->tensor_data_offset + 31) & ~31;
    
    // Detect architecture if not set
    if (gf->metadata.arch == ARCH_UNKNOWN) {
        gf->metadata.arch = detect_arch_from_tensors(gf);
    }
    
    // Set defaults for missing metadata
    if (gf->metadata.vocab_size == 0) gf->metadata.vocab_size = 32000;
    if (gf->metadata.context_length == 0) gf->metadata.context_length = 4096;
    if (gf->metadata.embedding_dim == 0) gf->metadata.embedding_dim = 4096;
    if (gf->metadata.layer_count == 0) gf->metadata.layer_count = 32;
    if (gf->metadata.head_count == 0) gf->metadata.head_count = 32;
    if (gf->metadata.kv_head_count == 0) gf->metadata.kv_head_count = gf->metadata.head_count;
    if (gf->metadata.rope_theta == 0.0f) gf->metadata.rope_theta = 10000.0f;
    
    printf("[GGUF] Loaded: %s\n", filepath);
    printf("[GGUF] Architecture: %d, Vocab: %u, Context: %u, Layers: %u\n",
           gf->metadata.arch, gf->metadata.vocab_size, gf->metadata.context_length, gf->metadata.layer_count);
    printf("[GGUF] Tensors: %llu\n", (unsigned long long)gf->tensor_count);
    
    return gf;
}

// Load a specific tensor
int gguf_load_tensor(struct gguf_file* gf, uint64_t tensor_idx) {
    if (!gf || !gf->fp || tensor_idx >= gf->tensor_count) return 0;
    
    struct gguf_tensor_info* ti = &gf->tensors[tensor_idx];
    if (ti->loaded) return 1;
    
    // Allocate memory for tensor data
    ti->data = malloc(ti->size);
    if (!ti->data) return 0;
    
    // Seek to tensor data
    uint64_t data_offset = gf->tensor_data_offset + ti->offset;
    if (fseek(gf->fp, (long)data_offset, SEEK_SET) != 0) {
        free(ti->data);
        ti->data = NULL;
        return 0;
    }
    
    // Read tensor data
    if (fread(ti->data, 1, ti->size, gf->fp) != ti->size) {
        free(ti->data);
        ti->data = NULL;
        return 0;
    }
    
    ti->loaded = 1;
    return 1;
}

// Load tensor by name
int gguf_load_tensor_by_name(struct gguf_file* gf, const char* name) {
    if (!gf) return 0;
    
    for (uint64_t i = 0; i < gf->tensor_count; i++) {
        if (strcmp(gf->tensors[i].name, name) == 0) {
            return gguf_load_tensor(gf, i);
        }
    }
    return 0;
}

// Get tensor info
const struct gguf_tensor_info* gguf_get_tensor(struct gguf_file* gf, uint64_t idx) {
    if (!gf || idx >= gf->tensor_count) return NULL;
    return &gf->tensors[idx];
}

// Get tensor by name
const struct gguf_tensor_info* gguf_find_tensor(struct gguf_file* gf, const char* name) {
    if (!gf) return NULL;
    
    for (uint64_t i = 0; i < gf->tensor_count; i++) {
        if (strcmp(gf->tensors[i].name, name) == 0) {
            return &gf->tensors[i];
        }
    }
    return NULL;
}

// Get metadata
const struct model_metadata* gguf_get_metadata(struct gguf_file* gf) {
    if (!gf) return NULL;
    return &gf->metadata;
}

// Close GGUF file
void gguf_close(struct gguf_file* gf) {
    if (!gf) return;
    
    // Free tensor data
    if (gf->tensors) {
        for (uint64_t i = 0; i < gf->tensor_count; i++) {
            if (gf->tensors[i].data) {
                free(gf->tensors[i].data);
            }
        }
        free(gf->tensors);
    }
    
    // Free vocab
    if (gf->vocab) {
        for (uint32_t i = 0; i < gf->vocab_size; i++) {
            free(gf->vocab[i]);
        }
        free(gf->vocab);
    }
    
    // Close file
    if (gf->fp) {
        fclose(gf->fp);
    }
    
    free(gf);
}

// Get total loaded memory
size_t gguf_get_loaded_memory(struct gguf_file* gf) {
    if (!gf) return 0;
    
    size_t total = 0;
    for (uint64_t i = 0; i < gf->tensor_count; i++) {
        if (gf->tensors[i].loaded) {
            total += gf->tensors[i].size;
        }
    }
    return total;
}

// Get total model size
size_t gguf_get_total_size(struct gguf_file* gf) {
    if (!gf) return 0;
    
    size_t total = 0;
    for (uint64_t i = 0; i < gf->tensor_count; i++) {
        total += gf->tensors[i].size;
    }
    return total;
}

// Load all tensors
int gguf_load_all_tensors(struct gguf_file* gf) {
    if (!gf) return 0;
    
    int success = 1;
    for (uint64_t i = 0; i < gf->tensor_count; i++) {
        if (!gguf_load_tensor(gf, i)) {
            success = 0;
        }
    }
    return success;
}

// Unload a tensor to free memory
void gguf_unload_tensor(struct gguf_file* gf, uint64_t tensor_idx) {
    if (!gf || tensor_idx >= gf->tensor_count) return;
    
    struct gguf_tensor_info* ti = &gf->tensors[tensor_idx];
    if (ti->data) {
        free(ti->data);
        ti->data = NULL;
        ti->loaded = 0;
    }
}

// Print model info
void gguf_print_info(struct gguf_file* gf) {
    if (!gf) return;
    
    printf("=== GGUF Model Info ===\n");
    printf("File size: %zu bytes (%.2f MB)\n", gf->file_size, gf->file_size / (1024.0 * 1024.0));
    printf("Tensor count: %llu\n", (unsigned long long)gf->tensor_count);
    printf("Metadata entries: %llu\n", (unsigned long long)gf->metadata_kv_count);
    printf("\n");
    
    const char* arch_names[] = {"unknown", "llama", "qwen2", "phi3", "gemma", "mistral"};
    printf("Architecture: %s\n", arch_names[gf->metadata.arch]);
    printf("Vocab size: %u\n", gf->metadata.vocab_size);
    printf("Context length: %u\n", gf->metadata.context_length);
    printf("Embedding dim: %u\n", gf->metadata.embedding_dim);
    printf("Layer count: %u\n", gf->metadata.layer_count);
    printf("Head count: %u\n", gf->metadata.head_count);
    printf("KV head count: %u\n", gf->metadata.kv_head_count);
    printf("RoPE theta: %f\n", gf->metadata.rope_theta);
    printf("\n");
    
    printf("Tensors:\n");
    for (uint64_t i = 0; i < gf->tensor_count && i < 20; i++) {
        struct gguf_tensor_info* ti = &gf->tensors[i];
        printf("  [%llu] %s: type=%d, dims=[", (unsigned long long)i, ti->name, ti->type);
        for (uint32_t j = 0; j < ti->n_dims; j++) {
            printf("%llu%s", (unsigned long long)ti->dims[j], j < ti->n_dims - 1 ? ", " : "");
        }
        printf("], size=%zu, loaded=%s\n", ti->size, ti->loaded ? "yes" : "no");
    }
    if (gf->tensor_count > 20) {
        printf("  ... and %llu more tensors\n", (unsigned long long)(gf->tensor_count - 20));
    }
    
    size_t loaded = gguf_get_loaded_memory(gf);
    size_t total = gguf_get_total_size(gf);
    printf("\nMemory: %zu / %zu bytes loaded (%.1f%%)\n", loaded, total, 100.0 * loaded / total);
}

// Test main
#ifdef TEST_GGUF_LOADER
int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <model.gguf>\n", argv[0]);
        return 1;
    }
    
    struct gguf_file* gf = gguf_open(argv[1]);
    if (!gf) {
        fprintf(stderr, "Failed to open %s\n", argv[1]);
        return 1;
    }
    
    gguf_print_info(gf);
    
    // Load first few tensors as test
    printf("\nLoading first 5 tensors...\n");
    for (uint64_t i = 0; i < 5 && i < gf->tensor_count; i++) {
        if (gguf_load_tensor(gf, i)) {
            printf("  Loaded: %s (%zu bytes)\n", gf->tensors[i].name, gf->tensors[i].size);
        } else {
            printf("  Failed to load: %s\n", gf->tensors[i].name);
        }
    }
    
    printf("\nTotal loaded: %zu bytes\n", gguf_get_loaded_memory(gf));
    
    gguf_close(gf);
    return 0;
}
#endif
